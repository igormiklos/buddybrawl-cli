#!/usr/bin/env node
import * as fs from "fs";
import * as path from "path";
import * as os from "os";
import { fileURLToPath } from "url";
import { execSync } from "child_process";
import { createHash, randomBytes } from "crypto";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const PKG_VERSION = JSON.parse(fs.readFileSync(path.join(__dirname, "../package.json"), "utf8")).version;

const CONFIG_DIR  = path.join(os.homedir(), ".buddybrawl");
const CONFIG_FILE = path.join(CONFIG_DIR, "config.json");
const HOOK_DEST   = path.join(CONFIG_DIR, "buddy-sync.mjs");
const CLAUDE_SETTINGS = path.join(os.homedir(), ".claude", "settings.json");

// Canonical owned domain. Deliberately NOT the *.vercel.app subdomain: that one
// is Vercel's to reclaim, and every published CLI hardcodes this host, so a lost
// subdomain would break `npx buddybrawl init` for installs we can't update.
const PROD_HOST = "www.buddybrawl.xyz";

// Per-install identifier for token binding (a stolen config.json won't work elsewhere
// without also copying this ID — and copying both is equivalent to copying the install).
// Random, minted at init, stored in config.json next to the token it binds. It is
// deliberately NOT derived from hostname/username: macOS rewrites the kernel hostname
// from DHCP/mDNS as laptops move between networks, which flipped the old derived ID
// and 403-killed every sync until re-init; os.userInfo() can also throw on containers
// with unmapped UIDs. The hook has no derivation fallback either — that legacy
// hostname-hash path was deleted on 2026-08-15 (see getMachineId in buddy-sync.mjs);
// a config without this value is refused rather than synced under a weaker identifier.
function mintMachineId() {
  return randomBytes(16).toString("hex");
}

// Local-only salt for the file-path tokens the hook sends. Deliberately NOT the
// machineId: that one is transmitted on every sync and recorded server-side, so
// salting with it would still let anyone holding the database hash a guessed path
// and confirm it. This value never leaves the machine, which is what makes those
// tokens genuinely opaque rather than a lookup table.
function mintPathSalt() {
  return randomBytes(16).toString("hex");
}

// Re-running init mints a new token and leaves the old one usable forever unless
// we say so. Returns sha256 of the token this run is about to replace, so the
// server can retire that row. The raw secret is deliberately never sent here —
// it belongs to the sync endpoint, and hashing keeps this host from ever seeing
// a working credential. Returns null on a first install or an unreadable config.
function previousTokenHash() {
  try {
    const prev = JSON.parse(fs.readFileSync(CONFIG_FILE, "utf8"));
    if (typeof prev?.syncSecret !== "string" || !prev.syncSecret) return null;
    return createHash("sha256").update(prev.syncSecret).digest("hex");
  } catch {
    return null;
  }
}

// Require https for all apiUrls (protects against http token+data leakage and malicious redirects).
// For self-hosted use --api-url must still be https; local testing users can edit config.json.
//
// Also reject userinfo, a query and a fragment — the same three the hook rejects, and
// for the same reason: the sync URL is built by appending a path to this value, so a
// query string swallows the function path and sends the secret to the site root, and
// credentials in the URL end up printed to the terminal and stored in config.json.
// Keep this in sync with isValidHttpsUrl in hooks/buddy-sync.mjs.
function isValidHttpsUrl(u) {
  if (typeof u !== "string") return false;
  try {
    const url = new URL(u);
    if (url.protocol !== "https:") return false;
    if (url.username || url.password) return false;
    if (url.search || url.hash) return false;
    return true;
  } catch {
    return false;
  }
}

// Hosts a *server-supplied* apiUrl must never point at.
//
// `https://` is the only thing that used to gate the endpoint, so a compromised
// /api/init-config could hand back https://192.168.1.5 or https://169.254.169.254 and
// every later sync would POST the token and session data there — reaching inside the
// user's own network from their machine. That is a different kind of harm from "the
// config host is malicious and takes your data", which is a trust you accept by running
// init at all: this one turns the hook into an SSRF probe on a network the operator of
// that endpoint cannot otherwise touch. Raised by the 2026-08-15 external audit, which
// found loopback, RFC1918, IPv6 and cloud-metadata targets all accepted.
//
// Deliberately NOT applied to an apiUrl the user passed with --api-url, or to one they
// hand-edited into config.json: self-hosting against localhost is a documented workflow
// and their own decision. This guards the value that arrives over the network.
//
// Literal addresses and obvious local names only. A public hostname that *resolves* to a
// private address is not caught — that needs DNS resolution plus a re-check at connect
// time to be worth anything, which is not a trade a session-end hook should make. This
// closes the direct case, and does not claim to close DNS rebinding.
function isPrivateHost(hostname) {
  const h = String(hostname).toLowerCase().replace(/^\[|\]$/g, "").replace(/\.$/, "");
  if (!h) return true;

  // Local / internal names, plus any single-label host (never our production endpoint).
  if (h === "localhost" || /\.(localhost|local|internal|lan|home\.arpa)$/.test(h)) return true;

  // IPv4 literal, including the ::ffff:a.b.c.d mapped form.
  const v4 = /^(?:::ffff:)?(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(h);
  if (v4) {
    const [a, b] = v4.slice(1).map(Number);
    if (a === 0 || a === 10 || a === 127) return true;               // this-network, private, loopback
    if (a === 169 && b === 254) return true;                          // link-local (cloud metadata)
    if (a === 172 && b >= 16 && b <= 31) return true;                 // private
    if (a === 192 && b === 168) return true;                          // private
    if (a === 100 && b >= 64 && b <= 127) return true;                // CGNAT
    return false;
  }

  // IPv6 literal.
  if (h.includes(":")) {
    if (h === "::1" || h === "::") return true;                       // loopback, unspecified
    if (/^f[cd]/.test(h)) return true;                                // unique local fc00::/7
    if (/^fe[89ab]/.test(h)) return true;                             // link-local fe80::/10
    return false;
  }

  // A bare single-label hostname ("intranet", "supabase") is internal by definition.
  return !h.includes(".");
}

// ─── Settings.json helpers ───────────────────────────────────────────────────

function readSettings() {
  if (!fs.existsSync(CLAUDE_SETTINGS)) return {};
  let parsed;
  try {
    let raw = fs.readFileSync(CLAUDE_SETTINGS, "utf8");
    // Strip a UTF-8 BOM — Notepad and PowerShell on Windows write one by default.
    if (raw.charCodeAt(0) === 0xfeff) raw = raw.slice(1);
    parsed = JSON.parse(raw);
  } catch (e) {
    // The file exists but doesn't parse — writing would destroy the user's settings.
    console.error(`  ✗ ${CLAUDE_SETTINGS} exists but is not valid JSON (${e.message}).`);
    console.error("    Fix the file (or remove it), then re-run npx buddybrawl init.");
    process.exit(1);
  }
  // Valid JSON is not the same as a usable settings file. `null`, a bare string and a
  // number all parse cleanly and then blew up in addHook with an unhandled
  // "TypeError: Cannot read properties of null (reading 'hooks')" and a raw stack
  // trace; a top-level array parsed, took the hook as a non-index property, and lost
  // it silently at JSON.stringify. Give all of them the same friendly error the
  // unparseable branch already produces. Found by the 2026-08-15 audit.
  if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed)) {
    const kind = parsed === null ? "null" : Array.isArray(parsed) ? "an array" : `a ${typeof parsed}`;
    console.error(`  ✗ ${CLAUDE_SETTINGS} is valid JSON but contains ${kind}, not a settings object.`);
    console.error("    Fix the file (or remove it), then re-run npx buddybrawl init.");
    process.exit(1);
  }
  return parsed;
}

// Write via a temp file + rename, so the settings file is never observably truncated.
//
// writeFileSync truncates and then writes, which leaves a window where the file on disk
// is empty or half-written. Anyone reading it in that window sees invalid JSON — and
// that is not hypothetical: with two inits running at once, the second one read the
// first one's partial write and told the user "settings.json exists but is not valid
// JSON", blaming them for a file that was fine. Claude Code reads this same file at
// startup, so the torn read could just as easily have been a session losing every hook
// it has. rename is atomic: readers see either the old file or the new one.
function writeSettings(settings) {
  const dir = path.dirname(CLAUDE_SETTINGS);
  fs.mkdirSync(dir, { recursive: true });
  const tmp = `${CLAUDE_SETTINGS}.tmp-${process.pid}-${randomBytes(4).toString("hex")}`;
  try {
    fs.writeFileSync(tmp, JSON.stringify(settings, null, 2) + "\n");
    for (let attempt = 1; ; attempt++) {
      try {
        fs.renameSync(tmp, CLAUDE_SETTINGS);
        return;
      } catch (err) {
        if (attempt >= 3) throw err;
        sleepSync(120);
      }
    }
  } finally {
    if (fs.existsSync(tmp)) { try { fs.unlinkSync(tmp); } catch {} }
  }
}

// Escape embedded quotes in paths when embedding in the command string written to settings.json.
// This reduces (but does not eliminate) risk of malformed commands if homedir/execPath contains " (rare).
function escapeForHookCommand(str) {
  return String(str).replace(/"/g, '\\"');
}

const HOOK_COMMAND = `"${escapeForHookCommand(process.execPath)}" "${escapeForHookCommand(HOOK_DEST)}"`;

function hasHook(settings) {
  const stops = settings?.hooks?.Stop ?? [];
  return stops.some((entry) =>
    (entry.hooks ?? []).some((h) => h.command === HOOK_COMMAND)
  );
}

// Does this Stop entry point at OUR installed hook file?
//
// This used to be `h.command?.includes("buddy-sync")` — a bare substring test against
// the whole command line, which deleted any hook whose command merely contained that
// text. The 2026-08-15 external audit fed init a settings.json with two unrelated
// entries, `node ~/tools/buddy-sync-to-jira.js` and `/usr/local/bin/my-buddy-sync-backup
// --all`, and both were removed silently; the second took its `matcher: "src/**"` with
// it, because an entry left with an empty hooks array is dropped below. /privacy §01
// tells users init "adds exactly three things" and that deleting a folder and one line
// is "the whole uninstall" — neither is true if init also removes hooks it didn't write
// and cannot restore.
//
// Match on the destination path instead. That is still broader than an exact compare on
// HOOK_COMMAND, and deliberately so: the command embeds process.execPath, so switching
// Node (nvm/fnm) leaves a stale entry pointing at the same file with a different binary,
// and clearing that is the whole reason this cleanup exists. Nothing but our own
// installer ever writes that path.
function isOurHookCommand(command) {
  if (typeof command !== "string") return false;
  const norm = (s) => {
    const t = s.replace(/\\/g, "/");
    return process.platform === "win32" ? t.toLowerCase() : t;
  };
  return norm(command).includes(norm(HOOK_DEST));
}

function addHook(settings) {
  if (!settings.hooks) settings.hooks = {};
  if (!settings.hooks.Stop) settings.hooks.Stop = [];
  // Remove any stale entry pointing at our hook file before adding the current one.
  const removed = [];
  settings.hooks.Stop = settings.hooks.Stop.map((entry) => ({
    ...entry,
    hooks: (entry.hooks ?? []).filter((h) => {
      if (!isOurHookCommand(h.command)) return true;
      removed.push(h.command);
      return false;
    }),
  })).filter((entry) => (entry.hooks ?? []).length > 0);
  settings.hooks.Stop.push({
    matcher: "",
    hooks: [{ type: "command", command: HOOK_COMMAND }],
  });
  return { settings, removed };
}

// ─── Config security ─────────────────────────────────────────────────────────

function secureConfigPermissions() {
  if (process.platform !== "win32") {
    try {
      fs.chmodSync(CONFIG_DIR,  0o700);
      fs.chmodSync(CONFIG_FILE, 0o600);
      return { status: "secured" };
    } catch (err) {
      return { status: "failed", reason: err.code || err.message };
    }
  }

  // Windows: attempt icacls before giving up. Use %USERNAME% (expanded by cmd) but quote defensively.
  try {
    execSync(`icacls "${CONFIG_DIR}" /inheritance:r /grant:r "%USERNAME%:(F)" /T`, { stdio: "ignore" });
    return { status: "secured", method: "icacls" };
  } catch {
    return { status: "insecure", reason: "windows_no_acl" };
  }
}

// ─── Hook installation ───────────────────────────────────────────────────────

/** Synchronous sleep — this whole command is sync, and a retry needs a real pause. */
function sleepSync(ms) {
  Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, ms);
}

// Copy to a unique temp file in the destination directory, verify THAT, then rename
// into place. rename is atomic, so the registered path only ever holds a fully
// written, hash-checked file.
//
// The previous version copied straight onto HOOK_DEST and, if the re-read hash didn't
// match, unlinked HOOK_DEST. Correct for one process; destructive for two. The
// 2026-08-15 audit ran three inits concurrently, five times: the loser's copy tore,
// its verify failed, and its cleanup deleted the good file the winner had already
// installed and registered — leaving settings.json pointing at a missing hook in
// three of five trials, after another init had printed "✓ Sync script installed".
// Scoping the cleanup to a file this process created is what fixes it; the atomic
// rename is what stops a torn file being observable at the real path at all.
function installHook(hookSource, expectedHash) {
  const tmpDest = `${HOOK_DEST}.tmp-${process.pid}-${randomBytes(4).toString("hex")}`;
  try {
    fs.copyFileSync(hookSource, tmpDest);

    if (expectedHash) {
      const actual = createHash("sha256").update(fs.readFileSync(tmpDest)).digest("hex");
      if (actual !== expectedHash) {
        console.error("  ✗ Hook integrity check failed — the file written to disk does not match the published hash.");
        console.error("    The incomplete copy has been discarded and your existing install left untouched.");
        console.error("    Re-run npx buddybrawl init to retry.");
        process.exit(1);
      }
    }

    // Best-effort: lock down the executable hook script itself (owner only). Config is
    // more critical. Do it before the rename so the file is never briefly world-readable
    // at the path Claude Code executes.
    if (process.platform !== "win32") {
      try { fs.chmodSync(tmpDest, 0o700); } catch {}
    }

    // Windows can briefly hold a lock on the destination if a session-end hook is
    // reading it right now. Retry a couple of times before giving up with something
    // the user can act on.
    for (let attempt = 1; ; attempt++) {
      try {
        fs.renameSync(tmpDest, HOOK_DEST);
        return;
      } catch (err) {
        if (attempt >= 3) {
          console.error(`  ✗ Could not install the sync script (${err.code || err.message}).`);
          console.error("    A Claude Code session may be running the current hook right now.");
          console.error("    Close your Claude Code sessions, then re-run npx buddybrawl init.");
          process.exit(1);
        }
        sleepSync(120);
      }
    }
  } finally {
    // Only ever removes a temp file this process created — never the installed hook.
    if (fs.existsSync(tmpDest)) { try { fs.unlinkSync(tmpDest); } catch {} }
  }
}

// ─── Production config fetch ──────────────────────────────────────────────────

const CONFIG_ENDPOINT = `https://${PROD_HOST}/api/init-config`;

async function fetchProdConfig(machineId, previousTokenSha256) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), 8000);
  try {
    const res = await fetch(CONFIG_ENDPOINT, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "User-Agent": `buddybrawl-cli/${PKG_VERSION}`,
      },
      body: JSON.stringify({
        machineId,
        cliVersion: PKG_VERSION,
        ...(previousTokenSha256 ? { previousTokenSha256 } : {}),
      }),
      signal: controller.signal,
      // Same rule as the sync POST: never follow a redirect. This request carries the
      // hash of the token being retired and receives a working credential back, and
      // PROD_HOST is a fixed endpoint that has no reason to redirect. Following one
      // would also silently move the config host away from the one named in the banner
      // three lines above.
      redirect: "error",
    });
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const cfg = await res.json();
    // Server may return apiUrl (e.g. for flexibility); client forces https validation for safety.
    if (cfg && cfg.apiUrl && !isValidHttpsUrl(cfg.apiUrl)) {
      throw new Error("Non-HTTPS apiUrl in config response");
    }
    return cfg;
  } finally {
    clearTimeout(timer);
  }
}

// ─── Init command ────────────────────────────────────────────────────────────

function hr(label) {
  const line = "─".repeat(46);
  console.log(`\n${label ? `── ${label} ${"─".repeat(Math.max(0, 43 - label.length))}` : line}`);
}

async function cmdInit(flags = {}) {
  console.log("\n  BuddyBrawl — Setup");
  console.log("  Claude Code companion battle game\n");
  console.log("  ── What this hook collects ──────────────────────");
  console.log(`  Config is fetched once from ${PROD_HOST}.`);
  console.log("  After that, each session syncs to our Supabase");
  console.log("  API endpoint — printed below when setup finishes,");
  console.log("  and saved in ~/.buddybrawl/config.json:");
  console.log("    • git user.email and user.name");
  console.log("    • Anthropic companion name, species, and Anthropic");
  console.log("      user ID — plus the rarity and shiny flag, which");
  console.log("      are derived from that ID on your machine");
  console.log("    • Session stats: duration, tool call count,");
  console.log("      message count, and the names of the tools");
  console.log("      used (including any MCP tool names)");
  console.log("    • A count of files created or edited — paths are");
  console.log("      hashed to opaque tokens first, never the file or");
  console.log("      folder names themselves, plus the total count of");
  console.log("      distinct files and the total count of distinct");
  console.log("      tools so a big session's stats stay accurate");
  console.log("    • A random install ID, re-sent each sync so we can");
  console.log("      check the token is used from this machine (not");
  console.log("      derived from your hostname or username)");
  console.log("  No source code is ever transmitted.");
  console.log("  ─────────────────────────────────────────────────\n");

  // Read and validate ~/.claude/settings.json FIRST — before minting a token, before
  // telling the server to retire the old one, before touching the disk at all.
  //
  // It used to be read at the end, so every way this file can be unusable (comments,
  // a trailing comma, `null`, an array) exited 1 *after* config.json had been written
  // with a fresh token and after init had already asked the server to revoke the
  // previous one. That left a live config, a retired old token, a copied hook and no
  // registration: syncing silently stopped, and the file the user had to fix was the
  // one init refused to touch. Reading it here costs nothing and makes the failure
  // clean — nothing has changed yet. Found by the 2026-08-15 external audit.
  const settings = readSettings();

  let apiUrl     = flags.apiUrl;
  let syncSecret = flags.syncSecret;
  const machineId = mintMachineId();
  const pathSalt  = mintPathSalt();
  // Read before the config file is overwritten below.
  const prevTokenSha256 = previousTokenHash();
  let previousRevoked = false;

  if (!apiUrl || !syncSecret) {
    process.stdout.write("  Fetching config...");
    try {
      const config = await fetchProdConfig(machineId, prevTokenSha256);
      apiUrl     = apiUrl     || config.apiUrl;
      syncSecret = syncSecret || config.syncSecret;
      previousRevoked = config.previousRevoked === true;
      process.stdout.write(" done\n");
    } catch (e) {
      process.stdout.write(` failed (${e.message})\n`);
      const proxied = process.env.HTTPS_PROXY || process.env.https_proxy ||
        process.env.HTTP_PROXY || process.env.http_proxy;
      if (proxied) {
        console.error("  A proxy is configured in your environment, but Node's fetch does");
        console.error("  not route through proxy env vars, so BuddyBrawl cannot connect");
        console.error("  through an HTTP proxy. On Node 24+, retry with NODE_USE_ENV_PROXY=1;");
        console.error("  otherwise use a direct connection for this one-time setup.");
      } else {
        console.error(`  Could not reach ${PROD_HOST}. Check your internet connection and try again.`);
      }
      process.exit(1);
    }
  }

  // High-impact safety: never persist or use an endpoint that isn't a plain https base
  // URL (prevents token+data exfil to attacker servers, and the query-string misroute
  // described on isValidHttpsUrl).
  if (!isValidHttpsUrl(apiUrl)) {
    console.error("  ✗ Refusing this apiUrl. It must be an https:// base URL with no credentials, query string or fragment.");
    console.error("    If you are self-hosting for testing, run init then manually edit ~/.buddybrawl/config.json.");
    process.exit(1);
  }

  // A private or loopback target is fine when the user asked for it, and never fine when
  // the network chose it — see isPrivateHost.
  if (!flags.apiUrl && isPrivateHost(new URL(apiUrl).hostname)) {
    console.error(`  ✗ Refusing an endpoint on a private or loopback address (${new URL(apiUrl).hostname}).`);
    console.error(`    ${PROD_HOST} returned it, and syncs would be sent inside your own network.`);
    console.error("    Nothing was installed. If you meant to self-host, pass it yourself:");
    console.error("      npx buddybrawl init --api-url <url> --sync-secret <secret>");
    process.exit(1);
  }

  hr("Step 1: Sync hook");

  const hookSource = path.join(__dirname, "buddy-sync.mjs");
  if (!fs.existsSync(hookSource)) {
    console.error(`  buddy-sync.mjs not found at ${hookSource}`);
    process.exit(1);
  }

  fs.mkdirSync(CONFIG_DIR, { recursive: true, mode: 0o700 });

  // Verify the package file BEFORE copying it into place. Checking only after the
  // copy fails open: on a re-run over an existing install, ~/.buddybrawl/buddy-sync.mjs
  // is already registered in settings.json, so exiting without undoing the copy leaves
  // Claude Code executing a file that just failed its own hash check on every session.
  // Found by the 2026-08-15 external tarball audit, which corrupted the package hook
  // and watched the bad copy survive the failure.
  const integrityFile = path.join(__dirname, "hook-integrity.json");
  const expectedHash = fs.existsSync(integrityFile)
    ? JSON.parse(fs.readFileSync(integrityFile, "utf8")).sha256
    : null;
  if (expectedHash) {
    const sourceHash = createHash("sha256").update(fs.readFileSync(hookSource)).digest("hex");
    if (sourceHash !== expectedHash) {
      console.error("  ✗ Hook integrity check failed — package file does not match published hash.");
      console.error("    This may indicate a corrupted download. Re-run npx buddybrawl init to retry.");
      console.error("    Your existing install was left untouched.");
      process.exit(1);
    }
  }

  installHook(hookSource, expectedHash);
  console.log(`  ✓ Sync script installed`);

  // machineId is stored beside the token it binds — the hook sends it on every
  // sync, and the server only accepts this token+machineId pair together.
  // pathSalt sits here too but is the opposite kind of value: read by the hook,
  // never sent anywhere. Re-running init mints a fresh one, which is harmless —
  // the server only ever counts unique tokens within a single session.
  //
  // Written after the hook, not before: every failure above exits, and doing this
  // first meant a failed integrity check left a fresh token on disk with the previous
  // one already retired server-side.
  fs.writeFileSync(
    CONFIG_FILE,
    JSON.stringify({ apiUrl, syncSecret, machineId, pathSalt }, null, 2) + "\n",
    { mode: 0o600 },
  );
  if (previousRevoked) {
    console.log("  ✓ Previous install token revoked (this machine had an older one)");
  }
  // Harden once, now that BOTH files are in place. This used to run between the config
  // write and the hook copy, so `icacls ... /T` walked a directory the hook was not in
  // yet and the executable Claude Code runs every session was left out of the very
  // hardening the next line advertises. Noted by the 2026-08-15 audit.
  const sec = secureConfigPermissions();
  if (sec.status === "secured") {
    console.log(`  ✓ Config saved (owner-only access)`);
  } else if (sec.status === "insecure") {
    console.log(`  ✓ Config saved`);
    console.log("  ⚠  Windows: could not restrict file access. On shared machines, run:");
    console.log(`     icacls "${CONFIG_DIR}" /inheritance:r /grant:r "%USERNAME%":(F) /T`);
  } else {
    console.log(`  ✓ Config saved`);
    console.log(`  ⚠  Could not secure permissions (${sec.reason}). Keep this file private.`);
  }

  if (hasHook(settings)) {
    console.log("  ✓ Claude Code hook already registered");
  } else {
    const { settings: updated, removed } = addHook(settings);
    // Say what was taken out. Replacing a stale entry is correct; doing it silently is
    // what let the old substring match remove unrelated hooks without anyone noticing.
    for (const cmd of removed) {
      console.log(`  ✓ Replaced a previous BuddyBrawl hook entry (${cmd})`);
    }
    writeSettings(updated);
    // Re-read and verify the exact command was written (defense against write races or schema surprises).
    const verified = readSettings();
    if (!hasHook(verified)) {
      console.log("  ⚠ Hook registration written but verification read did not find it. Check ~/.claude/settings.json manually.");
    } else {
      console.log("  ✓ Claude Code Stop hook registered");
    }
  }

  hr("Step 2: Claude Code required");
  console.log("  BuddyBrawl only works with Claude Code.");
  console.log("  Your buddy is your real Claude Code companion — its name");
  console.log("  and species come from Claude Code; rarity is computed by BuddyBrawl.");
  console.log();
  console.log("  Already have Claude Code?");
  console.log("    → Start a NEW session (hooks load at startup, so a");
  console.log("      session that was already open will not sync)");
  console.log("    → Your buddy syncs automatically as you work — no need");
  console.log("      to close the session");
  console.log();
  console.log("  Don't have Claude Code yet?");
  console.log("    → Download it at https://claude.ai/code");

  hr("Done");
  // Audit line: users can see exactly where their sync secret + session data will be sent.
  //
  // Built from a parsed URL rather than a regex. The old
  // `apiUrl.replace(/^(https:\/\/[^\/]+).*/, "$1")` stopped at the first slash, which
  // meant it kept everything before it — including userinfo, so an apiUrl carrying
  // credentials printed the password to the terminal — and threw away everything after
  // it, so the path actually being posted to was hidden. isValidHttpsUrl now rejects
  // both shapes outright; this keeps the line honest regardless. Found by the
  // 2026-08-15 audit.
  const parsedApi = new URL(apiUrl);
  const displayUrl = parsedApi.origin + parsedApi.pathname.replace(/\/+$/, "");
  console.log(`  Using endpoint: ${displayUrl} (HTTPS enforced)`);
  console.log("  Your buddy will appear after your first Claude Code session.");
  console.log("  Then sign in with GitHub at buddybrawl.xyz/dashboard.");
  console.log("  If your GitHub email differs from git config user.email,");
  console.log("  the sync hook prints a 6-char link code after each session —");
  console.log("  enter it on the dashboard to connect your buddy.");
  console.log();
  console.log("  Note: the hook is pinned to today's Node binary. If you");
  console.log("  upgrade or switch Node (nvm/fnm), re-run npx buddybrawl init.\n");
}

// ─── Help ────────────────────────────────────────────────────────────────────

function showHelp() {
  console.log(`
  Usage: npx buddybrawl init [options]

  Installs the BuddyBrawl sync hook into Claude Code.
  Requires Claude Code — https://claude.ai/code

  Options:
    --api-url <url>        Override production API URL (self-hosted)
    --sync-secret <secret> Override production sync secret (self-hosted)

  Example:
    npx buddybrawl init
`);
}

// ─── Entry ───────────────────────────────────────────────────────────────────

// Node < 18 has no global fetch — fail with the real reason, not a fake
// network error ("check your internet"). npx does not enforce `engines`.
if (typeof fetch === "undefined") {
  console.error(`  ✗ BuddyBrawl needs Node 18 or newer — you're running ${process.version}.`);
  console.error("    Upgrade Node (https://nodejs.org), then re-run npx buddybrawl init.");
  process.exit(1);
}

const args = process.argv.slice(2);
const cmd  = args[0];

function parseFlags(argv) {
  const flags = {};
  for (let i = 0; i < argv.length; i++) {
    if (argv[i] === "--api-url"     && argv[i + 1]) flags.apiUrl     = argv[++i];
    if (argv[i] === "--sync-secret" && argv[i + 1]) flags.syncSecret = argv[++i];
  }
  return flags;
}

if (cmd === "init") {
  cmdInit(parseFlags(args)).catch((e) => { console.error(e); process.exit(1); });
} else {
  showHelp();
}
