#!/usr/bin/env node
import * as fs from "fs";
import * as path from "path";
import * as os from "os";
import { fileURLToPath } from "url";
import { execFileSync } from "child_process";
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
//
// `uninstall` reads the same value for the same purpose: the token it is about to
// delete is a token that should stop working, and the hash is the only part of it
// this host is ever allowed to see.
function previousTokenHash() {
  try {
    const prev = JSON.parse(fs.readFileSync(CONFIG_FILE, "utf8"));
    if (typeof prev?.syncSecret !== "string" || !prev.syncSecret) return null;
    return createHash("sha256").update(prev.syncSecret).digest("hex");
  } catch {
    return null;
  }
}

// The whole config, for the one caller that needs the secret itself rather than its
// hash: deleting an account is authenticated to the sync endpoint, which is the only
// host that has ever been allowed to see a working credential.
function readConfig() {
  try {
    let raw = fs.readFileSync(CONFIG_FILE, "utf8");
    if (raw.charCodeAt(0) === 0xfeff) raw = raw.slice(1);   // Notepad/PowerShell BOM
    const cfg = JSON.parse(raw);
    if (!cfg || typeof cfg !== "object" || Array.isArray(cfg)) return null;
    return cfg;
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

// ─── Exiting ─────────────────────────────────────────────────────────────────

// Why this exists instead of process.exit().
//
// Every error path in both commands runs *after* a fetch, and calling process.exit()
// while undici is still holding a keep-alive socket aborts the process on Windows:
//
//   Assertion failed: !(handle->flags & UV_HANDLE_CLOSING), ...\deps\uv\src\win\async.c
//
// The message the user needed still prints, and then that line lands underneath it and
// the exit code is 127 rather than 1 — a crash report stapled to a handled error, which
// is the worst possible way to tell someone their install was rate-limited. It is
// reachable from init today: any non-2xx from the config endpoint (429 when a room
// installs at once, 503 before the server has its env) takes that path. Found while
// testing `uninstall` against an endpoint that was not deployed yet.
//
// Setting exitCode and unwinding instead lets the socket close on its own. The process
// still exits promptly — measured at ~450ms against a live 404 — with the code we asked
// for. Nothing between here and the dispatch catches broadly enough to swallow it.
class ExitSignal extends Error {}

function exitWith(code) {
  process.exitCode = code;
  throw new ExitSignal(`exit ${code}`);
}

// ─── Settings.json helpers ───────────────────────────────────────────────────

// `cmd` only names the command to retry in the two error messages. Both failures are
// "this file is unusable and we will not write over it", which is as true of uninstall
// as of init — but telling someone who ran uninstall to re-run init is how you get an
// install they were trying to remove.
function readSettings(cmd = "init") {
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
    console.error(`    Fix the file (or remove it), then re-run npx buddybrawl ${cmd}.`);
    exitWith(1);
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
    console.error(`    Fix the file (or remove it), then re-run npx buddybrawl ${cmd}.`);
    exitWith(1);
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

// Take every hook of ours out of a Stop list, and report what came out.
//
// Shared by addHook (replacing a stale entry) and removeHook (taking ours out for
// good) so the two rules below exist in exactly one place. They were both written in
// response to real settings damage, and a second hand-kept copy is how one of them
// quietly stops applying to one of the two commands.
//
//   1. Only hooks pointing at HOOK_DEST are ours — see isOurHookCommand.
//   2. The drop-empty-entries rule used to run over every entry unconditionally, so an
//      entry the user had already left with an empty `hooks` array was deleted even
//      though this installer never touched it — taking its matcher with it. That is the
//      same silent settings damage isOurHookCommand was written to end, one rule
//      further down: scoping *which hooks* we remove does not help if the entry cleanup
//      is still global. An entry is only ours to drop when removing our own hook is
//      what emptied it.
function stripOurHooks(stops) {
  const removed = [];
  const kept = [];
  for (const entry of stops) {
    const before = entry.hooks ?? [];
    const after = before.filter((h) => {
      if (!isOurHookCommand(h.command)) return true;
      removed.push(h.command);
      return false;
    });
    // Nothing of ours in here. Push the original object through by reference so an entry
    // without a `hooks` key does not gain an empty one, and key order survives the trip.
    if (after.length === before.length) { kept.push(entry); continue; }
    // It held nothing but our hook, so the wrapper is ours too — drop it.
    if (after.length === 0) continue;
    kept.push({ ...entry, hooks: after });
  }
  return { kept, removed };
}

/** Every registered hook command of ours, for reporting before anything is touched. */
function ourHooksIn(settings) {
  const stops = settings?.hooks?.Stop;
  if (!Array.isArray(stops)) return [];
  return stops
    .flatMap((entry) => entry?.hooks ?? [])
    .map((h) => h?.command)
    .filter((c) => isOurHookCommand(c));
}

function addHook(settings) {
  if (!settings.hooks) settings.hooks = {};
  if (!settings.hooks.Stop) settings.hooks.Stop = [];
  // Remove any stale entry pointing at our hook file before adding the current one.
  const { kept, removed } = stripOurHooks(settings.hooks.Stop);
  settings.hooks.Stop = kept;
  settings.hooks.Stop.push({
    matcher: "",
    hooks: [{ type: "command", command: HOOK_COMMAND }],
  });
  return { settings, removed };
}

// The inverse of addHook: take ours out and put nothing back.
//
// Empty containers are pruned rather than left as `"Stop": []` inside `"hooks": {}`.
// An uninstall that leaves scaffolding behind is one a reader cannot tell apart from a
// half-finished one, and an absent key and an empty array mean the same thing to Claude
// Code. Anything the user or another tool put in Stop keeps the key alive.
function removeHook(settings) {
  const stops = settings?.hooks?.Stop;
  if (!Array.isArray(stops)) return { settings, removed: [] };
  const { kept, removed } = stripOurHooks(stops);
  if (kept.length) {
    settings.hooks.Stop = kept;
  } else {
    delete settings.hooks.Stop;
    if (Object.keys(settings.hooks).length === 0) delete settings.hooks;
  }
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

  // Windows: attempt icacls before giving up.
  //
  // This used to be execSync with the path interpolated into a command string and
  // `%USERNAME%` left for cmd.exe to expand. It worked, and the injection risk was
  // theoretical — CONFIG_DIR is built from os.homedir(), and Windows does not allow
  // `"` or `&` in account names. But it was the only shell-string exec in the whole
  // package, right next to a hook that runs `git` through execFileSync with an
  // explicit argv array *and a comment saying that is the point*. An auditor greps
  // for exec and reads the two side by side; the inconsistency costs more than the
  // line was worth. No shell, no interpolation, nothing to quote.
  //
  // Absolute path rather than bare "icacls": a PATH entry the user does not control
  // should not decide which binary gets to rewrite the ACL on the directory holding
  // their sync token.
  //
  // USERNAME is used here as an ACL principal and nowhere else. It is never stored,
  // never hashed into an identifier, and never transmitted — the install ID is
  // random (see mintMachineId).
  const user = process.env.USERNAME;
  if (!user) return { status: "insecure", reason: "windows_no_username" };
  const systemRoot = process.env.SystemRoot || process.env.SYSTEMROOT || "C:\\Windows";
  const icaclsPath = path.join(systemRoot, "System32", "icacls.exe");
  const icacls = fs.existsSync(icaclsPath) ? icaclsPath : "icacls";
  try {
    execFileSync(icacls, [CONFIG_DIR, "/inheritance:r", "/grant:r", `${user}:(F)`, "/T"], {
      stdio: "ignore",
      // A hung icacls would hang `npx buddybrawl init` with no output and no reason.
      timeout: 10000,
    });
    return { status: "secured", method: "icacls" };
  } catch {
    return { status: "insecure", reason: "windows_no_acl", user };
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
        exitWith(1);
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
          exitWith(1);
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

// ─── Token revocation ────────────────────────────────────────────────────────

const REVOKE_ENDPOINT = `https://${PROD_HOST}/api/revoke-install`;

// Retire this install's sync token server-side.
//
// The only endpoint besides the config fetch that this CLI ever talks to, and it
// exists because uninstalling without it was a lie by omission: deleting the folder
// and the hook line stops the machine from syncing, and leaves a credential that
// still works for anyone who copied config.json before it went. Re-running init was
// the only thing that ever retired a token, which made the *documented* removal path
// the one path that never did.
//
// Sends sha256(token), never the token: possession of the hash is the authority to
// revoke (see supabase/migrations/20260815090000_revoke_install_token.sql), so this
// needs no credential of its own and hands the config host nothing usable. Same
// redirect:"error" rule as everywhere else — a bounce would relay the hash to a host
// the user never configured.
//
// Throws on anything that is not a clean answer. The caller has to know the
// difference, because it decides what is safe to delete afterwards.
async function revokeInstallToken(tokenSha256) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), 8000);
  try {
    const res = await fetch(REVOKE_ENDPOINT, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "User-Agent": `buddybrawl-cli/${PKG_VERSION}`,
      },
      body: JSON.stringify({ tokenSha256, cliVersion: PKG_VERSION }),
      signal: controller.signal,
      redirect: "error",
    });
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const body = await res.json();
    return { revoked: body?.revoked === true };
  } finally {
    clearTimeout(timer);
  }
}

// ─── Account deletion ────────────────────────────────────────────────────────

// Built by appending to the configured apiUrl, exactly like the hook builds its sync
// URL — and deliberately NOT from PROD_HOST. This request carries the working sync
// secret, and the only host that has ever been allowed to see one is the endpoint
// printed at setup and saved in config.json. Sending it to the config host instead
// would hand a second server a live credential, which is the one thing every other
// part of this package is arranged to prevent.
function buildDeleteUrl(apiUrl) {
  const url = new URL(apiUrl);
  url.pathname = url.pathname.replace(/\/+$/, "") + "/functions/v1/delete-account";
  return url.toString();
}

// Ask the server to delete the account this install belongs to.
//
// Authenticated by the install token plus the machine ID it was bound to — the same
// pair the sync endpoint checks. That pair is the only proof of ownership someone who
// never signed in on the web will ever have, and `uninstall` is about to destroy it,
// which is precisely why deletion is offered here rather than only on a dashboard.
async function deleteAccount(cfg) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), 15000);
  try {
    const endpoint = buildDeleteUrl(cfg.apiUrl);
    const res = await fetch(endpoint, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "User-Agent": `buddybrawl-cli/${PKG_VERSION}`,
        "x-sync-secret": cfg.syncSecret,
      },
      // The server refuses anything without this. It is not a formality: it means a
      // stray or replayed POST cannot delete somebody's account.
      body: JSON.stringify({ confirm: "DELETE", machineId: cfg.machineId }),
      signal: controller.signal,
      redirect: "error",
    });
    const body = await res.json().catch(() => ({}));
    if (!res.ok) throw new Error(body?.error || `HTTP ${res.status}`);
    return {
      deleted: body?.deleted === true,
      reason: body?.reason ?? null,
      battlesAnonymized: body?.battlesAnonymized ?? 0,
    };
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
  console.log("      message count, and the names of the built-in");
  console.log("      tools used. MCP tool names are hashed on your");
  console.log("      machine first — we count them, never read them");
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

  // --dry-run: say exactly what would change, change nothing, and — the part that
  // matters — reach no network at all. It has to sit above the config fetch rather
  // than inside it: that request *mints a token* and retires the previous one, so a
  // dry run that called it would leave the account in a state a dry run has no
  // business creating. Everything below this point either writes or registers.
  if (flags.dryRun) {
    const already = hasHook(settings);
    console.log("  Dry run — nothing is written, no token is issued, no request is sent.\n");
    console.log(`  would POST to ${CONFIG_ENDPOINT}`);
    console.log("     sending a random install ID and the CLI version" +
      (previousTokenHash() ? "," : "."));
    if (previousTokenHash()) {
      console.log("     plus the sha256 of the token in your existing config, so the");
      console.log("     server can retire it. Never the token itself.");
    }
    console.log(`  would write   ${HOOK_DEST}`);
    console.log("     the sync hook, copied from this package and hash-checked");
    console.log(`  would write   ${CONFIG_FILE}`);
    console.log("     endpoint URL, sync token, install ID, path salt (owner-only)");
    console.log(`  would ${already ? "keep the existing" : "add one"} Stop hook entry in ${CLAUDE_SETTINGS}:`);
    console.log(`     ${HOOK_COMMAND}`);
    const stale = ourHooksIn(settings).filter((c) => c !== HOOK_COMMAND);
    for (const cmd of stale) {
      console.log(`  would replace a stale BuddyBrawl entry (${cmd})`);
    }
    console.log("\n  Nothing else on this machine is read, written or registered.");
    console.log("  Run without --dry-run to install.\n");
    return;
  }

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
      exitWith(1);
    }
  }

  // High-impact safety: never persist or use an endpoint that isn't a plain https base
  // URL (prevents token+data exfil to attacker servers, and the query-string misroute
  // described on isValidHttpsUrl).
  if (!isValidHttpsUrl(apiUrl)) {
    console.error("  ✗ Refusing this apiUrl. It must be an https:// base URL with no credentials, query string or fragment.");
    console.error("    If you are self-hosting for testing, run init then manually edit ~/.buddybrawl/config.json.");
    exitWith(1);
  }

  // A private or loopback target is fine when the user asked for it, and never fine when
  // the network chose it — see isPrivateHost.
  if (!flags.apiUrl && isPrivateHost(new URL(apiUrl).hostname)) {
    console.error(`  ✗ Refusing an endpoint on a private or loopback address (${new URL(apiUrl).hostname}).`);
    console.error(`    ${PROD_HOST} returned it, and syncs would be sent inside your own network.`);
    console.error("    Nothing was installed. If you meant to self-host, pass it yourself:");
    console.error("      npx buddybrawl init --api-url <url> --sync-secret <secret>");
    exitWith(1);
  }

  hr("Step 1: Sync hook");

  const hookSource = path.join(__dirname, "buddy-sync.mjs");
  if (!fs.existsSync(hookSource)) {
    console.error(`  buddy-sync.mjs not found at ${hookSource}`);
    exitWith(1);
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
      exitWith(1);
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
    // Print the resolved account name when we have one. `%USERNAME%` only expands
    // in cmd.exe, so pasting this line into PowerShell — where `npx` is usually
    // run — produced a command that granted rights to a literal "%USERNAME%".
    const principal = sec.user ? `"${sec.user}"` : `"%USERNAME%"`;
    console.log(`     icacls "${CONFIG_DIR}" /inheritance:r /grant:r ${principal}:(F) /T`);
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

// ─── Uninstall command ───────────────────────────────────────────────────────

// Undo everything init did, in the order that leaves the safest partial state at
// every point it can fail:
//
//   1. unregister the hook   — the step that actually stops data leaving the machine
//   1b. --delete-account     — optional, and must be here: it authenticates with the
//                              token that step 3 destroys (see cmdUninstall body)
//   2. revoke the token      — needs config.json, so it has to happen before step 3
//   3. delete ~/.buddybrawl  — the point of no return for step 2
//
// Any other order has a failure mode that is worse than not running it. Deleting the
// folder first destroys the only copy of the secret this machine can hash, so the
// token can never be retired. Revoking first and then failing to unregister leaves a
// registered hook whose every sync 403s. And a hook left pointing at a deleted script
// errors at the end of every Claude Code session, which is a worse thing to leave
// behind than the install itself.
//
// There is no confirmation prompt. Typing `uninstall` is the confirmation, and the
// only irreversible part — the token — is reissued by re-running init.
async function cmdUninstall(flags = {}) {
  console.log("\n  BuddyBrawl — Uninstall");
  console.log("  Removes the Claude Code hook, the local config, and this");
  console.log("  install's sync token.");
  if (flags.deleteAccount) {
    console.log("  --delete-account: your buddy, stats, gear and rank go too.");
  }
  console.log();

  // Validated first, for the same reason init reads it first: if this file is
  // unusable we are not going to rewrite it, and nothing should have changed by the
  // time we say so.
  const settings = readSettings("uninstall");
  const registered = ourHooksIn(settings);
  const tokenSha256 = previousTokenHash();
  const dirExists = fs.existsSync(CONFIG_DIR);
  const cfg = flags.deleteAccount ? readConfig() : null;

  // Say this before anything is touched. --delete-account with no credential left is
  // a request we cannot honour, and finding that out after the hook is gone would
  // leave someone believing their data was deleted when it was not.
  if (flags.deleteAccount && !(cfg?.syncSecret && cfg?.machineId && cfg?.apiUrl)) {
    console.error("  ✗ Cannot delete the account: no usable ~/.buddybrawl/config.json.");
    console.error("    Deleting an account is authenticated with this install's sync");
    console.error("    token, and that token is the only proof of ownership an install");
    console.error("    has. Without it, email hi@buddybrawl.xyz instead — or sign in at");
    console.error(`    https://${PROD_HOST}/dashboard and delete it there.`);
    console.error("    Nothing was removed. Re-run without --delete-account to uninstall.");
    exitWith(1);
  }

  if (!registered.length && !dirExists) {
    console.log("  Nothing to remove — no BuddyBrawl hook is registered and");
    console.log(`  ${CONFIG_DIR} does not exist.\n`);
    return;
  }

  if (flags.dryRun) {
    console.log("  Dry run — nothing is removed and no request is sent.\n");
    if (registered.length) {
      for (const cmd of registered) console.log(`  would unregister  ${cmd}`);
    } else {
      console.log("  would unregister  nothing (no BuddyBrawl Stop hook registered)");
    }
    console.log(dirExists
      ? `  would delete      ${CONFIG_DIR} and everything in it`
      : `  would delete      nothing (${CONFIG_DIR} does not exist)`);
    // Printed in execution order, and honest about what the other steps become as a
    // result: a preview that lists a request the real run skips is a preview that
    // teaches the wrong thing about what this command does.
    if (flags.deleteAccount) {
      console.log(`  would POST to     ${buildDeleteUrl(cfg.apiUrl)}`);
      console.log("     deleting your buddy, stats, gear and rank — permanently, and");
      console.log("     first, while this install's token can still prove it is yours.");
      console.log("     Battles you fought stay, with you replaced by 'Deleted player'");
      console.log("     so opponents keep their own history.");
      console.log("  would skip        the revoke call — the account's tokens are");
      console.log("     deleted outright with it, which is stronger than revoking them");
    } else {
      console.log(tokenSha256
        ? `  would POST to     ${REVOKE_ENDPOINT}\n     sending sha256 of this install's token, so the server retires it`
        : "  would revoke      nothing (no token found in config.json)");
    }
    console.log("\n  Run without --dry-run to remove it.\n");
    return;
  }

  // ── 1. Unregister ──────────────────────────────────────────────────────────
  if (registered.length) {
    const { settings: updated, removed } = removeHook(settings);
    writeSettings(updated);
    // Same verification read init does after registering. A write that silently did
    // not take is the one failure that would leave the user believing syncing stopped
    // when it has not.
    if (ourHooksIn(readSettings("uninstall")).length) {
      console.error("  ✗ Wrote settings.json but a BuddyBrawl hook entry is still there.");
      console.error(`    Remove the buddy-sync line from ${CLAUDE_SETTINGS} by hand.`);
      console.error("    Nothing else was removed.");
      exitWith(1);
    }
    for (const cmd of removed) console.log(`  ✓ Claude Code Stop hook unregistered (${cmd})`);
    console.log("  ✓ No further session data will be sent from this machine");
  } else {
    console.log("  ✓ No BuddyBrawl Stop hook was registered");
  }

  // ── 1b. Delete the account, if asked ───────────────────────────────────────
  //
  // Before the revoke and long before the delete, because this call authenticates
  // with the live token — and both of those steps exist to destroy it. Get the order
  // wrong and the request cannot be made at all.
  //
  // A failure here stops everything. Someone who typed --delete-account came for the
  // deletion, not the uninstall; carrying on and removing their credential would take
  // away the only means they had of asking again.
  let accountDeleted = false;
  if (flags.deleteAccount) {
    process.stdout.write("  Deleting your account...");
    try {
      const res = await deleteAccount(cfg);
      accountDeleted = res.deleted;
      if (res.deleted) {
        process.stdout.write(` done (${res.battlesAnonymized} battles kept, you anonymized)\n`);
      } else {
        process.stdout.write(` nothing to delete (${res.reason ?? "no account"})\n`);
      }
    } catch (e) {
      process.stdout.write(` failed (${e.message})\n`);
      console.error();
      console.error("  Nothing was deleted, and nothing local was removed either —");
      console.error("  your sync token is still in place, so you can try again.");
      console.error("  Syncing has already stopped: the hook is unregistered.");
      console.error("    → try again:      npx buddybrawl uninstall --delete-account");
      console.error("    → uninstall only: npx buddybrawl uninstall");
      console.error(`    → or sign in at   https://${PROD_HOST}/dashboard`);
      console.error("    → or email        hi@buddybrawl.xyz\n");
      exitWith(1);
    }
  }

  // ── 2. Revoke ──────────────────────────────────────────────────────────────
  let revokeError = null;
  if (accountDeleted) {
    // The account's install tokens went with it — the rows are gone, not merely
    // flagged revoked, which is strictly stronger than what this step achieves.
    console.log("  ✓ Sync token deleted with the account");
  } else if (tokenSha256) {
    process.stdout.write("  Deactivating this install's sync token...");
    try {
      const { revoked } = await revokeInstallToken(tokenSha256);
      // `false` is not a failure: a self-hosted install, a token already retired by a
      // later init, or one this server never issued all land here, and all three mean
      // the same thing to the user — nothing of theirs is left live.
      process.stdout.write(revoked ? " done\n" : " already inactive\n");
    } catch (e) {
      revokeError = e.message;
      process.stdout.write(` failed (${e.message})\n`);
    }
  } else if (dirExists) {
    console.log("  ✓ No sync token found in config.json (nothing to deactivate)");
  }

  // ── 3. Delete ──────────────────────────────────────────────────────────────
  //
  // Stop here if the token could not be retired. config.json holds the only copy of
  // the secret this machine can hash, so deleting it now would make the token
  // permanently unrevocable — and there is no hurry: step 1 already stopped the
  // syncing, which is what the user came for.
  if (revokeError && !flags.force) {
    console.log();
    console.log(`  Stopped before deleting ${CONFIG_DIR}.`);
    console.log("  Syncing has already stopped. What is left is the token itself,");
    console.log("  still live on the server, and config.json is the only proof this");
    console.log("  machine can offer that the token is yours to retire.");
    console.log("    → back online?  npx buddybrawl uninstall");
    console.log("    → delete anyway: npx buddybrawl uninstall --force");
    console.log(`    → or email hi@buddybrawl.xyz quoting ${tokenSha256}`);
    console.log("      (that is a hash, not the token — it is safe to send)\n");
    exitWith(1);
  }

  if (dirExists) {
    try {
      // Everything in the folder, including a hand-written buddy.json: this is the
      // same "delete the ~/.buddybrawl folder" the privacy page has always described.
      fs.rmSync(CONFIG_DIR, { recursive: true, force: true });
      console.log(`  ✓ Removed ${CONFIG_DIR}`);
    } catch (e) {
      console.error(`  ✗ Could not remove ${CONFIG_DIR} (${e.code || e.message}).`);
      console.error("    The hook is already unregistered, so nothing is syncing.");
      console.error("    Delete the folder by hand to finish.");
      exitWith(1);
    }
  }

  hr("Done");
  if (revokeError) {
    console.log("  ⚠ The sync token could not be deactivated and its local copy is");
    console.log("    now gone. Email hi@buddybrawl.xyz if you want it retired.");
    console.log();
  }
  console.log("  BuddyBrawl is off this machine. Nothing was left behind");
  console.log("  outside the two paths above.");
  console.log();
  if (accountDeleted) {
    console.log("  Your account is deleted: buddy, stats, gear, rank and the");
    console.log("  session records behind them. Battles you fought are still");
    console.log("  in your opponents' history with you as 'Deleted player' —");
    console.log("  their record of their own games does not depend on you");
    console.log("  staying. Nothing left can be traced back to you.");
    console.log();
    console.log("  Starting fresh later gives you a new buddy, not the old one.");
  } else {
    console.log("  Your buddy, stats, gear and rank still exist on the server —");
    console.log("  uninstalling stops the sync, it does not delete the account.");
    console.log("  To delete that too, while this install can still prove it is");
    console.log("  yours:  npx buddybrawl uninstall --delete-account");
    console.log(`  Signed in on the web? https://${PROD_HOST}/dashboard has a button.`);
    console.log(`  (details: https://${PROD_HOST}/privacy)`);
  }
  console.log();
  console.log("  Changed your mind? npx buddybrawl@latest init\n");
}

// ─── Help ────────────────────────────────────────────────────────────────────

function showHelp() {
  console.log(`
  Usage: npx buddybrawl <command> [options]

  Commands:
    init         Install the BuddyBrawl sync hook into Claude Code
    uninstall    Remove the hook, the local config, and this install's
                 sync token (alias: remove)

  Options:
    --dry-run              Print what would change, change nothing,
                           send no request. Works with both commands.
    --api-url <url>        init: override production API URL (self-hosted)
    --sync-secret <secret> init: override production sync secret (self-hosted)
    --force                uninstall: delete local files even if the token
                           could not be deactivated
    --delete-account       uninstall: also delete your buddy, stats, gear
                           and rank from the server. Permanent. Run it
                           BEFORE a plain uninstall — it needs this
                           install's token to prove the account is yours.
    --version              Print the CLI version and exit

  Requires Claude Code — https://claude.ai/code
  Security policy and reports — hi@buddybrawl.xyz

  Examples:
    npx buddybrawl init
    npx buddybrawl init --dry-run
    npx buddybrawl uninstall
`);
}

// ─── Entry ───────────────────────────────────────────────────────────────────

// Node < 18 has no global fetch — fail with the real reason, not a fake
// network error ("check your internet"). npx does not enforce `engines`.
if (typeof fetch === "undefined") {
  console.error(`  ✗ BuddyBrawl needs Node 18 or newer — you're running ${process.version}.`);
  console.error("    Upgrade Node (https://nodejs.org), then re-run npx buddybrawl init.");
  // The one place process.exit stays: this is module top level, so exitWith's throw
  // would print an ExitSignal stack under the message instead of ending quietly. It is
  // also the one exit that cannot have a socket open behind it — there is no fetch on
  // this Node at all, which is the whole point of the branch.
  process.exit(1);
}

const args = process.argv.slice(2);
const cmd  = args[0];

// An ExitSignal has already printed everything the user needs and set the exit code —
// re-printing it would put a stack trace under a message written to avoid one. Anything
// else really is unexpected and gets shown in full.
function fatal(e) {
  if (e instanceof ExitSignal) return;
  console.error(e);
  process.exitCode = 1;
}

function parseFlags(argv) {
  const flags = {};
  for (let i = 0; i < argv.length; i++) {
    if (argv[i] === "--api-url"     && argv[i + 1]) flags.apiUrl     = argv[++i];
    if (argv[i] === "--sync-secret" && argv[i + 1]) flags.syncSecret = argv[++i];
    if (argv[i] === "--dry-run") flags.dryRun = true;
    if (argv[i] === "--force")   flags.force  = true;
    if (argv[i] === "--delete-account") flags.deleteAccount = true;
  }
  return flags;
}

if (cmd === "--version" || cmd === "-v" || cmd === "version") {
  // SECURITY.md asks reporters for the version, so there has to be one command that
  // prints it without installing anything or reaching the network.
  console.log(PKG_VERSION);
} else if (cmd === "init") {
  cmdInit(parseFlags(args)).catch(fatal);
} else if (cmd === "uninstall" || cmd === "remove") {
  cmdUninstall(parseFlags(args)).catch(fatal);
} else {
  showHelp();
}
