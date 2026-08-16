#!/usr/bin/env node
// BuddyBrawl session sync hook for Claude Code (cross-platform).
// Fires at end of each conversation to sync coding activity to the database.
//
// Required env vars:
//   BUDDYBRAWL_API_URL    — Supabase project URL (e.g. https://xyz.supabase.co)
//   BUDDYBRAWL_SYNC_SECRET — shared secret for the buddy-sync edge function
//
// Install:
//   Add to ~/.claude/settings.json under hooks.Stop:
//     "command": "node <path-to>/buddy-sync.mjs"

import { readFileSync, existsSync, statSync } from "fs";
import { join } from "path";
import * as os from "os";
import { execFileSync } from "child_process";
import { createHash } from "crypto";

function readFileConfig() {
  try {
    // Strip a UTF-8 BOM before parsing. `npx buddybrawl init` writes this file without
    // one, but the init banner tells self-hosters to hand-edit it, and both Notepad and
    // PowerShell's Set-Content/Out-File prepend U+FEFF. That makes JSON.parse throw, so
    // the whole config reads as {} and the hook takes the "config not found" branch —
    // silently, forever, pointing the user at the wrong fix. readSettings() in
    // cli/index.mjs already does this for ~/.claude/settings.json; this is the same bug
    // one file over. Found by the 2026-08-15 external tarball audit.
    let raw = readFileSync(join(os.homedir(), ".buddybrawl", "config.json"), "utf8");
    if (raw.charCodeAt(0) === 0xfeff) raw = raw.slice(1);
    return JSON.parse(raw);
  } catch {
    return {};
  }
}

// Machine identifier sent on every sync for server-side token binding — a stolen
// config.json (syncSecret) cannot be used without its paired machineId. It is the
// random ID minted by `npx buddybrawl init`, and it comes from config.json or not
// at all: there is deliberately no derivation fallback here.
//
// A legacy sha256(hostname + username) fallback lived here until 2026-08-15. It was
// removed pre-launch for two reasons. Reliability: macOS rewrites its kernel hostname
// from DHCP/mDNS as laptops change networks, which flipped the derived ID and 403'd
// every sync until re-init. Truthfulness: /privacy tells users the install ID is "not
// derived from your hostname, username, or any hardware identifier", and a fallback
// that reads both made that sentence conditional on which version you installed.
// Do not restore it — tests/privacy-disclosure.test.ts fails if you do.
function getMachineId(fileConfig) {
  return typeof fileConfig?.machineId === "string" && fileConfig.machineId
    ? fileConfig.machineId
    : null;
}

// An API base URL. https is necessary but not sufficient: userinfo, a query string
// and a fragment all survive `new URL()` and then wreck the URL this gets pasted
// into. `${apiUrl}/functions/v1/buddy-sync` on an apiUrl ending in `?token=abc`
// puts the whole function path inside the query, so the POST lands on `/` instead
// — carrying the sync secret to whatever answers the site root. Credentials in the
// URL are worse: no endpoint here needs them, and they end up echoed to the
// terminal and stored in config.json. Reject all three rather than sanitise them
// at each call site. Found by the 2026-08-15 external tarball audit.
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

// Join, don't concatenate. Preserves a base path for self-hosters, collapses the
// trailing slash that used to yield `//functions/v1/...`, and cannot smuggle the
// path into a query string because isValidHttpsUrl already refused one.
function buildSyncUrl(apiUrl) {
  const url = new URL(apiUrl);
  url.pathname = url.pathname.replace(/\/+$/, "") + "/functions/v1/buddy-sync";
  return url.toString();
}

// ─── Helpers ───────────────────────────────────────────────────────────────

function log(msg) {
  process.stderr.write(msg + "\n");
}

// Every string the server sends back — buddy name, species, rarity, milestones,
// link code, error bodies — is untrusted: it crosses the network and lands
// straight in the user's terminal. The old version stripped only CSI (ESC [ ...),
// which left three holes: an OSC-8 sequence could render the buddy's "name" as a
// clickable link to anywhere, a bare newline could forge extra "[BuddyBrawl]"
// lines, and an unbounded string could flood the screen. So: remove every escape
// *form*, then drop any surviving control byte, then cap the length. Only a
// hostile or compromised server can reach this code — but that is exactly the
// case this defense exists for, and it was being applied to two fields out of six.
function stripAnsi(s, max = 200) {
  const cleaned = String(s)
    .replace(/\x1b\][\s\S]*?(?:\x07|\x1b\\|$)/g, "") // OSC (incl. OSC-8 hyperlinks)
    .replace(/\x1b[PX^_][\s\S]*?(?:\x1b\\|$)/g, "")  // DCS / SOS / PM / APC
    .replace(/\x1b\[[0-?]*[ -/]*[@-~]/g, "")         // CSI
    .replace(/\x1b[@-Z\\-_]/g, "")                   // other two-char Fe escapes
    .replace(/[\x00-\x1f\x7f-\x9f]/g, "");           // leftovers, C1, newlines
  return cleaned.length > max ? cleaned.slice(0, max) + "…" : cleaned;
}

function gitConfig(key) {
  // Use execFileSync + explicit array + no shell: prevents command injection even if key were untrusted in future.
  // Added hard timeout (2s) so a misbehaving git binary cannot hang the hook indefinitely.
  try {
    return execFileSync("git", ["config", key], {
      encoding: "utf8",
      stdio: ["pipe", "pipe", "pipe"],
      timeout: 2000,
    }).trim();
  } catch {
    return null;
  }
}

// A git config value is attacker-shaped input, not a trusted string: git parses \n
// and \t escapes inside quoted values, a raw ESC byte passes through untouched, and
// the only ceiling is execFileSync's 1MB maxBuffer — a 512KB user.email arrived
// intact and produced a 1MB POST body. None of it reaches the terminal (the hook
// never logs these), but user.email becomes `userId`, the primary account key the
// server looks accounts up by, so it should be a plausible identity or nothing at
// all. Verified by the 2026-08-15 audit, which put newlines, control bytes and half
// a megabyte through both fields.
//
// Reject rather than truncate: a mangled value silently becomes a *different*
// account, and the fallback chain below (Anthropic id, then install id) already
// handles "no usable email" correctly.
const MAX_GIT_EMAIL = 320;  // 64-char local-part + "@" + 255-char domain (RFC 5321)
const MAX_GIT_NAME  = 100;

function cleanGitValue(v, max) {
  if (typeof v !== "string") return null;
  if (v.length > max) return null;
  if (/[\x00-\x1f\x7f-\x9f]/.test(v)) return null;
  const trimmed = v.trim();
  return trimmed || null;
}

function gitEmail() {
  const v = cleanGitValue(gitConfig("user.email"), MAX_GIT_EMAIL);
  return v && /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(v) ? v : null;
}

function gitName() {
  return cleanGitValue(gitConfig("user.name"), MAX_GIT_NAME);
}

function readBuddyOverride() {
  const overridePath = join(os.homedir(), ".buddybrawl", "buddy.json");
  if (!existsSync(overridePath)) return null;

  try {
    // buddy.json is hand-written by definition, so a BOM is likelier here than in
    // config.json. This path at least warns rather than failing silently, but the
    // warning blames the user's JSON for something they cannot see.
    let raw = readFileSync(overridePath, "utf8");
    if (raw.charCodeAt(0) === 0xfeff) raw = raw.slice(1);
    const parsed = JSON.parse(raw);
    log(`[BuddyBrawl] Using buddy override from ${overridePath}`);
    return parsed;
  } catch (e) {
    log(`[BuddyBrawl] Warning: ${overridePath} contains invalid JSON, ignoring (${e.message})`);
    return null;
  }
}

// ─── Anthropic buddy derivation ────────────────────────────────────────────

function fnv1a(str) {
  let hash = 2166136261;
  for (let i = 0; i < str.length; i++) {
    hash ^= str.charCodeAt(i);
    hash = Math.imul(hash, 16777619);
  }
  return hash >>> 0;
}

function mulberry32(seed) {
  return function () {
    seed |= 0;
    seed = (seed + 0x6d2b79f5) | 0;
    let t = Math.imul(seed ^ (seed >>> 15), 1 | seed);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

const SPECIES = [
  "axolotl","blob","cactus","capybara","cat","chonk",
  "dragon","duck","ghost","goose","mushroom","octopus",
  "owl","penguin","rabbit","robot","snail","turtle",
];

// Match each species as a whole word, optionally plural, and take the one named
// earliest in the text. This replaces `SPECIES.find((s) => personality.includes(s))`,
// which had two independent bugs:
//
//   1. Substring, not word. "cat" is inside dedicated, communicate, complicated,
//      indicate, application and category; "owl" is inside growl, howl and prowl.
//      "a dedicated turtle who loves clean code" resolved to cat.
//   2. List order, not text order. `.find` returns the first species in THIS array
//      that appears anywhere, so "cat" (index 4) beat "turtle" (index 17) even when
//      turtle was the only species actually named. "a turtle raised by a dragon"
//      resolved to dragon.
//
// Because the two compounded, a personality naming no species at all still matched —
// almost any English sentence contains "cat" somewhere — so the failure was silent:
// users got a confidently wrong companion rather than the no-match path below.
//
// Species names are plain lowercase ASCII, so they need no regex escaping. Patterns
// are built once at module load rather than per call.
const SPECIES_PATTERNS = SPECIES.map((species) => ({
  species,
  re: new RegExp(`\\b${species}s?\\b`),
}));

/** The species named earliest in `personality`, or null when none is named. */
function findSpecies(personality) {
  let found = null;
  let foundAt = Infinity;
  for (const { species, re } of SPECIES_PATTERNS) {
    const m = re.exec(personality);
    if (m && m.index < foundAt) {
      foundAt = m.index;
      found = species;
    }
  }
  return found;
}

const RARITY_THRESHOLDS = [
  { rarity: "legendary", cutoff: 0.02 },
  { rarity: "epic",      cutoff: 0.10 },
  { rarity: "rare",      cutoff: 0.25 },
  { rarity: "uncommon",  cutoff: 0.50 },
  { rarity: "common",    cutoff: 1.00 },
];

// ~/.claude.json was the one local file read with no size guard, and it is the local
// file most likely to be enormous: Claude Code keeps per-project history in it, so
// multi-megabyte copies are normal and much larger ones happen. Unguarded,
// readFileSync + JSON.parse held roughly 2.4x the file size resident (626MB at a
// 256MB file), and past V8's ~512MB string limit the read still costs the disk time
// before it throws — a 1.2GB file added 26 SECONDS to the end of the session, with no
// cap, no timeout and no message, because this is a Stop hook and Claude Code waits
// for it. /privacy §03 says "input sizes are capped": stdin (64KB) and the transcript
// (50MB) were, this was not. Measured by the 2026-08-15 external tarball audit.
//
// 16MB is far above any real ~/.claude.json and far below the point where reading one
// is felt at session end.
const MAX_CLAUDE_JSON_BYTES = 16 * 1024 * 1024;

// Returns { buddy, anthropicUserId }. The two are independent on purpose: the
// userID exists in ~/.claude.json even before the user has run /buddy, and it is
// a far more stable account key than the machine-id fallback — so surface it
// even when no companion can be resolved. `buddy` is only non-null when the full
// companion identity (name + species) resolved.
//
// Over the size cap both come back null, which is the same shape as a missing or
// unparseable file: the companion is skipped, the sync still goes out, and userId
// falls back down the chain in main().
function readClaudeJson() {
  try {
    const p = join(os.homedir(), ".claude.json");
    if (!existsSync(p) || statSync(p).size > MAX_CLAUDE_JSON_BYTES) {
      return { buddy: null, anthropicUserId: null };
    }
    const raw = readFileSync(p, "utf8");
    const data = JSON.parse(raw);
    const anthropicUserId =
      typeof data.userID === "string" && data.userID ? data.userID : null;
    if (!data.companion?.name || !anthropicUserId) return { buddy: null, anthropicUserId };

    // Species is named explicitly in the personality text — more reliable than hash position
    const personality = (data.companion.personality || "").toLowerCase();
    const species = findSpecies(personality);
    if (!species) return { buddy: null, anthropicUserId };

    // Rarity and isShiny via hash (seed positions 1-2 consumed, 3 = rarity, 4 = isShiny)
    const seed = fnv1a("friend-2026-401" + data.userID);
    const rng = mulberry32(seed);
    rng(); rng(); // consume species + adjective positions
    const rarityRoll = rng();
    let rarity = "common";
    for (const t of RARITY_THRESHOLDS) {
      if (rarityRoll <= t.cutoff) { rarity = t.rarity; break; }
    }
    const isShiny = rng() < 0.05;

    return {
      buddy: { name: data.companion.name.trim(), species, rarity, isShiny, anthropicUserId },
      anthropicUserId,
    };
  } catch {
    return { buddy: null, anthropicUserId: null };
  }
}

function readStdin() {
  return new Promise((resolve) => {
    if (process.stdin.isTTY) { resolve("{}"); return; }
    let data = "";
    const MAX = 65536; // 64KB safety cap — Claude session JSON is tiny; prevents memory DoS / huge exfil from malicious stdin.
    // Fallback timer must not keep the event loop alive after stdin ends,
    // or every hook run gets a hard 3s exit delay.
    const timer = setTimeout(() => {
      process.stdin.destroy(); // release the stream so the process can exit
      resolve(data || "{}");
    }, 3000);
    const done = (result) => { clearTimeout(timer); resolve(result); };
    process.stdin.setEncoding("utf8");
    process.stdin.on("data", (chunk) => {
      data += chunk;
      if (data.length > MAX) {
        data = data.slice(0, MAX);
      }
    });
    process.stdin.on("end", () => done(data || "{}"));
    process.stdin.on("error", () => done("{}"));
  });
}

// ─── Transcript metrics ────────────────────────────────────────────────────
// Claude Code's Stop payload carries no activity metrics — only session_id,
// transcript_path, cwd. All stat growth except LCK depends on these numbers,
// so derive them from the session transcript (JSONL) ourselves.

const FILE_EDIT_TOOLS = new Set(["Edit", "Write", "MultiEdit", "NotebookEdit"]);
const MAX_TRANSCRIPT_BYTES = 50 * 1024 * 1024;

function computeSessionMetrics(transcriptPath) {
  try {
    if (typeof transcriptPath !== "string" || !transcriptPath) return null;
    let p = transcriptPath;
    if (p.startsWith("~")) p = join(os.homedir(), p.slice(1));
    if (!existsSync(p) || statSync(p).size > MAX_TRANSCRIPT_BYTES) return null;

    let firstTs = null;
    let lastTs = null;
    let toolCalls = 0;
    let userMsgs = 0;
    const toolsUsed = new Set();
    const filesModified = new Set();

    for (const line of readFileSync(p, "utf8").split("\n")) {
      if (!line) continue;
      let entry;
      try { entry = JSON.parse(line); } catch { continue; }

      if (entry?.timestamp) {
        const t = Date.parse(entry.timestamp);
        if (!Number.isNaN(t)) {
          if (firstTs === null || t < firstTs) firstTs = t;
          if (lastTs === null || t > lastTs) lastTs = t;
        }
      }

      const content = entry?.message?.content;
      if (entry?.type === "assistant" && Array.isArray(content)) {
        for (const block of content) {
          if (block?.type !== "tool_use") continue;
          toolCalls++;
          if (block.name) toolsUsed.add(String(block.name));
          if (FILE_EDIT_TOOLS.has(block.name)) {
            const fp = block.input?.file_path ?? block.input?.notebook_path;
            if (fp) filesModified.add(String(fp));
          }
        }
      } else if (entry?.type === "user" && !entry.isSidechain && !entry.isMeta) {
        // Real prompts have string content or a text block; tool results don't.
        const isPrompt = typeof content === "string"
          ? content.length > 0
          : Array.isArray(content) && content.some((b) => b?.type === "text");
        if (isPrompt) userMsgs++;
      }
    }

    return {
      duration_seconds: firstTs !== null ? Math.max(0, Math.round((lastTs - firstTs) / 1000)) : 0,
      num_tool_calls: toolCalls,
      num_user_messages: userMsgs,
      files_modified: [...filesModified],
      tools_used: [...toolsUsed],
      // The two arrays below get capped before they are sent (100 and 50), but
      // num_tool_calls is not — so a heavy session reported 500 tool calls beside
      // 50 distinct tools and 100 files, with no field saying either list was
      // partial. /privacy promises the file token yields "a count of how many
      // distinct files you created or edited"; above the cap that count was simply
      // wrong, and understated the user's own stats. Send the true totals as plain
      // numbers alongside the capped lists. Found by the 2026-08-15 audit.
      files_modified_total: filesModified.size,
      tools_used_total: toolsUsed.size,
    };
  } catch {
    return null;
  }
}

async function post(url, headers, body) {
  // Always enforce https: before any network (high-impact: even if config tampered or env override, never send secret over cleartext or to http server).
  if (!isValidHttpsUrl(url)) {
    throw new Error("Refusing to POST to non-HTTPS URL");
  }
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), 10000);
  try {
    const res = await fetch(url, {
      method: "POST",
      headers: { "Content-Type": "application/json", ...headers },
      body,
      signal: controller.signal,
      // Never follow a redirect. `fetch` defaults to "follow", and unlike
      // Authorization, a custom header is NOT stripped when the redirect crosses
      // to another origin — so a 301/302 relayed x-sync-secret to a different host
      // and a 307 relayed the entire payload with it. The https check above is a
      // one-time check on this URL string, not a transport guarantee: a redirect
      // to http:// sent the secret in cleartext. Both were reproduced against real
      // servers by the 2026-08-15 external tarball audit.
      //
      // This is also what keeps /privacy honest. That page tells users the exact
      // host "is printed when setup finishes and saved in ~/.buddybrawl/config.json,
      // so you can always check where your data goes" — a post-install redirect
      // changes the destination without changing either of those. The sync endpoint
      // is a fixed API path and has no legitimate reason to redirect, so failing
      // closed costs nothing.
      redirect: "error",
    });
    const text = await res.text();
    return { status: res.status, body: text };
  } finally {
    clearTimeout(timer);
  }
}

// ─── Stat gain display ─────────────────────────────────────────────────────

// Companion to stripAnsi for the numeric half of the response. Every count and
// stat below is interpolated into a log line as-is, and `?? 0` only defends
// against null/undefined — a *string* passes straight through it and out to the
// terminal unsanitized. Coerce rather than strip: these fields are numbers by
// contract, so anything non-numeric is a hostile or broken response and 0 is the
// honest rendering. This also keeps the gain arithmetic finite, which matters
// because NaN gains fail every `<` comparison below and silently route a hostile
// response to the most verbose branch.
function num(v) {
  const n = Number(v);
  return Number.isFinite(n) ? n : 0;
}

function normalize(s) {
  // Defensive: handle both 'int' and 'int_stat' key names from API
  return {
    str: num(s?.str),
    agi: num(s?.agi),
    int: num(s?.int ?? s?.int_stat),
    vit: num(s?.vit),
    lck: num(s?.lck),
  };
}

function printStatGains(buddy, rawBefore, rawAfter, summary, isNew, milestones, xp) {
  const before = normalize(rawBefore);
  const after  = normalize(rawAfter);

  const P = "[BuddyBrawl]";
  const useColor = !process.env.NO_COLOR && process.env.TERM !== "dumb";
  const green = useColor ? "\x1b[32m" : "";
  const reset = useColor ? "\x1b[0m"  : "";

  // Level-gated progression servers return an xp block; older servers don't.
  // Tier > 0 means the account has ascended past level 100 at least once.
  // These three are interpolated as-is, so they are validated as numbers rather
  // than sanitized as text — a non-numeric level just drops the line entirely.
  const xpLevel = Number(xp?.level);
  const xpTier  = Number.isFinite(Number(xp?.tier)) ? Number(xp.tier) : 0;
  const xpLine  = xp && Number.isFinite(xp.gained) && Number.isFinite(xpLevel)
    ? `${green}+${xp.gained} XP${reset} · ${xpTier > 0 ? `tier ${xpTier} · ` : ""}level ${xpLevel}`
    : null;

  const isLegendary = buddy?.rarity === "legendary";
  const DIV = (isLegendary ? "═" : "─").repeat(46);

  const STATS = [
    { key: "str", label: "STR" },
    { key: "agi", label: "AGI" },
    { key: "int", label: "INT" },
    { key: "vit", label: "VIT" },
    { key: "lck", label: "LCK" },
  ];

  const gains = STATS.map(s => ({ ...s, gain: (after[s.key] ?? 0) - (before[s.key] ?? 0) }));
  const totalGain = gains.reduce((sum, s) => sum + s.gain, 0);
  const maxSingleGain = Math.max(...gains.map(s => s.gain));
  const shiny = buddy?.isShiny ? " · ✦ shiny" : "";
  const name    = stripAnsi(buddy?.name ?? "", 60);
  const species = stripAnsi(buddy?.species ?? "", 40);
  const rarity  = stripAnsi(buddy?.rarity ?? "", 40);

  // ── New user: full hatch ceremony ──
  if (isNew) {
    log(`${P} ${DIV}`);
    log(`${P} ✦ ${name} has hatched!`);
    log(`${P}   ${species} · ${rarity}${shiny}`);
    log(`${P}   Your coding sessions now power your buddy.`);
    log(`${P}   Battle other developers → buddybrawl.xyz`);
    if (xpLine) log(`${P}   ${xpLine}`);
    if (totalGain > 0) {
      log(`${P} ${DIV}`);
      for (const { label, key, gain } of gains) {
        const b = before[key];
        const a = after[key];
        const gainStr = gain > 0 ? `${green}+${gain}${reset}` : "  ─";
        log(`${P}   ${label.padEnd(4)}  ${String(b).padStart(3)}  →  ${String(a).padStart(3)}   ${gainStr}`);
      }
    }
    log(`${P} ${DIV}`);
    return;
  }

  // ── Tier 1: No level-up this session — quiet single line with XP progress ──
  if (totalGain <= 2) {
    if (xpLine && xp.gained > 0) {
      log(`${P} ${name} · ${xpLine}`);
    } else {
      log(`${P} ${name} · light session · no stat changes`);
    }
    for (const m of milestones ?? []) {
      log(`${P} ✦ ${stripAnsi(m)}!`);
    }
    return;
  }

  // ── Tier 2: Compact — scannable single line ──
  if (totalGain < 10 && maxSingleGain < 5) {
    const parts = gains
      .filter(s => s.gain > 0)
      .map(s => `${green}+${s.gain}${reset} ${s.label}`)
      .join("  ");
    log(`${P} ${name} grew stronger  ·  ${parts}${xpLine ? `  ·  ${xpLine}` : ""}`);
    for (const m of milestones ?? []) {
      log(`${P} ✦ ${stripAnsi(m)}!`);
    }
    return;
  }

  // ── Tier 3: Expanded — full victory screen ──
  // sessionSummary is server-controlled like everything else in the response.
  // duration_seconds was already safe via Math.floor; these two were the last
  // two raw interpolations in the file, and a string here rendered a live
  // OSC-8 hyperlink and a forged "[BuddyBrawl]" line straight to the terminal.
  const mins = Math.floor(num(summary?.duration_seconds) / 60);
  const tools = num(summary?.num_tool_calls);
  const files = num(summary?.files_count);

  log(`${P} ${DIV}`);
  log(`${P}   ${name} · ${species} · ${rarity}${shiny}`);
  log(`${P}   ${mins}min · ${tools} tools · ${files} files`);
  log(`${P} ${DIV}`);

  for (const { label, key, gain } of gains) {
    const b = before[key];
    const a = after[key];
    const gainStr = gain > 0 ? `${green}+${gain}${reset}` : "  ─";
    log(`${P}   ${label.padEnd(4)}  ${String(b).padStart(3)}  →  ${String(a).padStart(3)}   ${gainStr}`);
  }

  log(`${P} ${DIV}`);

  if (xpLine) log(`${P}   ${xpLine}`);

  for (const m of milestones ?? []) {
    log(`${P} ✦ ${stripAnsi(m)}!`);
  }

  log(`${P} Battle at buddybrawl.xyz`);
}

// ─── Main ──────────────────────────────────────────────────────────────────

async function main() {
  // Node < 18 has no global fetch. Exit 0 — a session-end hook must not spam
  // a red error at the end of every single session over an environment issue.
  if (typeof fetch === "undefined") {
    log(`[BuddyBrawl] Sync skipped: Node 18+ required (hook ran with ${process.version}). Upgrade Node, then re-run npx buddybrawl init.`);
    process.exit(0);
  }

  const fileConfig = readFileConfig();
  const apiUrl = process.env.BUDDYBRAWL_API_URL || fileConfig.apiUrl;
  const syncSecret = process.env.BUDDYBRAWL_SYNC_SECRET || fileConfig.syncSecret;
  const machineId = getMachineId(fileConfig);
  // Read here rather than at point of use so the completeness check below can gate on it.
  // Never transmitted — see the file-token comment further down for why that matters.
  const pathSalt = fileConfig.pathSalt;

  if (!apiUrl || !syncSecret) {
    log("[BuddyBrawl] Skipping sync: config not found. Run `npx buddybrawl init` to set up.");
    process.exit(0);
  }

  // High-impact client hardening: refuse any apiUrl that is not a plain https base
  // URL — non-https, or carrying credentials, a query or a fragment (see
  // isValidHttpsUrl for why each of those breaks the URL this gets pasted into).
  if (!isValidHttpsUrl(apiUrl)) {
    log("[BuddyBrawl] Skipping sync: apiUrl must be a plain https:// base URL with no credentials, query or fragment (security policy). Re-run `npx buddybrawl init`.");
    process.exit(0);
  }

  // machineId and pathSalt are both minted by `npx buddybrawl init` (1.0.12+) and both
  // have privacy guarantees attached to them, so neither has a derivation fallback any
  // more — see getMachineId() and the pathSalt comment below. A config written by an
  // older CLI is missing them: skip rather than sync with a weaker identifier, and exit 0
  // because a session-end hook must not end every session with a red error.
  if (!machineId || typeof pathSalt !== "string" || !pathSalt) {
    log("[BuddyBrawl] Skipping sync: config is missing machineId/pathSalt (created by an older version).");
    log("[BuddyBrawl] Fix: re-run `npx buddybrawl init` to upgrade it — your buddy and progress are kept.");
    process.exit(0);
  }

  // Read session event data from stdin (Claude Code provides JSON on hook events)
  let session;
  try {
    let raw = await readStdin();
    // PowerShell pipes (and BOM-writing editors) prepend U+FEFF, which breaks JSON.parse
    if (raw.charCodeAt(0) === 0xfeff) raw = raw.slice(1);
    session = JSON.parse(raw);
  } catch {
    session = {};
  }
  if (!session || typeof session !== "object") session = {};

  // Fill in activity metrics from the transcript when the payload lacks them
  // (it always does — Claude Code sends only session_id + transcript_path).
  if (session.num_tool_calls === undefined && session.duration_seconds === undefined) {
    const metrics = computeSessionMetrics(session.transcript_path);
    if (metrics) session = { ...session, ...metrics };
  }

  // Privacy: build the outbound session from an explicit ALLOW-LIST, never by
  // stripping known-bad fields. Claude Code's Stop payload is Anthropic's to change:
  // a denylist forwards whatever they add next (a prompt, a summary, a file list)
  // with no code change here, which would quietly falsify "we never collect your
  // prompts". Only these fields ever leave — the five the server actually reads,
  // plus session_id because /privacy documents it as collected.
  // Dropped on purpose: transcript_path and cwd (they reveal the OS username and
  // every folder name in the path — client names, project names, codenames),
  // hook_event_name, stop_hook_active, permission_mode, and anything added later.
  const SEND_FIELDS = [
    "session_id",
    "duration_seconds",
    "num_tool_calls",
    "num_user_messages",
    "files_modified",
    "tools_used",
    // The true distinct counts, before the caps below truncate the two lists.
    // They go through the allow-list like everything else so the privacy-disclosure
    // drift guard covers them — adding them to the session object after this point
    // would have shipped two new fields past the one test that exists to catch that.
    "files_modified_total",
    "tools_used_total",
  ];
  if (session && typeof session === "object") {
    const allowed = {};
    for (const key of SEND_FIELDS) {
      if (session[key] !== undefined) allowed[key] = session[key];
    }
    session = allowed;
  }

  // Data minimization + exfil reduction: file *paths* never leave the machine.
  // The server only uses the count of unique files (Set(files).size), so each path
  // becomes a token derived from a per-install salt that is never transmitted and
  // never stored server-side. The salt is the point: an unsalted hash of a path is
  // a confirmation oracle, because the same path yields the same token for every
  // user — anyone holding the database could hash a guessed path and check it
  // against everyone at once. Salted + 64-bit, the tokens are opaque the way
  // README and /privacy claim.
  //
  // This reads pathSalt and nothing else. Until 2026-08-15 it fell back to machineId
  // for installs predating the salt — which quietly reopened the exact oracle the
  // salt exists to close, because machineId *is* transmitted and stored server-side.
  // /privacy states the salt "is never transmitted" unconditionally, so the fallback
  // is gone rather than footnoted. main() refuses to sync without a real salt, and
  // pathSalt is read at the top of main() so that check can gate on it.
  if (session && Array.isArray(session.files_modified)) {
    session = {
      ...session,
      files_modified: session.files_modified
        .slice(0, 100)
        .map((p) =>
          "f" + createHash("sha256").update(pathSalt + "\u0000" + String(p)).digest("hex").slice(0, 16),
        ),
    };
  }
  // MCP tool names are the one field here that can carry somebody else's name.
  //
  // Claude Code's own tools are a closed, public set — Read, Edit, Bash, Glob — and
  // say nothing about you. MCP tool names are user-authored and routinely built from
  // the thing they connect to: mcp__acme_internal__read_secrets, mcp__bigclient_crm__*.
  // Sending those verbatim meant a contractor's client list, or a company's internal
  // service names, arriving here as a side effect of a game. It was disclosed and it
  // was still more than we need: nothing scores or displays these names — stat growth
  // uses num_tool_calls, files_modified and duration (see sessionActivityProfile), and
  // tools_used is only ever counted. Raised by the 2026-08-16 external audit as the
  // finding most likely to surprise someone who skimmed /privacy.
  //
  // Salted with pathSalt for the same reason the file tokens are: it never leaves the
  // machine, so the same MCP server yields a different token for every user and the
  // result cannot be reversed by guessing common names. The mcp__ prefix survives so
  // the shape of a session is still legible — "five tools, two of them MCP" — which is
  // all the count ever needed.
  if (session && Array.isArray(session.tools_used)) {
    session = {
      ...session,
      tools_used: session.tools_used
        .slice(0, 50)
        .map(String)
        .map((t) =>
          t.startsWith("mcp__")
            ? "mcp__" + createHash("sha256").update(pathSalt + "\u0000" + t).digest("hex").slice(0, 12)
            : t,
        ),
    };
  }

  // Gather git identity for stable userId
  const email = gitEmail();
  const name = gitName() || "Trainer";
  const git = { email, name };

  // Resolve buddy identity: Anthropic > local override > derived hash (edge fn fallback)
  const { buddy: claudeBuddy, anthropicUserId } = readClaudeJson();
  const overrideBuddy = claudeBuddy ? null : readBuddyOverride();

  // Stable userId: git email when configured; otherwise the Anthropic account id
  // (present even before /buddy has hatched a companion), then the machine id.
  // Never a shared literal like "unknown" — that would collide every email-less
  // user onto one buddy (the server keys accounts on this value).
  const userId = email
    || (anthropicUserId ? `anthropic-${anthropicUserId}` : `machine-${machineId}`);

  let buddyOverride = null;
  if (claudeBuddy) {
    // stripAnsi here too. Every server-sent string already goes through it, but this
    // name comes from ~/.claude.json and reached the terminal raw — the only escape
    // sink in the file that the F6 sweep missed, because the danger looked local.
    // With `\x1b[2K\x1b[1G` it erased this line and reprinted a forged
    // "[BuddyBrawl] All clear, nothing was sent.", and an OSC-8 sequence rendered
    // the buddy's name as a live link to an attacker's host. Demonstrated by the
    // 2026-08-15 audit. species and rarity are safe by construction (SPECIES
    // allow-list, computed threshold) but cost nothing to route through the same
    // helper, and doing so keeps the rule "every interpolated string is stripped"
    // true without exceptions to remember.
    log(`[BuddyBrawl] Using Anthropic buddy: ${stripAnsi(claudeBuddy.name, 60)} (${stripAnsi(claudeBuddy.species, 40)}, ${stripAnsi(claudeBuddy.rarity, 40)})`);
    buddyOverride = claudeBuddy;
  } else if (overrideBuddy) {
    buddyOverride = overrideBuddy;
  } else {
    log("[BuddyBrawl] No Anthropic buddy found. Run /buddy in Claude Code to hatch your real companion. Using derived identity for now.");
  }

  // Build the sync payload. Include machineId so server can bind the per-install token to this machine.
  const payload = { userId, git, session, machineId };

  // Allow-list the override for the same reason SEND_FIELDS allow-lists the session.
  // The Anthropic path builds this object itself, but the ~/.buddybrawl/buddy.json path
  // hands back whatever JSON the user wrote and it was assigned to the payload verbatim
  // — so any stray key in that file shipped, nested objects included. That is the same
  // denylist shape as F3, and it is the only place a doc can be true today and false
  // after someone edits a file we never look at. These five are what the server reads
  // and what all three public documents describe.
  const BUDDY_FIELDS = ["name", "species", "rarity", "isShiny", "anthropicUserId"];
  if (buddyOverride) {
    const allowedBuddy = {};
    for (const key of BUDDY_FIELDS) {
      if (buddyOverride[key] !== undefined) allowedBuddy[key] = buddyOverride[key];
    }
    payload.buddyOverride = allowedBuddy;
  }

  // POST to the buddy-sync edge function
  try {
    const url = buildSyncUrl(apiUrl);
    const { status, body } = await post(
      url,
      { "x-sync-secret": syncSecret },
      JSON.stringify(payload),
    );

    if (status === 200) {
      try {
        const result = JSON.parse(body);

        if (!result.rateLimited) {
          if (result.statsBefore && result.statsAfter) {
            printStatGains(
              result.buddy,
              result.statsBefore,
              result.statsAfter,
              result.sessionSummary,
              result.isNew,
              result.milestones,
              result.xp,
            );
          } else {
            log("[BuddyBrawl] Session synced successfully");
          }

          // Buddy not yet claimed by a web/mobile account — surface the link
          // code. This is the escape hatch for git email ≠ GitHub email, where
          // the dashboard auto-link can never match. A fresh code prints after
          // every sync until the buddy is linked, then this goes quiet forever.
          // Allow-list rather than sanitize: a link code is alphanumeric by
          // construction, so anything else in it means the response is not one
          // we should be echoing to a terminal at all.
          if (result.linkCode && result.needsLink) {
            const linkCode = String(result.linkCode).replace(/[^A-Za-z0-9]/g, "").slice(0, 12);
            if (linkCode) {
              log(`[BuddyBrawl] Link your buddy to the web: sign in at buddybrawl.xyz/dashboard and enter code ${linkCode} (valid 15 min)`);
            }
          }
        }
        // rate-limited: completely silent — no log at all
      } catch {
        // Response wasn't JSON — fall back to generic success message
        log("[BuddyBrawl] Session synced successfully");
      }
    } else if (status === 401 || status === 403) {
      // Actionable: token invalid/revoked, or bound to a different machine id
      // (a legacy hostname-derived id that changed does this). Loud on purpose.
      log(`[BuddyBrawl] Sync rejected (HTTP ${status}): ${stripAnsi(body, 500)}`);
      log("[BuddyBrawl] Fix: re-run `npx buddybrawl init` to re-link this machine — your buddy and progress are kept.");
      process.exit(1);
    } else if (status >= 500 || status === 429) {
      // Server-side hiccup — nothing the user can act on at session end, and the
      // next session retries anyway. Exit 0 so it doesn't render as a hook error.
      log(`[BuddyBrawl] Sync skipped (server returned HTTP ${status}) — will retry next session.`);
      process.exit(0);
    } else {
      log(`[BuddyBrawl] Sync failed (HTTP ${status}): ${stripAnsi(body, 500)}`);
      process.exit(1);
    }
  } catch (e) {
    // Network failure (offline, VPN, captive portal, proxy). Exit 0 — a plane-wifi
    // day must not end every session with a red hook error.
    const proxied = process.env.HTTPS_PROXY || process.env.https_proxy ||
      process.env.HTTP_PROXY || process.env.http_proxy;
    if (proxied) {
      // Don't echo the proxy URL — it can embed credentials.
      log(`[BuddyBrawl] Sync skipped: could not reach the server (${e.message}). A proxy is configured, but Node's fetch ignores proxy env vars — on Node 24+ retry with NODE_USE_ENV_PROXY=1.`);
    } else {
      log(`[BuddyBrawl] Sync skipped: network unreachable (${e.message}) — will retry next session.`);
    }
    process.exit(0);
  }
}

main();
