# BuddyBrawl

![npm version](https://img.shields.io/npm/v/buddybrawl)
![license](https://img.shields.io/badge/license-proprietary-lightgrey)
![downloads](https://img.shields.io/npm/dw/buddybrawl)
![node](https://img.shields.io/node/v/buddybrawl)

> Your code has a companion. Gear it up. Fight.

![BuddyBrawl demo](https://www.buddybrawl.xyz/buddybrawl.gif)

You already have a Claude Code companion. It's waiting.

## Install

```
npx buddybrawl init
```

60 seconds. Hooks into Claude Code. Syncs your buddy automatically as you work — no need to close the session.

## How it works

**01 — Code with Claude**  
Install the hook. Every Claude Code session feeds your buddy: tool calls → STR, session length → VIT, unique files created or edited → INT, messages sent → AGI. LCK grows automatically with every level.

**02 — Earn Gear**  
Win battles → earn grzkies → craft legendary weapons, armor, and accessories. Dev-flavored loot with rarities from common to transcendent. 248 item bases, 16 affixes, 27 unique items.

**03 — Climb the Ranks**  
ELO-ranked, AI-narrated battles. Micro-leagues of 8 players. Weekly resets with promotion and demotion.

## Gear

```
⚔️  Segfault Blade      [Mythic]    — +42 STR, 15% lifesteal
🛡️  Heisenbug Ward      [Legendary] — +28 VIT, 20% dodge on special
🪖  Null Pointer Helm   [Rare]      — +18 INT, reflects 10% magic
💍  Callback Signet     [Epic]      — +12 AGI, first strike bonus
👢  Stack Overflow Treads [Legendary] — +22 AGI, on-hit slow
📿  Off-by-One Amulet   [Rare]      — +15 LCK, +8 INT
```

## Battle example

```
Round 2 — Dragon [Epic] uses ATTACK
Rabbit [Rare] attempts to dodge... fails.
Dragon lands 47 damage. Rabbit is at 53 HP.

"The Dragon's Segfault Blade tears through the Rabbit's defenses.
 One more round like this and it's over."

[Clutch Victory — you were 12 HP from losing]
```

## Why bother

- **Build your buddy** — every commit, every session, every file you touch feeds real stat growth. Your buddy is a byproduct of work you were already doing.
- **Defeat a colleague** — challenge anyone else running BuddyBrawl. Bragging rights are on the leaderboard, not just in Slack.
- **Gear obsession** — 248 item bases, 16 affixes, 27 uniques. Dev-flavored loot that actually matters in battle.
- **Weekly leagues** — 8-player pods, weekly promotion and demotion. Prove it every week, not just once.

## Links

- **Demo:** https://www.buddybrawl.xyz/demo
- **Play:** https://www.buddybrawl.xyz
- **Leaderboard:** https://www.buddybrawl.xyz/leaderboard
- **npm:** https://www.npmjs.com/package/buddybrawl

Built for Claude Code users. Your buddy is your real Claude Code companion.

## Privacy

The sync hook fires automatically as you work (a Stop hook, after each response — no need to close the session).

Two different endpoints are involved. `npx buddybrawl init` fetches your config once from `www.buddybrawl.xyz`. After that, every session syncs straight to our Supabase Functions endpoint (`*.supabase.co` — Supabase is our database provider); nothing routes back through buddybrawl.xyz. The exact host is printed when setup finishes and saved in `~/.buddybrawl/config.json`, so you can always see where your data goes.

Each sync sends:

| Data | Purpose |
|---|---|
| `git user.email` and `user.name` | Stable identity across sessions |
| Anthropic companion name, species, and Anthropic user ID — plus the rarity and shiny flag, derived from that ID on your machine rather than read from anywhere | Buddy identity |
| Session duration, tool call count, message count, session ID | Stat growth |
| The names of the tools used — `Read`, `Edit`, `Bash`, and any MCP tool names | Stat growth |
| A hashed token per file created or edited (used only to derive a count) — never the names or paths | Stat growth |
| The total count of distinct files and the total count of distinct tools, as plain numbers — at most 100 tokens and 50 tool names are sent, so these keep a big session's stats accurate | Stat growth |
| The random install ID from setup, re-sent each sync | Confirms the token is used from the machine it was issued to |

Setup itself sends only a random install ID and the CLI version — plus, if you're re-running it over an existing install, a one-way hash of the sync token being replaced, so the old one can be switched off instead of staying valid forever. The token itself never goes to that host.

No source code is transmitted. The hook ships as readable, unminified source — after install, `cli/buddy-sync.mjs` inside the package is the exact file that runs on your machine, and you can read every line of it.

## Security

HTTPS-only sync endpoint, per-install tokens bound to your machine, and rate-limited sync/battle/forge endpoints. Full detail at https://www.buddybrawl.xyz/privacy.

Don't take that on trust — the package is built to be checked. It ships **seven files, zero dependencies and no install scripts**, so `npm pack buddybrawl` downloads it without running anything and you can read 100% of what you'd be installing in a sitting:

```
npm pack buddybrawl
tar -xzf buddybrawl-*.tgz
cat package/package.json     # no dependencies, no scripts, no postinstall
cat package/cli/index.mjs     # the installer — what npx runs
cat package/cli/buddy-sync.mjs # the hook — what runs after each session
```

Point your own Claude Code at that folder and ask it what leaves your machine. The answer should match the table above; if it doesn't, that's a bug and we want to hear about it at hi@buddybrawl.xyz.

The sync request never follows a redirect: if the endpoint answers with "go ask this other server instead", the sync fails rather than follows. A custom header like the sync token is *not* stripped when a redirect crosses to another host the way `Authorization` is, so following one would hand the token — and, on a 307, the whole payload — to a server you never configured, possibly over plain HTTP. The endpoint is also required to be a plain `https://` base URL: no embedded credentials, no query string, no fragment.

`npx buddybrawl init` also checksums the hook as it copies it into place, so a corrupt or partial install fails loudly instead of running a half-written file. That is a corruption check, not tamper-proofing: the hash ships in the same package as the hook, so anyone able to alter one could alter the other. What actually secures the download is npm's own integrity verification over HTTPS — and, more than either, the fact that the hook is unminified source you can read end to end.

## License

All rights reserved — see [`LICENSE`](LICENSE). Free to install and use via `npx buddybrawl init`; source is not licensed for reuse or redistribution.
