# Security policy

BuddyBrawl installs a hook that runs on your machine after every Claude Code
response. That is a level of access worth taking seriously, and reports about it
get treated as the highest priority in this project.

## Reporting

Email **hi@buddybrawl.xyz**. Please don't open a public issue for anything that
looks exploitable — send it there first.

You can expect:

| | |
|---|---|
| First reply | within 72 hours |
| Assessment | within 7 days, with a fix or a reason it isn't one |
| Fix released | as a new npm version; the advisory follows once users can update |

Useful things to include: the version (`npx buddybrawl --version`), your OS, what
you did, and what happened that shouldn't have. A reproduction is welcome and not
required — a clear description of the flaw is enough to start.

Please don't send your sync token. If you believe it has leaked, run
`npx buddybrawl uninstall` (which retires it server-side) or re-run
`npx buddybrawl init`, which issues a new one and revokes the old.

## In scope

Everything that runs on a user's machine, which is everything in this package:

- `cli/index.mjs` — the installer, run once by `npx buddybrawl init`
- `cli/buddy-sync.mjs` — the Stop hook, run after each Claude Code response

Also in scope, though the source is not public:

- the sync, battle, forge and league endpoints the hook and site talk to
- the install-token model: issuance, machine binding, revocation
- anything that causes data to leave a machine that the [privacy
  page](https://www.buddybrawl.xyz/privacy) says does not leave it

That last one is the one we care about most. The privacy page and the README
make specific claims about what is transmitted; a way to make any of them false
is a security bug, even if nothing is "hacked" in the usual sense.

## Out of scope

- Denial of service, traffic floods, or resource exhaustion against the API
- Social engineering, phishing, or physical access to someone's machine
- Findings that require an attacker who already has write access to the user's
  home directory or their `~/.claude/settings.json` — at that point the hook is
  the least of their problems
- Missing hardening that isn't exploitable on its own (we'll still read it, it
  just won't be treated as a vulnerability)

## Supported versions

The latest published version, only. Fixes ship forward as a new release rather
than being backported — `npx buddybrawl@latest init` re-installs the current
hook, and the installed hook never updates itself.

## Safe harbour

Research done in good faith under this policy — your own installs, no third-party
data, no service degradation, no exfiltration beyond what proves the point — is
authorised, and we will not pursue legal action over it. Tell us before you go
public and we'll agree a date; credit in the advisory if you want it.

## What is already true

Before reporting, it may save you time to know:

- the package has **zero dependencies and no install scripts**, so `npm pack`
  downloads it without executing anything
- the hook ships as unminified source, and the published bytes can be diffed
  against the public mirror at https://github.com/igormiklos/buddybrawl-cli
- the sync request refuses redirects and requires a plain `https://` endpoint
- tokens are stored server-side as sha256, are bound to a random per-install ID,
  and are revoked on re-init and on uninstall

None of that means there's nothing left to find. It means these particular
answers are already known.
