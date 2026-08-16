# What this repository is

A read-only mirror of the `buddybrawl` npm package — the CLI installer and the
Claude Code hook, and nothing else. It exists so anyone deciding whether to
install can compare the bytes npm serves against readable source, without taking
anyone's word for it.

Every file here that the package also ships is byte-identical to what
`npm pack buddybrawl` downloads, because it *is* that tarball, extracted. Check it:

```bash
npm pack buddybrawl@1.0.21
tar -xzf buddybrawl-1.0.21.tgz
git clone https://github.com/igormiklos/buddybrawl-cli.git mirror
diff -r package mirror -x MIRROR.md -x SECURITY.md -x .gitattributes -x .git   # expect no output
```

`MIRROR.md`, `SECURITY.md` and `.gitattributes` are the only three files here
that the tarball does not contain: this page, the security policy (GitHub reads
that one from the repository root, and an npm package is not a repository), and
the rule that stops Git rewriting line endings on checkout so the comparison
above works on Windows too. Everything else is package bytes.

`npm pack` downloads without executing: no install scripts run, nothing is
unpacked into `node_modules`, and your `package.json` is untouched. The package
ships **no dependencies and no scripts**, so what you just extracted is 100% of
what you would be installing.

The hook that runs on your machine has its own hash, shipped beside it:

```bash
sha256sum package/cli/buddy-sync.mjs
cat package/cli/hook-integrity.json
# abb0c204aa8fa922508a52980066fe61c2405a9e7acc810365e129e9615a2c44
```

That hash is a corruption check, not tamper-proofing — it ships in the same
package as the file it describes, so anyone able to alter one could alter the
other. What it catches is a truncated download, and an installer that wrote
something different from what it shipped. The real assurance is that the hook is
unminified source you can read end to end, with no dependencies to read after it.

## Two files worth reading

| File | What it is |
|---|---|
| `cli/index.mjs` | the installer — what `npx buddybrawl init` runs, once |
| `cli/buddy-sync.mjs` | the hook — what Claude Code runs after each response |

Point your own Claude Code at this repo and ask what leaves your machine. The
answer should match the privacy table in [`README.md`](README.md) and
https://www.buddybrawl.xyz/privacy. If it doesn't, that's a bug and we want it:
**hi@buddybrawl.xyz**.

## What is not here

The game itself — battle engine, backend, web app, database — is closed source
and stays private. None of it runs on your machine. Everything that touches your
computer is in this repo.

## This is not where development happens

The mirror is regenerated and force-updated on each release, so pull requests
here can't be merged. Send bugs, and especially anything that looks like a
privacy or security problem, to **hi@buddybrawl.xyz**.

Security reports have their own page — [`SECURITY.md`](SECURITY.md) covers
scope, response times and safe harbour.

## Removing it

```bash
npx buddybrawl uninstall
```

Unregisters the Claude Code hook, deletes `~/.buddybrawl`, and asks the server to
retire this install's sync token. `--dry-run` prints what it would do and touches
nothing. The code for all of it is `cmdUninstall` in `cli/index.mjs`, in this
repository, so you can read what it does before you run it.

## License

See [`LICENSE`](LICENSE). Published so it can be read and verified — not
licensed for reuse, modification or redistribution.
