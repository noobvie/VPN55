Mechanical quality check on VPN55 shell code. Check the file(s) in $ARGUMENTS, or
everything if none given.

CI already enforces six of these. Run them locally first so the feedback is fast,
then do the part CI cannot: the checks that need judgment.

## 1. Run what CI runs

```bash
find . -name '*.sh' -not -path './.git/*' -exec bash -n {} \;
bash -n vpn55.sh helper/vpnctl
node .github/scripts/check-locales.mjs
```

`shellcheck` is **not installed on this machine** — fetch the standalone binary
rather than skipping it, or say plainly that lint did not run. Never report a
shellcheck pass that did not happen.

```bash
shellcheck --severity=warning --external-sources vpn55.sh helper/vpnctl lib/*.sh
```

The three hygiene greps in `.github/workflows/ci.yml` (protocol leakage, shebang in
`lib/`, unguarded `cp`/`mv`/`mkdir`/`rm`) are cheap — run them from the workflow
rather than re-typing them from memory, so local and CI cannot drift.

## 2. What CI cannot catch

- **`producer | grep -q` under `pipefail`** — `grep -q` exits as soon as it matches
  and SIGPIPEs the producer, so the pipeline reports failure on a *successful* match.
  This has already hit nine sites in this repo. Use `str_has_line` / `str_contains`
  from `lib/ui.sh` on a captured string instead. Flag every `| grep -q` and every
  `| head -n1` fed by a long producer.
- **Guarded, but guarded wrong.** CI's grep only proves a `||` is on the line. Check
  the guard actually returns: `cp … || error "…"` logs and carries on. It must be
  `|| { error "…"; return 1; }`.
- **A function ending in `[[ … ]] && cmd`** — a false test makes the function return
  1, which under a `||`-guarded caller is a silent wrong answer. Use the `if` form.
- **Menu `case` arms** — every arm `||`-guarded, every menu and sub-menu has a `0)`
  that actually returns, and the header comment's menu list matches the `case`.
- **`lib/` line 1 is `# shellcheck shell=bash`** — without it shellcheck cannot
  detect the dialect and silently checks less.

## 3. Naming and shape

- `lib/core_*.sh` → `core_`-family prefixes already in use (`net_`, `fw_`, `pool_`,
  `pki_`, `user_`, `fs_`); `lib/proto_<p>.sh` → `vpn_<p>_<verb>` and nothing else
  exported. A helper in an adapter that is not `vpn_<p>_*` must be `_`-prefixed.
- 4-space indent, no tabs. Unicode box-drawing section headers.
- Flag unquoted expansions in `rm`/`cd`/path arguments, and any `rm -rf $VAR`
  without `${VAR:?}`.

Report grouped by category with `file:line` and a concrete fix. End with a count,
and state explicitly which of the CI checks you actually executed.
