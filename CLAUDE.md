# VPN55 — Claude Instructions

## Project

A self-hosted multi-protocol VPN manager — **WireGuard, IKEv2/IPsec and OpenVPN**
behind one installer and one admin panel. Bash for the server side, Node for the
panel. Market is **Vietnam**; UI locales are **VI (default), EN, FR**.

Scripts target a **Linux VPS and run as root**. They are never executed on the
development machine (Windows). Verification here is `bash -n` and `shellcheck` only.

Full build plan: <https://claude.ai/code/artifact/525ea413-a7e9-46ef-bd28-f59fc3117a3f>

---

## The adapter contract

Every protocol module implements exactly this surface. **Nothing outside
`lib/proto_*.sh` may know which protocol it is talking to.**

```
vpn_<proto>_available      # can this host run it? (kernel, container, pkgs)
vpn_<proto>_capabilities   # what this adapter needs, and how it revokes
vpn_<proto>_install        # idempotent; safe to re-run
vpn_<proto>_uninstall      # fully reverses install, incl. NAT + firewall
vpn_<proto>_cred_add       # <user> [k=v …] → creates credential, returns id
vpn_<proto>_cred_remove    # <cred_id> → revokes (see revocation trap)
vpn_<proto>_cred_list      # machine-readable, one record per line
vpn_<proto>_artifacts      # <cred_id> → what a client can be given
vpn_<proto>_client_config  # <cred_id> [artifact] [locale] → that artifact on stdout
vpn_<proto>_status         # service state + per-cred rx/tx + last handshake
vpn_<proto>_restart        # cycle the daemon; NOT _install re-run
vpn_<proto>_backup_paths   # absolute paths this protocol cannot be rebuilt without
```

**`_backup_paths` is how `lib/core_backup.sh` stays protocol-blind.** It prints one
absolute path per line — the files that cannot be regenerated on a replacement host,
and nothing else. `/etc/wireguard`, `/etc/openvpn` and `/etc/swanctl` appear nowhere
in `core_backup.sh`; each adapter names its own. An adapter that does not implement
it is warned about **loudly** at backup time rather than skipped, because "your
protocol's state is not in the archive" is not a footnote to discover on restore day.

Three rules for what it may print:

  - **Never a client private key, and never a hand-off spool.** Those are shredded
    after delivery on purpose; an archive outlives that erasure by years.
    `_bak_guard` refuses the whole backup if a path under `pki/private/` turns out to
    be a credential id in the register, or if any path is under a spool.
  - **The server's private key, by the CN the adapter recorded** — yes, deliberately.
    An archive holding a server certificate without its key restores a daemon that
    cannot load its own identity, and `_ovpn_server_cert_ensure` skips reissue when
    the certificate looks valid, so nothing would fix it.
  - **Not what `_install` regenerates.** A daemon config built deterministically from
    `settings.conf` is not irreplaceable; it is rebuilt on the new host, where the
    interface name and addresses may differ anyway.

`_status` is the one that matters most: it is what the panel reads, and forcing all
three protocols through one output shape is what stops the panel from growing
protocol-specific branches.

**Contract defects are fixed in the contract, not worked around.** If `vpn55.sh` or
any panel code has to branch on protocol name, that is a defect — fix it while there
are few implementations to reconcile, not later. A grep for `wireguard|ipsec|openvpn`
outside `lib/proto_*.sh` should return nothing but comments and locale keys, and CI
enforces it — **extend that pattern in the same commit as a new adapter**, or the check
goes green precisely because it does not know the protocol that just arrived.

**`_restart` is not `_install` re-run.** A re-apply rewrites configuration and may
change nothing; a restart always cycles the daemon, which is the point when a service
is wedged. Conflating them means an operator asking to restart a stuck service silently
gets a config rewrite instead. It is also the only way to make a CRL-based revocation
take effect immediately, which is why the revocation paths point at it. The disruption
is declared in `_capabilities` so a caller can warn BEFORE the operator confirms — the
same ordering the revocation notice needed, for the same reason.

**One verb, three different operations.** `_cred_remove` is instant for WireGuard,
CRL-based for OpenVPN and IKEv2. The contract hides that; the *return value* must not.
Report the latency honestly so the panel can display it truthfully — and report the
declared worst case *before* the operator confirms, which is what `_capabilities` is for.

### Record shapes

Every record's **first field is its type**, so a reader never guesses from the field
count and can ignore a record type it does not understand.

```
# _capabilities
revoke    <immediate|crl>  <worst_case_seconds>   # -1 = no bound at all
custody   <server|client>  <one-line disclosure shown when issuing>
filtering <resistant|partial|exposed>  <one-line explanation in the adapter's words>
restart   <effect>  <what a restart costs the people connected right now>
option    <key>  <prompt>  <required 0|1>  <help text>

# _cred_list
<cred_id>  <user>  <state>  <address>  <created>  <custody>  <artifacts_held 0|1>

# _artifacts
artifact  <id>  <label>  <filename>  <text|base64>  <qr 0|1>  <note>
#   ⚠ the id vocabulary is the ADAPTER'S, and it is not fixed. WireGuard emits
#   conf, conf2, conf3 … — one per registered endpoint, because that protocol
#   has no client-side failover and the alternates have to be separate files.
#   A reader must take the ids from _artifacts and pass them back verbatim,
#   never assume the set.

# _status
service   <tag>  <state>  <enabled>  <listen>  <since>  <cred_count>
cred      <tag>  <cred_id>  <user>  <state>  <address>  <rx>  <tx>  <handshake>  <endpoint>  <connected 1|0|->
note      <tag>  <info|warn|crit>  <message>

# vpn55.sh --status only — the transport adds these, adapters do not emit them
credmeta  <tag>  <_cred_list's own record, verbatim>
```

**`cred` and `credmeta` are not two views of the same thing.** `cred` is LIVE state from
the running daemon — who is connected, how many bytes, when the last handshake was — and
says nothing about a credential the service is not currently carrying. `credmeta` is the
INVENTORY, from `_cred_list`: when it was issued, who holds the key, and whether a
configuration file for it still exists. The portal turns that last field into a decision,
because the adapters shred a spooled key hours after issue: `held 0` means "there is
nothing left to download, this has to be rotated", and a portal without it would offer a
download that can only fail. It costs one `_cred_list` per adapter per poll — three
subprocess trees on a three-protocol host, not one per credential.

Rules that are not obvious from the shapes:

- **`-` means "no reading". It is not zero and it is not "never".** `rx`/`tx` of `-` must
  not be treated as a counter reset by the collector. `handshake` of `0` asserts the
  credential has never been used; `-` says the adapter cannot tell — a daemon that keeps
  no history must emit `-`, because reporting `0` claims a fact it does not have.
- **`handshake 0` is scoped to the adapter's OWN observation window, and must be proved.**
  Every one of these daemons forgets on restart, so "no handshake recorded" and "never
  used" are the same reading unless the adapter can show the credential was issued *after*
  the window opened. An adapter emits `0` only when it holds that proof — it has the
  credential's issue time and the service's start time and the first is later. Otherwise
  `-`. WireGuard's kernel reports `0` for every peer after the interface comes up, so a
  bare pass-through would tell an operator that a fleet which connected an hour ago has
  never connected, and a reader that persists "last seen" would overwrite the real date.
  A reader must therefore also treat `never` as **fillable but not overwritable**: it may
  fill an unknown, it may never downgrade a timestamp it already holds.
- **`connected` is the liveness answer; `endpoint` is not.** `1` means the service is
  carrying a session for this credential right now, `0` means it is not, `-` means the
  adapter cannot tell (its daemon is stopped or unreadable). It exists because the obvious
  substitutes are all protocol-shaped: `handshake` is a *time*, not a state, and answers
  "when", not "now"; and `endpoint` is a *live* peer address on two of them but a **sticky
  last-known** address on WireGuard, where it survives for the life of the interface and
  would report a device that last connected in March as online. A peer-less protocol
  (a listener-shaped one — see `docs/circumvention.md` §6) has no endpoint to report at
  all and would otherwise be permanently invisible in a connections list. `endpoint`
  remains what it says: the remote address of the CURRENT session, `-` when there is none.
- **`handshake` is one quantity: the last moment the adapter OBSERVED this credential
  live.** Not the moment a session started. A session opened three days ago and carrying
  traffic right now was last seen *now*, and reporting its start time would show an active
  device as three days idle. Each daemon exposes this differently — a completed handshake,
  a status file's write time, a security association's last-use counter — and it is the
  adapter's job to reduce whichever it has to that one meaning before emitting it.
- **`address` is nullable, and `-` there means "this protocol has no per-credential
  address".** Two adapters pin one from `net_pool_alloc` and carry it in `_cred_list`; the
  third lets its daemon hand out a virtual IP at connect time, so it has nothing to report
  until a session exists. A reader renders the absence, never a placeholder dash.
- **`encoding: base64` is not decoration.** A caller reading a config through `$(…)`
  cannot carry binary — NULs are dropped and trailing newlines eaten. Anything not text
  goes base64 on the wire and the caller decodes.
- **`qr: 1` means a camera will actually resolve it**, not "this is a string". A QR of
  eight kilobytes is a picture of nothing, and offering one is worse than offering none
  because it looks like it should have worked. The caller encodes **exactly what
  `_client_config` returns for that artifact**, so an adapter may not set `qr 1` on an
  artifact whose size it does not control — in particular one carrying translated prose,
  whose length is a property of the locale chosen at handover and not of anything the
  adapter can measure. Prose belongs in its own `instructions` artifact; the scannable one
  stays machine-facing and small. The caller enforces a ceiling as well, because an
  adapter's promise here cannot be verified by the reader.
- **`option`s are declared, never assumed.** An adapter that receives a `k=v` it did not
  declare must fail, not ignore it: silently dropping a field an operator filled in and
  then reporting success is the worst of the three available behaviours.
- **`filtering` exists because the reader may not work it out for itself.** A UI that must
  warn which services survive a filtered network cannot compute that without learning which
  protocol it is holding — the one thing nothing outside `lib/proto_*.sh` may do. So the
  adapter states it. The **level** is the stable identifier a UI keys a translation on; the
  **sentence is adapter-authored data**, rendered verbatim and attributed, exactly like a
  `note` — a reader cannot translate a sentence it did not write without learning the same
  forbidden thing. Two of the three adapters COMPUTE their level from how they were
  installed (obfuscation mode; transport and port), so it is a live answer, not a constant.
- **An unrecognised enumerated value is shown, never swallowed.** A reader that meets a
  `filtering` level or a `note` severity it predates renders the word itself and says it
  does not recognise it. A `note` of unknown severity is shown at the LOUDEST known level,
  never the quietest: downgrading something an adapter went out of its way to raise is how
  a warning ends up rendered as chatter.

`listen` is a display string, not a port — a protocol serving two writes both.

---

## `core_users.sh` owns identity; adapters own credentials

**One person, one record, N credentials.**

`lib/core_users.sh` is the single user registry. Fields: `name`, `created`, `enabled`,
`quota_bytes|null`, `expires_at|null`, `conn_limit|null`, `quota_reset|null`,
`credentials[]`. Null means unlimited / never — permissive defaults are what let one
codebase serve an own-fleet deployment and a paid tier without a fork.

`conn_limit` (simultaneous devices) and `quota_reset` (monthly rollover vs a lifetime
cap) come from prior art: 3x-ui, Marzban and Hiddify converged independently on both.
They are cheap as nullable columns now and awkward once three adapters and the portal
read the registry — see `docs/prior-art.md` §4.

An adapter owns the credential — the keypair, the certificate, the peer entry — and
nothing else. **If an adapter keeps its own user list you get three parallel identity
systems and the panel cannot answer "who is this".** That failure is not visible on
day one; it surfaces as a user who exists in two protocols and no longer in the third.

The panel is **not** the source of truth either. On-disk server config is. The panel
reads `vpn_<proto>_status` from the adapters. A parallel panel DB that drifts from
actual server state is the most common failure in this product category.

---

## errexit does not protect lib bodies

A function called as `fn || warn` — or inside `if fn; then` — runs with **errexit
disabled for its entire body**, and re-issuing `set -e` inside it does not undo that
(POSIX ignores it there). Since every menu `case` arm must be `||`-guarded, that is
the **normal** case for every sourced lib, not an edge case.

So in `lib/`:

```bash
mkdir -p "$dir" || { error "cannot create $dir"; return 1; }
cp "$src" "$dst" || { error "cannot copy $src"; return 1; }
```

Guard **every** command that creates, copies, moves or deletes with its own
`|| { error "..."; return 1; }`. A bare `cp` or `mv` in a lib is a silent failure that
ships. `mv "$new" "$dir"` does not fail when `$dir` already exists — it nests inside it
while the success message prints.

Never write a header comment claiming the caller's `set -e` covers you. It does not.

Related bash rules:

- **Every menu `case` arm is `||`-guarded** (`fn || true`). An unguarded non-zero
  return kills the whole script instead of returning to the menu.
- **Never end a function with `[[ ... ]] && cmd`** — a false test makes the function
  return 1. Use the `if` form.
- **`lib/` files are sourced, not executed — no shebang.** They carry
  `# shellcheck shell=bash` on line 1 instead, or shellcheck cannot detect the dialect.
- `set -euo pipefail` at the top of the entry script and of `helper/vpnctl`.

---

## ⚠ `${!arr[@]+"${!arr[@]}"}` does not iterate a populated array

The defensive idiom for "expand an array that may be empty under `set -u`" is

```bash
for x in ${arr[@]+"${arr[@]}"}; do        # VALUES — correct
```

The same shape for **indices is silently wrong**:

```bash
for i in ${!arr[@]+"${!arr[@]}"}; do      # KEYS — BROKEN
```

With an operator attached, bash stops reading the leading `!` as "the keys of" and
reads it as **indirect expansion**: it takes the array's joined value as a variable
NAME, fails with `alpha beta: invalid variable name`, and **the loop body never runs
at all**. Not on an empty array — on a *populated* one, which is the only case that
matters. Verified on bash 5.2.

It shipped in two places and was found in 2026-09 while adding a third. `cli_adapters`
printed nothing, which would have ended every `tests/vps-acceptance.sh` run with *"no
tunnel service can run on this host"*; `vpn_adapter_label` returned the raw tag with
rc 1 for every adapter, masked by the `|| true` at its call sites. Neither was noticed
because nothing in this repository has ever run on a VPS.

Use the count guard, which is what `cli_status` already did correctly:

```bash
[[ ${#arr[@]} -gt 0 ]] || return 0
for i in "${!arr[@]}"; do
```

The value form is unaffected and stays as it is.

---

## i18n — keyed catalogs, never phrase maps

`t('peer.add.button')` resolving against `panel/locales/{vi,en,fr}.json`. **Never a map
keyed on English strings.**

A phrase map keyed on English word order misses every translator who reorders the
sentence. In a sibling project two such maps were byte-identical across two files — it
felt like proof of correctness and proved nothing: Dutch, Greek and Chinese shipped 27
unbranded strings, including the page title and a currency label. Key on stable
identifiers, and check a new locale against the catalog **programmatically** before
shipping it.

- **Vietnamese is the default locale.** English is the fallback *and* the
  key-authoring source language. `vi.json` is the file that must never have a missing
  key — it is what most users see.
- A missing key falls back to English **and logs**. Silent blanks are worse than an
  untranslated string.
- **The panel's catalogs live at `panel/locales/`.** The adapters' text catalogs live
  at `lib/locales/<tag>/<locale>.txt` — a different FORMAT for a different consumer
  (bash cannot parse JSON without a dependency), not a second catalog of the same
  strings. Never add a third.
- **Use `Intl`** for dates, numbers and byte sizes, in the BROWSER — it is the only
  place that knows the viewer's time zone. `view.js` sends raw numbers and Unix
  epochs on purpose. Vietnamese has no plural inflection and French pluralises
  differently from English, so there is no `+ 's'` anywhere and there must not be.
- **Lay out against the LONGEST locale.** Measured: French is +18% over English
  across the catalog, but of the 84 strings in a box that cannot wrap, English is
  longest for **ten**. Sizing to English is sizing to the wrong language 88% of the
  time.
- **The font stack is measured, not assumed.** Vietnamese stacked diacritics live in
  Latin Extended Additional; a face without it falls back PER CHARACTER, mid-word,
  and reads as a fault on the reader's machine. `panel.css` overrides `--font` for
  every theme because two of the vendored stacks had that hole. Re-derive coverage
  with `check-fonts.mjs --probe <font dir>`; never by eye.
- UTF-8 end to end. `LC_ALL=C` is PINNED in both `spawn` envs — C is the
  byte-transparent locale, so UTF-8 passes through untouched, and pinning stops the
  child's behaviour depending on how the unit was started.
- Locale persists **per browser** (cookie), defaulting from `Accept-Language`.
  **Never geolocate it.** Not per account: that would mean the panel writing
  `admins.json`, and every panel write goes through vpnctl's seven verbs — an
  eighth is a security-model change, not a convenience.
- **User names stay ASCII** (`^[a-z][a-z0-9_-]{1,31}$`). That is an identifier that
  becomes a filename, a certificate subject and an argv word to a root helper — not
  an i18n gap to close by widening the regex.
- **The bash installer stays English-only.** Operators are technical, and translating a
  root installer multiplies the test surface for no reach. The files it HANDS OVER are
  a different audience and are translated; it asks which language once per delivery,
  or takes `VPN55_ARTIFACT_LOCALE`.
- **Instructions render at handover, not at issue.** Adapters spool the FACTS
  (`<cred>.meta`) and render any locale on demand — the operator issuing a credential
  and the person receiving it are usually not the same person.
- **Five CI checks, not one.** Key parity, key USAGE (a key the panel looks up that
  nobody authored — this found a live bug), shell-text section/placeholder parity,
  font coverage, expansion ceiling. Full contract → `docs/i18n.md`.

---

## Repo layout

```
vpn55.sh              # single entry — bootstrap, main menu, argument dispatch
lib/
  ui.sh                 # colors, logging, prompts, QR
  ui_adapter.sh         # the per-service screens — presentation over the contract
  ui_screens.sh         # host / network / users / panel / teardown / update screens
  cli.sh                # --status (the panel's read) + the verbs acceptance drives
  core_distro.sh        # OS, kernel module, container detect
  core_net.sh           # forwarding, NAT, firewall, IP pool allocator
  core_fs.sh            # atomic write, shred, key=value conf, uuid, xml escape
  core_i18n.sh          # locale resolve + @@section render, for END-USER text only
  core_source.sh        # the ONLY lib that touches the network: fetch, revision, update
  core_pki.sh           # cert ops shared by OpenVPN + IKEv2
  core_backup.sh        # the one archive that outlives the host, and its restore
  core_users.sh         # owns IDENTITY — the single user registry
  proto_wireguard.sh    # adapters own CREDENTIALS only
  proto_ipsec.sh
  proto_openvpn.sh
  locales/<tag>/        # vi.txt · en.txt · fr.txt — setup pages, config comments
panel/
  server.js             # own port, own systemd unit, own nginx vhost
  lib/config.js         # panel.conf → typed, validated, frozen; refuses a wildcard bind
  lib/status-read.js    # the ONE privileged READ  (vpn55.sh --status)
  lib/privileged.js     # the ONLY caller of the root helper — the write path
  lib/privileged-path.js # can we rewrite what we ask root to run? asked about both
  lib/auth.js           # admin session, scrypt, (username, IP) lockout
  lib/audit.js          # the panel's half of the audit trail
  lib/routes-admin.js   # sign-in + every write route
  lib/enforcement.js    # the periodic quota / expiry job
  lib/collector.js      # polls adapters, persists traffic across resets
  lib/records.js        # the TSV status stream → a structure
  lib/store.js          # atomic durable JSON — traffic totals are NOT a cache
  lib/view.js  lib/i18n.js  lib/log.js
  scripts/admin.js      # administrator accounts; console-only, never over HTTP
  scripts/portal.js     # portal access codes: issue / list / withdraw / link
  scripts/portal-selftest.js  # Phase 8's acceptance criteria, run in CI
  locales/              # vi.json · en.json · fr.json
  public/               # admin UI
  portal/               # SELF-SERVE — a second express app on a second socket
    tokens.js           #   access codes; stores a SHA-256, never a code
    auth.js             #   its OWN session map, cookie and CSRF header
    logic.js            #   PURE — every ownership decision, so it can be tested
    routes.js           #   seven routes; none takes a user identifier
    shell.js            #   the page, and a NAMED list of the assets it may have
    public/             #   its own CSS (incl. the --font overrides) and JS
helper/
  vpnctl                # narrow root helper, fixed verb list
deploy/                 # nginx templates, systemd units, certbot
docs/                   # design, security model, protocol notes, i18n contract
tests/                  # vps-acceptance.sh — the launch gate, run on a throwaway VPS
tools/                  # manifest.sh, release.sh — dev machine only, not shipped
site/                   # the landing page: one file, zero external requests
MANIFEST.sha256         # generated — what a mirror install fetches, and the revision
```

---

## Security model — settled decisions

Read `docs/security-model.md` before touching anything privileged. Two points bind
every phase:

- **Narrow root helper, fixed verb list** (DECIDED, Phase 0). `helper/vpnctl` accepts
  `user-add user-remove user-enable user-disable cred-add cred-revoke service-restart`
  and nothing else. No blanket sudo. The helper validates its own arguments — it never
  trusts the panel. `panel/lib/privileged.js` is the only module that invokes it.
  **Phase 8 added one READ verb, `cred-config`, and that is the only addition ever
  made** (§6F). Seven write verbs is still the number a panel compromise costs, and CI
  counts the two separately so a write verb cannot arrive hidden inside the total.
  Another verb is a security-model change, not a convenience: §3, §6F, the sudoers
  comment and the CI count get updated together, deliberately, in one commit.
- **The self-serve portal is a SECOND EXPRESS APPLICATION on a second socket**, never
  the admin app with a role check (Phase 8). The admin router is attached to one app
  only, so on the portal's socket there is no admin route to reach — for any token,
  session or header. Everything portal lives in `panel/portal/`; it never imports
  `panel/lib/auth.js` or `panel/lib/routes-admin.js`, and `panel/scripts/portal-selftest.js`
  asserts that on every push. **The portal never accepts a user identifier from a
  request**: the user comes from the session, and an id in a URL only ever selects from
  what that user already owns. Read `panel/portal/README.md` before touching it.
- **WireGuard key custody is OPEN** and is decided in Phase 2 (§6 of the security
  model). Whichever way it goes, the UI must state it on the credential-issue screen.
- **There are TWO privileged programs, not one** (§6E.7). `vpn55.sh --status` is the
  read path and its sudo rule pins the argument, because the same file with no argument
  is the interactive installer and that is unrestricted root. `helper/vpnctl` is the
  write path and its rule pins only the path, because the helper refuses anything
  outside its seven verbs and sudoers cannot express an argument pattern anyway.
  `panel/lib/status-read.js` and `panel/lib/privileged.js` are the only modules in
  `panel/` allowed to start a process, and CI enforces that.
- **Disabling a user is a policy flag, not a disconnection** (§6E.5). It stops new
  credentials being issued; it does not end a tunnel already up, and nothing in these
  three protocols can. Any surface that reports a disable must report the count of
  credentials still carrying traffic rather than a bare success.

Panel binding: the **WireGuard interface IP**, never `0.0.0.0` with an allowlist — an
ACL still lets a stranger complete the TLS handshake. Pair with DNS-01 certbot so no
inbound port is needed.

## Licensing — read anything, copy only MIT and Apache-2.0

VPN55 is **MIT**, and stays MIT: the point is that anyone can reuse, redistribute, fork
or refactor it. That constrains what may be copied *in*.

- **Copy from MIT / Apache-2.0 only.** `Nyr/openvpn-install`, `angristan/openvpn-install`
  and `angristan/wireguard-install` are MIT — those are the liftable ones.
- **Read-only:** `hwdsl2/setup-ipsec-vpn` is **CC BY-SA 3.0** (a content licence with
  viral share-alike, applied to software), `wg-easy` / `algo` / `Marzban` are AGPL-3.0,
  `3x-ui` / `Hiddify` are GPL-3.0, Pritunl is proprietary. Learn from them; write your
  own. **Phase 3 (IKEv2) therefore has no liftable source at all** — that is expected,
  not a research failure.
- **Every reshaped file gets an `ATTRIBUTIONS.md` entry in the same commit.**
- **Re-verify a licence via the GitHub API before copying**, never from a README badge.
  `NOASSERTION` means *read the licence file*, not *permissive*.
- **Never append terms to `LICENSE`.** The MIT text stays unmodified — custom additions
  make GitHub report `NOASSERTION` and stop others reusing the project. The
  plain-language legal disclaimer lives in `DISCLAIMER.md`, separately, and is
  summarised in the README.

Full table and per-phase guidance: `docs/prior-art.md`.

## Distribution — the domain is never in the critical path

`docs/distribution.md` §1 is a constraint on Phase 1 code, not a Phase 9 chore:

**`vpn55.sh` fetches nothing from `vpn55.org`.** No version check, no mirror list, no
asset. The canonical install path is the `raw.githubusercontent.com` URL, because
github.com is effectively unblockable in the target market and the website is not. The
site being blocked must cost traffic, never function — a user who already has the
install command must never need the website for anything.

Phase 1 implements a `VPN55_MIRROR` base-URL override so the escape hatch exists without
shipping a new script. Note `raw.githubusercontent.com` is **case-sensitive** on the repo
path: `noobvie/VPN55` keeps its capitals there.

Phase 9 turned that override into an actual transport — `lib/core_source.sh` — and CI
now installs a whole tree through it on every push. Three rules come with it:

- **`MANIFEST.sha256` is generated, never hand-edited.** Run `tools/manifest.sh` after
  changing any shipped file; CI fails on a stale one. It is what a mirror install
  fetches *and* what `src_revision` hashes, so a stale manifest is two bugs at once:
  files that never reach a server, and a self-update that reports "already current"
  after downloading new code.
- **Never let `vpn55.sh` continue after updating itself.** Bash runs the copy it
  parsed at launch, including every lib sourced then. `src_update` returns **10** to
  mean *new code is on disk and this process is still the old one*; the only correct
  response is `src_relaunch`. Continuing would apply the old firewall and config writers
  while reporting the new version — and those writers are exactly what gets fixed.
- **`bash <(curl …)` has no directory.** `BASH_SOURCE[0]` is `/dev/fd/63`, so a
  directory-less run cannot source `lib/`. The bootstrap at the top of `vpn55.sh`
  handles it; do not "simplify" `VPN55_ROOT` back into a bare `dirname`, and do not move
  library sourcing above it. A CI step runs the script with no directory beside it and
  fails if it reports a missing library instead of asking for root.

**A distro row in the README needs a run behind it**, not a belief:
`tests/vps-acceptance.sh --yes-destroy-this-host`, on a throwaway VPS, over SSH. It
installs three times (two passes cannot tell a converged installer from an oscillating
one), uninstalls, and diffs the host against the baseline taken before anything happened.

---

## Versioning — the version IS the release date

`VPN55_VERSION` in `vpn55.sh` is CalVer, `YYYY.MM.DD`. Go-live is **2026.09.09**; every
release after it carries the day it was cut, and a second cut on the same day appends a
counter (`2026.09.09.1`). `tools/release.sh` validates the shape and refuses to build
unless the string in `vpn55.sh` equals the version it was given.

- **A date answers the question an operator actually has** — *how old is this install?* —
  on a box set up months ago with no changelog to hand. `0.9.0` never could.
- **It is the RELEASE date, not today.** Between releases it reads behind or ahead of the
  calendar. Never "correct" it to the current date: a version that moves on its own
  identifies nothing.
- **It does not identify the code.** Two trees can both say `2026.09.09` and differ, so
  the revision (`src_revision` — `git:<sha>` in a checkout, `mf:<hash>` of
  `MANIFEST.sha256` in an installed copy) is printed beside it everywhere the version
  appears: the menu banner, `--version`, `--revision`. The self-update guard keys on the
  revision, never on the version.
- **The banner is drawn on every menu render**, not once at startup — `main_banner` in
  `vpn55.sh`. Its rows are padded from `${#text}`, so the box only lines up while the
  text stays ASCII: an em dash inside the box is three bytes and one column.

---

## Networking

One parent subnet, partitioned once, so NAT and routing stay a single rule set:

| Slot | Range | Use |
|---|---|---|
| — | `10.8.0.0/16` | parent (`VPN55_NET_PARENT`, must be an `x.y.0.0/16`) |
| `0` | `10.8.0.0/24` | WireGuard |
| `1` | `10.8.1.0/24` | OpenVPN |
| `2` | `10.8.2.0/24` | IKEv2/IPsec |

Three protocols independently allocating from one range is a routing bug that looks
like a firewall bug and gets found in week three.

**This table is the only place the slot assignment is written down.** `core_net.sh`
deliberately does not contain it: an adapter claims its slot by an opaque owner tag,
so the allocator never learns a protocol name.

**An adapter that needs host IP forwarding must claim a pool slot**, even one it barely
uses. The claim is not only an address allocation: every `_uninstall` asks
`net_pool_claims` whether any OTHER tunnel service is still on the host before turning
forwarding off, and that is the only protocol-neutral way to ask. A routed protocol that
skipped the claim would have its traffic killed by the next uninstall of something else.
A protocol that forwards nothing — a proxy-shaped one, `docs/circumvention.md` §6 — needs
no slot and correctly does not count toward that question.

```bash
net_pool_claim wireguard 0            # once, in _install; idempotent, refuses a conflict
ip=$(net_pool_alloc wireguard "$cred_id")   # next free host; same cred_id → same address
net_pool_free    wireguard "$cred_id"
net_pool_release wireguard            # _uninstall: drops the claim and every lease
```

**Adopt one firewall abstraction** (ufw / firewalld / raw nft) and route every rule
through it. Mixing two is how a rule survives an uninstall.

`net_fw_backend` picks one per host — whichever is already managing the firewall —
and records it in `/etc/vpn55/net.conf`. Every rule goes through the tagged verbs, and
**every applied rule is recorded in a ledger at `/etc/vpn55/fw.state`**:

```bash
net_fw_open_port    <tag> <tcp|udp> <port>
net_fw_allow_subnet <tag> <cidr>
net_fw_masquerade   <tag> <cidr> [wan_iface]
net_fw_revoke_tag   <tag>              # reverses exactly what the ledger records
```

Revocation reads the **ledger**, not the live ruleset. No backend is trusted to
remember what VPN55 added — firewalld has no rule comments at all, and a rule whose
comment was rewritten is a rule an uninstall would walk straight past.

## Adapter registration

`vpn55.sh` never names a protocol. It sources `lib/proto_*.sh` by glob and each
adapter announces itself:

```bash
vpn_adapter_register wireguard "WireGuard"   # <tag> <display label>
```

The tag is the `<proto>` in every contract verb — registering `wireguard` means
`vpn55.sh` will call `vpn_wireguard_status` and friends through `vpn_adapter_call`.
Adding a fourth adapter is dropping in a file; there is no list in `vpn55.sh` to
extend, which is the property that makes the contract real rather than aspirational.

⚠ **The rule is about every file outside `lib/proto_*.sh`, not about `vpn55.sh`.** The
per-service screens live in `lib/ui_adapter.sh` and the panel's status stream in
`lib/cli.sh` — being in `lib/` exempts neither, and CI's hygiene sweep greps every
`*.sh` outside `lib/proto_*.sh` for protocol vocabulary. Moving code out of the entry
point moved the code, not the rule.

**Traffic counters reset** on every protocol — WireGuard when the interface drops,
OpenVPN per connection, IPsec per SA rekey. `panel/lib/collector.js` accumulates:
`new < last` means a fresh session, so add the full new value to a durable total. One
algorithm, all three protocols.

---

## Commands

```bash
# Syntax-check every shell file (what CI runs)
find . -name '*.sh' -not -path './.git/*' -exec bash -n {} \;
bash -n vpn55.sh helper/vpnctl

# Lint
shellcheck vpn55.sh helper/vpnctl
shellcheck lib/*.sh          # lib files carry `# shellcheck shell=bash`

# i18n — all five, the same ones CI runs
node .github/scripts/check-locales.mjs        # key parity across vi/en/fr
node .github/scripts/check-i18n-usage.mjs     # every key the panel asks for exists
node .github/scripts/check-locale-text.mjs    # lib/locales sections + placeholders
node .github/scripts/check-fonts.mjs          # stacks carry Vietnamese
node .github/scripts/check-expansion.mjs      # nothing past its ceiling in any locale

# Re-derive the font coverage table from real font files
node .github/scripts/check-fonts.mjs --probe C:/Windows/Fonts

# Distribution — after changing any shipped file
tools/manifest.sh                 # rewrite MANIFEST.sha256
tools/manifest.sh --check         # what CI runs

# Release (dev machine, clean tree, minisign key present)
tools/release.sh 2026.09.09 --tag

# Acceptance (ON A THROWAWAY VPS, as root, over SSH — never here)
./tests/vps-acceptance.sh --yes-destroy-this-host
```

---

## Do not

- Never run these scripts locally — they assume a Linux VPS with root.
- Never add a shebang to a `lib/` file.
- Never let anything outside `lib/proto_*.sh` know which protocol it is talking to.
- Never leave a `cp`/`mv`/`mkdir`/`rm` in `lib/` unguarded.
- Never leave a menu `case` arm unguarded.
- Never build a phrase map keyed on English strings.
- Never claim a distro in the README that has not had a real install / uninstall /
  reinstall run on it.
- Never let `vpn55.sh` fetch anything from `vpn55.org` — see `docs/distribution.md` §1.
- Never hand-edit `MANIFEST.sha256`; run `tools/manifest.sh`.
- Never continue a run after the code updated itself — relaunch.
- Never mark a distribution ✅ in the README without an acceptance run behind it.
- Never copy code from a GPL, AGPL, CC BY-SA or proprietary project — see
  `docs/prior-art.md`. Reading them is fine; copying is not.
- Never modify the MIT text in `LICENSE`; the disclaimer belongs in `DISCLAIMER.md`.
- Never commit unless asked.
