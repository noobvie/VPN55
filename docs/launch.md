# VPN55 — Launch readiness

What is done, what is left, and which half of it is code.

This file was rewritten on **2026-09-02** to agree with the consolidated review
(passes R0–R9, plus the consolidation itself). It is the project's own account of what
remains, and it should not disagree with that review. Where it once listed work, it now
lists work **in the order it can actually be done**.

The headline from the consolidation is not a long list. It is this: **most of what the
ten passes found has already been built, and the engineering residue is four items.**
What has not moved at all is the evidence. Every adapter, the panel, the portal, the
three locales, the backup engine and the launch tooling are written. **Nothing has run
on a server.** A release is not software that compiles; it is software somebody watched
work, published in a way a blocked user can still reach, signed so an impersonator
cannot pass for it.

---

## 1. Where the review left this

Nine passes reported. Several findings were the same root cause seen from different
angles, and merging them is most of the value:

- **"Nothing has ever run on a VPS"** is the single cause behind the eight unverified
  distribution rows, the unexercised panel deployment, and the class of bug where a
  whole verb is dead and nobody knows — `--adapters` printed nothing for weeks. It is
  one item, not four, and everything in §2 exists so that the first run is not wasted.
- **The panel is not installed by anything.** The privileged-path pass (the sudo rule
  pins an installed path), the panel pass (the settings screen writes to a directory
  nothing creates) and the lifecycle pass (partial failure, convergence) all point at
  one absent thing: there is no panel install path, only a README code block that starts
  at step four.
- **Endpoints and Nostr were one finding wearing two hats** — *a client must be able to
  re-find a working way in when the first is blocked.* The discovery half shipped as a
  signed statement; the transport half is capped at one host by the unbuilt **fleet
  seed**. One deferred item, named once, in §4.
- **"A check that cannot check is worse than no check, because it gets believed"** turned
  up three times. Two instances are closed. The third is live and is item **M1** below:
  a hygiene job that has been failing on test fixtures is a job people learn to ignore.

### Closed since the passes ran — do not re-open these

| | Where |
|---|---|
| Second factor — TOTP gates sign-in, console enrolment, `totp --clear` break-glass | `panel/lib/totp.js`, `panel/scripts/admin.js` |
| Settings screen, writing to the panel's own directory | `panel/lib/settings.js` |
| Alerting, with three layers against a storm | `panel/lib/alerts.js` |
| CA and state backup, plus a restore the harness exercises by **signing with the restored key** | `lib/core_backup.sh`, `tests/vps-acceptance.sh` stage 5 |
| Remote addresses masked to /24 · /48 by default, display-only, CI-enforced | `tests/mask-endpoint.mjs` |
| Contrast — every rule that paints a background names its colour, 189 pairings, CI-enforced | `.github/scripts/check-contrast.mjs` |
| Themes cut to three, on measured grounds | `panel/public/js/theme.js` |
| The kill-switch fact told to the *user*, in three languages | `portal.nokillswitch.*` |
| Overview screen — built deliberately without history | `panel/public/js/app.js` |
| The filtering badge derived from each adapter's **running** configuration | `lib/proto_*.sh` |
| Multi-endpoint mechanism, with the operator told what it is not | `lib/core_net.sh`, `--endpoint-add` |
| Signed rendezvous, verified before it is parsed | `lib/cli.sh:149`, `--rendezvous` |
| The advertised install command actually works | `vpn55.sh` bootstrap → `lib/core_source.sh` |
| `VPN55_MIRROR` is a real transport, not a variable nobody reads | `src_fetch`, CI job **distribution** |
| Self-update keyed on the tree's revision, forcing a relaunch | `src_update` (returns 10) |
| Release build and signing | `tools/release.sh`, `tools/manifest.sh` |

Every local gate passes today except one: `bash -n` on all 22 shell files,
`MANIFEST.sha256` current at 99 files, the six i18n and contrast scripts, four self-test
suites (116 + 50 + 32 + 16 assertions), the verb-list parity check, the no-shell-eval
sweep, the spawn-module check and `node --check`. The exception is **M1**.

### The two traps that shaped the code, kept because they generalise

**`bash <(curl …)` has no directory.** The README's one-line install runs `vpn55.sh`
from `/dev/fd/63`, whose dirname is `/dev/fd` — so every `. lib/…` resolved to a path
that cannot exist. The one command the project advertises could not work, and nobody
running from a checkout would ever have seen it. There is now a bootstrap, and a CI
step that runs the script with no directory beside it and fails if it reports a missing
library instead of asking for root.

**bash runs the copy it parsed at launch.** Pulling new code into the running tree does
not hot-reload it — not `vpn55.sh`, and not one of the eighteen libraries sourced at
startup. An update that carried on in the same process would apply the *old* code while
reporting the new version, and the functions that get fixed are exactly the ones that
write firewall rules. So `src_update` keys on the revision of the whole tree, and when
it changes it stops: return code `10` means *relaunch, and do nothing else first*.

---

## 2. MUST — before this runs as root on a real server

Four items. Each names **one** file, because a fix that needs four files is usually a
finding diagnosed at the wrong level.

### M1 · CI is red, and has been through several sessions

Two unrelated causes behind one failing job, so two fixes — one file each.

**M1a — a real contract leak.** `lib/core_net.sh:487`: `net_endpoints_explain` prints
*"…and for WireGuard the same server key…"*. A core lib has learned which protocol it
is talking to. It is operator-facing prose, which is exactly how this rule gets bent —
the sentence is true and useful and still belongs to the adapter, not to `core_net`.
→ **`lib/core_net.sh`**

**M1b — the sweep has no exemption for an adapter's own unit test.**
`tests/awg-params.sh:77` and `:147`, `tests/vpnctl-ownership.sh:114`. A test that
exercises the WireGuard parameter validator cannot avoid naming it, and `ovpn` as a
deliberately-invalid sample tag is the fixture doing its job. The contract rule is about
shipped code; the check's scope never said so.
→ **`.github/workflows/ci.yml`**

Why this is first: every gate downstream — `tools/release.sh`, the manifest, the
distribution matrix — is read through CI, and a job that is *always* red is how the next
real leak ships without anyone noticing. M1a is the proof: a genuine violation has been
sitting in the same output as three false ones.

### M2 · The panel deployment sequence starts at step four, and points sudo at a source tree

→ **`panel/README.md`** (the "Running it" block)

The block begins by installing `panel.conf`. Nothing before it exists. Missing, in order:

1. the `vpn55-panel` system user, with `/usr/sbin/nologin` and no password — **nothing
   anywhere in the repo creates it**;
2. `/etc/vpn55`, `/var/lib/vpn55/panel`, `/var/log/vpn55`. The state directory is created
   lazily by whichever subsystem needs it first, so on a host where the panel is
   installed **before** any tunnel it does not exist — and `deploy/vpn55-panel.service`
   names `/etc/vpn55` and `/var/log/vpn55` in `ReadWritePaths=` *without* the `-` prefix.
   systemd refuses to start the unit, and the message is about namespaces, not about a
   missing directory;
3. the tree copy to `/usr/local/lib/vpn55`, `chown -R root:root`, `chmod -R go-w`;
4. `npm ci` — see M3.

**And the security edge, which is the reason this is a MUST and not a documentation
chore.** The sudoers rule pins `/usr/local/lib/vpn55/vpn55.sh --status` and
`/usr/local/lib/vpn55/helper/vpnctl`. The README's own commands run from a checkout. An
operator who deploys the panel from `/root/VPN55` installs a rule pointing at a path that
does not exist, gets a panel that fails, and reaches for the obvious fix: repoint the
rule at the checkout. That path is writable by the user the NOPASSWD rule is written for
— which is precisely the escalation the pinned-argument comment in
`deploy/sudoers.d/vpn55-panel` exists to prevent, reintroduced by the install
instructions sitting one directory away.

`panel/lib/privileged-path.js` refuses to start in that state, so the failure is loud
rather than silent. That is a backstop, and the sudoers comment already says it is not a
substitute for getting the ownership right.

### M3 · The panel cannot start on any freshly installed host

→ **`panel/README.md`** — the same edit as M2, which is why they are one item and not two.

`panel/package.json` declares `express@4.21.2` as a runtime dependency.
`tools/manifest.sh` excludes `*/node_modules/*` (correctly — vendoring a dependency tree
into the manifest would put it in every mirror fetch), and **nothing anywhere in the repo
runs `npm install` or `npm ci`.** A mirror install produces a complete VPN55 tree and a
panel that exits with `Cannot find module 'express'`.

The lockfile is a separate concern and is in §3, not here.

### M4 · `VPN55_PUBKEY` is empty

→ **`vpn55.sh`**

It lives there, not in `lib/core_source.sh` where it started, and the move is the point
rather than a tidy-up. The bootstrap fetches `core_source.sh` from the mirror and sources
it as root *before* anything has been verified — so a key declared in that file was a key
the mirror supplied, checked by a verifier the same mirror supplied. A hostile mirror
served both halves and passed, and no amount of filling the key in would have changed
that. In `vpn55.sh` it is part of the one file a user can download, check against the
README's public key, and then run.

What filling it in turns on, precisely:

| Path | With the key set |
|---|---|
| Bootstrap (`bash <(curl …)`, or a run with no `lib/` beside it) | Verifies `MANIFEST.sha256.minisig` with the **minisign binary** before sourcing anything. No minisign on the host → **refuses**, and says to install it or use the README's verified path. |
| `--update` / `src_fetch` on an installed copy | Verifies the same signature via minisign or the openssl fallback. A bad or missing signature aborts; nothing is touched. |
| `--verify` | Reports the signature and the file digests separately — a bad signature fails, a missing one warns and degrades to the corruption check. |

The bootstrap deliberately will **not** use the openssl fallback in
`lib/core_source.sh`: that code is the mirror's, and letting it check the mirror's own
manifest proves nothing. That is why it fails closed there and not elsewhere.

None of this fixes `curl … | bash` itself — by the time any of it runs, the code is
already root and is whatever the mirror sent. It protects the other eighteen files, and
the README's verified path covers the first one. Say it that way everywhere; claiming
more would be worse than not signing.

M4 gates **publication**, not the first VPS run. It is in this list because generating
the key is an offline human action with a lead time, and because a stranger running this
as root is exactly what it exists to protect.

### ⚠ What must happen before the first VPS run

**M0 — commit the tree.** 84 files are modified on top of a single initial commit. Two
sessions editing one uncommitted tree destroyed two files beyond git's reach on this
project before. Nothing below is worth starting until this is recoverable.

Then **M1** and **M2 / M3**, and only then the run.

The reason is the cost, not tidiness. `tests/vps-acceptance.sh` destroys the host it runs
on. A run that dies partway because the panel could not find `express`, or because a sudo
rule pointed at a checkout, costs a VPS rebuild and tells you nothing about the thing you
were actually testing. And that first run is the gate on the whole distribution matrix:
eight rows, five client platforms and every ✅ in the README are downstream of it.

**M4 is not in that set.** The key is needed to publish, not to test.

---

## 3. SHOULD — before the first tagged release

- **A committed `package-lock.json`, and `npm ci` rather than `npm install`.** Without a
  lockfile the transitive tree under `express` is resolved at install time, on a host in
  a censored market, next to a process that can reach root through two sudo rules. The
  single-dependency property is a stated security argument in `docs/security-model.md`;
  it is only worth what the lockfile makes it worth.
- **Acceptance harness stage 6 — install the panel.** Stages 1–5 prove the shell
  installer converges, reverses and can be restored onto another machine. The panel is
  never installed, so its unit, its sudo rules and its directories are the one part of
  the system the project's own evidence does not cover. The corrected M2 sequence is what
  a stage 6 would automate. → `tests/vps-acceptance.sh`
- **`panel/README.md:16` says seven verbs.** There are eight; CI fails a build that
  disagrees, and `docs/security-model.md` §6E.1 says eight. The count is a security-model
  number, so drift in it is not cosmetic.
- **An hourly rollup in `panel/lib/collector.js`.** The collector keeps lifetime totals
  only. The overview screen shipped deliberately without history — *the "is anything
  wrong right now" half of an overview needs no history at all* — so this is now a chart
  feature rather than a blocker, and it is still the most visible difference between
  VPN55 and every panel it will be compared to.
- **Snowflake documented as the bootstrap path of last resort** — the one unticked
  Phase 9 box in `docs/circumvention.md` §10.
- **The distribution work in §5 below**, all of it.
- **Turn README matrix rows ✅** — only rows with a kept `result.tsv` line.
- **Connect a real client on each platform**: iOS, macOS, Windows, Android, Linux. The
  harness deliberately does not, and says so.
- **Record the terminal GIF and the panel screenshot.** Both README placeholders render
  as broken images until then, on the page that converts a visitor. The Connections table
  masks remote addresses by default, so the shot is safe to take without preparation —
  but the reveal control is on that same screen and its state persists per browser, so
  check the button reads *Show addresses* before pressing record.

---

## 4. LATER — deferred, with the reason written down

- **The fleet seed.** Exporting one host's server identity — the CA and server
  certificate, and for WireGuard the server private key *and* the nine obfuscation
  parameters — so that a second host in a second ASN answers as the same server.
  **Reason:** it creates a new key-custody surface by design (a portable copy of the CA
  key), and the thing it buys cannot be tested without two paid hosts in two networks.
  `net_endpoints_explain` already tells the operator to their face that today's list
  covers the several addresses of one host. Deferring it is honest; letting a working
  `--endpoint-add` imply a fleet would not be.
- **The Nostr transport for the rendezvous.** **Reason:** decided 2026-09-02 —
  documented, not shipped; see §6. The signature was the point and it ships without
  Nostr. Revisit only if the signed statement's own distribution is what gets blocked.
- **Escalation ladder rungs 3 and 4** — listener-shaped protocols (VLESS, Hysteria2).
  **Reason:** deferred, not excluded. The cheap half is still open and is not a build:
  *can a non-peer, inbound protocol implement the adapter contract unchanged, and which
  function breaks first?* Answer it at the next contract review; build nothing.
- **Splitting the panel and portal into two systemd units.** **Reason:** deferred
  deliberately with the cost stated — `docs/security-model.md` §6F.2 and
  `panel/server.js:455`. One process, two listeners, and the containment argument written
  down rather than assumed.
- **Two audit logs, neither a backup of the other.** **Reason:** recorded as a property,
  not a defect — §6E.4. The narrower root-written log is the one to read after a suspected
  panel compromise, and §5 of the security model already says so.

---

## 5. Left — distribution

Work `docs/distribution.md` §8. The market is Vietnam and the brand domain has `vpn` in
the name, so **assume a block and make it cost traffic rather than function.**

### Domains

- [ ] Primary domain at an **offshore** registrar. Never `.vn`, never a Vietnamese
      registrar — those sit under VNNIC and can be suspended by administrative order,
      with no court and no recourse.
- [ ] **WHOIS privacy enabled in the same transaction.** It is not retroactive:
      registration records are scraped within hours of a domain going live.
- [ ] Two or three backup domains at a **second** registrar, **without** `vpn` in the
      name. Bulk blocklists are seeded by keyword sweeps over DNS and SNI — the brand
      domain is caught by a script nobody had to write; a neutral name falls only when a
      human decides to. **The brand domain markets; the neutral ones survive.**

### Reach

- [ ] Landing page live at both `vpn55.org` and `noobvie.github.io/VPN55` — the page is
      in [`site/`](../site/), see `site/README.md`. A DNS block on the custom domain does
      not touch the `github.io` hostname.
- [ ] Cloudflare in front, so IP blackholing carries collateral damage.
- [ ] Codeberg or GitLab git mirror, added as a second remote.
- [ ] `.onion` mirror.
- [ ] Fill in the **Mirrors** table in the README. That table is the root of trust.

### Integrity — do this before the project is worth impersonating

The moment the site is blocked and users start hunting for a mirror is exactly when
someone publishes a trojaned "VPN55". To a user who just wants it to work, a censored
project and a compromised one look identical — and this one runs as root.

- [ ] `minisign -G -p vpn55.pub -s vpn55.key`; keep the secret half **offline**.
- [ ] Put the public key in the **README**, not only on the site.
- [ ] Set `VPN55_PUBKEY` in `vpn55.sh` — item **M4**.
- [ ] `tools/release.sh 2026.09.09 --tag` — the version IS the go-live date (CalVer,
      `YYYY.MM.DD`; CLAUDE.md *Versioning*). It builds the tarball from
      `MANIFEST.sha256`, writes `SHA256SUMS`, signs it, and signs the git tag. It refuses
      to run unless `VPN55_VERSION` in `vpn55.sh` already says the same date, so a
      slipped launch means editing that string and committing it first — the release date
      and the code have to agree before either is published.
- [ ] Publish the signed `rendezvous.txt` on the site, the `.onion`, every mirror and in
      the announcement channel. `vpn55.sh --rendezvous` is what checks it.
- [ ] Verify from a **different machine**, as a user would, before publishing.
- [ ] Keep the honesty about `curl | bash` in the README exactly as written. Claiming
      signing makes the one-liner safe would be worse than not signing.

### Channels

- [ ] Telegram announcement channel live **before** launch. Not blocked in Vietnam,
      enormous there, and a channel posting the current working mirror is how users in a
      censored market re-find a project. Ten minutes of setup.
- [ ] Write down the mirror-of-record posting procedure, so it happens under pressure.
- [ ] Zalo for **reach only**. It is VNG: domestic, and compliant with takedown and
      disclosure requests. Never the resilience channel.
- [ ] Seed r/selfhosted, an awesome-selfhosted PR, voz.vn and the Vietnamese communities.
      GitHub discovery is the international channel; it is not how the target end user
      finds this.

### Endpoints

- [~] Multi-endpoint client configs across at least **two ASNs and two providers**. Three
      VPSes in one subnet is one endpoint wearing three hats. **The mechanism is built**
      (2026-09-02): `--endpoint-add`, one shared list, per-protocol emission — see
      `docs/circumvention.md` §4 "As built". **The two-ASN half is the fleet seed and is
      deferred** — §4 above.
- [ ] A burned IP stays burned — blocklist entries are effectively never reviewed. Plan
      to rotate rather than to appeal.

---

## 6. The two open decisions — both closed

**Themes: it is three, and it should stay three.** The question in the review was four or
two. Neither is the answer: `panel/public/js/theme.js` now offers **light, dark and
`mina`**. `matrix` and `anime` went on measured grounds — the vendored anime palette put
a warning badge at 1.93:1 and a quota bar at 1.80:1 against its own track, and its
decoration sat at z-index 9999 over the top-bar controls; matrix was legible but is a
saturated monochrome, which is a poor surface for a table of numbers.
`check-contrast.mjs` now passes 189 pairings across three themes and two stylesheets.
**Recommendation: do not reopen it.** Two things must survive any future tidy-up: the
vendored stylesheet deliberately keeps its dead `[data-theme="matrix"]` and
`[data-theme="anime"]` rules so a re-vendor is still a diff — `check-fonts.mjs` reports
them as unreachable and that report is correct — and the stale-value validation in
`theme.js` is what makes somebody's old `matrix` in localStorage load as `dark` rather
than as an unstyled page.

**Nostr rendezvous: documented, not shipped — hold it there.** Decided 2026-09-02. The
signature was always the point, so the signed statement ships without Nostr:
`rendezvous.txt`, signed with the minisign key already used for `SHA256SUMS`, published
on the site, the `.onion`, every mirror and in the announcement channel, and checked with
`vpn55.sh --rendezvous`. **Recommendation: ship v1 without the transport.** Adding it
means a secp256k1 dependency in a codebase whose single-dependency property is itself a
security argument, in exchange for a discovery channel we do not yet need — and the same
pass that made this call closed a live hole, `MANIFEST.sha256` being fetched from the
mirror it was meant to vouch for. Reasoning, and the order to add the transport in if it
is ever needed, are in `docs/circumvention.md` §8.

**Still genuinely open, and unbundled from both:** whether the Office Tools card links to
this project. Registering offshore with WHOIS privacy under the `noobvie` account, and
linking the project from a site that carries a commercial identity, have materially
different exposure profiles. There is no technical reason to do them together, and **the
project ships fine with the first and not the second.**

---

## 7. The order

No item depends on one below it.

1. **M0** — commit the 84-file working tree to a branch. Do not push.
2. **M1a**, **M1b** — green CI. Everything below is read through it.
3. **M2 / M3** — the panel deployment sequence, in one edit to `panel/README.md`.
4. **The first VPS run.** `tests/vps-acceptance.sh --yes-destroy-this-host` on a
   throwaway host, over SSH, on one distribution. Install the panel by the corrected
   sequence in the same session. Keep the `result.tsv` line.
5. The remaining seven distribution rows, same harness, same evidence rule.
6. Connect a real client on all five platforms.
7. `package-lock.json` and `npm ci`; harness stage 6; the verb-count correction.
8. **M4** — generate the signing key, publish the public half in the README, set
   `VPN55_PUBKEY`.
9. Distribution §5: domains, mirrors, Cloudflare, `.onion`, Telegram, the mirrors table.
10. `tools/release.sh 2026.09.09 --tag`, then verify from a different machine.

Steps 4 and 6 are the two that cannot be done from a development machine, and step 4 is
the gate on everything after it.

> A distribution row is a promise to a stranger who will run this as root. The harness
> exists so that promise costs one command instead of an afternoon — but somebody still
> has to run it.

---

## 8. What would make this launch badly

Three failure modes, in the order they are likely:

1. **A distro claimed on the strength of "it should work."** The first issue filed is
   against the one row nobody ran.
2. **Publishing before the signing key exists.** Signatures added after a project is
   worth impersonating cannot retroactively authenticate what people already downloaded.
3. **The website becoming load-bearing by accident** — a version ping, a mirror list, an
   asset fetch added later because it was convenient. CI fails the build for it now, and
   that check should be understood as a product constraint rather than a lint rule.

A fourth, added by this review because it has already happened here: **a hygiene check
left failing long enough that its output stops being read.** M1a is a genuine contract
violation that has been sitting in the same red output as three false positives, through
several sessions. A check nobody reads is worse than the check nobody wrote.
