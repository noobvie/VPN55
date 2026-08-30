# Attributions

Third-party code reshaped into VPN55, and the licence it arrived under.

**Add the entry in the same commit as the code.** Provenance reconstructed later from
memory is provenance you cannot defend, and an MIT notice you cannot trace back to its
source is a licence violation that stays invisible until someone asks.

Only **MIT** and **Apache-2.0** sources may be copied — VPN55 is MIT. See
[docs/prior-art.md](docs/prior-art.md) for the licence table of every project in this
space and the read-vs-lift rule per phase. Reading a GPL, AGPL, CC BY-SA or proprietary
project is fine; copying from one is not.

---

## Format

```
### <project> — <SPDX licence>
Source:  https://github.com/OWNER/REPO  (commit <sha>, retrieved YYYY-MM-DD)
Taken:   <what was actually reused — be specific>
Lives in: <our file paths>
```

For Apache-2.0 sources, any upstream `NOTICE` content must also be reproduced below the
entry.

---

## Entries

### angristan/wireguard-install — MIT
```
Source:   https://github.com/angristan/wireguard-install  (branch master, retrieved 2026-08-27)
Licence:  MIT — re-verified via the GitHub API on 2026-08-27, not from the README badge
Taken:    the per-distro package sets for the tunnel tooling — which packages are
          needed on Debian/Ubuntu, on the Fedora/RHEL/Rocky/Alma/Oracle side, and on
          Arch, including the out-of-tree kmod package that EL 8 needs and later
          releases do not.
Lives in: lib/proto_wireguard.sh — _wg_packages() and _wg_install_packages()
```

**Deliberately NOT taken: its firewall handling.** Upstream puts `iptables` and
`firewall-cmd` rules in the interface config's `PostUp`/`PostDown`, which is the normal
way to do this and is correct for a single-purpose installer. VPN55 routes every rule
through one firewall backend and records it in a ledger (`docs/security-model.md`,
`lib/core_net.sh`), because a rule added by `PostUp` is invisible to that ledger and
would survive an uninstall. The *lesson* — whatever goes up must come down, symmetrically
— is kept; the mechanism is ours. Nothing of upstream's rule code is present.

### AmneziaWG — checked, nothing taken

```
Checked:  amnezia-vpn/amneziawg-go                     MIT
          amnezia-vpn/amneziawg-tools                  GPL-2.0
          amnezia-vpn/amneziawg-linux-kernel-module    GPL-2.0
Method:   GitHub API, 2026-08-29 — licence.spdx_id on each repository
          individually, not the umbrella project and not a README badge.
Taken:    NOTHING. There is no entry above because there is nothing to attribute.
```

The build plan required a licence check on the specific AmneziaWG repository before any of
its code was reshaped. This records the outcome. The obfuscation mode in
`lib/proto_wireguard.sh` copies no third-party code: the nine parameter names, their
numeric bounds and the constraints between them were read from the project's documentation
and reimplemented. Facts about a wire format are not copyrightable expression, and none of
their code is present.

**Deploying them is fine and needs no entry here.** VPN55 requires the operator to install
`amneziawg-tools` and the kernel module themselves, and then invokes `awg` and `awg-quick`
as programs. Running a GPL-2.0 program is not distributing it. Had we lifted so much as one
function out of `amneziawg-tools`, VPN55 could not have stayed MIT — which is why the
check comes before the code rather than after it.

If a later phase does need code, `amneziawg-go` is the MIT one, and it gets a full entry in
the format above, in the same commit.

**An absent entry after a licence review is a result, not an oversight** — which is why it
is written down rather than left as silence.

---

### angristan/openvpn-install — MIT
```
Source:   https://github.com/angristan/openvpn-install  (commit ad22fd9eb0c8569a885f836ef6e37576d8702e9f, retrieved 2026-08-29)
Licence:  MIT — re-verified via the GitHub API on 2026-08-29, not from the README badge
Taken:    the single-file client emit. Specifically: the inline <ca>/<cert>/<key>
          block structure and the order the directives are written in; the
          `awk '/BEGIN/,/END CERTIFICATE/'` that trims the authority's text dump
          off the front of a certificate before inlining it; the
          `ignore-unknown-option` guards that let one emitted file serve both an
          old and a new client; the client-side transport spelling, where the
          connection-oriented protocol has to name which end it is; and the
          three-way service-user split (a dedicated user on the RHEL family, the
          same user in a different primary group on Arch, neither on the Debian
          family — plus the check for whether the packaged unit already drops
          privileges, because a second drop in the config is an error).
Lives in: lib/proto_openvpn.sh — _ovpn_build_profile(), _ovpn_render_conf() and
          _ovpn_resolve_service_user()
```

### Nyr/openvpn-install — MIT
```
Source:   https://github.com/Nyr/openvpn-install  (commit db36a24549164ce4e6ff4c0ba2cec6eb213daae5, retrieved 2026-08-29)
Licence:  MIT — re-verified via the GitHub API on 2026-08-29, not from the README badge
Taken:    two platform facts, each of which costs an afternoon to rediscover.
          One: on an SELinux host the daemon may only bind a port carrying the
          right label, so a non-default port needs `semanage port` or the
          service simply will not start. Two: the revocation list is re-read on
          every client connection, after the daemon has dropped privileges — so
          it is the one file that has to be readable by the unprivileged user,
          and referencing it inside a root-only directory works until the first
          connection after start-up and then refuses everyone.
Lives in: lib/proto_openvpn.sh — _ovpn_selinux_port_ensure() and
          _ovpn_publish_crl() / _ovpn_install_hook()
```

**Deliberately NOT taken from either: easy-rsa.** Both upstreams vendor it as their
PKI — Nyr downloads a release tarball, angristan builds one into
`/etc/openvpn/server/easy-rsa/`. VPN55 issues from `lib/core_pki.sh`, the same
authority the other certificate protocol uses. A second PKI would mean two
certificate authorities, two revocation lists and two answers to "is this credential
still valid", which is the same class of failure as two parallel user registries.

**Deliberately NOT taken: their firewall handling**, for the reason already recorded
above — Nyr generates a systemd unit carrying `iptables` rules and angristan applies
them directly; both are invisible to VPN55's ledger and would survive an uninstall.

**Deliberately NOT taken: the SELinux relabel.** Nyr's `semanage port -a` is correct
for the port it uses and cannot work for 443, which already carries the web label — a
port carries one type. Relabelling it would repair the tunnel by breaking the
operator's web server, so this refuses and explains instead. The idea is theirs; the
refusal is ours.

**Phase 3 (IKEv2) added nothing here, as expected — confirmed 2026-08-28.** There is no
permissively-licensed IKEv2 installer to reshape: `hwdsl2/setup-ipsec-vpn` is
CC BY-SA 3.0 and `algo` is AGPL-3.0, both reading references only. `lib/core_pki.sh`,
`lib/proto_ipsec.sh`, the swanctl configuration and the configuration-profile generator
are original work. **If an entry ever appears here for Phase 3, it needs a second look** —
a licence-clean phase that suddenly acquires provenance is the shape a deadline-driven
paste leaves behind.

---

### Office Tools — first-party, moved between our own repositories

`panel/lib/rate-limit.js` is the `makeRateLimiter` fixed-window factory from Office
Tools `backend/lib/rate-limit.js` (same author, MIT, pinned copy — not a dependency).
The counter and its shape are unchanged. Three things are different, and each is a
change this deployment needs rather than a preference:

1. **The client IP is not taken from a header by default.** Upstream reads the first
   `X-Forwarded-For` hop unconditionally, which is correct there — every request
   arrives through nginx and Cloudflare, so the header is written by infrastructure.
   Here the same line would be a hole: the login lockout is keyed on the client IP, so
   anyone able to set that header freely gets an unlimited supply of distinct clients
   and is never locked out. It is consulted only when `trust_proxy` says a proxy is
   the sole way in.
2. **The prune timer is `unref`'d**, so a process that loads this module can still
   exit. Invisible in a server that never exits; a hang with no message in a one-shot
   script.
3. **The lockout is a separate primitive** (`makeLockout`). Rate limiting and lockout
   answer different questions — "too many requests" versus "too many FAILURES for this
   identity" — and conflating them means a correct password is throttled by whoever
   guessed wrong before it.

---

## First-party code moved between our own repositories

Not third-party, listed for traceability rather than obligation.

- **`lib/ui.sh`** — vendored from Office Tools `lib/ui.sh` (same author). Pinned copy,
  deliberately not a submodule.
- **`panel/lib/rate-limit.js`** — from Office Tools `backend/lib/rate-limit.js` (same
  author). Full entry above: three deliberate changes, one of which closes a hole that
  copying it verbatim would have opened.
- **`panel/public/css/vendor/office-tools.css`** and **`panel/public/js/theme.js`** —
  vendored from Office Tools `css/style.css` and the theme block of `js/common.js`
  (same author, MIT). Pinned at commit `f0897cb105bdea4cdd27961e7f368802e780f188`
  (2026-07-23), repo HEAD `f8cae459efb69e7d4bdee1d77fc05285990dd454` (2026-08-27),
  `sha256 6c1740ab13b8755ffd0be7b5d997da52422272826420cb3bd8125a7d16f59de4`; vendored
  2026-08-29 for Phase 5.

  **Pinned, not tracked.** The admin UI must not shift the day the tools site is
  restyled. The stylesheet is byte-identical to upstream and is never edited: the
  panel's own styling lives in `panel/public/css/panel.css`, which is loaded second
  and wins by cascade. Re-pinning is a deliberate act with a new sha recorded here.

  Two documented deltas in `theme.js`, both in the file's own header: the storage key
  is `vpn55-theme` rather than `ot-theme` (different origin, different product), and
  the default theme is `dark` rather than `matrix` (this is an operations console read
  while something is wrong, not a public tools site). The four theme NAMES —
  `light`, `dark`, `matrix`, `anime` — are carried over exactly, because they are what
  the vendored stylesheet's selectors are written against and renaming one here would
  silently unstyle it.

  The upstream English theme labels were **dropped** rather than carried: every string
  the panel shows comes from a locale catalog, so `theme.js` exposes the theme list and
  the current name, and the label is rendered by `app.js` through `t('theme.<name>')`.
- **`lib/proto_wireguard.sh`** — reshaped from Grin Node Toolkit
  `scripts/lib/grin_wg_access.sh` (same author). Carried across: server key generation
  and interface bring-up, the peer add/remove/list shape with identifying comments kept
  out of `SaveConfig`'s reach, next-free-address allocation, `wg syncconf` instead of a
  restart so live peers survive a change, and last-handshake detection. Inverted on
  purpose: the original is a split-tunnel path to one host with forwarding off and no
  NAT, and this is a full-tunnel VPN — the reasoning is in the file header.
