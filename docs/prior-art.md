# VPN55 — Prior art, licensing, and what may be lifted

**The rule this document exists to enforce:** VPN55 is MIT. Reading any project is
always fine. **Copying code is fine only from MIT and Apache-2.0 sources.** Everything
else in this space is GPL, AGPL, CC BY-SA or proprietary, and lifting from it would
either force VPN55 to change licence or make it un-redistributable.

Licence and activity data below was pulled from the GitHub API on **2026-08-27**.
Licences change. Re-verify before copying anything:

```bash
curl -s https://api.github.com/repos/OWNER/REPO | \
  python3 -c "import sys,json;d=json.load(sys.stdin);print((d.get('license') or {}).get('spdx_id'))"
```

A result of `NOASSERTION` means GitHub could not match a standard licence — it does
**not** mean permissive. Read the file by hand; two of the projects below are
`NOASSERTION` and one of those is proprietary.

---

## 1. The table

| Project | Licence | Stars | Last push | Stack | Verdict |
|---|---|---|---|---|---|
| [Nyr/openvpn-install](https://github.com/Nyr/openvpn-install) | **MIT** | 20.6k | 2026-07-02 | Shell | ✅ **Lift** |
| [angristan/openvpn-install](https://github.com/angristan/openvpn-install) | **MIT** | 16.1k | 2026-08-19 | Shell | ✅ **Lift** |
| [angristan/wireguard-install](https://github.com/angristan/wireguard-install) | **MIT** | 11.2k | 2026-05-02 | Shell | ✅ **Lift** |
| [amnezia-vpn/amneziawg-go](https://github.com/amnezia-vpn/amneziawg-go) | **MIT** | — | 2026-08-28 | Go | ✅ **Lift** |
| [amnezia-vpn/amneziawg-tools](https://github.com/amnezia-vpn/amneziawg-tools) | GPL-2.0 | — | — | C/Shell | 📖 Read only — **deploy freely** |
| [amnezia-vpn/amneziawg-linux-kernel-module](https://github.com/amnezia-vpn/amneziawg-linux-kernel-module) | GPL-2.0 | — | — | C | 📖 Read only — **deploy freely** |
| [firezone/firezone](https://github.com/firezone/firezone) | **Apache-2.0** | 9.0k | 2026-08-27 | Elixir | ✅ Lift (needs NOTICE) |
| [hwdsl2/setup-ipsec-vpn](https://github.com/hwdsl2/setup-ipsec-vpn) | **CC BY-SA 3.0** | 28.4k | 2026-08-27 | Shell | 📖 **Read only** |
| [wg-easy/wg-easy](https://github.com/wg-easy/wg-easy) | AGPL-3.0 | 26.8k | 2026-08-27 | TypeScript | 📖 Read only |
| [trailofbits/algo](https://github.com/trailofbits/algo) | AGPL-3.0 | 30.4k | 2026-08-26 | Python | 📖 Read only |
| [MHSanaei/3x-ui](https://github.com/MHSanaei/3x-ui) | GPL-3.0 | 45.4k | 2026-08-24 | Go | 📖 Read only |
| [hiddify/Hiddify-Manager](https://github.com/hiddify/Hiddify-Manager) | GPL-3.0 | 9.2k | 2026-08-21 | Python | 📖 Read only |
| [Gozargah/Marzban](https://github.com/Gozargah/Marzban) | AGPL-3.0 | 7.3k | 2026-06-08 | Python | 📖 Read only |
| [pritunl/pritunl](https://github.com/pritunl/pritunl) | **Proprietary** | 5.0k | 2026-08-27 | Python/Go | ⛔ Avoid |
| [eylandoo/openvpn_webpanel_manager](https://github.com/eylandoo/openvpn_webpanel_manager) | **All Rights Reserved** | 282 | — | Python/Flask | ⛔ Avoid |

**Only the top four are compatible with MIT.**

### AmneziaWG is three repositories with two licences

Checked against the GitHub API on 2026-08-29, not a README badge:

- **`amneziawg-go`** — MIT. The userspace implementation, forked from `wireguard-go`,
  which is MIT. Liftable.
- **`amneziawg-tools`** — GPL-2.0. The `awg` / `awg-quick` userspace tools, forked from
  `wireguard-tools`, which is GPL-2.0. Read only.
- **`amneziawg-linux-kernel-module`** — GPL-2.0, inherited from WireGuard's kernel code.
  Read only.

**"AmneziaWG" is not one licence, and checking the umbrella project answers the wrong
question.** The split falls exactly where the upstream split falls, which is the thing to
remember: a fork keeps the licence of what it forked.

**Deploying is not distributing.** VPN55 installs and drives these tools; it does not ship
their source. That is why a GPL-2.0 kernel module is fine to require and a GPL-2.0 shell
script is not fine to copy three lines out of. Phase 2 copied nothing from any of them —
the parameter semantics were read from documentation and reimplemented, which is why
`ATTRIBUTIONS.md` records the check and not a lift.

### The two that need explaining

**`hwdsl2/setup-ipsec-vpn` is CC BY-SA 3.0.** That is a *content* licence with viral
share-alike terms, applied to software — Creative Commons themselves advise against
using CC licences for code. It is the best-maintained IKEv2 installer in existence and
the plan names it as the Phase 3 reference, which is correct: **read it, learn from it,
write your own.** Copying from it would oblige VPN55 to relicense BY-SA.

**Pritunl is proprietary**, despite living on GitHub. Its LICENSE reads: *"Source-code
or binary products cannot be resold or distributed / Non-commercial use only / Can
modify source-code but cannot distribute modifications."* Do not use it as a reference
at all — with a licence that restrictive, "I read it and then wrote something similar"
is a harder conversation than it is worth. There are better references.

---

## 2. Read vs lift, per phase

| Phase | May be lifted (MIT/Apache) | Read only | Practical consequence |
|---|---|---|---|
| **1** Core libs | angristan + Nyr installers — distro matrix, package-manager abstraction, container detection | — | Fine. Vendored `ui.sh` is your own code anyway. |
| **2** WireGuard | `angristan/wireguard-install` (MIT) — distro matrix, PostUp/PostDown symmetry. Plus our own `grin_wg_access.sh`. `amneziawg-go` (MIT) if the obfuscation mode ever needs code rather than configuration. | `wg-easy` (AGPL) for the panel/key-custody model; `amneziawg-tools` and the kernel module (both GPL-2.0) — deploy them, never copy them | Good coverage. The bulk is reshaping code you already own, and the AmneziaWG mode turned out to need no third-party code at all. |
| **3** IKEv2 | **nothing** | `hwdsl2/setup-ipsec-vpn` (CC BY-SA), `algo` (AGPL) | ⚠️ **No legal shortcut exists.** Write `core_pki.sh`, the swanctl config and the `.mobileconfig` generator from scratch. |
| **4** OpenVPN | `Nyr/openvpn-install` + `angristan/openvpn-install` (both MIT) — single-file `.ovpn` inline-cert emit, TCP/443 handling | — | Best-covered phase of the three. |
| **5–6** Panel | `firezone` (Apache-2.0) | `wg-easy`, `3x-ui`, `Marzban`, `Hiddify` | Design reference only; none of them is Node/Express anyway. |
| **8** Portal | — | `3x-ui`, `Marzban`, `Hiddify` subscription pages | The pattern is well-established; the code is not usable. |

**The scheduling consequence:** Phase 3 is expensive for two independent reasons —
it is the contract stress test *and* it is the one phase with no permissively-licensed
source to reshape. Budget for that; it is not a surprise to discover in week three.

---

## 3. `ATTRIBUTIONS.md` is not optional

Every time code is reshaped from an MIT or Apache source, add the entry **in the same
commit**. Reconstructing provenance in Phase 9 from memory does not work, and an MIT
notice you cannot trace is a licence violation that is invisible until someone asks.

The file lives at the repo root. Format is one block per upstream: project, URL,
licence, what was taken, and which of our files it lives in.

Apache-2.0 additionally requires preserving any `NOTICE` file content — if anything is
ever taken from Firezone, that obligation comes with it.

---

## 4. What the prior art actually tells us

### The niche is real, and the closest competitor demonstrates the failure mode

[eylandoo/openvpn_webpanel_manager](https://github.com/eylandoo/openvpn_webpanel_manager)
pitches almost exactly VPN55: one panel over OpenVPN, AnyConnect, L2TP/IPsec, WireGuard
and Sing-box, with quotas, expiry, resellers and subscription QR pages. It has 282 stars
and is actively developed.

It is also **proprietary**, ships **no threat model or disclosure policy**, and its own
documentation says it "interacts directly with `systemctl`" while saying nothing about
privilege separation or service isolation.

That is not a competitor to copy. It is a live demonstration of the thing
`docs/security-model.md` §3 was written to avoid: a root-capable web panel with no
documented privilege boundary. **The narrow-helper decision is the differentiator, and
it should be said out loud on the landing page** — "a panel compromise costs seven
verbs, not your server" is a claim almost nothing else in this category can make.

### The user model is a solved problem — and ours is missing two fields

3x-ui, Marzban and Hiddify converged independently on the same per-user schema. Ours
matches on quota and expiry, but **all three carry two fields the plan's registry does
not**:

- **connection / device limit** — how many simultaneous clients one user may run
- **quota reset interval** — monthly rollover, not only a lifetime cap

Both are cheap as nullable columns in Phase 1 and awkward to retrofit once three
adapters and the portal all read the registry. Null keeps the own-fleet case unchanged.

### Algo confirms the security posture, it does not need to be copied

[Algo](https://github.com/trailofbits/algo) is written by Trail of Bits, a security
firm. It supports only IKEv2 with AES-GCM / SHA2 / P-256 and refuses L2TP, IKEv1 and
RSA outright, and states plainly that the goal "is not to provide anonymity, but to
ensure confidentiality of network traffic."

That is the same posture `docs/security-model.md` §7 already takes. Useful as
confirmation that the honest framing is the professional one rather than a hedge — and
as a precedent for refusing legacy crypto rather than offering it as an option.

### The most tempting repo is the most dangerous

3x-ui has 45k stars and does much of what the panel needs. It is GPL-3.0, and the
AGPL projects are worse: **AGPL on a hosted panel means anyone you deploy for can
demand your source.** For a project intended to stay MIT and freely forkable, these are
reading material and nothing else.

---

## 5. Before copying anything — the checklist

- [ ] Re-verify the licence via the API (see the top of this file); do not trust a README badge
- [ ] Confirm it is MIT or Apache-2.0. `NOASSERTION` means *read the file*, not *permissive*
- [ ] Copy the upstream copyright header along with the code
- [ ] Add the `ATTRIBUTIONS.md` entry **in the same commit**
- [ ] For Apache-2.0, carry any `NOTICE` content across
- [ ] If it is GPL/AGPL/CC/proprietary: close the tab, write it yourself
