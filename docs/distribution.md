# VPN55 — Distribution and censorship resilience

**Phase 9 checklist.** How VPN55 reaches its users, and what happens when part of
that path is blocked.

**Companion document:** `docs/circumvention.md` covers how the *tunnel* survives
filtering once the user already has the software. The two fail independently — a user
can hold a perfect copy of `vpn55.sh`, have a working server, and still have every
packet dropped. This page is about reach; that one is about the tunnel.

This is not a hypothetical for this project. The market is Vietnam, the product is a
VPN manager, and the landing page has a `vpn` string in its domain name. Plan for the
block before it happens, because every option below is cheap in advance and expensive
under pressure.

Last revised: 2026-08-27 (Phase 0 — written early because two of the decisions here,
§1 and §5, constrain code that gets written in Phase 1).

---

## 1. The architectural rule: the domain is never in the critical path

**`vpn55.sh` must never fetch anything from `vpn55.org`.** Not a version check, not
a mirror list, not an asset, not a telemetry ping (there is no telemetry — see the
security model — but the rule stands regardless).

The canonical install path is, and stays:

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/noobvie/VPN55/main/vpn55.sh)
```

**Why this specific host.** `github.com` is effectively unblockable in Vietnam.
Blocking it breaks every software outsourcing shop in the country — an industry the
government has spent a decade building. That makes GitHub the most censorship-durable
hosting available to this project, and it is free. Nothing else on this page is as
valuable as simply not depending on anything else.

The consequence, stated as a rule for every later phase:

> **The website being blocked must cost traffic, never function.** A user who already
> has the install command must never need the website for anything.

Two supporting requirements, implemented in Phase 1:

- **`VPN55_MIRROR` environment override.** The installer reads a base URL from the
  environment and falls back to the GitHub raw URL. This is the documented escape
  hatch that does not require shipping a new script when one is needed.
- **Case sensitivity.** `raw.githubusercontent.com` is case-sensitive on the repository
  path. `noobvie/VPN55` must keep its capitals there, even though `github.com` would
  redirect a lowercase URL happily. A lowercase raw URL 404s.

---

## 2. Domain registration

| | |
|---|---|
| **Never** | A `.vn` domain, or any Vietnamese registrar (PA Vietnam, Mắt Bão, Nhân Hòa, iNET) |
| **Why** | Those sit under VNNIC and can be suspended by administrative order — no court, no notice, no recourse, and the domain is gone with whatever is on it |
| **Use** | `.org` under PIR, registered offshore: Porkbun, Cloudflare Registrar, Namecheap |
| **WHOIS privacy** | On at the moment of purchase, not afterwards |

**WHOIS privacy is not retroactive.** Registration records are scraped and archived
within hours of a domain going live. Buying first and enabling privacy later publishes
a permanent, searchable link between the domain and whatever contact details were used.
Enable it in the same transaction.

### Backup domains — and why they should not say "vpn"

Register **two or three backups at a different registrar** from the primary, so that a
single registrar action cannot take everything.

The non-obvious part: **do not put `vpn` in the backup names.**

Bulk blocklists in most censoring countries are seeded by keyword sweeps over DNS query
logs and TLS SNI. `vpn55.org` gets caught by a script that nobody had to think about.
A neutral two-word name that reads like a personal blog survives the automated pass and
falls only when a human decides to block that specific host.

So the two kinds of domain do different jobs, and should be named differently:

- **The brand domain** (`vpn55.org`) — marketing, memorability, what goes on a business
  card. Assume it is the first to die.
- **The neutral domains** — the ones that actually have to survive. Named to be
  uninteresting. Not advertised on the brand domain, because a blocklist maintainer who
  finds one finds all of them.

---

## 3. What a block actually looks like, and how to tell them apart

Vietnamese ISP filtering (VNPT, Viettel, FPT, CMC) is overwhelmingly **resolver-level
DNS poisoning** — the weakest form, and the one that DNS-over-HTTPS defeats outright.
When a user reports "the site is down", these three commands separate the causes:

```bash
# 1. DNS poisoning?  ISP resolver disagrees with a public one.
dig +short vpn55.org @8.8.8.8
dig +short vpn55.org            # user's ISP resolver — differs, or returns NXDOMAIN

# 2. IP blackhole?  TCP never completes.
curl -sv --connect-timeout 5 https://vpn55.org 2>&1 | head -20

# 3. SNI filtering?  TCP connects, then the handshake is reset.
#    Connection succeeds to the IP but dies on the ClientHello.
curl -sv --connect-timeout 5 --resolve vpn55.org:443:<IP> https://vpn55.org 2>&1 | head
```

**Escalation ladder, cheapest defence first:**

| Method | Defeated by | Cost to the censor |
|---|---|---|
| DNS poisoning | DoH / DoT, or any public resolver | Trivial — expect this first |
| IP blackhole | Shared-IP CDN (Cloudflare) makes it collateral-heavy | Moderate |
| SNI / TLS fingerprint reset | Domain fronting, ECH where available | Higher, and increasingly common |

Put the site behind **Cloudflare** so its IPs are shared and blackholing them carries
collateral damage. Encrypted Client Hello would blunt the SNI tier, but its availability
has been on and off — treat it as a bonus if it is enabled when you need it, never as
the plan.

---

## 4. Mirrors that do not share a failure domain

One mirror on the same DNS, same registrar, same host is not a mirror. Each entry below
fails independently of the others.

- **GitHub Pages — `noobvie.github.io/VPN55`.** Publish the landing page here *as well
  as* on `vpn55.org`, same content, both live permanently. A DNS block on the custom
  domain does not touch the `github.io` hostname. Nothing to seize, nothing to pay for.
  (Note the distinction: a custom domain pointed at GitHub Pages dies with the domain;
  the `github.io` URL does not.)
- **Codeberg or GitLab mirror.** A second company in a second jurisdiction, kept current
  with one `git push`. Add it as a second remote and push both.
- **A `.onion` service** for the docs. Cheap, zero-maintenance, and on-brand for exactly
  this audience.

Skip IPFS unless you specifically want it — the uptake among the target users does not
justify the maintenance.

---

## 5. Signed releases — the item most projects skip, and the one that bites

**When the domain goes dark and users start searching for mirrors, that is precisely
when someone publishes a trojaned "VPN55" installer.** To a user who just wants the
thing to work, a censored project and a compromised project look identical. A VPN
installer running as root is close to the highest-value trojan target there is.

This is the one section on the page that is a *security* control rather than an
availability one, and it must be in place **before** the project is well-known enough
to be worth impersonating — not after.

### Set up once

```bash
# Generate a signing keypair. Keep vpn55.key offline; publish vpn55.pub.
minisign -G -p vpn55.pub -s vpn55.key
```

Publish the public key **in the README itself**, not only on the website — the README
lives on the host that cannot be blocked.

### Every release

```bash
# Checksums for the release artifacts, then one signature over the checksum file.
sha256sum vpn55.sh vpn55-*.tar.gz > SHA256SUMS
minisign -Sm SHA256SUMS -s vpn55.key

# Sign the git tag too — this is what proves the commit, not just the tarball.
git tag -s v1.0.0 -m 'VPN55 v1.0.0'
```

### What the user runs — document this in Vietnamese

```bash
curl -fsSLO https://raw.githubusercontent.com/noobvie/VPN55/main/SHA256SUMS
curl -fsSLO https://raw.githubusercontent.com/noobvie/VPN55/main/SHA256SUMS.minisig
minisign -Vm SHA256SUMS -P <public key from the README>
sha256sum -c SHA256SUMS
```

**Be honest about the limit.** `curl | bash` cannot verify itself — by the time the
script could check a signature it is already running. Signing does not fix that, and
claiming otherwise would be worse than not signing. What signing *does* fix is the
mirror problem: it gives a user who found VPN55 somewhere other than GitHub a way to
prove that what they found is what you published. Present the one-line install as the
convenience path and the verified path as the recommended one, and say plainly which
is which.

---

## 6. Channels

**Telegram is the highest-leverage item on this page after §1.** It is not blocked in
Vietnam, it is enormous there, and a channel that posts the current working mirror is
genuinely how users in censored markets re-find a project after it disappears. Ten
minutes of setup. Do it before launch, not after the first block.

| Channel | Use it for | Do not use it for |
|---|---|---|
| **Telegram** | The mirror-of-record announcement channel. Release notes. | — |
| **Zalo** | Reach — it is where the users actually are | Anything resilience-critical. It is VNG: domestic, and compliant with takedown and disclosure requests. Assume everything posted is visible. |
| **voz.vn** | Close to a bullseye for the target demographic | A mirror. Domestic and moderated — treat a post as marketing that may vanish. |
| **r/selfhosted, awesome-selfhosted** | International discovery, GitHub stars | Reaching the actual Vietnamese end user |

**The root of trust is the GitHub README.** Everything else — Telegram, mirrors, the
website — points back to it, and it lists the current mirrors. That inverts the usual
arrangement, where a website lists mirrors and dies with them.

---

## 7. Publishing identity — an unbundled decision

Two choices that are easy to make accidentally as one:

1. **Registering `vpn55.org`** offshore with WHOIS privacy, publishing under the
   `noobvie` GitHub account.
2. **Linking it from Office Tools** — a card and a landing page on a site that carries
   a commercial identity.

These have materially different exposure profiles and there is no technical reason to
do them at the same time. The build plan currently bundles both into Phase 9. **They
should be separate line items, and the project ships fine with the first and not the
second.**

The relevant legal ground — Vietnam's Cybersecurity Law and its 2022 implementing
decree, and the administrative-penalty rules around VPN and circumvention guidance — is
not something to take on the word of a documentation file. If step 2 is on the table,
that is the point to get advice from someone who practises in Vietnam.

---

## 8. Phase 9 checklist

Ticked boxes are enforced by code or CI and cannot silently regress. Everything still
unticked needs a human, a VPS or a credit card — the operator half is worked through in
`docs/launch.md`.

Availability:

- [x] `vpn55.sh` fetches nothing from `vpn55.org` — CI job **distribution** greps
      `vpn55.sh`, `lib/`, `helper/`, `panel/`, `tools/` and `tests/` on every push,
      and fails on anything outside a comment
- [x] `VPN55_MIRROR` override implemented and documented — and *exercised*: CI serves
      the checkout over HTTP, installs a complete tree from that base URL and verifies
      it. It was a variable expansion before it was a transport; a sentence in a README
      is not an escape hatch until something has actually escaped through it
- [x] The advertised install command works at all — `bash <(curl …)` runs from
      `/dev/fd/63` and could not source `lib/`; `vpn55.sh` now bootstraps to
      `VPN55_HOME` and CI fails if a directory-less run reports a missing library
- [ ] Primary domain registered offshore, WHOIS privacy enabled in the same transaction
- [ ] 2–3 backup domains at a **second** registrar, **without** `vpn` in the name
- [ ] Site behind Cloudflare
- [ ] Landing page live at **both** `vpn55.org` and `noobvie.github.io/VPN55` — the page
      exists at `site/index.html` (one file, zero external requests, so it renders from
      an onion service); publishing it is outstanding
- [ ] Codeberg or GitLab mirror, second git remote configured
- [ ] `.onion` mirror published
- [ ] README lists all current mirrors — it is the root of trust, not the website. The
      table is in place; three of its rows still say *to be added*, and the landing page
      deliberately does not carry a copy

Integrity:

- [ ] minisign keypair generated, private key held offline
- [ ] Public key published in the README, not only on the website — the placeholder and
      the surrounding section are in place; the key itself is not
- [x] `SHA256SUMS` + `.minisig` shipped with every release — `tools/release.sh` builds
      the tarball **from `MANIFEST.sha256`**, so what a release contains and what a
      mirror serves are one list by construction. It refuses a dirty tree, refuses a
      stale manifest, and refuses a version string that disagrees with the tag
- [x] Git tags signed — `tools/release.sh <version> --tag`
- [x] Verification instructions written **in Vietnamese**, with the `curl | bash`
      limitation stated plainly — README *Kiểm tra bản tải về*, and again on the landing
      page. Both say the same thing: signing fixes the mirror problem, not that one
- [x] An installed copy can check itself — `vpn55.sh --verify` against
      `MANIFEST.sha256`. Corruption and accidental edits only; a mirror that serves a
      consistent lie is caught by the signature above and by nothing else

Channels:

- [ ] Telegram announcement channel live before launch
- [ ] Mirror-of-record posting procedure written down
- [ ] Office Tools card — **decided separately** from everything above (§7)
