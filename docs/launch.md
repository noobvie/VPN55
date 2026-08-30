# VPN55 — Launch readiness

What is done, what is left, and which half of it is code.

Phase 9 splits cleanly in two, and the split matters more than the list: **the
engineering is finished and the evidence is not.** Every adapter, the panel, the portal
and the three locales are written. Nothing has run on a server. A release is not
software that compiles; it is software somebody watched work, published in a way a
blocked user can still reach, signed so an impersonator cannot pass for it.

---

## 1. Done — in code

| | Where |
|---|---|
| The advertised install command actually works | `vpn55.sh` bootstrap → `lib/core_source.sh` |
| `VPN55_MIRROR` is a real transport, not a variable nobody reads | `src_fetch`, CI job **distribution** |
| Self-update keyed on the tree's revision, forcing a relaunch | `src_update` (returns 10), `vpn55.sh --update` |
| An installed copy can check itself | `vpn55.sh --verify`, `MANIFEST.sha256` |
| Non-interactive verbs so a release can be *tested* | `--adapters`, `--install <tag>`, `--uninstall <tag>` |
| The acceptance harness | `tests/vps-acceptance.sh` |
| Release build + signing | `tools/release.sh`, `tools/manifest.sh` |
| CI proves the website is not in the critical path | `.github/workflows/ci.yml` job **distribution** |

### The two traps that shaped this

**`bash <(curl …)` has no directory.** The README's one-line install runs `vpn55.sh`
from `/dev/fd/63`, whose dirname is `/dev/fd` — so every `. lib/…` resolved to a path
that cannot exist. The one command the project advertises could not work, and nobody
running from a checkout would ever have seen it. There is now a bootstrap, and a CI step
that runs the script with no directory beside it and fails if it reports a missing
library instead of asking for root.

**bash runs the copy it parsed at launch.** Pulling new code into the running tree does
not hot-reload it — not `vpn55.sh`, and not one of the eighteen libraries sourced at
startup. An update that carried on in the same process would apply the *old* code while
reporting the new version, and the functions that get fixed are exactly the ones that
write firewall rules. So `src_update` keys on the revision of the whole tree, and when
it changes it stops: return code `10` means *relaunch, and do nothing else first*.

---

## 2. Left — the VPS runs

**Nothing below can be done from a development machine, and none of it is optional.**

- [ ] Run `tests/vps-acceptance.sh --yes-destroy-this-host` on a throwaway VPS, over
      SSH, for **every** distribution the README claims. Keep the `result.tsv` line.
- [ ] Turn each verified row in the README matrix from 🚧 to ✅ — and only those.
- [ ] Connect a real client on each platform: iOS, macOS, Windows, Android, Linux. The
      harness deliberately does not do this. A tunnel that installs reversibly is not a
      tunnel that carries traffic.
- [ ] Install the panel and the portal end to end, from the deploy assets, and confirm
      the sudo rules match the installed paths rather than a source tree.
- [ ] Record the terminal GIF and the panel screenshot. Both README placeholders render
      as broken images until then, on the page that converts a visitor.

> A distribution row is a promise to a stranger who will run this as root. The harness
> exists so that promise costs one command instead of an afternoon — but somebody still
> has to run it.

---

## 3. Left — distribution

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
- [ ] `tools/release.sh <version> --tag` — builds the tarball from `MANIFEST.sha256`,
      writes `SHA256SUMS`, signs it, and signs the git tag.
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
- [ ] Seed r/selfhosted, an awesome-selfhosted PR, voz.vn and the Vietnamese
      communities. GitHub discovery is the international channel; it is not how the
      target end user finds this.

### Endpoints

- [ ] Multi-endpoint client configs across at least **two ASNs and two providers**.
      Three VPSes in one subnet is one endpoint wearing three hats.
- [ ] A burned IP stays burned — blocklist entries are effectively never reviewed. Plan
      to rotate rather than to appeal.

---

## 4. Decisions still open

**The Office Tools card is a separate decision from registering the domain** — open
question 1 in the build plan. Registering offshore with WHOIS privacy under the
`noobvie` account, and linking the project from a site that carries a commercial
identity, have materially different exposure profiles. There is no technical reason to
do them together, and **the project ships fine with the first and not the second.**

**Whether the Nostr rendezvous event ships in v1** or is documented only —
`docs/circumvention.md` §8. A small signed event carrying the current mirror, the
endpoints and the `vpn55.sh` hash, published to relays you do *not* control. The
signature is the point: it defeats an ISP injecting a fake mirror list, which a plain
mirror page cannot.

---

## 5. What would make this launch badly

Three failure modes, in the order they are likely:

1. **A distro claimed on the strength of "it should work."** The first issue filed is
   against the one row nobody ran.
2. **Publishing before the signing key exists.** Signatures added after a project is
   worth impersonating cannot retroactively authenticate what people already downloaded.
3. **The website becoming load-bearing by accident** — a version ping, a mirror list, an
   asset fetch added later because it was convenient. CI fails the build for it now, and
   that check should be understood as a product constraint rather than a lint rule.
