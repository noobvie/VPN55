# VPN55 — Tunnel circumvention and DPI resistance

**How the tunnel itself survives ISP filtering**, once the user already has the software.

This is the companion to `docs/distribution.md`, and the split between them matters:

| Document | Problem |
|---|---|
| `distribution.md` | How the **software** reaches a user whose ISP is filtering |
| **this document** | How the **tunnel** keeps working once they run it |

Those fail independently. A user can have a perfect copy of `vpn55.sh` and a working
server, and still have every packet dropped. Solving one does nothing for the other.

Last revised: 2026-08-29 (Phase 2 — written now because two items here, §5 and §6,
change code in Phases 2 and 4).

---

## 1. Calibrate the adversary before building anything

**Vietnam is a moderate censor, not a China-grade one.** This is the single most
important sentence on this page, because almost all published circumvention advice is
written against the Great Firewall, and applying it here would cost months for a threat
that does not currently exist.

What Vietnamese ISP filtering (VNPT, Viettel, FPT, CMC) actually does, in rough order
of how often it is what you are looking at:

| Technique | Prevalence | Defeated by |
|---|---|---|
| Resolver-level DNS poisoning | Overwhelmingly the most common | DoH/DoT — completely |
| IP blocklisting | Common for specific targets | Endpoint diversity across ASNs |
| SNI filtering | Used for specific named targets | Protocols that do not expose a real SNI |
| Protocol fingerprinting (DPI) | Limited, target-specific | Obfuscation — see §5 |
| Active probing | **No publicly documented evidence** | Probe-resistant protocols (§6) — not needed yet |

The two conclusions:

> **Build to defeat DNS poisoning, IP blocks and SNI filtering. Architect so that
> defeating fingerprinting and active probing is an added adapter, not a rewrite.**

> **Do not build Great Firewall countermeasures in v1.** They are the most expensive
> work in this space, and every hour spent there is an hour not spent on Phase 3, which
> is already the expensive phase for unrelated reasons.

---

## 2. The collateral-damage principle

Underneath every technique below is one idea: **you are not trying to be undetectable,
you are trying to be expensive to block.**

A censor blocks what is cheap to block. A protocol that is trivially fingerprinted and
lives on its own IP range costs nothing to kill. Traffic that is indistinguishable from
ordinary HTTPS, arriving at an IP shared with a thousand legitimate services, costs a
political decision and a pile of angry businesses.

Every design choice below is chosen to move VPN55 from the first category to the second.

---

## 3. Layer 1 — DNS

VN's primary method, and the cheapest to defeat outright.

- **Push a DoH/DoT resolver in every client config.** This is already the direction the
  security model takes (`system` is rejected as a resolver choice, §7 there) — that
  decision was made for privacy reasons and happens to also close this hole.
- Never rely on the ISP resolver for anything, including the server's own lookups.

Nothing else in this document is as cheap as this.

---

## 4. Layer 2 — endpoints

- **Ship multi-endpoint client configs.** One blocked IP must degrade the service, never
  end it. A config listing a single endpoint is a single point of failure by design.
- **Spread endpoints across different ASNs and different providers.** Three VPSes at one
  host in one subnet is one endpoint wearing three hats — the whole range goes together.
- **A burned IP stays burned.** Blocklist entries are rarely reviewed and effectively
  never removed. Once an endpoint is blocked, rotate it out; do not wait for it to come
  back, because it will not.
- Prefer providers whose ranges carry heavy legitimate traffic (§2). A range that hosts
  only VPN endpoints is a free win for a blocklist maintainer.

---

## 5. Layer 3 — protocol fingerprint

This is where the real engineering is, and it is different for each of the three
protocols. **Be honest in the docs about which is which** — an operator choosing a
protocol for a censored network needs to know that the three are not equivalent.

| Protocol | Exposure | Mitigation | Phase |
|---|---|---|---|
| **WireGuard** | **Weakest.** The handshake initiation is a fixed-size packet with a fixed type byte and fixed reserved bytes. It is trivially fingerprinted and needs no heuristics | **AmneziaWG** — a WireGuard fork adding configurable junk packets before the handshake and randomised header values. Alternatively wrap in `wstunnel` (WebSocket over TLS) or `udp2raw` | 2 |
| **OpenVPN** | Control-channel handshake is identifiable in the clear | **`tls-crypt`** (2.4+) encrypts and authenticates the control channel, hiding the handshake entirely. **`tls-crypt-v2`** (2.5+) does it with per-client keys. Combine with TCP/443 | 4 |
| **IKEv2** | **Strongest fingerprint, least fixable.** IKE on UDP 500, NAT-T on UDP 4500, ESP payloads — all recognisable, and none of it is meaningfully disguisable without abandoning the protocol | None worth building. Accept it | 3 |

### As built — Phase 4

The OpenVPN row above is now implemented, and two details of it are worth pinning down
because the table's shorthand hides them:

- **`tls-crypt` is unconditional.** It is not a prompt, not a default that can be
  overridden and not an environment switch. Where the daemon is 2.5 or later,
  **`tls-crypt-v2`** is used instead, giving each client its own wrapped key — evaluated
  and adopted, not deferred. What it does not do is revoke: see
  `docs/security-model.md` §6C.1.
- **TCP/443 is the first question the install asks**, with its cost stated in the same
  breath. It is slower, structurally — a TCP tunnel carrying TCP stacks two
  retransmission timers on one path — and an operator who is not told that chooses
  badly. Two host collisions are checked before anything is written: the port itself,
  which every web server already holds, and the SELinux port label, which cannot be
  taken from the web server without breaking it. Details in §6C.6 of the security model.

Rung 0 of the ladder below is therefore complete on this protocol.

### The IKEv2 admission

IKEv2 earns its place in VPN55 for **native client support with no app install** — that
is a real convenience advantage on iOS, macOS and Windows. It does **not** earn its place
as a censorship-resistant transport, and the UI must not imply otherwise.

State this plainly wherever a user picks a protocol. Someone on a filtered network who
picks IKEv2 because it was listed alongside the others, with no indication that it is the
one that will be blocked first, has been failed by the interface.

### WireGuard and AmneziaWG

This is the **highest value-per-hour item in this document**. The Phase 2 adapter already
exists; AmneziaWG is a mode on top of it rather than a new protocol, and it closes the
worst fingerprint of the three.

- Ship it as a **mode of the WireGuard adapter**, not a fourth protocol. Same identity,
  same credentials, same IP pool — the adapter contract does not change.
- The obfuscation parameters (junk packet counts and sizes, header values) must be
  **identical on server and client** or the tunnel simply does not come up. They are part
  of the emitted client config, not a server-side-only setting.
- ⚠ **Verify the licence before lifting any code.** The kernel-module side inherits
  WireGuard's GPL-2.0; the userspace Go implementation is more permissive. Per
  `docs/prior-art.md`, *installing a package* is not *distributing their source* — so
  deploying it is fine under our MIT-pristine rule, and copying code from it is what
  needs care. Check the specific repository, not the umbrella project.

---

## 6. The escalation ladder

Build downward only when the layer above stops working. Each rung costs more than the
one before it.

| Rung | Trigger | Response |
|---|---|---|
| **0** | Baseline | DoH, multi-endpoint configs, OpenVPN TCP/443 + `tls-crypt` on by default |
| **1** | WireGuard specifically being blocked | AmneziaWG mode |
| **2** | TLS-wrapped traffic being blocked by SNI | `wstunnel` / WebSocket wrapping with a plausible SNI |
| **3** | Active probing appears — a censor connects to the endpoint to test whether it is a proxy | **VLESS + XTLS-Reality**, or **Trojan**. Both answer a probe by serving real traffic from a real site, so the probe learns nothing |
| **4** | QUIC/UDP throttling, heavy packet loss on mobile | **Hysteria2** or **TUIC** |

Rungs 3 and 4 are **deferred, not excluded.** The architectural note that matters:

> When the adapter contract is next revised, sanity-check that a **non-peer protocol**
> could implement it. Reality and Hysteria2 are inbound/listener-shaped, not
> peer-shaped like WireGuard. That check is nearly free now and is the difference
> between "deferred" and "impossible".

This supersedes the earlier framing that Xray-family protocols were excluded on
architectural grounds. The architectural point stands; the priority changed when the
market clarified from *self-hosters* to *users on a filtered network*.

---

## 7. Tor — the right tool for a different job

Tor is worth carrying, but not as transport.

| Variant | Blockable? | Notes |
|---|---|---|
| Plain Tor | **Easily** | Relay IPs and directory authorities are public lists |
| obfs4 bridges | Hard | Unlisted relays, traffic looks like uniform random bytes, resists active probing via an out-of-band secret |
| **Snowflake** | **Very hard** | Ephemeral WebRTC proxies in volunteers' browsers. The peer set rotates constantly and the traffic looks like a video call. Blocking it means breaking WebRTC broadly |

**But Tor is slow**, and pitching it to Vietnamese users as a daily-driver VPN would fail
on first contact. Its role here is **bootstrap and rendezvous** — how someone re-finds
the project after a block, not how they browse.

That is the same slot `distribution.md` §4 already fills with a `.onion` for the docs.
Snowflake extends it: a user who cannot reach GitHub, the mirrors, or Telegram can still
reach a `.onion` over Snowflake and get the current install command.

---

## 8. Nostr — evaluated and scoped

Nostr came up as a way to host content unblockably. **It does not do that**, and the
distinction is worth recording so it is not re-proposed:

- **Nostr protects the content.** Signed events replicated across many relays: no host to
  seize, no registrar to pressure, no takedown target. Genuinely excellent at this.
- **Nostr does not protect the connection.** Reading it in a normal browser requires a
  gateway (`<npub>.nsite.lol` and similar), which is an ordinary HTTPS host and is exactly
  as blockable as any website — and blocking one gateway takes out every site behind it.
  Reading it in a native client means reaching relays, each of which has a domain visible
  in the TLS SNI.

Nostr was designed against **deplatforming**, where the adversary deletes your content.
It was not designed against **national network filtering**, where the adversary never
touches your content and simply drops the packets. Vietnam is the second kind.

**Where it does earn a place: as a rendezvous channel**, alongside Telegram and the
`.onion` in `distribution.md` §6.

- Publish a small signed event — current mirror URL, current endpoints, `vpn55.sh`
  SHA-256 — to **many public relays you do not control** (`relay.damus.io`, `nos.lol`,
  `relay.primal.net`, and others).
- The signature is the point: it defeats an ISP injecting a fake mirror list, which is a
  real attack that a plain mirror page has no answer to.
- ⚠ **Do not run your own relay as the mechanism.** Your relay has a domain and gets
  blocked exactly like `vpn55.org`. The resistance comes from redundancy across relays
  you do not own. Run one if you like, as a convenience, never as the path.
- Prior art for the server side, if wanted: `scripts/lib/nostr_relay_deploy.sh` in the
  Grin Node Toolkit already deploys `nostr-rs-relay` behind nginx over `wss://` with the
  certbot HTTP-first bootstrap.

---

## 9. What not to build

- **Domain fronting.** AWS, Google Cloud and Cloudflare all disabled it years ago. Any
  guide recommending it is stale.
- **Your own obfuscation protocol.** Rolling a custom cipher or handshake produces a
  fingerprint that is unique to you, which is worse than looking like everyone else.
- **Nostr or IPFS as the hosting layer**, for the reasons in §8.
- **GFW-grade defences in v1**, per §1.

---

## 10. Phase checklist deltas

Items this document adds to the build plan:

**Phase 2 — WireGuard** — done 2026-08-29
- [x] AmneziaWG as a **mode** of the WireGuard adapter, not a fourth protocol
- [x] Obfuscation parameters emitted into the client config, server and client identical
      — one emitter, `_awg_params`, called by both renderers so they cannot drift
- [x] Licence check on the specific AmneziaWG repository before any code is reshaped
      — `amneziawg-go` MIT, `amneziawg-tools` and the kernel module GPL-2.0; nothing
      copied from any of them (`ATTRIBUTIONS.md`)
- [x] Parameters drawn **per server**, not the published example values — a shared set
      would be a fleet-wide signature replacing the one it removes (security-model §6.4)
- [x] A stock-WireGuard userspace fallback is refused in this mode; it would produce a
      tunnel that works and is trivially fingerprinted

**Phase 4 — OpenVPN**
- [ ] `tls-crypt` enabled **by default**, not offered as an option
- [ ] Evaluate `tls-crypt-v2` for per-client keys
- [ ] TCP/443 as a first-class install choice (already planned)

**Phase 5 — Panel** — done 2026-08-30
- [x] Protocol picker states plainly which protocols resist filtering and which do not
      — via a new `filtering <level> <explanation>` capability record (CLAUDE.md, record
      shapes), because the panel cannot work this out for itself without learning which
      protocol it is holding, and it may not
- [x] The level is COMPUTED, not a constant, for the two adapters where it depends on how
      they were installed: unobfuscated mode reports `exposed` and says so in its own
      words, and the same adapter reports `resistant` once obfuscation is on. An operator
      who reads "easy to block" is reading a fact about *this* install, not about the
      protocol in general
- [x] The service that cannot be disguised says so plainly rather than being quietly
      omitted — it is there for devices that connect with no app installed, and an
      operator choosing it should know what they are choosing (§ "The IKEv2 admission")
- [x] The explanation is the adapter's own sentence, shown verbatim and attributed, and
      the panel marks it as coming from the service rather than silently leaving one line
      untranslated

**Phase 9 — Launch**
- [ ] Multi-endpoint configs across ≥2 ASNs
- [ ] Snowflake documented as the bootstrap path of last resort
- [ ] Decide whether the Nostr rendezvous event ships in v1 or is documented only

**Contract review, whenever it next happens**
- [ ] Confirm a non-peer (inbound/listener-shaped) protocol could implement the adapter
      contract, so rung 3 stays possible
