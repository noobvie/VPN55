# VPN55 — Tunnel circumvention and DPI resistance

**How the tunnel itself survives ISP filtering**, once the user already has the software.

This is the companion to `docs/distribution.md`, and the split between them matters:

| Document | Problem |
|---|---|
| `distribution.md` | How the **software** reaches a user whose ISP is filtering |
| **this document** | How the **tunnel** keeps working once they run it |

Those fail independently. A user can have a perfect copy of `vpn55.sh` and a working
server, and still have every packet dropped. Solving one does nothing for the other.

Last revised: 2026-09-02 — §4 (endpoints, as built), §5 (the admission now reaches
the terminal), §8 (the Nostr decision) and the §10 checklists, after a verification
pass over the adapters against this document. Before that: 2026-08-29 (Phase 2).

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

### As built — 2026-09-02

The mechanism exists. **The ≥2 ASN requirement does not yet, and the gap is not
where it looks.**

- **One shared list, not one per protocol.** `net_endpoints_*` in `core_net.sh`,
  managed with `--endpoint-add` / `--endpoint-remove` / `--endpoints`. All three
  protocols run on the same host and reach it at the same addresses; only the
  PORT differs. So the list holds **hosts**, each adapter pairs each host with
  its own port, and an entry carrying a port is refused — one `host:port` cannot
  serve three protocols, and accepting the syntax would invite an operator to
  write something only one of them honours.
- **The primary stays the adapter's own.** Each adapter keeps the `endpoint` it
  resolved at install and that is still the first entry; this list is what comes
  after it. Callers ask `net_endpoints_all "<their primary>"`. The
  single-endpoint case is the one-element case, so there is no second code path
  to drift, and an install predating this behaves identically.
- **An IPv6 literal is refused**, deliberately rather than by omission. The three
  protocols spell a v6 endpoint differently — WireGuard `[addr]:port`, OpenVPN
  the address bare with a `udp6`/`tcp6-client` transport, strongSwan differently
  again — so one accepted string would emit three files of which at best one
  connects, with no error on any of them. `net_wan_address` resolves through
  `ip -4` anyway, so there is no v6 primary to pair one with.

**What a client actually does when the first endpoint is blocked — three
different answers, which is why this could not be one switch:**

| | Behaviour | Cost |
|---|---|---|
| **OpenVPN** | Native. Every endpoint becomes a `remote` line, plus `remote-random` and a `server-poll-timeout`. The client walks the list itself | None. No second file, nothing for the user to do |
| **WireGuard** | **No client-side failover exists.** One `Endpoint` per peer — no list, no ordering, no rotation, in the format or in any mainstream client | One extra config file per endpoint, and the user switches tunnels in the app by hand |
| **IKEv2** | Deliberately **not** given a list | The clients this protocol exists for store one server address and cannot move |

Three things in that table are worth stating rather than leaving to be inferred:

- ⚠ **`remote-random` is not a nicety.** Without it every client dials entry one,
  so the second address carries nothing until the first is blocked — at which
  point the whole user base arrives at it simultaneously and the untested
  endpoint gets its first real traffic during an incident.
- ⚠ **For WireGuard, the DNS trick is specifically wrong here.** Pointing
  `Endpoint` at a name with several A records is the tidier-looking answer and
  it is the worse one on this network: §1 names resolver-level DNS poisoning as
  *overwhelmingly the most common* Vietnamese filtering method, so putting
  endpoint resolution behind DNS re-opens the exact hole §3 closes. Several
  files, chosen by hand, is uglier and survives.
- **IKEv2 gets a `warn` note when endpoints exist**, rather than silence.
  strongSwan's own client honours a list of remote addresses; iOS, macOS and
  Windows — the whole reason this protocol is carried — store one. Emitting a
  list would serve the users with the least need of it and none of the users it
  is for, while letting the endpoint list read as though it covered all three
  services. Saying nothing would be the quieter version of the same claim.

**Endpoints added later do not reach configs already issued, and cannot.** The
certificate protocols erase the client private key after hand-off, so those
files are unrebuildable *by design* — the same property that makes
`_ovpn_transport_bootstrap` refuse a transport change. Every registered endpoint
is therefore emitted at issue time, and additions apply to credentials issued
from then on. Removing an endpoint does not reach them either; a client simply
fails over past a dead one, which is the point.

**⚠ The remaining gap, and it is the expensive half.** Adding an address does not
make a second host work. That host must answer with the same server identity —
the same CA and server certificate for the certificate protocols, and for
WireGuard the same server private key **and the same nine obfuscation
parameters**, which `_awg_settings_bootstrap` draws per server and then refuses
to change. Exporting that identity from one host and importing it at another is
a **fleet seed**, and it is not built. Until it is, this list covers the several
addresses of **one** host: a second IP, a domain beside the address it resolves
to, a front terminating elsewhere. That is a real and useful case. It is not the
multi-ASN case, and `net_endpoints_explain` says so to the operator's face
rather than letting a working command imply a fleet.

**Nothing here can check the ASN requirement**, and nothing pretends to.
`net_public_endpoint` refuses to ask a third party what this host's own address
is — that is the telemetry this project does not have — and an ASN lookup is the
same outbound call wearing a different hat. So it is a warning at add time and a
line on the launch checklist, never a validator. A check that cannot check is
worse than no check, because it gets believed.

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

As built (2026-09-02): the `filtering` capability record carries it, and **both**
front ends now read that record — the panel since Phase 5, the terminal since
2026-09-02. "Wherever a user picks a protocol" is three places in `vpn55.sh`
alone: the service list, each service's own screen, and immediately before an
install. It is stated before the install rather than after, because an operator
who learns it afterwards has already chosen.

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

**That check was done, 2026-08-30, and it found one thing.** The answer is recorded here
rather than left as a standing question.

Everything else ports. `_available` is easier for a listener-shaped protocol than for any
adapter here — a userspace binary, no kernel module to find. `_capabilities` fits: a UUID
or a password is `custody server`, a config reload is `revoke immediate 0`,
`filtering resistant` is the whole reason the rung exists. `_cred_add` / `_cred_remove` /
`_cred_list` are an inbound entry keyed by an id, which is no harder than a certificate,
and `address -` was already legal because IKEv2 needs it. `_artifacts` and
`_client_config` are the easy case: a `vless://` or `hysteria2://` URI is a few hundred
bytes, which is the one payload in this project a QR code genuinely fits. `rx`/`tx` come
from Xray's stats API or Hysteria2's traffic API, both cumulative and both reset on
reload, which is exactly what `panel/lib/collector.js` already assumes.

**`_status` was the one that broke, on liveness.** Neither of those APIs exposes a peer
address or a last-seen time per user, so a conformant adapter had to emit `handshake -`
and `endpoint -` for every credential, always — correctly, under the contract as it then
stood. But the panel read presence off `endpoint`, on the reasoning that a remote address
was the one signal all three existing protocols could answer the same way. A protocol with
no peers cannot answer it, so every credential on such a service would have been
permanently absent from the connections list and from every count built on it: a
fully-loaded service rendering as empty. Not a crash — a silent, plausible zero.

The fix is in the contract, not in the adapter: `_status` now carries an explicit
`connected 1|0|-` that the adapter answers, and nothing reads liveness off `endpoint` any
more. That also fixed a live bug in the WireGuard adapter, where the endpoint is the LAST
address a peer was seen at and outlives the session for the life of the interface. Both
failures had the same root — a peer-shaped field doing a job that is not peer-shaped.

One thing to know before writing such an adapter: `net_pool_claim` is not only an address
allocation. All three uninstalls use `net_pool_claims` as the protocol-neutral test for
"is any other tunnel service still on this host?" before turning IP forwarding off. A
proxy-shaped protocol routes nothing and needs no forwarding, so it correctly claims no
slot and correctly does not count — but the invariant that makes that safe is **an adapter
that needs host IP forwarding must claim a pool slot**, and it is written down in
`CLAUDE.md`'s networking section rather than being a property anyone can see from here.

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

### The decision — 2026-09-02: documented, not shipped. The signature ships instead.

The question this section left open was whether the rendezvous event ships in
v1. It does not. **What ships is the signed statement it was built around**,
carried over the channels that already exist.

The reasoning is one line, and this section already contains it: *the signature
is the point.* Nostr is one transport for a signed blob, not the source of the
guarantee. So the guarantee ships now and the transport can be added later.

**What shipped instead — `rendezvous.txt`.** A small key=value file listing the
current mirrors, the release, the `.onion`, the SHA-256 of `vpn55.sh`, a serial
and an expiry — signed with **the minisign key already used for `SHA256SUMS`**,
and published on the site, the `.onion`, every mirror, and pasted into the
announcement channel. `vpn55.sh --rendezvous <file>` verifies one and prints it
only if the signature is good.

Three reasons that ordering is not merely cheaper but **better**:

- **The key already exists, on the wrong curve for Nostr.** `tools/release.sh`
  signs with minisign, which is Ed25519, and the README already publishes that
  public key. Nostr needs secp256k1 Schnorr: a different curve, a second key, a
  second custody story, and a second thing to publish — before the first one has
  ever cut a release.
- **The key custody is inverted.** The minisign key is offline, permanently. A
  rendezvous key has to come back online to re-publish, because an event
  advertising a dead endpoint is worse than no event. Adding that requirement to
  the release key's discipline is a real cost that "just publish an event" hides.
- **It closes a hole that was already open, today.** `src_fetch` downloaded
  `MANIFEST.sha256` from `VPN55_MIRROR` and then checked the tree against it —
  both halves from the same place, so a hostile mirror served both and passed.
  That is precisely the injected-mirror attack described above, reachable with no
  Nostr involved. The manifest is now signed and the signature is verified
  **before a single manifest line is parsed**, since those lines decide what gets
  fetched.

⚠ **Verification does not depend on minisign being installed.** It is not, on a
fresh VPS, and that is the install where this matters most — so
`src_minisign_verify` uses minisign when present and otherwise does the same
check through openssl, which is everywhere. A minisign signature is plain
Ed25519 in a documented envelope. Every branch fails **closed**: no tool, no key,
an unknown algorithm, a truncated file, a key id that is not ours. That property
is what `tests/signature-verify.sh` is mostly about — a good signature verifying
is one assertion out of twenty-one, and the other twenty are the file's purpose,
because the failure mode of hand-rolled signature plumbing is never "rejects a
good signature" (that is noticed on the first release) but "returns success
without checking".

**Enforcement is switched on by one variable.** `VPN55_PUBKEY` is empty until the
release key exists, and while it is empty an unverifiable manifest produces a
loud warning and continues — refusing would make `--update` impossible before
launch. Filling it in turns every check into a hard failure at once. That is a
launch-blocking step, not later polish.

### If the Nostr transport is added later, do it in this order

The layering below is strictly stronger than signing with a Nostr key, and it is
only available if the minisign statement exists first:

> **minisign signs the payload; the Nostr key signs the envelope.** A compromised
> or coerced Nostr key then still cannot forge the contents — it can only
> withhold them, which redundancy across relays already covers.

The work it implies, so the decision stays priced rather than remembered as
"small":

- A BIP-340 Schnorr signer. Not in the openssl CLI. The panel has **exactly one**
  dependency (`express`); a secp256k1 package breaks that, and the alternative is
  vendoring and auditing a signer.
- NIP-01 event construction (canonical serialisation → id → signature), NIP-19
  `npub` encoding, and a WebSocket client with retry across N relays. The panel
  is Express; there is no ws client in the tree.
- ⚠ **Bootstrap circularity this section did not address.** A reader needs the
  `npub`, and the `npub` has to reach them through the same blocked channels. It
  must be baked into `vpn55.sh` and the README exactly like the minisign public
  key — otherwise the rendezvous needs a rendezvous.
- ⚠ **An operational risk this section did not mention.** The warning above about
  not running your own relay is right, and its consequence is a dependency on
  relays that rate-limit and drop unknown pubkeys. A brand-new `npub` with no
  web of trust is dropped outright by several of the relays named above. Test
  publication before depending on it.


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

**Phase 4 — OpenVPN** — done 2026-08-30
- [x] `tls-crypt` enabled **by default**, not offered as an option — and not
      overridable: there is no prompt, no environment switch and no reachable
      configuration without it. Three independent guards, any one of which would
      do it alone: install refuses a daemon below 2.4, `_ovpn_tls_key_ensure`
      always records a mode, and the config render hard-fails on an empty one
- [x] Evaluate `tls-crypt-v2` for per-client keys — evaluated AND adopted.
      `_ovpn_tls_mode_for_host` picks it on 2.5+, the server key is minted at
      install and a per-client wrapped key at issue. Where the recorded mode is
      lost the KEY is the authority, because the two forms are not
      interchangeable and guessing wrong makes a daemon that starts and a client
      that cannot connect
- [x] TCP/443 as a first-class install choice — it is the first question the
      adapter asks, it is the default, and the prompt states the
      two-retransmission-timers cost in the same breath

⚠ These three were built in Phase 4 and the boxes above were left unticked until
2026-09-02, while §5's "As built" prose eight screens up said they were done. A
checklist in the authority document is the thing a reader trusts; when it
disagrees with the prose in the same file, the reader is being misled by
whichever one they happened to read. Tick the box in the same commit as the
code.

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
- [x] **The terminal shows it too** — added 2026-09-02, and it was missing for
      two Phase-5 items' worth of time. Everything above was built against the
      panel, which is read-only; `vpn55.sh` is where services are actually
      installed, and it read the `custody`, `option` and `revoke` capability
      records while never reading `filtering`. So the one interface that acts on
      the answer was the one interface that never printed it. It is now on the
      service list, on each service's own screen, and immediately before an
      install. ⚠ The lesson generalises past this record: a capability consumed
      by only one of two front ends is a capability half-shipped, and neither
      front end's code says so

**Phase 9 — Launch**
- [~] Multi-endpoint configs across ≥2 ASNs — the **mechanism** is built
      (2026-09-02): a shared list in `core_net.sh` (`net_endpoints_*`),
      `--endpoint-add` / `--endpoint-remove` / `--endpoints`, and per-protocol
      emission described in §4. The **≥2 ASNs** half is NOT met and cannot be
      met by this alone: a second host has to answer with the same server
      identity, and sharing that between hosts is unbuilt. See the fleet-seed
      paragraph in §4
- [ ] Snowflake documented as the bootstrap path of last resort
- [x] Decide whether the Nostr rendezvous event ships in v1 or is documented
      only — **decided 2026-09-02: documented, not shipped.** The signed
      statement it was built around ships instead. Reasoning and the work it
      implies are in §8

**Contract review, whenever it next happens**
- [ ] Confirm a non-peer (inbound/listener-shaped) protocol could implement the adapter
      contract, so rung 3 stays possible
