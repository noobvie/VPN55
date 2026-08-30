Research before implementing $ARGUMENTS. **Write no code** — research and summarise.

## 1. The licence gate comes first

VPN55 is MIT and stays MIT, so what may be copied *in* is constrained. Settle this
before reading any source, because it changes what the research is for.

- **Copy from MIT / Apache-2.0 only.** `Nyr/openvpn-install`,
  `angristan/openvpn-install`, `angristan/wireguard-install` are the liftable ones.
- **Read-only:** `hwdsl2/setup-ipsec-vpn` (CC BY-SA 3.0 — viral share-alike applied
  to software), `wg-easy` / `algo` / `Marzban` (AGPL-3.0), `3x-ui` / `Hiddify`
  (GPL-3.0), Pritunl (proprietary). Learn from them; write your own.
- **IKEv2 has no liftable source at all.** That is expected, not a research failure —
  say so plainly rather than stretching a licence.
- Re-verify via the GitHub API before copying, never from a README badge.
  `NOASSERTION` means *read the licence file*, not *permissive*.
- If anything will be reshaped from a permissive source, note that it needs an
  `ATTRIBUTIONS.md` entry **in the same commit**.

Full table: `docs/prior-art.md`.

## 2. What already exists here

```bash
git log --oneline -20
git log --all --oneline -- <relevant-file>
grep -rn '<function-ish name>' lib/ vpn55.sh helper/ panel/
```

- `lib/ui.sh` — logging, prompts, QR, `str_has_line` / `str_contains`
- `lib/core_fs.sh` — atomic write, shred, key=value conf, uuid, xml escape
- `lib/core_net.sh` — `net_pool_*`, `net_fw_*`, backend detection
- `lib/core_pki.sh` — cert ops shared by OpenVPN and IKEv2
- `lib/core_users.sh` — the single identity registry
- `lib/proto_wireguard.sh` — the reference adapter; read it before writing another

Check whether the thing already exists under a different name before proposing it.

## 3. The three design docs

- `docs/security-model.md` — read before anything privileged. The narrow root helper
  and its seven verbs are DECIDED; WireGuard key custody is §6.
- `docs/prior-art.md` — the licence table and per-phase guidance, plus §4 on why
  `conn_limit` and `quota_reset` exist as nullable columns.
- `docs/distribution.md` §1 — `vpn55.sh` fetches nothing from `vpn55.org`. This is
  a constraint on the code, not a later chore.

## 4. Does it fit the contract?

Anything protocol-touching has to land inside the ten contract verbs and the record
shapes in CLAUDE.md. If the feature seems to need a protocol branch outside
`lib/proto_*.sh`, that is the finding — report what the contract is missing (usually
a `note`, an `option`, or a new record type) rather than proposing the branch.

## 5. Output

1. What already exists in this repo that is relevant
2. What the prior art does, and its **licence verdict** (liftable / read-only)
3. Gaps to fill, and where each belongs in the layout
4. Recommended approach, and what it costs in the contract — no code
