Audit adapter-contract conformance for the adapter(s) in $ARGUMENTS, or all of
`lib/proto_*.sh` if none given. This is the check no generic shell review performs.

## 1. The surface is complete and named exactly

Ten verbs, no more and no fewer, each as `vpn_<tag>_<verb>`:

```
available  capabilities  install  uninstall  cred_add  cred_remove
cred_list  artifacts  client_config  status
```

- `<tag>` must match the tag passed to `vpn_adapter_register` in the adapter's own
  file — `vpn55.sh` builds the call name from the tag, so a mismatch is a runtime
  "command not found" that no syntax check sees.
- `_install` is idempotent (safe to re-run). `_uninstall` reverses it **including
  NAT and firewall** — verify it calls `net_fw_revoke_tag` and `net_pool_release`.

## 2. Record shapes — first field is the type

Read every `printf`/`echo` that emits a record and check it against the shapes in
CLAUDE.md. Field count is not a type; a reader must be able to skip an unknown
record type. Specifically:

- **`-` is not `0` and not "never".** `rx`/`tx` of `-` means no reading — the
  collector must not read it as a counter reset. `handshake 0` asserts the credential
  was never used; an adapter whose daemon keeps no history must emit `-`, because `0`
  claims a fact it does not have. Grep the adapter for a default that turns an
  unknown into `0`.
- **`encoding: base64` where the artifact is not text.** A caller reading through
  `$(…)` drops NULs and eats trailing newlines.
- **`qr 1` only where a camera will actually resolve it.** An 8 KB QR is a picture of
  nothing, and offering one is worse than offering none.
- **`listen` is a display string**, not a port — a protocol serving two writes both.
- `_cred_list` is one record per line, machine-readable, no decoration, no colour.

## 2a. The locale argument

`_client_config` takes `<cred_id> [artifact] [locale]`. The third argument is a
BCP 47 language tag and it arrives from a caller that does not know which protocol
it is talking to — which is correct, because a language tag is not protocol
vocabulary. Check:

- An unknown or absent tag **renders in the default locale**, never fails. Somebody
  still needs the file. `i18n_resolve` does this; do not re-implement it.
- Prose artifacts honour it; **binary and parser-facing artifacts ignore it**. There
  is no Vietnamese spelling of a certificate.
- Translated text comes from `lib/locales/<tag>/<locale>.txt` through `i18n_render`,
  looked up by SECTION NAME. An English sentence written inline in the adapter is the
  defect — it is a string no translator will ever see.
- **Prose is rendered at handover, not spooled at issue.** An adapter that spools one
  rendered language has made the credential's language a property of whoever issued
  it, and the recipient is usually somebody else. Spool the facts.

## 3. Options are declared, never assumed

Every `k=v` `_cred_add` accepts must appear as an `option` record in
`_capabilities`. An undeclared key must make `_cred_add` **fail** — silently
dropping a field the operator filled in and then reporting success is the worst of
the three behaviours available.

## 4. Revocation tells the truth

`_capabilities` declares `revoke immediate|crl <worst_case_seconds>` (`-1` = no
bound). Check the declared worst case matches what `_cred_remove` actually does —
WireGuard is instant, OpenVPN and IKEv2 are CRL-bound. The contract hides the
difference; the *return value* must not. The operator sees the declared latency
**before** confirming.

Same for `custody server|client` — whatever WireGuard key custody was settled as in
`docs/security-model.md` §6, the disclosure string must be present and shown on the
credential-issue screen.

## 5. No protocol leaks, and the leak check knows this protocol

```bash
grep -rniE '\b(wireguard|openvpn|strongswan|swanctl|ipsec|ikev2|mobileconfig)\b' \
  --include='*.sh' --include='*.js' --include='*.mjs' . \
  | grep -v '^\./lib/proto_' | grep -vE ':[0-9]+:[[:space:]]*(#|//)'
```

Then check the reverse, which is the failure that actually happened here: **does
that pattern in `.github/workflows/ci.yml` contain the vocabulary of the newest
adapter?** A hygiene check that does not know the protocol that just arrived goes
green exactly when it matters. Artifact **format** names count — an installer that
says `mobileconfig` has learned which protocol it is talking to.

## 6. Identity vs credentials

- The adapter owns the keypair / certificate / peer entry and **nothing else**. If it
  keeps any list of users, that is three parallel identity systems and the panel can
  no longer answer "who is this". Only `lib/core_users.sh` holds `name`, `enabled`,
  `quota_bytes`, `expires_at`, `conn_limit`, `quota_reset`.
- Address allocation goes through `net_pool_claim` / `net_pool_alloc` /
  `net_pool_free` with an opaque owner tag. An adapter that hardcodes `10.8.x.0/24`
  has re-learned the slot table that only CLAUDE.md is allowed to hold.
- Firewall rules go through the tagged `net_fw_*` verbs so the ledger at
  `/etc/vpn55/fw.state` records them. A rule applied directly survives uninstall.

Report per verb with `file:line`, and separate **contract defects** (fix in the
contract) from **adapter defects** (fix in the adapter). If `vpn55.sh` or any panel
code has to branch on protocol name to make something work, that is a contract
defect — say so rather than proposing the branch.
