Deep logic and security review of the file(s) in $ARGUMENTS, or of
`git diff --name-only HEAD` if none given. Nothing here has ever run on a VPS —
review as if you are the only test.

Run `/check` first for the mechanical layer, and `/contract` if an adapter is in
scope. This command covers what neither of those does.

## 1. Privilege

- **`helper/vpnctl` accepts seven verbs and nothing else**: `user-add user-remove
  user-enable user-disable cred-add cred-revoke service-restart`. A new verb is a
  security decision, not a convenience — flag any addition and say what a panel
  compromise now costs.
- The helper **validates its own arguments**. It never trusts the panel: strict
  whitelist regex on usernames, numeric bounds on anything numeric, no path taken
  from the caller unchecked. A validation that lives only in the panel is not
  validation.
- `panel/lib/privileged.js` is the **only** module that invokes it. Grep for any
  other caller, and for any `sudo`, `child_process` or shell string built elsewhere.
- No blanket sudo, no sudoers wildcard, no `NOPASSWD: ALL`.

## 2. Command injection and quoting

- Every value that reaches a command line — username, cred id, interface, endpoint,
  filename — is quoted and validated at the boundary. Trace one user-supplied value
  end to end (panel → helper → adapter → `wg`/`swanctl`/`openvpn`) and show it is
  constrained at each hop.
- `eval` — flag every occurrence.
- Temp files via `mktemp`, never a fixed `/tmp` name.
- `printf %q` or an array, never string concatenation, for a built command.

## 3. Secrets and key material

- No key, cert, passphrase or token written to a world-readable path, to a log, or
  into argv (`ps aux` is readable by every local user). Private material is `600`,
  written through `core_fs.sh`'s atomic write, and shredded on revoke.
- Nothing matching `.gitignore`'s runtime-state list (`*.key *.pem *.p12 *.crt
  *.ovpn *.mobileconfig users.json`) may appear in the tree — check `git status`,
  not just the diff.
- If key custody is `server`, the disclosure string is present and truthful.

## 4. State that must reverse

- **The firewall ledger is the source of truth for revocation.** `net_fw_revoke_tag`
  reads `/etc/vpn55/fw.state`, never the live ruleset — firewalld has no rule
  comments at all, and a comment someone rewrote is a rule uninstall walks past.
  Flag any revoke path that greps live rules.
- One firewall backend per host, recorded in `/etc/vpn55/net.conf`. Mixing two is how
  a rule survives an uninstall.
- Uninstall reverses NAT, forwarding, the pool claim and every lease. Re-install
  after uninstall must work — check for state that only the *first* install creates.

## 5. Panel/server truth

- On-disk server config is the source of truth; the panel reads
  `vpn_<proto>_status`. Flag any panel-side table that caches credential state and
  can drift — that is the most common failure in this product category.
- `panel/lib/collector.js`: `new < last` means a fresh session, so add the **full
  new value** to a durable total. Check it does not treat `-` as zero (that
  double-counts a whole session on the next poll).
- Panel binds the **WireGuard interface IP**, never `0.0.0.0` plus an allowlist — an
  ACL still lets a stranger complete the TLS handshake.

## 6. Distribution constraint

`vpn55.sh` fetches **nothing** from `vpn55.org` — no version check, no mirror list,
no asset. The canonical path is the `raw.githubusercontent.com` URL; the site being
blocked must cost traffic, never function. Check `VPN55_MIRROR` overrides the base
URL, and that the repo path keeps its capitals (`noobvie/VPN55` — raw is
case-sensitive).

## 7. Honesty of output

- A failure is reported as a failure. Flag any path that prints success after a
  guarded command returned non-zero.
- An unknown is reported as unknown (`-`), never as `0`.
- No distro is claimed anywhere that has not had a real install / uninstall /
  reinstall run on it.

Report by category with `file:line` and a concrete fix. End with critical / medium /
low counts, and a separate list of anything that can only be settled by a VPS run.
