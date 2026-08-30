Debug a reported VPN55 issue. The problem is described in $ARGUMENTS.

## Mindset

Work down the chain of trust and **stop at the first layer that breaks** — that is
the root cause. Do not theorise past the evidence, and do not propose a fix until the
cause is confirmed. "It worked before" usually means a different host, not a
regression.

A VPN failure is layered, and the symptom almost never names the layer: a routing bug
looks like a firewall bug, a NAT bug looks like a DNS bug, and a revoked-but-still-
connected credential looks like a panel bug. Diagnose from the bottom.

## 1. Can this host run it at all?

```bash
vpn_<proto>_available          # what the adapter itself says
lsmod | grep -E 'wireguard|xfrm|tun'
systemd-detect-virt            # container? no kernel module, no netfilter
uname -r
```

A container or a kernel without the module is not a bug to fix in code — it is a
`_available` that must say so clearly.

## 2. Is the service up, and where is it listening?

```bash
systemctl status <unit>
journalctl -u <unit> -n 50 --no-pager
ss -ulnp; ss -tlnp
vpn_<proto>_status             # the contract's own answer
```

Compare the adapter's `service` record against reality. If they disagree, the bug is
in `_status`, and every downstream reading is untrustworthy until it is fixed.

## 3. Addressing — one pool, three claimants

```bash
net_pool_claims                # who owns which slot
net_pool_leases <tag>
ip -br addr; ip route
cat /etc/vpn55/net.conf
```

Two protocols allocating from one range is the classic week-three bug. Check the
credential's address against the slot table in CLAUDE.md — that table is the only
place the assignment is written down.

## 4. Forwarding, NAT and firewall — read the ledger

```bash
sysctl net.ipv4.ip_forward net.ipv6.conf.all.forwarding
cat /etc/vpn55/fw.state        # what VPN55 believes it applied
net_fw_rules                   # what the backend reports
nft list ruleset | head -60    # or: ufw status numbered / firewall-cmd --list-all
```

The **ledger** is the source of truth for what VPN55 added. If the ledger and the
live ruleset disagree, say which one is wrong before changing either — a rule added
outside the tagged verbs is invisible to uninstall, and a ledger entry with no live
rule means a reload was missed.

Handshake but no traffic ⇒ forwarding or masquerade. No handshake ⇒ port, UDP block,
or the client's endpoint.

## 5. The credential itself

```bash
vpn_<proto>_cred_list
vpn_<proto>_status | grep '^cred'
```

Read `handshake` carefully: `0` means never used, `-` means the adapter cannot tell.
Treating `-` as `0` is how "the client never connected" gets reported about a client
that has been connected for a week. For a CRL-based protocol, a revoked credential
staying up until the declared worst case is **correct behaviour**, not a bug.

## 6. Ownership and the privilege boundary

```bash
ls -la /etc/vpn55/ /var/lib/vpn55/
systemctl show <panel-unit> --property=User
sudo -u <panel-user> helper/vpnctl <verb> …     # does the helper accept it?
```

The panel runs unprivileged. A panel action that fails with nothing in the panel log
usually failed **inside `vpnctl`'s own validation** — check the helper's stderr, not
the panel's.

## 7. Panel vs reality

If the panel disagrees with the adapter, the adapter wins and the panel has cached
state it should not have. Check `panel/lib/collector.js` before anything else:
`new < last` must add the full new value to the durable total, and `-` must not enter
that arithmetic at all.

---

## If it is still not resolved

**Improve the error output before trying another fix.** Log the actual values —
path, tag, cred id, address, backend, exit code — not "error". Make the message tell
the operator what to run next. Only after the improved error has been reproduced
should you propose a code change, and then make the smallest fix at the true source
rather than compensating downstream.
