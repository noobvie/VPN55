# Acceptance testing

One script, run on a throwaway VPS, that decides whether a distribution may be
claimed in the README.

```bash
# On the VPS, as root, over SSH:
./tests/vps-acceptance.sh --yes-destroy-this-host
```

It refuses to run without that flag, because it installs and removes VPN
services, rewrites NAT and firewall rules and restarts daemons. On a host
anyone depends on, that is an outage.

---

## What it checks

| Check | Fails the run when |
|---|---|
| **Install** | any tunnel service the host reports as available cannot be installed |
| **Idempotency** | installing three times leaves the host in a different state on pass 3 than on pass 2 |
| **Uninstall** | a service cannot be removed |
| **Reversal** | firewall, routing, sysctl, interface, address or systemd-unit state differs from the baseline afterwards |
| **Reachability** | the default route disappears, or the port this SSH session arrived on stops listening |
| **Distribution** | `vpn55.sh`, `lib/` or `helper/` acquires a reference to the project website |

Warnings — reported, never fatal: no outbound TCP, DNS not resolving, packages
left installed, files left under `/etc/vpn55`.

## What it does **not** check

**It never connects a client.** A tunnel that installs reversibly is not a
tunnel that carries traffic, and a green run does not claim it does. Connecting
a real client on each platform stays a manual step, and the README matrix should
not get a ✅ on the strength of this script alone.

---

## Why three installs, not two

Two runs cannot tell a converged installer from an oscillating one. State that
alternates — a rule appended each time, a unit re-enabled, a lease reallocated —
shows up as a *stable* difference between run 1 and run 2, which reads as
"installing changed something", which is true and expected. The comparison that
means anything is **pass 2 against pass 3**.

## Why reversal is measured against the original baseline

Not against the state just before that service was installed. Per-service
baselines let every adapter leave a little behind and then call the sum of it
clean. There is one baseline, taken before anything happened.

## Why the SSH port is watched

The person running the test cannot see this failure. Their session is already
established and keeps working while every *new* connection is dropped — so a
firewall rule set that locks the host out looks like a successful run right up
until they log out. The port the current session arrived on is read from
`$SSH_CONNECTION` and re-checked after every step.

**Run it over SSH.** From a console the check has nothing to watch and says so.

---

## Reading the output

Everything lands in `/var/tmp/vpn55-acceptance` (or `--out DIR`):

```
snap-baseline/        one file per fact: routes, rules, listeners, units, …
snap-install-<tag>-N/ after each install pass
snap-final/           after everything was removed
drift-<tag>.diff      pass 2 vs pass 3 — MUST be empty
residue.diff          baseline vs final — network sections MUST be empty
install-<tag>-N.log   the installer's own output, per run
result.tsv            one machine-readable line: distro, kernel, pass/fail counts
```

Volatile fields — byte counters, PIDs, timestamps, nftables handles — are
stripped before comparison. A diff that is never empty is a diff nobody reads.

## Recording a result

A README matrix row is a claim about a distribution, and it needs a run behind
it. Keep the `result.tsv` line:

```
vpn55-acceptance   2026-08-30T09:12:44Z   debian   12   6.1.0-23-amd64   pass=14  fail=0  warn=2  adapters=…
```

Then, and only then, change that row from 🚧 to ✅.
