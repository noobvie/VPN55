# Tests

Two kinds of thing live here, and they answer different questions.

| | Needs | Answers |
|---|---|---|
| `vps-acceptance.sh` | a throwaway VPS, root | does this work on a host |
| `vpnctl-ownership.sh` | nothing — any machine | can one user revoke another's credential |
| `awg-params.sh` | nothing — any machine | are the obfuscation parameters within every bound, and drawn rather than nudged |
| `signature-verify.sh` | nothing — openssl | does signature verification actually verify, and does it fail closed |

```bash
./tests/vpnctl-ownership.sh          # anywhere, changes nothing, ~1 second
./tests/awg-params.sh                # ~2s on Linux; AWG_TEST_RUNS=n to change the sample
./tests/signature-verify.sh          # ~2s, mints its own throwaway keys
```

The three unit tests share a shape worth keeping: each **lifts the real function
out of the shipped file and evaluates it**, rather than re-typing the logic. A
test that re-states what it checks keeps passing on the day the real thing is
deleted.

They also share a reason for existing, which is not "coverage". Each covers
something whose failure is **silent**:

- `awg-params.sh` — a wrong obfuscation parameter does not degrade the tunnel and
  does not log. The handshake is simply never recognised, at both ends, and it
  looks exactly like a firewall problem. No VPS run would catch an off-by-one
  here; it would look like the server not working. Its third section is a
  regression test for a loop that had no iteration bound: fed a randomness source
  that has gone constant, `_awg_generate` used to spin forever inside an install
  with nothing to time out.
- `signature-verify.sh` — hand-rolled signature plumbing does not fail by
  rejecting good signatures (that is noticed on the first release). It fails by
  **returning success without having checked**. So one of its twenty-one
  assertions is a good signature verifying and the other twenty are refusals:
  a modified payload, another key, a rewritten trusted comment, a truncated
  file, an unknown algorithm, an empty public key.

The second is a unit test of `helper/vpnctl`'s `cred-revoke` ownership
assertion. It lifts the verb out of the shipped file and runs it against
stubbed collaborators, so it is testing the real function rather than a
description of it. It exists because that assertion is the only thing standing
between the self-serve portal's rotation and somebody else's credential, and
because the first version of it failed open on a bare `user=` — a bug no
amount of running the installer on a VPS would have found.

Run it before touching `verb_cred_revoke`, and after.

The rest of this file is about the other one.

---

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
| **Effect** | installing changed nothing — the snapshot after pass 1 is identical to the baseline |
| **Liveness** | after a successful install the adapter does not report `running`, or nothing is listening on the port it advertises |
| **Idempotency** | installing three times leaves the host in a different state on pass 3 than on pass 2 |
| **Uninstall** | a service cannot be removed |
| **Reversal** | firewall, routing, sysctl, interface, address, **listener** or systemd-unit state differs from the baseline afterwards |
| **Reachability** | the default route disappears, or the port this SSH session arrived on stops listening |
| **Distribution** | `vpn55.sh`, `lib/` or `helper/` acquires a reference to the project website |
| **Persistence** | a live firewall rule is not written anywhere that survives a reboot |
| **Backup / restore** | the archive is missing the CA key or an adapter's own state, a restore does not reproduce the host, or the **restored authority cannot sign** |

Warnings — reported, never fatal: no outbound TCP, DNS not resolving, packages
left installed, files left under `/etc/vpn55`. So a green run is **not** a claim
that the disk is byte-for-byte as it was found; it is a claim that no *network*
state was left behind.

### Why **Effect** and **Liveness** are separate rows

They exist because without them this harness could pass on a host where the
tunnel never came up, and that is not a subtle failure mode — it is the default
one. Idempotency compares pass 2 with pass 3 and reversal compares the baseline
with the final state. **Both are satisfied by nothing having happened.** An
install that returned 0 without starting a daemon leaves passes 2 and 3
identical to each other and the host identical to its baseline, so every other
check goes green.

The only thing between that and a false ✅ used to be the installer's exit code
— which is the code under test. A harness whose central guarantee is inherited
from the thing it is testing is not evidence, so the two assertions are made
here and independently: **Effect** says the host changed at all, **Liveness**
reads the same `--status` stream the panel reads and requires `running` plus an
open port. Neither proves traffic flows; see *What it does not check*.

## What it does **not** check

**It never reboots.** `persistence` decides the question a reboot would answer —
whether what is live has been written down — without ending the run. Unit
*ordering*, as opposed to unit existence, still needs a real reboot.

**The backup stage does not move the adapters' own directories aside.** Those
carry the running tunnels and the harness may not drop the session it is running
over, so the live restore round-trip covers the certificate authority, the
register and the leases. That an adapter's state reached the archive at all is
proved the weaker way, by reading the archive's manifest.

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
changed-<tag>.diff    baseline vs pass 1 — MUST NOT be empty
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
