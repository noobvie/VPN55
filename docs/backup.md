# Backup and restore

VPN55 holds four things that cannot be regenerated and are not stored anywhere
else on earth. Losing the host loses all four at once:

  - the certificate authority's private key — every OpenVPN and IKEv2
    credential on the fleet is signed by it, and a replacement CA invalidates
    every one of them,
  - the WireGuard server private key and its peer table — WireGuard has no CA,
    so this file *is* its authority; a new key means every client config ever
    handed out stops working,
  - the OpenVPN `tls-crypt` key — a shared control-channel key baked into every
    issued `.ovpn`,
  - the user register, the address leases and the panel's administrator
    hashes — the answer to "who is this" and "what were they allowed".

Until this document was written there was no backup of any of it. The uninstall
screen said so out loud (`lib/ui_screens.sh`, "there is no backup and no way to
reissue them"), which was honest and is not a plan.

This is the smallest thing that is actually honest. It is deliberately not a
disaster-recovery product.

**Implemented in** `lib/core_backup.sh`, with three adapter contributions
(`vpn_<tag>_backup_paths`), two CLI verbs in `lib/cli.sh`, and a stage in
`tests/vps-acceptance.sh`. §7 lists the six places where building it corrected
the design — or found something else that was wrong.

## 1. What goes in

One archive, one host, one moment. Members are listed by *what they are*, not by
a directory sweep — a sweep is how a client private key nobody meant to keep
ends up preserved forever.

| Member | Why it cannot be regenerated |
|---|---|
| `/etc/vpn55/pki/ca.crt` | the trust anchor every client pins |
| `/etc/vpn55/pki/private/ca.key` | the signing key; there is no second copy |
| `/etc/vpn55/pki/index.txt`, `index.txt.attr`, `serial`, `crlnumber` | the authority's database — without it revocation cannot be reconstructed and a reissued serial can collide |
| `/etc/vpn55/pki/crl.pem` | regenerable from the database, archived so a restore is usable before the first refresh |
| `/etc/vpn55/pki/openssl.cnf` | the issuing policy in force when these certs were signed |
| `/etc/vpn55/pki/issued/*.crt` | the public half of every live credential |
| `/etc/vpn55/users/*.conf`, `*.creds` | the register: identity, quota, expiry, device cap |
| `/etc/vpn55/pools.conf`, `/etc/vpn55/leases/*` | which address each credential was pinned to; losing this hands the same address to two people |
| `/etc/vpn55/panel.conf` | the panel's settings and session secret |
| `/var/lib/vpn55/panel/admins.json` | administrator password hashes and TOTP secrets |
| `/var/lib/vpn55/panel/state.json` | accumulated traffic totals; every service resets its own counters, so restoring a host without this sets every user's lifetime usage back to zero and nothing on the machine can rebuild it |
| *whatever each adapter answers to `backup_paths`* | see below |

### The adapters name their own

`lib/core_backup.sh` contains no protocol name. `/etc/wireguard`,
`/etc/openvpn` and `/etc/swanctl` appear nowhere in it. Each adapter implements
one more contract verb, `backup_paths`, printing one absolute path per line, and
the registry is iterated the same way it is for every other question — so a
fourth protocol is still a file you drop in.

An adapter that does not implement the verb is **warned about loudly**, not
skipped quietly. "Your protocol's state is not in the backup" is not a footnote
to be discovered on restore day.

What the three in-tree adapters currently answer:

| Adapter | Paths | Why |
|---|---|---|
| WireGuard | `/etc/vpn55/wireguard/settings.conf`, `/etc/wireguard/*.conf` | **the authority for this protocol.** No CA exists; the server private key sits beside every peer's public key, and there is not even a revocation story to fall back on |
| OpenVPN | `/etc/vpn55/openvpn/settings.conf`, `/etc/vpn55/openvpn/tls-crypt.key`, `/etc/vpn55/openvpn/creds/*`, the server's key by CN | a new `tls-crypt` key fails every existing profile's handshake *before* any certificate is examined, so it presents as "the server is not answering" |
| IKEv2 | `/etc/vpn55/ipsec/settings.conf`, `/etc/vpn55/ipsec/creds/*`, the server's key by CN | `_ipsec_server_cert_ensure` **revokes** the previous server certificate when it issues a replacement, so forcing a reissue would revoke the only one clients expect |

### What must never go in

  - **Any client private key.** Client keys are shredded after hand-off on
    purpose (`core_pki.sh`, "Resend my config is therefore not a supported
    operation"). A straggler left by an interrupted issue must not be preserved
    into an archive that outlives the revocation.

    Two mechanisms, not one. The member list is explicit rather than a glob, and
    `_bak_guard` **refuses the entire backup** if any named key under
    `pki/private/` turns out to be a credential id in the user register. The
    guard exists because the list is now written in four files — this one and
    three adapters — and a mistake in any of them must fail the run rather than
    ship a key.
  - **Anything under a hand-off spool.** Refused by the same guard, by path.
    The rule is the spool rather than a list of artifact file extensions: naming
    those would put protocol vocabulary in a file that is forbidden to have any,
    and every adapter spools its artifacts anyway because the key-expiry sweep
    that erases them depends on it.
  - **`/etc/vpn55/pki/reqs/*`** — transient CSR and extension files.
  - **`/etc/vpn55/pki/refresh.d/*`** — the CRL refresh hooks are executables
    that name paths on *this* host and are recreated by each adapter's install.
  - **`/etc/vpn55/fw.state` and `/etc/vpn55/net.conf`** — carried in a
    `reference/` area of the archive and **never placed by a restore**. They
    describe rules on *that* host; replaying them onto a replacement claims
    rules it never had, and the ledger is what an uninstall trusts when deciding
    what it may remove.
  - **The backup passphrase.** See §2.

## 2. Encrypted at rest, and the passphrase is not on the host

The archive contains the CA key. It is encrypted with

    openssl enc -aes-256-cbc -md sha512 -pbkdf2 -iter 600000 -salt -pass stdin

with the passphrase piped in from a bash builtin, never in argv —
`/proc/<pid>/cmdline` is world-readable for the life of the process — and never
through a temporary file. `printf` is a builtin, so no process ever exists whose
command line is the passphrase. The archive is read from `-in` and written to
`-out`, so stdin is free and nothing has to share a pipe.

**The passphrase is never written to this host, and there is no unattended
schedule by default.** Grin Node Toolkit's engine stores its key in a mode-600
file so cron can run unattended, which is right for its threat model and wrong
for this one: the host is the thing you are protecting against losing, so a key
stored on it is not a second copy of anything. An operator who wants a schedule
opts in explicitly with `--passfile <path>`, and is told, once, that anyone who
takes the box now has both halves. `VPN55_BACKUP_PASS` in the environment is the
same trade for automation and the acceptance harness — root can read
`/proc/<pid>/environ`, so it is no better than the file and no worse.

## 3. Where it lands

    /var/backups/vpn55/vpn55-<hostname>-<YYYY-MM-DD>.tar.gz.enc

Directory `0700 root:root`, archive `0600 root:root`. A second run on the same
day replaces the first rather than accumulating: a directory that grows a file
on every run is a disk that fills silently on the host this was meant to
protect.

**The panel must not be able to read it.** The panel runs as `vpn55-panel` and
DAC already stops it, but `deploy/vpn55-panel.service` grants
`ReadWritePaths=/etc/vpn55` and its mount namespace binds the sudo'd root child
too, so the exclusion is stated in the unit rather than left to file modes:

    InaccessiblePaths=-/var/backups/vpn55

The `-` prefix is deliberate: a host that has never taken a backup has no such
directory, and a unit that refused to start over a missing backup directory
would take the panel down for the least urgent reason available.

There is no panel route, no `vpnctl` verb and no sudoers rule for backup or
restore. A panel compromise costs the seven verbs it already costs; it must not
also cost the CA key in one file.

An archive that never leaves the box protects against nothing this document is
about. `bak_push` ends the run with an `scp` to `scp_dest=` in
`/etc/vpn55/backup.conf`. That push is optional, and **its absence is reported
as an absence** — never folded into the success line, because "backup written"
printed beside a push that silently did not happen is how a fleet discovers it
has no off-host copy on the day the host is gone.

## 4. Restore

    vpn55.sh --restore <archive> [--passfile <path>] [--force]

  1. Decrypt into a `mktemp -d` at `0700` and verify the in-archive `MANIFEST`
     (VPN55 version, hostname, UTC timestamp, and per member the SHA-256, mode
     and owner) before a single file is placed. A member that fails its digest
     aborts the whole restore; a partial PKI is worse than none, because an
     `index.txt` that disagrees with the certificates it describes issues
     colliding serials forever. A path in the manifest that is absolute or
     contains `..` is refused rather than normalised.
  2. **Refuse onto a host that already has a CA with a different fingerprint**,
     unless `--force`. Silently overwriting a live authority is the same
     catastrophe running the other way.
  3. Place each file with its own recorded mode, and its recorded owner **by
     name** — a uid is meaningless on a replacement host. Where the name does
     not resolve, the file lands root-owned and the mode still protects it.
  4. Regenerate the CRL and run the refresh hooks — the archived CRL may be past
     its `nextUpdate`, and a strict verifier refuses every user on an expired
     one.
  5. Print what was NOT restored and why: the firewall ledger, `net.conf`, and
     the fact that the adapters must be re-installed to lay their rules on this
     host.

**It does not stop the daemons, and says so.** The adapter contract has
`restart` and no `stop`, and inventing one here would mean `core_backup.sh`
learning unit names — the one thing the registry exists to prevent. Restore is
for a replacement host, where nothing is running. On a live host the files land
under running daemons that read them at start-up, so nothing is corrupted, but a
service keeps serving its old view until `--install` restarts it; the closing
report says exactly that.

## 5. The acceptance harness must restore it

A backup nobody restored is not a backup. `tests/vps-acceptance.sh` gained stage
5, between the install passes and the uninstall:

  1. Create a user through `helper/vpnctl` and issue one credential per adapter.
     Record four facts: the CA SHA-256 fingerprint, `--list-users`, the issued
     certificate list with `index.txt` and `serial`, and the lease table.
  2. `vpn55.sh --backup --out <run dir>`, passphrase from
     `VPN55_ACC_BACKUP_PASS` or generated per run.
  3. Read the manifest back **out of the encrypted archive** and assert three
     things: the CA key is in it, at least one path from outside `/etc/vpn55` is
     in it, and no client artifact is.
  4. **Move** `/etc/vpn55` and `/var/lib/vpn55` aside — move, never delete, so
     the harness can put the host back if the restore fails.
  5. `vpn55.sh --restore`, then re-record the four facts and diff them.
  6. **Sign a fresh certificate with the restored CA and verify it**
     (`openssl ca` then `openssl verify -CAfile`). This is the only check that
     matters: an archive that restores files but not a usable signing key passes
     every file comparison and fails the one thing it exists for.
  7. Put the moved-aside originals back, remove the test user, and re-compare,
     so this stage honours the harness's own promise to leave the host as it was
     found.

**What the stage cannot prove.** It does not move `/etc/wireguard`,
`/etc/openvpn` or `/etc/swanctl` aside, because those carry the running tunnels
and the harness may not drop the session it is running over. So the live
round-trip covers the CA, the register and the leases; the adapter-owned paths
are covered the weaker way, by step 3. That check is real — it is what fails the
day an adapter stops answering `backup_paths` — and it is not the same as having
restored them.

## 6. Not coupled to Grin Node Toolkit

The passphrase-off-argv trick, and the "one archive per product per day, named
by the date" naming, were read from that project's `gbe_*`/`gbp_*` engine and
are good. Nothing is sourced, shared or imported. The implementation lives in
`lib/core_backup.sh`, built on this repo's own `fs_*` primitives, with VPN55's
ISO dating and version stamping. The two projects have different threat models —
see §2 — and a shared lib would have to serve both.

## 7. What building it corrected in this design

Four things, recorded here because a design document that quietly absorbs its
own corrections teaches nobody:

1. **The server private keys ARE in the archive.** The first draft said "no key
   under `pki/private` except `ca.key`". Applied literally that breaks the
   restore it promises: `_ovpn_server_cert_ensure` skips reissue when the server
   certificate is present and valid, so an archive holding the certificate but
   not its key restores a host whose daemon has a certificate it cannot use and
   whose installer sees no reason to fix it. Each adapter names exactly one key,
   by the CN it recorded for its own server certificate. The rule that mattered
   was always "no *client* key, ever", and `_bak_guard` now enforces that
   directly.

2. **`age` is not supported.** The first draft preferred it where present. Its
   passphrase mode requires a terminal for entry, so it cannot serve the
   unattended path this same document promises, and its non-interactive path is
   identity files — a different key-management story. Two key models in one
   archive format is worse than one, and "the header records which was used" is
   not a substitute for a restore path that always works.

3. **The `tls-crypt` key is not in `/etc/openvpn/server/`.** The first draft's
   table put the OpenVPN server cert, key and `tls-crypt` key there. In fact the
   cert and key are in the PKI like everything else, and the `tls-crypt` key is
   at `/etc/vpn55/openvpn/tls-crypt.key`. `/etc/openvpn/server/<name>.conf` is
   regenerated deterministically by the next `--install` and is not archived.

4. **`--unattended-key` became `--passfile`**, and applies to restore as well as
   backup. One flag, one meaning, on both verbs.

5. **`-pass fd:3` became `-pass stdin`.** fd:3 is what Grin Node Toolkit uses and
   what §2 originally specified. It is equally safe and it is not portable:
   openssl built for Windows has no `fd:` handler and answers *"Invalid password
   argument, starting with fd:"*, which turned every local test of this file into
   "encryption failed". That matters more than it looks — nothing in this
   repository has ever run on a VPS, so a channel the maintainer cannot exercise
   on their own machine is one whose first real test would be somebody's disaster
   recovery. `-pass stdin` behaves identically on Linux and is testable here.

6. **The archive stage found a bug that had nothing to do with backups.** Copying
   the house idiom `${!arr[@]+"${!arr[@]}"}` into `_bak_adapter_members` made it
   iterate nothing. The idiom is broken for array *indices* — bash reads the `!`
   as indirect expansion once an operator follows — and it was already in
   `cli_adapters` and `vpn_adapter_label`, where it meant `--adapters` printed
   nothing and every adapter label came back as its raw tag. Both are fixed;
   CLAUDE.md carries the explanation.
