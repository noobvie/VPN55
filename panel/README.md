# VPN55 admin panel — Phase 6

A Node/Express service with its own systemd unit, its own port, its own nginx
vhost and its own service user. It shares a process with nothing public-facing.

Phase 5 shipped it read-only. Phase 6 added sign-in and the write actions, and
kept every read exactly as it was.

## What it can do to this host, in full

Two programs, two sudo rules, and nothing else:

| | Program | The rule pins | Why |
|---|---|---|---|
| read | `vpn55.sh --status` | **the argument** | The same file with no argument is the interactive installer, which is unrestricted root. |
| write | `helper/vpnctl` | the path only | The helper takes seven verbs and refuses everything else; sudoers cannot express an argument pattern anyway. |

Eight verbs are the whole privileged surface, and seven of them change the host:

```
WRITE   user-add   user-remove   user-enable   user-disable
        cred-add   cred-revoke   service-restart
READ    cred-config
```

**Seven is the number that matters** — it is what a panel compromise costs, and
it has not moved since Phase 0. `cred-config` arrived in Phase 8 and reads one
credential's own configuration back so the self-serve portal can hand somebody
their own file. It is the narrowest verb here: it takes the user *and* the
credential, and the register decides whether that person holds it. Every other
verb trusts this panel to have worked out who may ask. `docs/security-model.md`
§6F, and `panel/portal/README.md`.

No verb accepts a command, a path or a shell fragment. Every argument is
validated **inside** the helper, which never trusts this panel — the checks in
`lib/privileged.js` are for better error messages and are explicitly not the
control. `docs/security-model.md` §3 and §6E.

Only `lib/status-read.js` and `lib/privileged.js` may start a process at all, and
CI fails the build if a third module acquires the ability.

---

## The one idea everything else follows from

**The panel is not the source of truth. On-disk server configuration is.**

Every view is built from the adapters' own `_status` output, read fresh on each
poll. The panel keeps no copy of the user list, no cache of service state, and no
second opinion about what is running. There is exactly one thing it stores, and
only because no adapter can answer it:

> **Accumulated traffic totals.** All three protocols reset their counters — one
> when its interface goes down, one per connection, one per security-association
> rekey. A raw counter shown as "total usage" therefore goes *down*, which is
> something a usage total must never do.

That state lives in `/var/lib/vpn55/panel/state.json` and is **durable state, not
a cache**. Losing it sets every user's lifetime usage to zero and nothing on the
host can rebuild it. It belongs in the backup.

---

## Layout

```
server.js              Express app; routes, CSP, the shell page
lib/
  config.js            /etc/vpn55/panel.conf → typed, validated, frozen
  status-read.js       the ONE privileged READ  (vpn55.sh --status)
  privileged.js        the ONLY caller of the root helper — the write path
  privileged-path.js   can we rewrite what we ask root to run? asked about both
  auth.js              sessions, scrypt, the (username, IP) lockout
  audit.js             the panel's half of the audit trail
  routes-admin.js      sign-in + every write route
  enforcement.js       the periodic quota / expiry job
  records.js           the TSV status stream → a structure
  collector.js         polls and ACCUMULATES  ← the centrepiece
  store.js             atomic durable JSON
  view.js              the JSON the browser renders
  i18n.js              catalogs, negotiation, fallback
  log.js               leveled logging to journald
  rate-limit.js        vendored from Office Tools — see ATTRIBUTIONS.md
scripts/
  admin.js             administrator accounts; console-only, never over HTTP
  portal.js            portal access codes: issue, list, withdraw, link
  portal-selftest.js   Phase 8's acceptance criteria, run rather than asserted
portal/                THE SELF-SERVE SURFACE — a second express app on a second
                       socket, with its own auth model. Not this panel with a
                       role check; see portal/README.md
locales/
  vi.json en.json fr.json      keyed catalogs; CI enforces key parity
public/
  css/vendor/office-tools.css  PINNED copy of the tools theme — never edited
  css/panel.css                our layer, loaded second, wins by cascade
  js/theme.js                  PINNED four-theme switcher
  js/i18n.js js/format.js
  js/actions.js                session, CSRF, confirm-then-call
  js/app.js                    the views
```

---

## Sign-in

Sessions live **in memory**, so a restart signs everyone out. A token written to
disk survives a compromise, survives a backup, and outlives the process that
could have expired it.

- An **absolute** lifetime as well as an idle timeout, and the absolute one is
  capped at 24h in code that configuration cannot raise. A bearer token cannot be
  withdrawn from the client's side.
- The **idle clock counts interaction, never traffic.** The page polls every 15s;
  if a poll refreshed the clock, an unattended tab would hold a session open
  forever. Only writes and a gesture-driven heartbeat touch it.
- Failure lockout is keyed on **(username, IP)** — the pair. On the username
  alone, anyone could lock an administrator out of their own panel from anywhere;
  on the IP alone, a shared NAT locks out colleagues. A second plain per-IP
  limiter covers the gap the pair leaves: one address spraying many usernames
  would otherwise never trip it.
- Writes carry a **CSRF token in a header**, not only the cookie. A cross-origin
  page can cause a cookie to be sent; it cannot read a response body or set a
  custom header.
- `trust_proxy` is **off by default**, and that default is load-bearing: the
  lockout is keyed on the client IP, so a caller who can set `X-Forwarded-For`
  freely has an endless supply of identities.

Accounts are created at the console, as root, and never over HTTP:

```bash
node /usr/local/lib/vpn55/panel/scripts/admin.js add nam
node /usr/local/lib/vpn55/panel/scripts/admin.js list
node /usr/local/lib/vpn55/panel/scripts/admin.js passwd nam
```

The password is read with echo off and never appears in argv — `/proc/<pid>/cmdline`
is world-readable for the life of a process. The panel **refuses to start** when
sign-in is on and no account exists: a password prompt nobody can satisfy is
indistinguishable, from the operator's side, from a forgotten password.

---

## Two audit logs, and neither is a backup of the other

| | Written by | Survives a panel compromise |
|---|---|---|
| `/var/lib/vpn55/panel/audit.log` | the panel | **No** — anything that can write it can rewrite it |
| `/var/log/vpn55/vpnctl.log` | root, inside the helper | **Yes** |

The panel's is rich and records what the panel *believes* happened. The helper's
is narrower and is the one that still means something afterwards. Every write is
logged, **including the refusals** — a refused revocation is the record that
matters, because a successful one looks the same whoever asked for it.

---

## Disabling a user does not end their tunnel

This is the sharpest edge in the whole phase, so it is stated everywhere it can be.

`user-disable` sets a policy flag. It stops new credentials being issued and is
what the panel and the portal gate on. It does **not** end a session already up,
and it cannot: none of the three services can suspend a credential and later
restore it — revocation is the only lever and it is one-way, because the client
key is gone after the hand-off window.

So the helper counts the credentials still carrying traffic, the API returns that
count, and the panel says *"disabled, and N devices are still connected"*. A bare
success would be the same class of untruth as a revocation reported before it has
taken effect.

The quota and expiry job (`lib/enforcement.js`) inherits the same limit, and
**revocation is off by default** — a job that revoked on a monthly quota would
burn every user's configuration every month. `enforce_quota_revoke` and
`enforce_expiry_revoke` turn it on deliberately.

---

## Four things that are easy to get wrong here

### 1. `-` is not zero, and it is not a reset

An adapter emits `-` when it has **no reading**: the service is stopped, the
credential is not connected, the daemon could not be asked. Coercing that to `0`
makes `new < last` true and adds a phantom session to the durable total, so a
user's usage climbs every time their tunnel is merely idle.

`null` survives the whole journey — `records.js` → `collector.js` (which skips
the sample and leaves `last` untouched) → `view.js` → an em dash on screen, with
a tooltip saying what absent means. It is never rendered as an empty cell, which
reads as a design choice, or as a zero, which is a claim.

### 2. A handshake has three states, not two

`0` means **never**. `-` means **unknown** — the daemon keeps no history and
cannot assert "never". Collapsing them tells an operator that someone who
connected yesterday never has, and that is the kind of wrong that gets a person's
access removed.

### 3. `last` must be persisted, not just the total

Keeping `last` only in memory makes every panel restart look like a first
reading, which re-adds the whole live counter. A service that has moved a
terabyte since boot would gain a terabyte per restart. Both numbers are stored,
and the pipeline test covers exactly this case.

The algorithm **under-reports** a reset that climbs past its old value between
two polls — that traffic is unrecoverable, and nothing on the host records enough
to find it. It never over-reports, which is the right direction for a number a
quota may be enforced on. Stated here so nobody later "fixes" it by guessing.

### 4. Nothing here knows which protocol it is talking to

No file in `panel/` names a protocol, branches on one, or carries an icon keyed
to one. It renders whatever the adapters declare: tags, labels, states, filtering
levels. A fourth protocol needs no change to this directory, and CI greps for the
vocabulary to keep it that way.

That constraint is why the `filtering` capability record exists. A panel that has
to warn which services survive a filtered network cannot work that out for itself
without learning which protocol it holds — so the adapter says. The **level** is
a stable word the UI translates; the **sentence** is the adapter's own and is
shown verbatim, marked as coming from the service. It is the only text on the
page that stays in the language the service wrote it in, and the UI says so
rather than leaving one line looking like a failed translation.

---

## Every string comes from a catalog

Vietnamese default, English fallback and key-authoring source, French third.
There is no English sentence in the HTML, in `app.js`, or in an event record —
events store a **type plus structured data**, so an event recorded a month ago
renders today in whatever language the reader has chosen.

A missing key returns the key **visibly** and logs once. A blank would read as a
design decision and would never get reported.

```bash
node .github/scripts/check-locales.mjs     # key parity across the three files
```

The catalog for the negotiated locale is inlined into the shell page, so the
first paint is already in the viewer's language rather than a flash of key names.

Numbers and dates are **not** formatted server-side. They leave as integers and
Unix epochs and are formatted by `Intl` in the browser, which is the only place
the viewer's locale and time zone are actually known. Pluralisation and relative
times go through `Intl.RelativeTimeFormat` — never `n + 's'`, which is wrong in
two of our three languages and unfixable from a translation file.

---

## Running it

```bash
# Settings
install -o root -g vpn55-panel -m 0640 deploy/panel.conf.example /etc/vpn55/panel.conf

# The unit
install -o root -g root -m 0644 deploy/vpn55-panel.service /etc/systemd/system/
systemctl daemon-reload && systemctl enable --now vpn55-panel

# The sudo rule — read deploy/sudoers.d/vpn55-panel first; the pinned
# ARGUMENT is the control, and a path-only rule grants the interactive installer
install -o root -g root -m 0440 deploy/sudoers.d/vpn55-panel /etc/sudoers.d/
visudo -c -f /etc/sudoers.d/vpn55-panel

journalctl -u vpn55-panel -f
```

First administrator, before starting it:

```bash
node /usr/local/lib/vpn55/panel/scripts/admin.js add <name>
chown vpn55-panel:vpn55-panel /var/lib/vpn55/panel/admins.json
```

Health, with no auth and no data in it — for a monitor, not for a person:

```bash
curl -s http://127.0.0.1:8055/healthz
```

It is on the ADMIN listener only. Answering with no authentication at all is
right for a monitor on a private address and wrong for a socket the internet can
reach, so the portal has no equivalent.

The portal, if this deployment has self-serve users:

```bash
# Its own vhost, on the PUBLIC address — read the file first; it is the one
# part of VPN55 deliberately exposed, and it explains why that is safe.
install -o root -g root -m 0644 deploy/nginx/vpn55-portal.conf \
        /etc/nginx/sites-available/vpn55-portal.conf

# Somebody's first access code. It is shown once.
node /usr/local/lib/vpn55/panel/scripts/portal.js link nam --url https://vpn.example/
```

---

## Two failures that report themselves as something else

**`sudo: effective uid is not 0, is /usr/bin/sudo on a file system with the
'nosuid' option set…`** — almost certainly not a filesystem problem. A dozen
common systemd hardening options force `NoNewPrivileges=yes`, which stops setuid
sudo working. Check it:

```bash
systemctl show -p NoNewPrivileges vpn55-panel     # must print "no"
```

The shipped unit omits those options and lists them; do not add one back without
reading the comment there.

**The panel refuses to start, naming a bind address.** It checks the address is
actually assigned to an interface here, because a tunnel that has not come up yet
would otherwise produce a bare `EADDRNOTAVAIL` a moment later. The unit restarts
every 10s and it will come up on its own once the tunnel does.
