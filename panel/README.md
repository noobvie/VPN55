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

The other files in that directory are the panel's own — the administrator
records, the audit log, the enforcement state, the portal access codes, the
settings-screen overlay and what the alerter has already announced. None of them
is a second opinion about the host: they are things this process decided, which
is why it is allowed to hold them.

---

## Layout

```
server.js              Express app; routes, CSP, the shell page
lib/
  config.js            /etc/vpn55/panel.conf → typed, validated, frozen
  status-read.js       the ONE privileged READ  (vpn55.sh --status)
  privileged.js        the ONLY caller of the root helper — the write path
  privileged-path.js   can we rewrite what we ask root to run? asked about both
  auth.js              sessions, scrypt, the (username, IP) lockout, TOTP
  admins.js            the administrator file — ONE reader, ONE writer
  totp.js              RFC 6238, on node:crypto. SHA-1/6/30 and nothing else
  audit.js             the panel's half of the audit trail
  routes-admin.js      sign-in + every write route
  settings.js          the settings screen's half that touches disk
  alerts.js            five conditions, three layers against a storm
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
  css/brand.css                the footer signature + flag; shared with the portal
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
- `trust_proxy` is **on by default and refused unless `bind` is loopback**, and
  the two halves are one decision. The lockout is keyed on the client IP, so on a
  reachable bind a caller who can set the header has an endless supply of
  identities — *and* can aim a lockout at the operator by sending the operator's
  address. But `trust_proxy=0` behind the shipped loopback vhost is not the
  cautious setting it looks like: every request then arrives from `127.0.0.1`,
  the whole internet shares one bucket, and five wrong passwords lock the
  operator out of their own panel. `config.js` refuses both combinations rather
  than warning about either.
- The client address comes from **`X-Real-IP`, or the LAST `X-Forwarded-For`
  hop — never the first.** nginx *appends* to `X-Forwarded-For`, so the first hop
  is the caller's own claim; `proxy_set_header X-Real-IP` overwrites, so that one
  cannot be forged. A rate limiter keyed on caller-controlled input is not a rate
  limiter, and "we only read the header when trust_proxy is on" does not fix it
  if the part being read is the part the caller wrote.

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

## The second factor

TOTP — SHA-1, six digits, thirty seconds, which is the one shape every
authenticator application actually implements. `lib/totp.js` computes it on
`node:crypto` and there is no dependency and nothing tunable: an operator who
picked SHA-256 would enrol successfully, see a code on their phone, and be
unable to sign in, with both sides certain they were right.

```bash
node /usr/local/lib/vpn55/panel/scripts/admin.js totp nam            # enrol
node /usr/local/lib/vpn55/panel/scripts/admin.js totp --clear nam    # break glass
node /usr/local/lib/vpn55/panel/scripts/admin.js list                # who has one
```

- **It gates signing in, not each write.** Gating writes would protect the
  actions and leak the intelligence: a session opened on one factor could still
  read every user name, quota, endpoint address and traffic total on the host,
  which is most of what somebody would want it for. And a code demanded six
  times an hour teaches the reflex phishing needs — a person who enters a code
  whenever they are asked is a person who can be asked.
- **Enrolling stores nothing until a live code has been proved.** Writing the
  secret first and trusting that the scan worked is how somebody is locked out
  by a phone whose clock is wrong, an app that ignored the parameters, or a
  mistyped key — and the symptom is identical in all three.
- **The console draws a scannable QR,** using the portal's encoder rather than a
  second copy of it — that one is already checked against published values in
  CI, and a mistyped figure in a QR table produces a handsome square no phone can
  read. It names its own colours (black on white) instead of inheriting the
  terminal's, because a dark theme would otherwise invert it, and the key and the
  `otpauth://` URI are printed either way for a connection that mangles block
  characters.
- **A code is accepted once.** The verifier returns the step it matched and
  `auth.js` refuses a step already spent, so a code read off a shoulder or out of
  a phishing page is not still usable for the rest of its window. That record is
  in memory, like the sessions: persisting it would give the HTTP-facing process
  a write path into the file holding every hash, on every login, to close a gap a
  restart already bounds to ninety seconds.
- **The panel never writes `admins.json`.** Enrolling, clearing and changing a
  password are all console actions, so a stolen session can neither enrol a
  factor of its own nor remove the one that is there.
- **There are deliberately no recovery codes.** A stack of single-use secrets
  that skip the factor, stored on the same host as the hashes, is the bypass this
  was supposed to avoid — and it buys nothing, because whoever would use it is
  whoever can already run `totp --clear` at this console. Requiring root for the
  break-glass path is what stops it being a way in: root can already read the
  hashes, stop the panel, and change every credential the panel could.
- `require_totp=1` makes it policy rather than per-account. An account with no
  factor is then refused, and the panel names those accounts at start-up rather
  than leaving somebody to meet it as a refused login.

A wrong code costs the same against the same `(username, IP)` counter as a wrong
password. A *missing* code does not: the normal sign-in passes through that
branch exactly once, and counting it would spend a fifth of the operator's own
lockout budget every time they signed in.

---

## The settings screen

`panel.conf` was SSH-only. A fixed list of keys is now editable from the panel,
and the boundary is drawn by a rule rather than by taste:

> A key is exposed if the worst an authenticated administrator can do with it is
> make the panel **noisier, quieter, slower or stricter.**

Everything that can reduce authentication, change who can reach the process or
what it believes about a caller, redirect where data goes, move a path the panel
reads or writes, or cause an irreversible action on somebody's credentials stays
in the file. `lib/config.js`'s `EXPOSED` block names each one and says why —
`allow_unauthenticated`, `require_totp`, `trust_proxy`, the bind addresses, the
two privileged program paths, `state_dir`, the two revoke switches, and where
alerts are sent.

**How a write reaches a root-owned file: it does not.** `/etc/vpn55/panel.conf`
stays root-owned and read-only from this process, and `vpnctl` gains no verb.
Changes go to `<state_dir>/settings.json` — the directory the panel already owns
and already writes — and `config.js` merges it over the file at load, restricted
to that allowlist.

- **The overlay wins over `panel.conf`,** which is the surprising half. The
  alternative — the file wins, the overlay fills gaps — is unusable, because
  `panel.conf.example` ships almost every key set explicitly and most controls on
  the screen would silently do nothing. So the screen says per key when it is
  overriding the file, shows what the file says, and gives every overridden key a
  control that puts it back.
- **Every change takes effect at once.** The panel cannot restart itself —
  `service-restart` takes an adapter tag and the panel is not an adapter — so a
  settings screen whose changes needed a restart would be a settings screen that
  needs SSH. Each owning module has a setter and holds the live value; `cfg`
  stays frozen and stays the record of what was *loaded*.
- **A bad overlay is ignored, never fatal.** An out-of-range value, an unknown
  key, unreadable JSON: dropped with a warning, `panel.conf` in effect. And if a
  merged configuration is somehow unloadable, `load()` retries once without the
  overlay. A panel that refused to start over the file whose purpose was to save
  an SSH session would be the worst failure that feature could have.

---

## Alerting

Nothing here notified anyone of anything. `lib/alerts.js` sends five conditions
to one webhook — `alert_enabled` plus a URL, both off by default, because this is
an outbound connection from a host whose whole design is that it does not make
any.

| | |
|---|---|
| `status.unreadable` | the status read has failed N times running |
| `enforce.still_connected` | disabled accounts still hold working credentials |
| `enforce.quota_skipped` | accounts with a quota have no usage reading |
| `enforce.baselines_reset` | a lifetime total went **backwards** |
| `auth.locked_out` | a sign-in lockout tripped |

**No names are sent** — not a user's, not an administrator's, not an address. A
message is a type and a count. The webhook URL is the least trusted place
anything about this host ends up, and the audit log has the whole record one SSH
session away.

Format `json` posts `{source, host, type, state, severity, at, data}`. Format
`telegram` posts what the Bot API accepts, because a generic body cannot be one;
its text is rendered from the catalogs in `default_locale`, so an alert is
translated like every other string in the project rather than being the one
English sentence in it.

Three layers stop a flapping service turning the channel into something nobody
reads:

1. **A transition is announced, never a state.** Still true an hour later is not
   news.
2. **Confirmations** — N readings in a row must agree, in *both* directions, so
   one good poll in the middle of an outage does not send a spurious all-clear
   either.
3. **A cooldown** per condition, with a ceiling per hour underneath it, because a
   bug in either of the first two is a bug that sends messages. A *resolve* is
   never held back by the cooldown its own firing message started — an alert that
   fires and never says it is over fills a channel with conditions nobody can
   tell are stale.

⚠ Whether a condition is a **level** or an **edge** decides whether it can ever
be sent, and it is not obvious from the name. `baselines_reset` reads like a
level and is an edge: one run re-takes the baseline and the next finds nothing to
re-take, so as a level it would need two consecutive runs to agree and would be
silent for exactly the event it was written for. `quota_skipped` reads like an
edge and is a level: an account with no usage reading still has none an hour
later.

The wiring lives in `server.js`, not in the collector or the enforcer. Those two
keep knowing only about counters and quotas; the decision about what is worth
telling somebody sits in one file beside the logic that stops it becoming noise.
⚠ An enforcement run that could not read the host is skipped there rather than
resolving anything — its counters are all zero, and zero means "did not look",
not "nothing to report".

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
