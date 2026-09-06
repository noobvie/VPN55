# The self-serve portal — Phase 8

Core for VPN55: **the people using it are not the people running it.** This is the
surface most users actually see, and it is Vietnamese first.

A user can see their own usage and expiry, download their own configuration for any
protocol, show a QR for a phone, and replace their own credential. Nothing else.

---

## It is a second application, not a role check

```
panel   express app #1  →  bind:port                 /api/admin/*   the operator
portal  express app #2  →  portal_bind:portal_port   /api/portal/*  the user
```

Two `express()` instances and two `listen()` calls, in one process. The admin router
is attached to exactly one of them.

That is the whole of this phase's first acceptance criterion, and it is worth being
precise about why it is stated this way. "A portal token cannot reach an admin route"
is not a rule enforced by a guard that could be got wrong, or a flag that could be set
wrong. **On the portal's socket there is no admin route to reach** — no handler is
registered at that path, so there is nothing for a forged session, a stolen cookie or
a header anyone can set to unlock.

Underneath it there are two further separations, neither of which is load-bearing on
its own:

- **A different session map.** `auth.js` here has its own `Map` in its own class and
  never imports `panel/lib/auth.js`. A portal session id presented as an admin session
  id resolves to nothing, because it is not a key in that map and cannot become one.
- **A different cookie name.** `vpn55_portal` against `vpn55_sid`, so an operator who
  is also a user does not sign out of one by using the other.

`panel/scripts/portal-selftest.js` runs all three claims, plus the ownership rules
below, on every push. It needs no `node_modules` and starts nothing.

---

## The layout

```
tokens.js          access codes: issue, verify, withdraw. Stores a SHA-256, never a code
auth.js            portal sessions — its own map, its own cookie, its own CSRF header
logic.js           PURE. Every ownership decision, so the self-test can drive it directly
routes.js          the seven routes, and nothing else on this socket
shell.js           the HTML page, and the named list of assets it may have
public/css/portal.css   its own layer; it does NOT load the admin panel's
public/js/qr.js         a QR encoder — no CDN, because this page shows private keys
public/js/portal.js     the page
```

`panel/scripts/portal.js` is the console side: issue, list, withdraw, and `link`,
which prints a whole URL an operator can send.

---

## Nobody can name anybody else

**The portal never accepts a user identifier from the request.** There is no route
with a user name in its path, no query parameter that carries one, and no body field
that does. The user always comes from the session; an id from the URL is only ever
used to *select* from what that user already owns.

So changing an id in a URL cannot widen what comes back. The worst it can do is select
nothing — and `resolveOwnCredential()` returns the same `null` for a credential that
belongs to somebody else, one that was revoked, and one that never existed. All three
become the same 404 with the same body. A 403 for the second case would be more
informative, and that is exactly the objection: it would confirm the id is real, which
is most of what changing a number in a URL is for.

**That check happens twice, and this one is not the control.** `helper/vpnctl`'s
`cred-config` verb takes the user *and* the credential and re-derives ownership from
the register, as root, before it produces a single byte. Its `cred-revoke` verb does
the same when the caller passes `user=`, which the portal always does — the admin
panel does not, because revoking on somebody else's behalf is what an operator is
for. If every line of `logic.js` were wrong, a user still could not read or revoke
another user's credential.

That was a claim before it was a fact. Until 2026-08-31 `cred-revoke` took an id and
revoked it, so the destructive half of a rotation had exactly one ownership check —
this file's — while this paragraph said otherwise. The lesson is narrower than "add
a check": a defence-in-depth claim written about one verb quietly generalises to
every verb the reader is looking at. Say which verb.

---

## Access codes

An operator issues one; the user pastes it, or follows a link that carries it.

```bash
node /usr/local/lib/vpn55/panel/scripts/portal.js issue nam --label "phone"
node /usr/local/lib/vpn55/panel/scripts/portal.js link  nam --url https://vpn.example/
node /usr/local/lib/vpn55/panel/scripts/portal.js list
node /usr/local/lib/vpn55/panel/scripts/portal.js revoke <id>
```

- **256 bits from `crypto.randomBytes`, shown once.** Only its SHA-256 reaches disk.
  Nothing on the host can print it again; a lost code is re-issued, not recovered.
- **SHA-256, not scrypt** — the opposite of what `lib/auth.js` does with an admin
  password, and deliberately. scrypt is slow because a password has ~40 bits of
  entropy and an offline attacker gets unlimited guesses. This has no dictionary and
  no offline attack worth mounting, so a slow hash would buy nothing and cost ~100 ms
  of CPU on every portal request.
- **The link carries the code in the FRAGMENT** (`…/#code=…`). A browser never
  transmits a fragment, so it stays out of the web server's access log and out of the
  `Referer` header of whatever the person clicks next. The page posts it in a body and
  then removes it from the address bar. `link` refuses a non-HTTPS URL.
- **Withdrawing a code ends its sessions at the next request**, because the resolver
  re-checks the code every time. Unlike a tunnel, this one *can* be ended, so it is.
- `portal-tokens.json` is **durable state, not a cache.** Losing it locks every user
  out until each is issued a fresh code. It belongs in the same backup as the traffic
  totals.

---

## Four things that are easy to get wrong here

### 1. `configAvailable` has three values, and each gets a different control

The adapters shred a spooled private key some hours after issue — that is the hand-off
window in `docs/security-model.md` §6.1, not a bug. So:

| | Meaning | What the page does |
|---|---|---|
| `true` | there is a file to hand over | offers **Get configuration** |
| `false` | the key was erased on schedule | says so, and offers **Replace** |
| `null` | the service did not answer | offers the download anyway |

`null` is not `false`. Telling somebody their working credential is beyond recovery on
the strength of a missing field is the more expensive wrong answer, so a missing
reading gets the optimistic control and an honest failure if it is wrong.

This is why `vpn55.sh --status` grew a `credmeta` record: it is the adapters'
`_cred_list` — the credential inventory — as distinct from `cred`, which is what the
daemon is carrying right now.

### 2. Rotation issues before it revokes

`cred-add` first, then `cred-revoke`. The other order strands somebody with no access
and no way to get any, from a phone, on a network they have just lost.

This way the worst case is **two working credentials**, and the response says
`revoked: false` and the page says the old one still works. That is a state an
operator needs to know about, and reporting it as a clean success would be the same
class of untruth as a revocation reported before it has taken effect.

### 3. The QR is only offered where a camera will actually resolve it

Two gates, and both matter. The adapter says `qr: 1` or `qr: 0` about its own file —
a several-kilobyte certificate bundle is not scannable and says so. Then the encoder
returns `null` if the bytes do not fit in version 20 at error level M, and the page
says the file is too large rather than drawing a square nobody can read.

`qr.js` is written rather than loaded from a CDN because the portal's CSP is
`script-src 'self'`, and it is that way on purpose: this page shows people private
keys. Its tables are checked against published values in the self-test — the first run
of that check found a clobbered timing pattern and a mirrored format strip, both of
which draw a perfectly plausible square that no reader will touch.

### 4. It carries its own `--font` overrides

The portal does **not** load `panel.css`. Two of the four vendored theme font stacks
lack Latin Extended Additional, where Vietnamese stacked diacritics live, so a browser
substitutes per character and a word renders half in one face and half in another —
which reads as a fault on the reader's machine.

`panel.css` fixes that for the console. `portal.css` carries the same four overrides
itself rather than depending on a stylesheet it does not use, because the alternative
is being one forgotten `<link>` away from that failure on the surface where it matters
most. `.github/scripts/check-fonts.mjs` checks this file too.

---

## Turning it off

```
portal_enabled=0
```

For a pure self-host deployment where the operator is the only user. It is **on** by
default and inert until somebody is issued a code — with none, every request is one
401 — so leaving it on costs nothing until an operator decides to hand out access.

Full reasoning, including the cost of the two halves sharing one process:
`docs/security-model.md` §6F.
