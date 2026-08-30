Review the Node panel and its UI — `panel/` — for the file(s) in $ARGUMENTS, or the
changed panel files if none given.

The panel is a separate trust domain from the bash side: it runs unprivileged, on its
own port, its own systemd unit and its own nginx vhost, and it reaches root through
exactly one narrow helper.

## 1. Trust boundary

- `panel/lib/privileged.js` is the only caller of `helper/vpnctl`. Any other
  `child_process`, `exec`, or shell string is a finding.
- Every request that reaches a privileged verb is authenticated **and** authorised —
  admin routes and `portal/` routes are separate surfaces with separate sessions. A
  self-serve portal user must not reach an admin verb by URL.
- `panel/lib/auth.js`: session cookie is `HttpOnly`, `Secure`, `SameSite`; sessions
  are revocable server-side; login failures are rate-limited per (user, IP) and log
  a canonical audit action.
- Input validated server-side even where the UI validates it. A protocol name never
  arrives from the client — the client sends an adapter **tag**, and an unknown tag
  is rejected, not passed through.

## 2. No protocol branches

`grep -niE '\b(wireguard|openvpn|strongswan|swanctl|ipsec|ikev2|mobileconfig)\b'`
over `panel/` should return nothing but comments and locale keys. The panel renders
whatever `_status`, `_capabilities` and `_artifacts` return; if a screen needs to
know the protocol to look right, the missing information belongs in the contract
(usually a `note` or an `option` record).

## 3. Rendering the contract honestly

- `-` renders as "no reading" / an em-dash, never as `0` or `0 B`.
- `handshake 0` renders as "never used"; `-` renders as "unknown".
- Declared revoke latency is shown **before** the operator confirms a revoke, and a
  `crl` revoke does not draw a UI that implies the credential is dead instantly.
- Custody disclosure appears on the credential-issue screen itself, not in a help
  page.
- `qr 0` hides the QR affordance rather than rendering an unscannable one.
- An unknown record type is skipped silently; an unknown *field* does not crash a row.

## 4. Front-end

- Escape everything interpolated into HTML — usernames and endpoints are attacker-
  influenced. No `innerHTML` with a server value; no `dangerouslySetInnerHTML`.
- CSP with no `unsafe-inline`; no CDN dependency the target market cannot reach.
- Every string through `t('key')` — see `/i18n`. No English string literal in a
  template.
- Lay out against **French** (15–25% longer) and verify Vietnamese stacked diacritics
  (ế, ộ, ữ) render in the shipped font stack — programmatically, not by eye.
- Tables of credentials: no horizontal body scroll on a phone; the address and
  handshake columns are what people actually read.

## 5. State

- No panel-side copy of credential state that can drift from the adapters. Cached
  values carry the poll timestamp and the UI shows staleness.
- `panel/data/` and `panel/sessions/` are gitignored runtime state — nothing in the
  tree.

Report by category with `file:line`. Flag anything that would need a live VPS to
confirm as exactly that, rather than asserting it works.
