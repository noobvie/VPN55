#!/usr/bin/env node
'use strict';
//
// panel/scripts/portal-selftest.js — the Phase 8 acceptance evidence, run.
//
//     node panel/scripts/portal-selftest.js
//
// Two claims were made about the self-serve portal, and a claim in a comment is
// a claim that regresses silently. This runs them:
//
//   1. A PORTAL TOKEN CANNOT REACH ANY ADMIN ROUTE.
//   2. A USER CANNOT READ ANOTHER USER'S CONFIG BY CHANGING AN id IN THE URL.
//
// It needs no root, no network, no express and no node_modules — which is what
// lets it run in CI on every push, and on a developer's machine without an
// install step. It starts nothing and leaves nothing behind: the token store is
// exercised in a temporary directory that is removed at the end.
//
// ── Why it tests modules rather than a running server ────────────────────────
//
// Because the interesting claim is structural, and a server would test it less
// well rather than more. Claim 1 is true because the admin routes are NEVER
// REGISTERED on the portal's listener — two express apps, two listen() calls —
// so the only way to demonstrate it through HTTP would be to observe a 404 and
// argue that the 404 means what we hope. Asserting on the wiring is the
// stronger statement: an admin route reachable from the portal app would be a
// change to server.js that this file's last section refuses.
//
// The rest is genuinely unit-testable, because panel/portal/logic.js was
// written to be — every ownership decision is a pure function of a snapshot, a
// user and an id.
//
// ── The QR encoder is checked here too ───────────────────────────────────────
//
// It is not about the portal's security, and it is here because it is the one
// piece of this phase that can fail by producing something that LOOKS right. A
// QR that no camera resolves is worse than no QR, so its tables are checked
// against numbers published in the specification rather than believed.

const assert = require('node:assert');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

const { PortalTokens, fingerprint, RE_TOKEN } = require('../portal/tokens');
const { PortalAuth, COOKIE: PORTAL_COOKIE, CSRF_HEADER: PORTAL_CSRF, KIND } = require('../portal/auth');
const { COOKIE: ADMIN_COOKIE, CSRF_HEADER: ADMIN_CSRF } = require('../lib/auth');
const { ownCredentials, resolveOwnCredential, accountView, normaliseArtifact } = require('../portal/logic');
const { parseStatus } = require('../lib/records');
const QR = require('../portal/public/js/qr');

let passed = 0;
const failures = [];

function check(label, fn) {
  try {
    fn();
    passed += 1;
  } catch (err) {
    failures.push(`${label}\n      ${err.message.split('\n').join('\n      ')}`);
  }
}

function section(title) {
  process.stdout.write(`\n  ${title}\n`);
}

// ─── Fixtures ────────────────────────────────────────────────────────────────
//
// A status stream with two users on two services, built through the real
// parser rather than hand-assembled — so if the record format changes, this
// fixture changes with it instead of testing a shape nothing emits.
//
// Deliberately not named after any protocol: nothing outside lib/proto_*.sh may
// know which protocol it is talking to, and that includes a test fixture.

const T = '\t';
const STATUS = [
  ['stamp', '1800000000'],
  ['adapter', 'alpha', 'Alpha service', '1'],
  ['capability', 'alpha', 'custody', 'server', 'This server made the key.'],
  ['capability', 'alpha', 'filtering', 'resistant', 'Hard to spot on a filtered network.'],
  ['service', 'alpha', 'running', '1', 'udp/51820', '1799000000', '3'],
  ['cred', 'alpha', 'cred-nam-1', 'nam', 'active', '10.8.0.2', '5000', '9000', '1799999000', '1.2.3.4', '1'],
  ['credmeta', 'alpha', 'cred-nam-1', 'nam', 'active', '10.8.0.2', '2026-08-01', 'server', '1'],
  ['credmeta', 'alpha', 'cred-nam-2', 'nam', 'active', '10.8.0.3', '2026-08-02', 'server', '0'],
  ['credmeta', 'alpha', 'cred-linh-1', 'linh', 'active', '10.8.0.4', '2026-08-03', 'server', '1'],
  ['credmeta', 'alpha', 'cred-nam-old', 'nam', 'revoked', '10.8.0.9', '2026-07-01', 'server', '0'],
  ['adapter', 'beta', 'Beta service', '1'],
  ['service', 'beta', 'running', '1', 'tcp/443', '1799000000', '1'],
  ['credmeta', 'beta', 'cred-linh-2', 'linh', 'active', '10.8.1.4', '2026-08-04', 'server', '1'],
  // An orphan: the service is carrying it, the register never heard of it. It
  // must not become claimable by whoever happens to hold that name.
  ['cred', 'beta', 'cred-ghost', 'nam', 'active', '10.8.1.9', '10', '10', '0', '-', '0'],
  ['user', 'nam', '2026-07-01', '1', '', '', '', '', '2'],
  ['user', 'linh', '2026-07-02', '1', '1000000', '2027-01-01', '2', 'monthly', '2'],
  ['user', 'disabled_one', '2026-07-03', '0', '', '', '', '', '0'],
].map((r) => r.join(T)).join('\n');

const snapshot = parseStatus(STATUS);

// A collector stand-in. Only totalsFor() and health() are reached from the
// logic under test, so those are all it has — a fuller fake would be a second
// implementation of the collector to keep in step with the first.
const collector = {
  totalsFor(tag, credId) {
    if (tag === 'alpha' && credId === 'cred-nam-1') {
      return {
        rxTotal: 500000, txTotal: 250000, resets: 1, firstSeen: 1799000000,
        lastSeen: { kind: 'at', at: 1799999000 },
      };
    }
    return null;
  },
  health() { return { lastSuccessAt: 1800000000, consecutiveFailures: 0 }; },
};

function reqWith(cookies, headers = {}) {
  const cookie = Object.entries(cookies)
    .map(([k, v]) => `${k}=${encodeURIComponent(v)}`).join('; ');
  return {
    headers: { cookie, ...headers },
    socket: { remoteAddress: '10.8.0.2' },
  };
}

// ═════════════════════════════════════════════════════════════════════════════
section('1. Parsing the fixture');

check('the fixture parses with no malformed records', () => {
  assert.deepStrictEqual(snapshot.malformed, [], 'malformed records in the fixture');
  assert.deepStrictEqual(snapshot.unknownRecords, [], 'unknown record types in the fixture');
});

check('credmeta reached the parser', () => {
  const alpha = snapshot.adapters.find((a) => a.tag === 'alpha');
  assert.strictEqual(Object.keys(alpha.credmeta).length, 4);
  assert.strictEqual(alpha.credmeta['cred-nam-1'].held, true);
  assert.strictEqual(alpha.credmeta['cred-nam-2'].held, false,
    'held=0 must be false, and it is not the same as absent');
});

check('liveness comes from `connected`, never from the endpoint', () => {
  const alpha = snapshot.adapters.find((a) => a.tag === 'alpha');
  const live = alpha.creds.find((c) => c.id === 'cred-nam-1');
  assert.strictEqual(live.connected, true);

  // The reason this field exists. On a peer-based protocol the endpoint is the
  // last address a peer was ever seen at and outlives the session for the life
  // of the interface, so presence read off it reports a device that connected
  // months ago as online. A record carrying an endpoint and connected=0 must
  // come out as NOT connected.
  const stale = parseStatus([
    ['adapter', 'alpha', 'Alpha service', '1'],
    ['service', 'alpha', 'running', '1', 'udp/51820', '1799000000', '1'],
    ['cred', 'alpha', 'c-stale', 'nam', 'active', '10.8.0.5',
     '5000', '9000', '1780000000', '1.2.3.4', '0'],
  ].map((r) => r.join(T)).join('\n'));
  const c = stale.adapters[0].creds[0];
  assert.strictEqual(c.endpoint, '1.2.3.4', 'the endpoint is still carried');
  assert.strictEqual(c.connected, false, 'an endpoint must not imply a session');

  // And an adapter that cannot tell says so as null, which is not `false`: a
  // stopped daemon has not established that nobody is connected.
  const dark = parseStatus([
    ['adapter', 'alpha', 'Alpha service', '1'],
    ['service', 'alpha', 'stopped', '1', 'udp/51820', '-', '1'],
    ['cred', 'alpha', 'c-dark', 'nam', 'active', '10.8.0.6', '-', '-', '-', '-', '-'],
  ].map((r) => r.join(T)).join('\n'));
  assert.strictEqual(dark.adapters[0].creds[0].connected, null);
});

// ═════════════════════════════════════════════════════════════════════════════
section('2. A user sees their own credentials, and only their own');

check('nam holds exactly their own two active credentials', () => {
  const ids = ownCredentials(snapshot, 'nam').map((c) => c.meta.id).sort();
  assert.deepStrictEqual(ids, ['cred-nam-1', 'cred-nam-2']);
});

check('a revoked credential is not listed', () => {
  const ids = ownCredentials(snapshot, 'nam').map((c) => c.meta.id);
  assert.ok(!ids.includes('cred-nam-old'), 'a revoked credential was listed');
});

check('an orphan the register does not know is not claimable', () => {
  // `cred-ghost` is reported by the service with user "nam" and appears in NO
  // credmeta record. If ownership were read from live daemon state rather than
  // from the register, nam would be handed it.
  assert.strictEqual(resolveOwnCredential(snapshot, 'nam', 'cred-ghost'), null);
});

check('linh holds their own two, across two services', () => {
  const ids = ownCredentials(snapshot, 'linh').map((c) => c.meta.id).sort();
  assert.deepStrictEqual(ids, ['cred-linh-1', 'cred-linh-2']);
});

// ═════════════════════════════════════════════════════════════════════════════
section('3. ACCEPTANCE — changing an id in the URL reads nothing');

check("nam cannot resolve linh's credential", () => {
  assert.strictEqual(resolveOwnCredential(snapshot, 'nam', 'cred-linh-1'), null,
    "nam resolved linh's credential");
});

check("linh cannot resolve nam's credential", () => {
  assert.strictEqual(resolveOwnCredential(snapshot, 'linh', 'cred-nam-1'), null,
    "linh resolved nam's credential");
});

check('a credential that does not exist resolves the same way as one that does not belong to you', () => {
  // Byte-identical results, so the route above them cannot accidentally answer
  // differently and confirm that an id is real. That confirmation is most of
  // what changing a number in a URL is for.
  const notMine = resolveOwnCredential(snapshot, 'nam', 'cred-linh-1');
  const notReal = resolveOwnCredential(snapshot, 'nam', 'cred-does-not-exist');
  const revoked = resolveOwnCredential(snapshot, 'nam', 'cred-nam-old');
  assert.strictEqual(notMine, null);
  assert.strictEqual(notReal, null);
  assert.strictEqual(revoked, null);
});

check('a malformed id is refused rather than passed through', () => {
  for (const bad of ['../../etc/passwd', 'a/b', '-rf', '', 'a b', 'a;id', 'a'.repeat(65)]) {
    assert.strictEqual(resolveOwnCredential(snapshot, 'nam', bad), null, `accepted ${JSON.stringify(bad)}`);
  }
});

check('a user who is not in the register owns nothing', () => {
  assert.deepStrictEqual(ownCredentials(snapshot, 'nobody'), []);
  assert.strictEqual(resolveOwnCredential(snapshot, 'nobody', 'cred-nam-1'), null);
});

check('an artifact id from a URL is shape-checked', () => {
  assert.strictEqual(normaliseArtifact(undefined), null);
  assert.strictEqual(normaliseArtifact(''), null);
  assert.strictEqual(normaliseArtifact('conf'), 'conf');
  for (const bad of ['../../x', 'Conf', 'a-b', '-x', 'a;id']) {
    assert.strictEqual(normaliseArtifact(bad), false, `accepted ${JSON.stringify(bad)}`);
  }
});

// ═════════════════════════════════════════════════════════════════════════════
section('4. The account view answers about one person only');

check("nam's view names nam and carries no other user", () => {
  const view = accountView({ snapshot, collector, user: 'nam', health: collector.health() });
  assert.strictEqual(view.user.name, 'nam');
  const blob = JSON.stringify(view);
  assert.ok(!blob.includes('linh'), 'another user appeared in the view');
  assert.ok(!blob.includes('cred-linh'), "another user's credential appeared in the view");
  assert.ok(!blob.includes('disabled_one'), 'another user appeared in the view');
});

check('an unlimited quota stays null and never becomes a zero', () => {
  const view = accountView({ snapshot, collector, user: 'nam', health: collector.health() });
  assert.strictEqual(view.user.quotaBytes, null);
  assert.strictEqual(view.user.quotaUsedFraction, null,
    'an unlimited account must have no percentage, not 0%');
  assert.strictEqual(view.user.quotaRemaining, null);
});

check('a quota that IS set produces a fraction', () => {
  const view = accountView({ snapshot, collector, user: 'linh', health: collector.health() });
  assert.strictEqual(view.user.quotaBytes, 1000000);
  assert.strictEqual(typeof view.user.quotaUsedFraction, 'number');
});

check('a deleted account resolves to null rather than to an empty page', () => {
  assert.strictEqual(
    accountView({ snapshot, collector, user: 'ghost', health: collector.health() }), null);
});

check('nothing in the view is pre-formatted', () => {
  const view = accountView({ snapshot, collector, user: 'nam', health: collector.health() });
  assert.strictEqual(typeof view.user.total, 'number', 'bytes must leave as a number');
  const cred = view.credentials.find((c) => c.id === 'cred-nam-1');
  assert.strictEqual(typeof cred.rxTotal, 'number');
  // No reading is null all the way through, and is never a zero: a zero is a
  // claim about traffic and null is the absence of one.
  const noReading = view.credentials.find((c) => c.id === 'cred-nam-2');
  assert.strictEqual(noReading.rxTotal, null);
});

check('configAvailable carries the third state', () => {
  const view = accountView({ snapshot, collector, user: 'nam', health: collector.health() });
  assert.strictEqual(view.credentials.find((c) => c.id === 'cred-nam-1').configAvailable, true);
  assert.strictEqual(view.credentials.find((c) => c.id === 'cred-nam-2').configAvailable, false);
});

// ═════════════════════════════════════════════════════════════════════════════
section('5. ACCEPTANCE — a portal token cannot reach an admin route');

const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'vpn55-portal-selftest-'));
const tokensFile = path.join(tmpDir, 'portal-tokens.json');

const cfg = Object.freeze({
  portal_session_ttl_ms: 2 * 60 * 60 * 1000,
  portal_session_idle_ms: 20 * 60 * 1000,
  portal_window_ms: 900000,
  portal_ip_max: 60,
  portal_rotate_window_ms: 3600000,
  portal_rotate_max: 3,
  portal_trust_proxy: false,
});

const audit = { entries: [], write(rec) { this.entries.push(rec); } };
const tokens = new PortalTokens({ file: tokensFile, warn() {} });
tokens.load();
const portalAuth = new PortalAuth({ config: cfg, tokens, audit, warn() {} });

const issued = tokens.issue('nam', { label: 'phone' });
const redeemed = portalAuth.redeem(reqWith({}), issued.token);

check('a code redeems for a session', () => {
  assert.strictEqual(redeemed.ok, true, JSON.stringify(redeemed));
  assert.strictEqual(redeemed.session.user, 'nam');
  assert.strictEqual(redeemed.session.kind, KIND);
});

check('the two cookie names are different', () => {
  assert.notStrictEqual(PORTAL_COOKIE, ADMIN_COOKIE,
    'the portal and the panel would share a session cookie');
});

check('the two CSRF headers are different', () => {
  assert.notStrictEqual(PORTAL_CSRF, ADMIN_CSRF);
});

check("the admin Auth class never sees the portal's session map", () => {
  // Not "the lookup fails" but "there is nothing to look in". Auth resolves
  // against its own Map, constructed in its own module; a portal session id is
  // not a key in it and cannot become one.
  const { Auth } = require('../lib/auth');
  const adminAuth = new Auth({
    config: {
      session_ttl_ms: 3600000,
      session_idle_ms: 600000,
      login_max_failures: 5,
      login_window_ms: 900000,
      login_lock_ms: 900000,
      login_ip_max: 30,
      trust_proxy: false,
      admins_file: path.join(tmpDir, 'admins.json'),
    },
    audit,
    warn() {},
  });

  // The portal cookie, under its own name: the admin side does not read it.
  assert.strictEqual(
    adminAuth.resolve(reqWith({ [PORTAL_COOKIE]: redeemed.session.sid })), null);

  // And under the ADMIN cookie name, which is the attack rather than the
  // accident: a portal session id presented as an admin session id.
  assert.strictEqual(
    adminAuth.resolve(reqWith({ [ADMIN_COOKIE]: redeemed.session.sid })), null,
    'a portal session id resolved as an admin session');

  adminAuth.stop();
});

check('an admin session id does not resolve as a portal session', () => {
  // The other direction. An operator's cookie must not silently become a portal
  // identity either — that would make "who is this" answerable two ways.
  assert.strictEqual(
    portalAuth.resolve(reqWith({ [PORTAL_COOKIE]: 'an-admin-looking-session-id' })), null);
});

check('the portal router registers no admin path', () => {
  // The structural half of claim 1, asserted against the source rather than
  // against a running server: an admin route reachable from the portal app
  // would have to appear here first.
  const src = fs.readFileSync(path.join(__dirname, '..', 'portal', 'routes.js'), 'utf8');
  const code = src
    .replace(/\/\*[\s\S]*?\*\//g, ' ')
    .replace(/(^|[^:])\/\/[^\n]*/g, '$1 ');
  for (const forbidden of ['/users', '/creds\'', '/services', '/audit', '/enforcement', '/refresh']) {
    assert.ok(!code.includes(`router.post('${forbidden}`) && !code.includes(`router.get('${forbidden}`),
      `the portal router registers ${forbidden}`);
  }
  assert.ok(!/require\(['"]\.\.\/lib\/routes-admin/.test(code),
    'the portal router imports the admin router');
  assert.ok(!/require\(['"]\.\.\/lib\/auth['"]\)/.test(code),
    'the portal router imports the admin Auth');
});

check('the portal modules never import the admin session module', () => {
  const dir = path.join(__dirname, '..', 'portal');
  for (const name of fs.readdirSync(dir)) {
    if (!name.endsWith('.js')) continue;
    const src = fs.readFileSync(path.join(dir, name), 'utf8');
    const code = src
      .replace(/\/\*[\s\S]*?\*\//g, ' ')
      .replace(/(^|[^:])\/\/[^\n]*/g, '$1 ');
    assert.ok(!/require\(['"]\.\.\/lib\/auth['"]\)/.test(code),
      `panel/portal/${name} imports the admin Auth`);
    assert.ok(!/require\(['"]\.\.\/lib\/routes-admin['"]\)/.test(code),
      `panel/portal/${name} imports the admin routes`);
  }
});

check('server.js mounts the admin routes on the admin app only', () => {
  // The claim that actually settles it: two express apps, and the admin router
  // is attached to exactly one of them.
  const src = fs.readFileSync(path.join(__dirname, '..', 'server.js'), 'utf8');
  const code = src
    .replace(/\/\*[\s\S]*?\*\//g, ' ')
    .replace(/(^|[^:])\/\/[^\n]*/g, '$1 ');
  const adminMounts = code.match(/\w+\.use\(\s*'\/api\/admin'/g) || [];
  assert.strictEqual(adminMounts.length, 1,
    `/api/admin is mounted ${adminMounts.length} times; it must be mounted once, on the admin app`);
  assert.ok(/app\.use\(\s*'\/api\/admin'/.test(code),
    '/api/admin must be mounted on `app`, the admin application');
  assert.ok(!/portalApp\.use\(\s*'\/api\/admin'/.test(code),
    'the admin routes are mounted on the portal application');
  assert.ok(!/app\.use\(\s*'\/api\/portal'/.test(code) || /portalApp\.use\(\s*'\/api\/portal'/.test(code),
    'the portal routes must be mounted on the portal application');
});

// ═════════════════════════════════════════════════════════════════════════════
section('6. Codes, and what the store keeps');

check('the plaintext code is never written to disk', () => {
  const onDisk = fs.readFileSync(tokensFile, 'utf8');
  assert.ok(!onDisk.includes(issued.token), 'the access code itself was stored');
  assert.ok(onDisk.includes(fingerprint(issued.token)), 'the fingerprint was not stored');
});

check('the code matches the shape the verifier gates on', () => {
  assert.ok(RE_TOKEN.test(issued.token));
});

check('a wrong, revoked or expired code all verify as null', () => {
  assert.strictEqual(tokens.verify('vpn55_' + 'A'.repeat(43)), null);
  assert.strictEqual(tokens.verify('not-a-code'), null);
  assert.strictEqual(tokens.verify(''), null);
  assert.strictEqual(tokens.verify(null), null);

  const other = tokens.issue('linh', {});
  assert.ok(tokens.verify(other.token), 'a fresh code should verify');
  tokens.revoke(other.record.id);
  assert.strictEqual(tokens.verify(other.token), null, 'a revoked code still verifies');

  const expired = tokens.issue('linh', { expiresInDays: 1 });
  assert.strictEqual(
    tokens.verify(expired.token, { now: Date.now() + 2 * 86400000 }), null,
    'an expired code still verifies');
});

check('an unparseable expiry fails closed', () => {
  const rec = tokens.issue('linh', { expiresInDays: 30 });
  tokens.state.tokens[fingerprint(rec.token)].expiresAt = 'not a date';
  assert.strictEqual(tokens.verify(rec.token), null,
    'a corrupted expiry must expire the code, not disable the expiry');
});

check('revoking a code ends a live session at the next request', () => {
  const rec = tokens.issue('nam', {});
  const sess = portalAuth.redeem(reqWith({}), rec.token);
  assert.strictEqual(sess.ok, true);
  const req = reqWith({ [PORTAL_COOKIE]: sess.session.sid });
  assert.ok(portalAuth.resolve(req), 'the session should resolve before revocation');
  tokens.revoke(rec.record.id);
  assert.strictEqual(portalAuth.resolve(req), null,
    'a revoked code left a live session working');
});

check('a code for an invalid user name is refused at issue', () => {
  for (const bad of ['', 'A', '../x', 'a b', 'root;id']) {
    assert.throws(() => tokens.issue(bad, {}), /invalid user name/, `accepted ${JSON.stringify(bad)}`);
  }
});

check('every failed redemption is audited', () => {
  const before = audit.entries.length;
  portalAuth.redeem(reqWith({}), 'vpn55_' + 'B'.repeat(43));
  const written = audit.entries.slice(before);
  assert.strictEqual(written.length, 1);
  assert.strictEqual(written[0].result, 'denied');
});

// ═════════════════════════════════════════════════════════════════════════════
section('7. Two processes, one token file');

// panel/scripts/portal.js is the operator CLI and it is a SEPARATE PROCESS
// over the same file as the running daemon. Every case below was broken until
// 2026-08-31: the daemon read the file once at startup, so a revoke made on the
// console never took effect, and the daemon's next write — which happens on a
// plain sign-in, because verify() records lastUsedAt — erased it from disk.
//
// A second PortalTokens on the same path IS the second process for the purpose
// of this test: the two share nothing but the file, which is the whole point.

const twoDir = fs.mkdtempSync(path.join(os.tmpdir(), 'vpn55-portal-twowriter-'));
const twoFile = path.join(twoDir, 'portal-tokens.json');
const daemonStore = new PortalTokens({ file: twoFile, warn() {} });
daemonStore.load();
const dToken = daemonStore.issue('nam', { label: 'phone' });

function console_() {
  const t = new PortalTokens({ file: twoFile, warn() {} });
  t.load();
  return t;
}

check('a code revoked on the console stops working without a restart', () => {
  assert.ok(daemonStore.verify(dToken.token), 'the code did not work to begin with');
  const cli = console_();
  assert.ok(cli.revoke(dToken.record.id), 'the console could not revoke it');
  assert.strictEqual(daemonStore.verify(dToken.token), null,
    'the running process still honours a revoked code');
});

check("the console's revoke survives the daemon's next write", () => {
  // The erasure path: any later save() from the daemon serialises its whole
  // map, so a revoke it never saw would be written away.
  daemonStore.issue('linh', {});
  const onDisk = JSON.parse(fs.readFileSync(twoFile, 'utf8'));
  const row = Object.values(onDisk.tokens).find((r) => r.id === dToken.record.id);
  assert.ok(row, 'the record vanished from the file');
  assert.ok(row.revokedAt, 'the revoke was erased by a later write');
  assert.ok(Object.values(onDisk.tokens).some((r) => r.user === 'linh'),
    "the daemon's own new code was lost in the merge");
});

check('a code issued on the console works without a restart', () => {
  const minted = console_().issue('mai', {});
  const seen = daemonStore.verify(minted.token);
  assert.ok(seen && seen.user === 'mai', 'a console-issued code was not honoured');
});

check('the later lastUsedAt wins rather than whichever process wrote last', () => {
  const cli = console_();
  const future = new Date(Date.now() + 600000).toISOString();
  let target = null;
  for (const r of Object.values(cli.state.tokens)) if (r.user === 'mai') { r.lastUsedAt = future; target = r.id; }
  assert.ok(target, 'no record to age');
  cli.save();
  daemonStore.issue('hoa', {});
  const after = JSON.parse(fs.readFileSync(twoFile, 'utf8'));
  const row = Object.values(after.tokens).find((r) => r.id === target);
  assert.strictEqual(row.lastUsedAt, future, 'the newer reading was overwritten by an older one');
});

check('a corrupt file does not sign every user out', () => {
  // Adopting an unreadable file would empty the map and 401 everybody at once,
  // which is exactly what load()'s refusal to start empty exists to prevent.
  const good = console_().issue('quan', {});
  assert.ok(daemonStore.verify(good.token));
  fs.writeFileSync(twoFile, '{ not json');
  const still = daemonStore.verify(good.token);
  assert.ok(still && still.user === 'quan', 'a corrupt file emptied the in-memory map');
});

check('a stale tmp file from a dead process does not wedge every later save', () => {
  // The tmp name used to be <file>.<pid>.tmp and the open is 'wx'. A pid is
  // reused, so one crash mid-write made the state directory silently
  // unwritable for whatever process next got that pid.
  fs.writeFileSync(twoFile, JSON.stringify({ version: 1, tokens: {} }, null, 2));
  fs.writeFileSync(`${twoFile}.${process.pid}.tmp`, 'stale');
  assert.doesNotThrow(() => { daemonStore.issue('binh', {}); });
});

check('save() leaves no temporary file behind', () => {
  const left = fs.readdirSync(twoDir)
    .filter((f) => f.endsWith('.tmp') && f !== `${path.basename(twoFile)}.${process.pid}.tmp`);
  assert.deepStrictEqual(left, [], `temporary files left behind: ${left.join(', ')}`);
});

fs.rmSync(twoDir, { recursive: true, force: true });

section('8. The QR encoder, against published values');

check('the block table agrees with the published codeword totals', () => {
  const I = QR._internals;
  for (let v = I.MIN_VERSION; v <= I.MAX_VERSION; v++) {
    const [ec, g1, d1, g2, d2] = I.BLOCKS[v];
    const total = g1 * (d1 + ec) + g2 * (d2 + ec);
    assert.strictEqual(total, I.TOTAL[v],
      `version ${v}: blocks give ${total} codewords, the specification says ${I.TOTAL[v]}`);
  }
});

check('the module layout leaves room for exactly that many codewords', () => {
  // An independent check of the same numbers, from the other direction: after
  // every finder, alignment pattern, timing line and metadata strip is placed,
  // what is left must be 8 x codewords + the remainder bits. A mistake in the
  // layout OR in the table makes these disagree.
  const I = QR._internals;
  for (let v = I.MIN_VERSION; v <= I.MAX_VERSION; v++) {
    const built = I.placeFunctionPatterns(v);
    const free = I.dataPositions(built.functional, built.size).length;
    const expected = I.TOTAL[v] * 8 + I.remainderBits(v);
    assert.strictEqual(free, expected,
      `version ${v}: ${free} data modules available, ${expected} needed`);
  }
});

check('the format information matches the specification', () => {
  // Level M with mask 0 is published as 101010000010010. Pinning it means the
  // BCH computation is checked rather than assumed — and a wrong format strip
  // is the failure that looks most like success, because the code draws at the
  // right size and no reader will touch it.
  const I = QR._internals;
  assert.strictEqual(
    I.formatBits(I.EC_BITS_M, 0).toString(2).padStart(15, '0'), '101010000010010');
  assert.strictEqual(
    I.formatBits(1, 0).toString(2).padStart(15, '0'), '111011111000100', 'level L, mask 0');
});

check('the version information matches the specification', () => {
  const I = QR._internals;
  // Version 7 is published as 000111110010010100, and pinning one value pins
  // the BCH computation that produces all of them.
  assert.strictEqual(
    I.versionBits(7).toString(2).padStart(18, '0'), '000111110010010100');

  // The rest are checked by the property the code was designed around rather
  // than against more remembered constants: the version information is a BCH
  // code with a minimum Hamming distance of 8, so no two versions may be closer
  // than that. A single wrong bit anywhere in the range collapses some pair
  // below it. This is the stronger check — a table of transcribed numbers is
  // only ever as good as the transcription.
  const seen = [];
  for (let v = 7; v <= I.MAX_VERSION; v++) seen.push([v, I.versionBits(v)]);
  for (let a = 0; a < seen.length; a++) {
    for (let b = a + 1; b < seen.length; b++) {
      let diff = seen[a][1] ^ seen[b][1];
      let bits = 0;
      while (diff) { bits += diff & 1; diff >>>= 1; }
      assert.ok(bits >= 8,
        `versions ${seen[a][0]} and ${seen[b][0]} differ in only ${bits} bits; ` +
        'the version information code has a minimum distance of 8');
    }
    // The low twelve bits are the check, the high six are the version itself.
    assert.strictEqual(seen[a][1] >>> 12, seen[a][0], 'the version is not in its own field');
  }
});

check('the format strip is written the right way round, not mirrored', () => {
  // The region looks identical transposed, so a mirrored strip produces a code
  // that is the right size with correct finders, correct timing and correct
  // data — and that no reader will lock on to, because reading these fifteen
  // bits is the first thing it does. Both anchor positions are pinned.
  const I = QR._internals;
  const code = QR.encode('vpn55 format strip');
  const m = code.modules;
  const n = code.size;

  // Recover the fifteen bits from each copy, in the order each is written.
  let copy1 = 0;
  for (let i = 0; i <= 5; i++) copy1 |= m[i][8] << i;
  copy1 |= m[7][8] << 6;
  copy1 |= m[8][8] << 7;
  copy1 |= m[8][7] << 8;
  for (let i = 9; i < 15; i++) copy1 |= m[8][14 - i] << i;

  let copy2 = 0;
  for (let i = 0; i < 8; i++) copy2 |= m[8][n - 1 - i] << i;
  for (let i = 8; i < 15; i++) copy2 |= m[n - 15 + i][8] << i;

  assert.strictEqual(copy1, copy2, 'the two format copies disagree');

  // And it has to be a format word this build could have produced: level M,
  // with one of the eight masks. A mirrored strip is a value in neither list.
  const legal = [];
  for (let mask = 0; mask < 8; mask++) legal.push(I.formatBits(I.EC_BITS_M, mask));
  assert.ok(legal.includes(copy1),
    `the format strip reads ${copy1.toString(2).padStart(15, '0')}, which is not ` +
    'level M with any mask — the bits are in the wrong order or the wrong places');
});

check('the Reed-Solomon remainder divides cleanly', () => {
  // Re-encoding a codeword block that already carries its own error correction
  // must leave a zero remainder. That is the defining property, and it fails
  // for any error in the field tables or the generator polynomial.
  const I = QR._internals;
  const data = Uint8Array.from({ length: 16 }, (_, i) => (i * 37 + 11) & 0xff);
  const ec = I.rsEncode(data, 10);
  const together = Uint8Array.from([...data, ...ec]);
  const again = I.rsEncode(together, 10);
  assert.ok(again.every((b) => b === 0), 'the syndrome of a valid codeword is not zero');
});

check('encoding produces a square of the right size and stops at the limit', () => {
  // A string about the length of the smallest client configuration any adapter
  // produces. Not named after one — nothing outside lib/proto_*.sh may know
  // which protocol it is talking to, and a test fixture is not an exception.
  const small = QR.encode('a tunnel configuration file, roughly this long, give or take');
  assert.ok(small, 'a short string did not encode');
  assert.strictEqual(small.modules.length, small.size);
  assert.strictEqual(small.size, small.version * 4 + 17);

  const atLimit = QR.encode('x'.repeat(QR.MAX_BYTES));
  assert.ok(atLimit, 'the stated maximum did not encode');

  // One byte past, and it must return null rather than a code no camera reads.
  assert.strictEqual(QR.encode('x'.repeat(QR.MAX_BYTES + 1)), null,
    'oversized input produced a code instead of null');
});

check('the finder patterns land where a reader looks for them', () => {
  const code = QR.encode('vpn55');
  const m = code.modules;
  const n = code.size;
  for (const [r0, c0] of [[0, 0], [0, n - 7], [n - 7, 0]]) {
    assert.strictEqual(m[r0][c0], 1, 'finder corner');
    assert.strictEqual(m[r0 + 1][c0 + 1], 0, 'finder ring');
    assert.strictEqual(m[r0 + 3][c0 + 3], 1, 'finder centre');
  }
  // The dark module, which is dark in every code ever made.
  assert.strictEqual(m[n - 8][8], 1, 'the dark module is not set');
  // The timing patterns alternate.
  for (let i = 8; i < n - 8; i++) assert.strictEqual(m[6][i], i % 2 === 0 ? 1 : 0, 'timing row');
});

check('Vietnamese text encodes as UTF-8 rather than being mangled', () => {
  // The default locale. A config comment carries it, and a QR that dropped the
  // diacritics would still scan and would still be wrong.
  const code = QR.encode('Cấu hình VPN55 — giữ tệp này cẩn thận');
  assert.ok(code, 'Vietnamese text did not encode');
});

// ─── Report ──────────────────────────────────────────────────────────────────

fs.rmSync(tmpDir, { recursive: true, force: true });
portalAuth.stop();

process.stdout.write(`\n  ${passed} passed, ${failures.length} failed\n`);
if (failures.length) {
  process.stderr.write('\nPortal self-test FAILED:\n\n');
  for (const f of failures) process.stderr.write(`    ${f}\n\n`);
  process.exit(1);
}
process.stdout.write(
  '\n  A portal session cannot be resolved as an admin session, the admin routes\n' +
  '  are mounted on one application and the portal on another, and no id a user\n' +
  '  can put in a URL resolves to another user\'s credential.\n\n');
