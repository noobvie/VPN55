'use strict';
//
// panel/portal/logic.js — what one person may see, worked out from a snapshot.
//
// Pure functions. No express, no filesystem, no clock it does not take as an
// argument, no privileged call. Everything the portal decides about ownership
// and about what to show is decided here, so it can be exercised directly by
// panel/scripts/portal-selftest.js — the phase's acceptance evidence — rather
// than through a server that would have to be started to be asked a question.
//
// ═════════════════════════════════════════════════════════════════════════════
// THE RULE THIS FILE EXISTS FOR
//
//   THE PORTAL NEVER ACCEPTS A USER IDENTIFIER FROM THE REQUEST.
//
// Every function below takes the user from the session and the id from the URL,
// in that order, and the id is only ever used to SELECT from what that user
// already owns. There is no route anywhere in the portal with a user name in
// its path, no query parameter that names one, and no body field that carries
// one. Changing an id in the URL therefore cannot widen what is returned; the
// worst it can do is select nothing.
// ═════════════════════════════════════════════════════════════════════════════
//
// ── One answer for "not yours" and for "does not exist" ──────────────────────
//
// resolveOwnCredential returns null for a credential belonging to somebody
// else, one that was revoked, and one that never existed. The caller turns all
// three into the same 404. A 403 for the second case would be more informative
// and that is precisely the objection: it would confirm the id is real, and
// confirming which ids are real is most of what changing a number in a URL is
// for.
//
// ── This is the second of two checks, not the only one ───────────────────────
//
// helper/vpnctl re-derives ownership from the register, as root, before it will
// produce a single byte of a configuration — see `cred-config` there. So the
// checks in this file are what make the portal give a good answer; they are not
// what makes it a safe one. If everything below were deleted, a user still
// could not read another user's configuration. Worth stating because the
// tempting simplification — "the portal already checked, the helper can trust
// it" — is the change that turns two independent checks into one.
//
// ── Nothing here knows which protocol it is talking to ───────────────────────
//
// A service is a tag and a label the adapter declared. This file has no list of
// protocols, no branch on one, and no idea which of them is which.

/** The state words a credential must be in before the portal will act on it. */
const USABLE_CRED_STATE = 'active';

const RE_CRED = /^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/;
const RE_ARTIFACT = /^[a-z][a-z0-9_]{0,31}$/;

/**
 * Every credential the register says this person holds, across every service.
 *
 * Built from `credmeta` — the INVENTORY — and not from `cred`, which is live
 * daemon state. The difference matters in both directions: a credential that
 * exists and is simply not connected must still be listed and downloadable, and
 * an orphan the daemon is carrying for a name the register does not know must
 * NOT be claimable by somebody who happens to have that name. The admin panel
 * surfaces those orphans; the portal does not hand them out.
 */
function ownCredentials(snapshot, user) {
  if (!snapshot || !user) return [];

  const live = new Map();
  for (const adapter of snapshot.adapters) {
    for (const c of adapter.creds) live.set(`${adapter.tag}\u0000${c.id}`, c);
  }

  const out = [];
  for (const adapter of snapshot.adapters) {
    for (const meta of Object.values(adapter.credmeta)) {
      if (meta.user !== user) continue;
      if (meta.state !== USABLE_CRED_STATE) continue;
      out.push({
        meta,
        service: { tag: adapter.tag, label: adapter.label },
        // undefined when the service is not currently carrying it, which is a
        // perfectly ordinary state for a phone that is not connected.
        live: live.get(`${adapter.tag}\u0000${meta.id}`) || null,
        adapter,
      });
    }
  }
  out.sort((a, b) => String(a.meta.created).localeCompare(String(b.meta.created)));
  return out;
}

/**
 * One credential, if and only if this person holds it. null otherwise.
 *
 * The single choke point for every id that arrives in a portal URL. Both the
 * download route and the rotate route go through it, so there is one place to
 * read when asking whether an id can be swapped for somebody else's — rather
 * than two implementations that have to agree.
 */
function resolveOwnCredential(snapshot, user, credId) {
  if (typeof credId !== 'string' || !RE_CRED.test(credId)) return null;
  for (const owned of ownCredentials(snapshot, user)) {
    if (owned.meta.id === credId) return owned;
  }
  return null;
}

/** A valid artifact id, or null. Shape only — the adapter owns the vocabulary. */
function normaliseArtifact(value) {
  if (value === undefined || value === null || value === '') return null;
  const v = String(value);
  return RE_ARTIFACT.test(v) ? v : false;   // false = present and malformed
}

/**
 * The whole page, as data.
 *
 * NOTHING IS FORMATTED. Bytes leave as integers and instants as Unix epochs,
 * exactly as view.js does for the admin panel and for the same reason: the
 * browser is the only place that knows the viewer's locale and time zone, and a
 * number formatted here arrives pre-translated into the wrong language and
 * cannot be undone.
 *
 * Returns null when the register does not list this person — which happens when
 * an account is deleted while a code is still live. The caller turns that into
 * a signed-out response rather than an empty page, because an empty page reads
 * as "you have nothing" and the truth is "you are no longer here".
 */
function accountView({ snapshot, collector, user, health, now = Math.floor(Date.now() / 1000) }) {
  if (!snapshot) return { ready: false, user: null, credentials: [], health };

  const registered = snapshot.users.find((u) => u.name === user);
  if (!registered) return null;

  const owned = ownCredentials(snapshot, user);

  let rxTotal = 0;
  let txTotal = 0;
  const credentials = [];

  for (const { meta, service, live, adapter } of owned) {
    const slot = collector ? collector.totalsFor(service.tag, meta.id) : null;
    if (slot && typeof slot.rxTotal === 'number') rxTotal += slot.rxTotal;
    if (slot && typeof slot.txTotal === 'number') txTotal += slot.txTotal;

    credentials.push({
      id: meta.id,
      service: service.tag,
      serviceLabel: service.label,
      created: meta.created,
      address: meta.address,
      custody: meta.custody,
      // The whole reason `credmeta` was added to the status stream. true means
      // there is a file to download; false means the key was erased on schedule
      // and the only way back is a rotation; null means the service did not say,
      // and the page offers the download and lets it fail honestly rather than
      // telling somebody their working credential is beyond recovery.
      configAvailable: meta.held,
      // Live state, absent when the service is not carrying this credential.
      connected: Boolean(live && live.endpoint !== null),
      lastSeen: slot ? slot.lastSeen : (live ? live.handshake : { kind: 'unknown', at: null }),
      rxTotal: slot ? slot.rxTotal : null,
      txTotal: slot ? slot.txTotal : null,
      // Declared by the adapter, never inferred. Which services survive a
      // filtered network is not computable from this side without learning
      // which protocol each one is — the one thing nothing outside
      // lib/proto_*.sh may do — so the adapter says, and the sentence it wrote
      // is carried verbatim and attributed.
      filtering: adapter.capabilities.filtering,
      // Is the service actually up? A configuration is still worth downloading
      // when it is not, so this is shown rather than acted on.
      serviceState: adapter.service ? adapter.service.state : 'unknown',
    });
  }

  const total = rxTotal + txTotal;

  return {
    ready: true,
    generatedAt: now,
    health,
    user: {
      name: registered.name,
      enabled: registered.enabled,
      created: registered.created,
      expiresAt: registered.expiresAt,
      expired: isExpired(registered.expiresAt, now),
      quotaBytes: registered.quotaBytes,
      quotaReset: registered.quotaReset,
      connLimit: registered.connLimit,
      rxTotal,
      txTotal,
      total,
      // Computed here rather than in the browser because it needs the quota,
      // which is a null-means-unlimited field: a page that read the null as 0
      // would show every unlimited account as over its limit.
      quotaUsedFraction: (typeof registered.quotaBytes === 'number' && registered.quotaBytes > 0)
        ? total / registered.quotaBytes
        : null,
      quotaRemaining: (typeof registered.quotaBytes === 'number')
        ? Math.max(0, registered.quotaBytes - total)
        : null,
    },
    credentials,
  };
}

/** null expiry means never — not "expired at epoch 0". */
function isExpired(expiresAt, now) {
  if (!expiresAt) return false;
  const t = Date.parse(expiresAt);
  if (Number.isNaN(t)) return null;      // unparseable is unknown, not false
  return t / 1000 <= now;
}

module.exports = {
  ownCredentials,
  resolveOwnCredential,
  normaliseArtifact,
  accountView,
  isExpired,
  USABLE_CRED_STATE,
  RE_CRED,
  RE_ARTIFACT,
};
