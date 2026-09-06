'use strict';
//
// panel/lib/view.js — build the JSON the browser renders.
//
// Two rules shape everything here:
//
// 1. NOTHING IS FORMATTED. Every number leaves as a number and every instant
//    leaves as a Unix epoch. Bytes, dates and counts are rendered by Intl in the
//    browser, where the viewer's locale and time zone are actually known. A
//    value formatted here would arrive pre-translated into the wrong language,
//    and could not be re-formatted afterwards.
//
// 2. "NO READING" SURVIVES THE JOURNEY. A missing counter is `null` here and
//    renders as "—" there. It is never 0, and a credential the daemon cannot
//    describe is never rendered as an idle one.
//
// The panel holds no user list of its own. Users come from the registry, live
// state comes from the adapters, and the only thing this file adds is the
// accumulated totals — which exist precisely because they are the one number no
// adapter can answer, since every one of them resets its counters.

/**
 * A credential is "reported" when its service says it is carrying a session for
 * it right now. That is the `connected` field, which the adapter answers because
 * only the adapter can: this side may not learn which protocol it is holding.
 *
 * It used to be read off `endpoint`, on the reasoning that a current remote
 * address was the one liveness signal every protocol could answer the same way.
 * It is not one. On a peer-based protocol the endpoint is the LAST address the
 * peer was seen at and survives for the life of the interface, so a device that
 * connected once in March reads as online for ever; and a protocol with no peers
 * at all has no endpoint to give, which would make every credential on such a
 * service permanently invisible here. Both are silent, plausible-looking wrong
 * answers, which is the worst kind.
 *
 * `connected` is deliberately NOT folded together with the handshake. The
 * handshake is a TIME — when this credential was last observed live — and the
 * two answer different questions. Both facts are carried; the UI shows both.
 *
 * null means the adapter could not tell (its daemon is stopped or unreadable),
 * and that is not "disconnected": it is treated as not-reported for counting,
 * but the service's own state is what says why.
 */
function isReported(cred) {
  return cred.connected === true;
}

function buildView({ snapshot, collector, cfg, health }) {
  const now = Math.floor(Date.now() / 1000);

  if (!snapshot) {
    return {
      generatedAt: now,
      ready: false,
      health,
      services: [],
      users: [],
      connections: [],
      // collector.eventLimit, not cfg.event_limit: the settings screen changes
      // it without a restart, and cfg is the record of what was loaded.
      events: collector.events(collector.eventLimit).slice(0, 100),
      orphanCredentials: [],
      counts: { services: 0, users: 0, credentials: 0, reported: 0 },
    };
  }

  const services = [];
  const credentials = [];

  for (const a of snapshot.adapters) {
    services.push({
      tag: a.tag,
      label: a.label,
      available: a.available,
      state: a.service ? a.service.state : 'unknown',
      enabled: a.service ? a.service.enabled : null,
      listen: a.service ? a.service.listen : null,
      since: a.service ? a.service.since : null,
      credCount: a.service ? a.service.credCount : 0,
      // Declared by the adapter, never inferred here. Working out which
      // services survive a filtered network from this side would mean learning
      // which protocol each one is, which is the one thing this side may not do.
      filtering: a.capabilities.filtering,
      custody: a.capabilities.custody,
      revoke: a.capabilities.revoke,
      restart: a.capabilities.restart,
      // What this adapter needs in order to issue a credential. Declared, never
      // assumed: the issue form prompts for whatever is in here and knows what
      // none of it means, which is what stopped the installer asking every
      // service for a public key because one of them wanted one.
      options: a.capabilities.options || [],
      notes: a.notes,
    });

    for (const c of a.creds) {
      const slot = collector.totalsFor(a.tag, c.id);
      credentials.push({
        tag: a.tag,
        serviceLabel: a.label,
        id: c.id,
        user: c.user,
        state: c.state,
        address: c.address,
        endpoint: c.endpoint,
        reported: isReported(c),
        // The live counters, as read this poll. Null means no reading.
        rx: c.rx,
        tx: c.tx,
        // The accumulated totals, which is what "usage" means. These survive
        // every counter reset; the live pair above does not.
        rxTotal: slot ? slot.rxTotal : null,
        txTotal: slot ? slot.txTotal : null,
        resets: slot ? slot.resets : 0,
        firstSeen: slot ? slot.firstSeen : null,
        handshake: c.handshake,
        connected: c.connected,
        lastSeen: slot ? slot.lastSeen : c.handshake,
      });
    }
  }

  // ── Users: the registry is the list; credentials attach to it ──────────────
  const byUser = new Map();
  for (const c of credentials) {
    if (!c.user) continue;
    if (!byUser.has(c.user)) byUser.set(c.user, []);
    byUser.get(c.user).push(c);
  }

  const registryNames = new Set(snapshot.users.map((u) => u.name));

  const users = snapshot.users.map((u) => {
    const creds = byUser.get(u.name) || [];
    let rxTotal = 0;
    let txTotal = 0;
    let lastSeen = { kind: 'unknown', at: null };
    let reported = 0;

    for (const c of creds) {
      if (typeof c.rxTotal === 'number') rxTotal += c.rxTotal;
      if (typeof c.txTotal === 'number') txTotal += c.txTotal;
      if (c.reported) reported += 1;
      lastSeen = laterOf(lastSeen, c.lastSeen);
    }

    return {
      ...u,
      credentials: creds.length,
      reportedCredentials: reported,
      rxTotal,
      txTotal,
      total: rxTotal + txTotal,
      lastSeen,
      // Computed here rather than by the browser because it needs the quota,
      // which is a null-means-unlimited field: a UI that treated the null as 0
      // would show every unlimited user as over quota.
      quotaUsedFraction: (typeof u.quotaBytes === 'number' && u.quotaBytes > 0)
        ? (rxTotal + txTotal) / u.quotaBytes
        : null,
      expired: isExpired(u.expiresAt, now),
    };
  });

  // A credential the services know about whose user is not in the registry.
  // This is the drift the architecture exists to prevent, so it is surfaced
  // rather than quietly dropped from the user list.
  const orphanCredentials = credentials.filter(
    (c) => !c.user || !registryNames.has(c.user));

  const connections = credentials
    .filter((c) => c.reported)
    .sort((a, b) => (b.lastSeen.at || 0) - (a.lastSeen.at || 0));

  return {
    generatedAt: now,
    ready: true,
    stamp: snapshot.stamp,
    health,
    services,
    users,
    credentials,
    connections,
    orphanCredentials,
    events: collector.events(200),
    counts: {
      services: services.length,
      users: users.length,
      credentials: credentials.length,
      reported: connections.length,
    },
  };
}

/** 'at' beats 'never' beats 'unknown'; two 'at's compare by time. */
function laterOf(a, b) {
  const rank = (h) => (h.kind === 'at' ? 2 : h.kind === 'never' ? 1 : 0);
  if (rank(b) > rank(a)) return b;
  if (rank(a) > rank(b)) return a;
  if (a.kind === 'at' && b.kind === 'at') return (b.at > a.at ? b : a);
  return a;
}

function isExpired(expiresAt, now) {
  if (!expiresAt) return false;      // null means never — not "expired at epoch 0"
  const t = Date.parse(expiresAt);
  if (Number.isNaN(t)) return null;  // unparseable is unknown, not false
  return t / 1000 <= now;
}

module.exports = { buildView, isReported, laterOf, isExpired };
