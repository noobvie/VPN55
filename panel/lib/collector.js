'use strict';
//
// panel/lib/collector.js — polls the adapters and ACCUMULATES.
//
// ═════════════════════════════════════════════════════════════════════════════
// THE ALGORITHM. Written once; identical for all three protocols, which is the
// point — nothing in this file knows or can ask which protocol a counter
// belongs to.
//
//     read new value
//     ├─ no reading at all      → skip the sample, leave `last` untouched
//     ├─ first ever reading     → total += new          (and remember it)
//     ├─ new  <  last           → a fresh session: total += new   (the FULL
//     │                            new value, not a delta against a counter
//     │                            that no longer exists)
//     └─ otherwise              → total += (new - last)
//     remember new as `last`
//
// All three protocols reset their counters, at different moments and for
// different reasons: one when its interface goes down, one per connection, one
// per security-association rekey. Displaying a raw counter as "total usage"
// therefore under-reports on every restart — the number goes DOWN, which is
// something a usage total must never do.
// ═════════════════════════════════════════════════════════════════════════════
//
// ── Three things that are easy to get wrong here, and are silent when wrong ──
//
// 1. "-" IS NOT ZERO, AND IT IS NOT A RESET.
//    An adapter emits "-" when it has no reading: the service is stopped, the
//    credential is not connected, the daemon could not be asked. Coercing that
//    to 0 makes `new < last` true and adds a phantom session to the durable
//    total, so a user's usage climbs every time their tunnel is merely idle.
//    The sample is skipped entirely and `last` is left alone, so the next real
//    reading is compared against the last REAL one.
//
// 2. `last` MUST BE PERSISTED, not just the total.
//    Keeping `last` in memory only means every panel restart looks like a first
//    reading, which adds the whole live counter to the total again. A service
//    that has moved a terabyte since boot would gain a terabyte per panel
//    restart. Both numbers go in the store.
//
// 3. THE ALGORITHM CANNOT SEE EVERY RESET, AND DOES NOT PRETEND TO.
//    If a counter resets and climbs past its old value between two polls, the
//    reset is invisible and that traffic is lost from the total. Nothing on the
//    host records enough to recover it. This under-reports; it never
//    over-reports, which is the right direction for a number that may be used
//    to enforce a quota. Stated here so nobody later "fixes" it by guessing.

const log = require('./log');
const { parseStatus } = require('./records');
const { StatusError } = require('./status-read');

const EVENT_TYPES = Object.freeze({
  SERVICE_STATE: 'service.state',
  COUNTER_RESET: 'counter.reset',
  CRED_APPEARED: 'cred.appeared',
  CRED_VANISHED: 'cred.vanished',
  NOTE_RAISED: 'note.raised',
  STATUS_UNREADABLE: 'status.unreadable',
  STATUS_RECOVERED: 'status.recovered',
  RECORD_UNKNOWN: 'record.unknown',
});

function counterKey(tag, credId) {
  return `${tag}\u0000${credId}`;
}

function freshSlot(now) {
  return {
    user: null,
    address: null,
    rxTotal: 0,
    txTotal: 0,
    rxLast: null,
    txLast: null,
    resets: 0,
    firstSeen: now,
    lastSample: now,
    // Best knowledge of when this credential was last used. `kind` is one of
    // 'never' | 'unknown' | 'at' — carried, not collapsed. A credential whose
    // adapter cannot answer keeps the last answer we DID get rather than
    // reverting to "unknown", because "we saw it at 14:02" stays true after the
    // daemon that told us forgets.
    lastSeen: { kind: 'unknown', at: null },
  };
}

/**
 * One direction of one credential's counters.
 * Returns { added, reset, skipped }.
 */
function accumulate(slot, dir, value) {
  const lastKey = `${dir}Last`;
  const totalKey = `${dir}Total`;

  // Rule 1: no reading. Not a zero, not a reset — nothing happened that we know
  // about, so nothing is recorded and `last` is preserved.
  if (value === null) return { added: 0, reset: false, skipped: true };

  const last = slot[lastKey];
  let added;
  let reset = false;

  if (last === null || last === undefined) {
    // First reading of this credential. The counter already holds traffic
    // nobody has counted, and our total starts at zero, so the whole value is
    // ours to add — the same arithmetic as a fresh session.
    added = value;
  } else if (value < last) {
    // Rule: the counter went backwards. The only way that happens is a reset,
    // so everything the new counter holds belongs to a session we have not
    // counted any of yet.
    added = value;
    reset = true;
  } else {
    added = value - last;
  }

  slot[totalKey] += added;
  slot[lastKey] = value;
  return { added, reset, skipped: false };
}

class Collector {
  constructor({ privileged, store, cfg, onPoll = null }) {
    this.privileged = privileged;
    this.store = store;
    this.cfg = cfg;
    this.timer = null;
    this.stopped = false;
    this.polling = false;

    // Live values, owned here rather than read from the frozen cfg on every
    // tick. The settings screen changes them without a restart, and the panel
    // cannot restart itself — see panel/lib/settings.js. cfg stays the record of
    // what was loaded at start-up; this is the record of what is in effect.
    this.pollSeconds = cfg.poll_seconds;
    this.eventLimit = cfg.event_limit;

    // Called after every poll attempt, successful or not. It exists so that
    // ALERTING is wired in one place (server.js) instead of this file learning
    // what an alert is — the same reason it does not know what a protocol is.
    // A throwing callback must never break the poll loop.
    this.onPoll = onPoll;

    // The most recent successful parse, plus how the last attempt went. Both,
    // always: a page that shows stale data must be able to say it is stale.
    this.snapshot = null;
    this.lastSuccessAt = null;
    this.lastAttemptAt = null;
    this.lastError = null;
    this.consecutiveFailures = 0;
  }

  start() {
    const tick = () => {
      if (this.stopped) return;
      this.poll()
        .catch((err) => log.error('poll threw', err && err.stack ? err.stack : String(err)))
        .finally(() => {
          if (this.stopped) return;
          // Read at the moment the next tick is scheduled, not once at start:
          // a period captured in a closure would keep the old interval until
          // the next restart, so the settings screen would report a change it
          // had not made.
          this.timer = setTimeout(tick, this.pollSeconds * 1000);
          if (this.timer.unref) this.timer.unref();
        });
    };
    tick();
  }

  /**
   * Change the poll interval, in effect from the next tick.
   *
   * The tick in flight keeps the old one — cancelling and rescheduling would
   * mean a settings change could reset the interval indefinitely if it were
   * repeated, and one interval of latency is not worth that.
   */
  setPollSeconds(seconds) {
    if (!Number.isFinite(seconds) || seconds < 1) return;
    this.pollSeconds = Math.floor(seconds);
  }

  /**
   * Change how many events are kept.
   *
   * Lowering it does not truncate the history that is already stored — the next
   * recorded event does that, in record(). Truncating here would throw away
   * events the moment somebody dragged a slider, before they had confirmed
   * anything.
   */
  setEventLimit(limit) {
    if (!Number.isFinite(limit) || limit < 1) return;
    this.eventLimit = Math.floor(limit);
  }

  stop() {
    this.stopped = true;
    if (this.timer) clearTimeout(this.timer);
    this.timer = null;
  }

  async poll() {
    // Overlap guard. A status read slower than the poll interval would otherwise
    // stack readers, and two of them accumulating the same sample would
    // double-count it.
    if (this.polling) {
      log.debug('poll still running — skipping this tick');
      return;
    }
    this.polling = true;
    const now = Math.floor(Date.now() / 1000);
    this.lastAttemptAt = now;

    try {
      const { text } = await this.privileged.readStatus();
      const parsed = parseStatus(text);

      if (this.consecutiveFailures > 0) {
        this.record(now, EVENT_TYPES.STATUS_RECOVERED, {
          afterFailures: this.consecutiveFailures,
        });
        log.clearOnce('status-read');
      }
      this.consecutiveFailures = 0;
      this.lastError = null;

      this.ingest(parsed, now);
      this.snapshot = parsed;
      this.lastSuccessAt = now;
      this.store.state.lastPollAt = now;
      this.store.markDirty();
    } catch (err) {
      this.consecutiveFailures += 1;
      const kind = err instanceof StatusError ? err.kind : 'failed';
      this.lastError = { kind, message: err.message, at: now };
      // The first failure is an event; the rest are the same failure continuing.
      // A poll loop that logs and records every 15 seconds buries the change.
      if (this.consecutiveFailures === 1) {
        this.record(now, EVENT_TYPES.STATUS_UNREADABLE, { kind });
      }
      log.warnOnce('status-read', `status read failed (${kind}): ${err.message}`,
                   err.detail ? err.detail.slice(0, 500) : undefined);
    } finally {
      this.polling = false;
      try {
        this.store.flush();
      } catch (err) {
        log.error('could not write state', err.message);
      }
      if (this.onPoll) {
        // Guarded, and reported once. A monitoring hook that could break the
        // poll loop would be a monitoring system that causes outages.
        try {
          this.onPoll(this.health());
        } catch (err) {
          log.warnOnce('collector-onpoll', `the poll hook threw: ${err.message}`);
        }
      }
    }
  }

  /** Fold one parsed snapshot into the durable state. */
  ingest(parsed, now) {
    const state = this.store.state;
    const seen = new Set();

    for (const adapter of parsed.adapters) {
      this.ingestService(adapter, now);
      this.ingestNotes(adapter, now);

      for (const cred of adapter.creds) {
        const key = counterKey(adapter.tag, cred.id);
        seen.add(key);

        let slot = state.counters[key];
        if (!slot) {
          slot = freshSlot(now);
          state.counters[key] = slot;
          this.record(now, EVENT_TYPES.CRED_APPEARED, {
            tag: adapter.tag, credId: cred.id, user: cred.user,
          });
        }

        slot.user = cred.user;
        slot.address = cred.address;
        slot.lastSample = now;

        const rx = accumulate(slot, 'rx', cred.rx);
        const tx = accumulate(slot, 'tx', cred.tx);

        // One reset event per credential per poll, not one per direction — the
        // counters reset together and reporting it twice reads as two incidents.
        if (rx.reset || tx.reset) {
          slot.resets += 1;
          this.record(now, EVENT_TYPES.COUNTER_RESET, {
            tag: adapter.tag, credId: cred.id, user: cred.user,
            carried: rx.added + tx.added,
          });
        }

        // `lastSeen` only ever moves FORWARD in confidence. Two ways to get this
        // wrong, and both destroy a stored fact rather than failing visibly:
        //
        //   'unknown' must not overwrite anything. The daemon forgetting is not
        //   the credential never having been used.
        //
        //   'never' must not overwrite a timestamp either. It may FILL an
        //   unknown — that is a real first answer — but a stored "seen at 14:02"
        //   is evidence, and "never" is the absence of evidence. These daemons
        //   forget on restart, so an adapter can legitimately report `never`
        //   about a credential this panel already watched connect; taking it as
        //   a correction would rewrite the real date, and `lastSeen` is in the
        //   durable store, so the real date would be gone for good.
        if (cred.handshake.kind === 'at') {
          slot.lastSeen = cred.handshake;
        } else if (cred.handshake.kind === 'never' && slot.lastSeen.kind === 'unknown') {
          slot.lastSeen = cred.handshake;
        }
      }
    }

    // A credential the host no longer reports. Its totals are KEPT — the traffic
    // happened, and a revoked credential's usage is exactly what an operator
    // looks for afterwards. Only the fact that it went is recorded.
    for (const key of Object.keys(state.counters)) {
      if (seen.has(key)) continue;
      const slot = state.counters[key];
      if (slot.vanishedAt) continue;
      slot.vanishedAt = now;
      const [tag, credId] = key.split('\u0000');
      this.record(now, EVENT_TYPES.CRED_VANISHED, { tag, credId, user: slot.user });
    }

    for (const unknown of parsed.unknownRecords) {
      log.warnOnce(`unknown-record:${unknown.type}`,
        `status stream carried an unrecognised record type "${unknown.type}" ` +
        `(${unknown.count} line(s)) — this panel is older than the adapter that wrote it`);
      this.record(now, EVENT_TYPES.RECORD_UNKNOWN, { type: unknown.type, count: unknown.count });
    }

    if (parsed.malformed.length) {
      log.warnOnce('malformed-records',
        `${parsed.malformed.length} malformed record(s) in the status stream`);
    }

    this.store.markDirty();
  }

  ingestService(adapter, now) {
    const state = this.store.state;
    const current = adapter.service ? adapter.service.state : 'unknown';
    const prev = state.services[adapter.tag];
    if (!prev) {
      state.services[adapter.tag] = { state: current, changedAt: now };
      return;
    }
    if (prev.state !== current) {
      this.record(now, EVENT_TYPES.SERVICE_STATE, {
        tag: adapter.tag, from: prev.state, to: current,
      });
      state.services[adapter.tag] = { state: current, changedAt: now };
    }
  }

  ingestNotes(adapter, now) {
    const state = this.store.state;
    const svc = state.services[adapter.tag] || (state.services[adapter.tag] = { state: 'unknown', changedAt: now });
    const active = adapter.notes.map((n) => `${n.severity}\u0000${n.message}`);
    const previous = new Set(svc.notes || []);

    for (const n of adapter.notes) {
      const fingerprint = `${n.severity}\u0000${n.message}`;
      if (previous.has(fingerprint)) continue;
      // Only warn and crit become events. An info note is standing context an
      // adapter prints every poll; turning that into an event stream makes the
      // event log a place nobody looks.
      if (n.severity === 'info') continue;
      this.record(now, EVENT_TYPES.NOTE_RAISED, {
        tag: adapter.tag,
        severity: n.severity,
        // Adapter-authored text, carried verbatim. This side cannot translate a
        // sentence it did not write without learning which protocol wrote it —
        // so it is rendered as data, marked as coming from the service.
        message: n.message,
      });
    }
    svc.notes = active;
  }

  /**
   * Append an event. Events store a TYPE and structured data, never a rendered
   * sentence — the sentence is built in the viewer's locale at display time.
   * The one exception is an adapter's own note text, which is data.
   */
  record(at, type, data) {
    const events = this.store.state.events;
    events.push({ at, type, data });
    const limit = this.eventLimit;
    if (events.length > limit) events.splice(0, events.length - limit);
    this.store.markDirty();
  }

  /** Newest first. */
  events(limit = 100) {
    const all = this.store.state.events;
    return all.slice(Math.max(0, all.length - limit)).reverse();
  }

  totalsFor(tag, credId) {
    return this.store.state.counters[counterKey(tag, credId)] || null;
  }

  health() {
    return {
      lastSuccessAt: this.lastSuccessAt,
      lastAttemptAt: this.lastAttemptAt,
      consecutiveFailures: this.consecutiveFailures,
      error: this.lastError,
      pollSeconds: this.pollSeconds,
    };
  }
}

module.exports = { Collector, accumulate, counterKey, freshSlot, EVENT_TYPES };
