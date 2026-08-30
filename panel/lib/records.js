'use strict';
//
// panel/lib/records.js — turn the status stream into a structure.
//
// The stream is TAB-separated, one record per line, FIRST FIELD IS THE TYPE. So
// this parser dispatches on field 1 and drops nothing it cannot place: a record
// type it does not understand is counted and reported, never silently discarded.
// That is the whole reason the type leads the line — a future adapter emitting
// a new record must be visible here as "something new arrived", not as nothing.
//
//   stamp       <epoch>
//   adapter     <tag>  <label>  <available 0|1>
//   capability  <tag>  <record…>
//   service     <tag>  <state> <enabled> <listen> <since> <cred_count>
//   cred        <tag>  <cred_id> <user> <state> <address> <rx> <tx> <handshake> <endpoint>
//   credmeta    <tag>  <cred_id> <user> <state> <address> <created> <custody> <held 0|1>
//   note        <tag>  <info|warn|crit>  <message>
//   user        <name> <created> <enabled> <quota> <expires> <conn_limit> <reset> <creds>
//
// ── The three values that are NOT what they look like ────────────────────────
//
// 1. "-" IS NOT ZERO. It means the adapter had no reading — the service is
//    stopped, the credential is not connected, the daemon could not be asked.
//    It stays `null` all the way to the browser, where it renders as "—". Every
//    numeric field goes through `num()`, which returns null for "-" and for
//    anything that is not a plain non-negative integer.
//
// 2. handshake 0 means NEVER; handshake "-" means UNKNOWN. Three states, not
//    two. A daemon that keeps no history cannot assert "never" and must not be
//    read as having done so — telling an operator that a user who connected
//    yesterday has never connected is the kind of wrong that gets someone's
//    access removed.
//
// 3. An EMPTY user-registry column is a genuine null, not a zero. `quota_bytes`
//    empty means unlimited; reading it as 0 would render every user as being
//    over quota.

/** A non-negative integer, or null for "-", "", and anything unparseable. */
function num(raw) {
  if (raw === undefined || raw === null) return null;
  const v = String(raw).trim();
  if (v === '' || v === '-') return null;
  if (!/^\d+$/.test(v)) return null;
  const n = Number(v);
  return Number.isSafeInteger(n) ? n : null;
}

/** A display string, or null when the adapter had nothing to say. */
function str(raw) {
  if (raw === undefined || raw === null) return null;
  const v = String(raw).trim();
  return v === '' || v === '-' ? null : v;
}

/** 1/0 flag. Anything else is null — an unknown flag is not a false one. */
function flag(raw) {
  const v = String(raw ?? '').trim();
  if (v === '1') return true;
  if (v === '0') return false;
  return null;
}

/**
 * handshake: { kind: 'never' | 'unknown' | 'at', at: epoch|null }
 * The three states the contract distinguishes, carried as three states.
 */
function handshake(raw) {
  const v = String(raw ?? '').trim();
  if (v === '' || v === '-') return { kind: 'unknown', at: null };
  if (!/^\d+$/.test(v)) return { kind: 'unknown', at: null };
  const n = Number(v);
  if (n === 0) return { kind: 'never', at: null };
  return Number.isSafeInteger(n) ? { kind: 'at', at: n } : { kind: 'unknown', at: null };
}

const SEVERITIES = new Set(['info', 'warn', 'crit']);
const FILTERING_LEVELS = new Set(['resistant', 'partial', 'exposed']);

function blankAdapter(tag) {
  return {
    tag,
    label: tag,
    available: null,
    service: null,
    creds: [],
    // The credential INVENTORY, keyed by id. Not the same thing as `creds`,
    // which is what the daemon is carrying right now: a credential that exists
    // and is not connected appears here and not there, and a credential the
    // register has forgotten appears there and not here.
    credmeta: Object.create(null),
    notes: [],
    capabilities: {
      revoke: null,       // { latency, worstCaseSeconds }
      custody: null,      // { who, disclosure }
      filtering: null,    // { level, explanation }
      restart: null,      // { effect, explanation }
      options: [],
    },
  };
}

/**
 * Parse a full status stream.
 * Returns { stamp, adapters, users, unknownRecords, malformed }.
 * Never throws on content: a stream that is half garbage still yields the half
 * that parsed, plus a count of what did not.
 */
function parseStatus(text) {
  const adapters = new Map();
  const users = [];
  const unknownRecords = new Map();
  const malformed = [];
  let stamp = null;

  const lines = String(text ?? '').split('\n');
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i].replace(/\r$/, '');
    if (line === '') continue;
    const f = line.split('\t');
    const kind = f[0];

    switch (kind) {
      case 'stamp': {
        stamp = num(f[1]);
        break;
      }

      case 'adapter': {
        const tag = str(f[1]);
        if (!tag) { malformed.push({ line: i + 1, kind }); break; }
        const a = adapters.get(tag) || blankAdapter(tag);
        a.label = str(f[2]) || tag;
        a.available = flag(f[3]);
        adapters.set(tag, a);
        break;
      }

      case 'capability': {
        const tag = str(f[1]);
        if (!tag) { malformed.push({ line: i + 1, kind }); break; }
        const a = adapters.get(tag) || blankAdapter(tag);
        adapters.set(tag, a);
        applyCapability(a.capabilities, f.slice(2), () => malformed.push({ line: i + 1, kind }));
        break;
      }

      case 'service': {
        const tag = str(f[1]);
        if (!tag) { malformed.push({ line: i + 1, kind }); break; }
        const a = adapters.get(tag) || blankAdapter(tag);
        adapters.set(tag, a);
        a.service = {
          // The state word is the adapter's, passed through: `running`,
          // `stopped`, `absent` today, and whatever a future adapter needs. The
          // UI keys a translation on it and falls back to showing the word
          // itself, so a new state renders as a new state, not as a blank.
          state: str(f[2]) || 'unknown',
          enabled: flag(f[3]),
          listen: str(f[4]),
          since: num(f[5]),
          credCount: num(f[6]) ?? 0,
        };
        break;
      }

      case 'cred': {
        const tag = str(f[1]);
        const id = str(f[2]);
        if (!tag || !id) { malformed.push({ line: i + 1, kind }); break; }
        const a = adapters.get(tag) || blankAdapter(tag);
        adapters.set(tag, a);
        a.creds.push({
          tag,
          id,
          user: str(f[3]),
          state: str(f[4]) || 'unknown',
          address: str(f[5]),
          rx: num(f[6]),
          tx: num(f[7]),
          handshake: handshake(f[8]),
          endpoint: str(f[9]),
        });
        break;
      }

      case 'credmeta': {
        const tag = str(f[1]);
        const id = str(f[2]);
        if (!tag || !id) { malformed.push({ line: i + 1, kind }); break; }
        const a = adapters.get(tag) || blankAdapter(tag);
        adapters.set(tag, a);
        a.credmeta[id] = {
          tag,
          id,
          user: str(f[3]),
          state: str(f[4]) || 'unknown',
          address: str(f[5]),
          created: str(f[6]),
          // Who made the private key. Declared per credential rather than read
          // off the service's `custody` capability, because one adapter offers
          // both paths and the answer is a property of the issue, not of the
          // protocol.
          custody: str(f[7]),
          // Is there still a configuration file on this host for it?
          //
          // `null`, not `false`, when the adapter did not say. The adapters
          // shred a spooled key hours after issue, so `false` is a real and
          // common answer meaning "rotate, there is nothing to download" — and
          // rendering "did not say" as that would tell somebody their working
          // credential is unrecoverable when it may not be.
          held: flag(f[8]),
        };
        break;
      }

      case 'note': {
        const tag = str(f[1]);
        const severity = str(f[2]);
        const message = f.slice(3).join('\t').trim();
        if (!tag || !message) { malformed.push({ line: i + 1, kind }); break; }
        const a = adapters.get(tag) || blankAdapter(tag);
        adapters.set(tag, a);
        // An unrecognised severity is shown, at the loudest of the ones we know.
        // Downgrading something we do not understand to "info" is how a warning
        // an adapter went out of its way to raise ends up rendered as chatter.
        a.notes.push({
          severity: SEVERITIES.has(severity) ? severity : 'crit',
          severityKnown: SEVERITIES.has(severity),
          message,
        });
        break;
      }

      case 'user': {
        const name = str(f[1]);
        if (!name) { malformed.push({ line: i + 1, kind }); break; }
        users.push({
          name,
          created: str(f[2]),
          enabled: flag(f[3]),
          // Empty is a genuine null here: unlimited quota, never expires, no
          // device limit, no reset window. Not zero, and never rendered as one.
          quotaBytes: num(f[4]),
          expiresAt: str(f[5]),
          connLimit: num(f[6]),
          quotaReset: str(f[7]),
          activeCreds: num(f[8]) ?? 0,
        });
        break;
      }

      default: {
        unknownRecords.set(kind, (unknownRecords.get(kind) || 0) + 1);
      }
    }
  }

  return {
    stamp,
    adapters: [...adapters.values()],
    users,
    unknownRecords: [...unknownRecords.entries()].map(([type, count]) => ({ type, count })),
    malformed,
  };
}

function applyCapability(caps, f, onBad) {
  switch (f[0]) {
    case 'revoke': {
      const latency = str(f[1]);
      if (!latency) return onBad();
      // -1 is the contract's "no bound at all", and it is not a duration. It
      // stays distinguishable from a real number all the way to the UI.
      const raw = String(f[2] ?? '').trim();
      const bounded = /^\d+$/.test(raw);
      caps.revoke = {
        latency,
        worstCaseSeconds: bounded ? Number(raw) : null,
        unbounded: raw === '-1',
      };
      return undefined;
    }
    case 'custody': {
      const who = str(f[1]);
      if (!who) return onBad();
      caps.custody = { who, disclosure: f.slice(2).join('\t').trim() || null };
      return undefined;
    }
    case 'filtering': {
      const level = str(f[1]);
      if (!level) return onBad();
      caps.filtering = {
        // The LEVEL is the stable identifier the UI keys its translation on.
        // The sentence is the adapter's own words, rendered as data — like a
        // note, and for the same reason: this side cannot translate a sentence
        // it did not author without learning which protocol wrote it.
        level,
        levelKnown: FILTERING_LEVELS.has(level),
        explanation: f.slice(2).join('\t').trim() || null,
      };
      return undefined;
    }
    case 'restart': {
      const effect = str(f[1]);
      if (!effect) return onBad();
      caps.restart = { effect, explanation: f.slice(2).join('\t').trim() || null };
      return undefined;
    }
    case 'option': {
      const key = str(f[1]);
      if (!key) return onBad();
      caps.options.push({
        key,
        prompt: str(f[2]),
        required: flag(f[3]) === true,
        help: str(f[4]),
      });
      return undefined;
    }
    default:
      // A capability type from a newer adapter. Not an error, and not something
      // to invent a rendering for.
      return undefined;
  }
}

module.exports = { parseStatus, num, str, flag, handshake, FILTERING_LEVELS };
