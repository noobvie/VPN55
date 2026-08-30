'use strict';
//
// panel/lib/enforcement.js — the periodic job that acts on quota and expiry.
//
// Null still means unlimited. A user with `quota_bytes` unset and `expires_at`
// unset is never touched by this job, which is what keeps the own-fleet case
// simple: an operator running VPN55 for their own household never configures a
// limit and never meets this code.
//
// ═════════════════════════════════════════════════════════════════════════════
// WHAT THIS JOB CAN AND CANNOT ACTUALLY DO
//
// It can set the register's `enabled` flag through `user-disable`. That stops
// new credentials being issued and is what the panel and the portal gate on.
//
// It CANNOT, by itself, end a tunnel that is already up. None of these services
// can suspend a credential and later restore it — revocation is the only lever
// and it is one-way, because the client key is gone after the hand-off window.
// So a person already connected when they cross their quota stays connected
// until they disconnect.
//
// That limit is stated here, counted in every run summary, and shown in the
// panel. It is not worked around, because both available work-arounds are worse:
// revoking on a monthly quota burns every user's configuration every month, and
// pretending the flag ended the session is the same class of lie as reporting a
// revocation that has not taken effect.
//
// An operator who wants hard enforcement opts in — `enforce_quota_revoke` and
// `enforce_expiry_revoke` — and then a disabled account's credentials really are
// revoked, really are gone, and really do need reissuing.
// ═════════════════════════════════════════════════════════════════════════════
//
// ── Where its two inputs come from, and why not from the register ────────────
//
// The user list comes from the STATUS SNAPSHOT, the same stream every view is
// built from, and the usage figures come from the collector's durable totals.
// Neither is read out of /etc/vpn55/users directly, and that is deliberate:
// a second reader of the register is a second opinion about who exists, which is
// the drift the whole architecture exists to prevent. It also means the panel
// needs no read access to a root-owned directory holding key material — it
// already has the one privileged read, and this rides on it.
//
// ── A quota window needs a baseline, because the collector counts lifetimes ──
//
// The collector accumulates a LIFETIME total per credential; it has to, because
// every service resets its own counters and a lifetime figure is the only one
// that can be reconstructed. A `quota_reset` of daily/weekly/monthly needs usage
// SINCE the window opened, so this job records the lifetime total at each
// rollover and subtracts it. `quota_reset` null is a lifetime cap and needs no
// baseline at all.
//
// ⚠ If the lifetime total is ever BELOW its own baseline, the durable state was
// lost or rebuilt — state.json deleted, restored from an old backup. The baseline
// is then meaningless and is re-taken at the current figure. Subtracting it
// anyway would produce a negative, clamp to zero, and quietly stop enforcing
// every windowed quota on the host with nothing in the log to say so.
//
// ── A missing usage figure is not zero ──────────────────────────────────────
//
// A user with no entry in the usage map has NO READING — no credential has ever
// reported, or the collector has not polled successfully yet. The quota check is
// SKIPPED for them and the skip is counted. Reading a missing figure as 0 would
// silently stop enforcing the moment the collector broke; reading it as
// over-quota would disable everyone the instant it did. Neither failure
// announces itself, so the run says how many it skipped.
//
// Expiry needs no usage figure at all, so it runs regardless — which matters,
// because expiry is the check that still works while the collector is failing.

const fs = require('node:fs');
const path = require('node:path');

const log = require('./log');

const ACTOR = 'enforcer';

/**
 * Per-user accumulated bytes, from the collector's durable state.
 *
 * A credential whose user is not yet known — seen by a service but not matched
 * to a register entry — is left out rather than bucketed under a placeholder.
 * It shows up in the panel as an orphan credential, which is the right place for
 * it; silently adding its traffic to somebody would be worse than not counting it.
 */
function usageFromStore(store) {
  const totals = new Map();
  const counters = (store && store.state && store.state.counters) || {};
  for (const slot of Object.values(counters)) {
    if (!slot || !slot.user) continue;
    const rx = typeof slot.rxTotal === 'number' ? slot.rxTotal : 0;
    const tx = typeof slot.txTotal === 'number' ? slot.txTotal : 0;
    totals.set(slot.user, (totals.get(slot.user) || 0) + rx + tx);
  }
  return totals;
}

/**
 * The start of the current accounting window, as epoch milliseconds, or null for
 * a lifetime cap.
 *
 * The weekly case does day-of-week arithmetic rather than "last Monday", because
 * on a Monday that phrase means the PREVIOUS Monday — so one day in seven the
 * window would open a week early and hand out double the quota. `users_quota_
 * window_start` in lib/core_users.sh avoids the same trap the same way; the two
 * must agree, or the installer and the panel would disagree about who is over.
 */
function windowStart(quotaReset, now = new Date()) {
  const midnight = Date.UTC(now.getUTCFullYear(), now.getUTCMonth(), now.getUTCDate());
  switch (quotaReset) {
    case 'daily':
      return midnight;
    case 'weekly': {
      // getUTCDay() is 0..6 with Sunday = 0; the bash side uses %u, 1..7 with
      // Monday = 1. Both land on this week's Monday, including on a Monday.
      const dow = (new Date(midnight).getUTCDay() + 6) % 7;
      return midnight - dow * 86_400_000;
    }
    case 'monthly':
      return Date.UTC(now.getUTCFullYear(), now.getUTCMonth(), 1);
    default:
      return null;
  }
}

/**
 * Whether an expiry date has passed. `null` means never, and an UNPARSEABLE date
 * is treated as NOT expired, with a warning — failing the other way would
 * disable an account because of a typo in a settings file, which is a bigger
 * harm than an account living a day too long.
 */
function isExpired(expiresAt, now = Date.now()) {
  if (!expiresAt) return false;
  const iso = /^\d{4}-\d{2}-\d{2}$/.test(expiresAt) ? `${expiresAt}T00:00:00Z` : expiresAt;
  const t = Date.parse(iso);
  if (!Number.isFinite(t)) {
    log.warnOnce(`expires-${expiresAt}`,
      `unparseable expires_at "${expiresAt}" — treating that account as not expired`);
    return false;
  }
  return now >= t;
}

class Enforcer {
  /**
   * @param {object} deps
   * @param {object} deps.cfg
   * @param {object} deps.collector   read for `snapshot.users`
   * @param {object} deps.store       read for accumulated totals
   * @param {object} deps.privileged  panel/lib/privileged.js — the only root path
   * @param {object} deps.audit       panel/lib/audit.js
   */
  constructor({ cfg, collector, store, privileged, audit }) {
    this.cfg = cfg;
    this.collector = collector;
    this.store = store;
    this.privileged = privileged;
    this.audit = audit;

    this.timer = null;
    this.running = false;
    this.lastRun = null;

    // Two things, persisted:
    //
    //   disabled   which accounts THIS JOB switched off, and why. The decision
    //              to switch one back on depends on it, and a panel restart must
    //              not lose it — otherwise every account an OPERATOR disabled by
    //              hand would come back the moment a usage window rolled over,
    //              and there would be no way to keep anybody off.
    //   baselines  the lifetime total at each quota window's rollover.
    const loaded = this._loadState();
    this.disabled = loaded.disabled;
    this.baselines = loaded.baselines;
  }

  _loadState() {
    const empty = { disabled: Object.create(null), baselines: Object.create(null) };
    let parsed;
    try {
      parsed = JSON.parse(fs.readFileSync(this.cfg.enforcement_file, 'utf8'));
    } catch (err) {
      if (err.code !== 'ENOENT') {
        log.warn(`cannot read ${this.cfg.enforcement_file}`, err.code || err.message);
      }
      return empty;
    }
    if (!parsed || typeof parsed !== 'object') return empty;
    // Null-prototype: a user name of `__proto__` must look up nothing rather
    // than find a function.
    return {
      disabled: (parsed.disabled && typeof parsed.disabled === 'object')
        ? Object.assign(Object.create(null), parsed.disabled) : Object.create(null),
      baselines: (parsed.baselines && typeof parsed.baselines === 'object')
        ? Object.assign(Object.create(null), parsed.baselines) : Object.create(null),
    };
  }

  _saveState() {
    const tmp = `${this.cfg.enforcement_file}.tmp`;
    const body = JSON.stringify({ disabled: this.disabled, baselines: this.baselines }, null, 2);
    try {
      fs.mkdirSync(path.dirname(this.cfg.enforcement_file), { recursive: true, mode: 0o750 });
      fs.writeFileSync(tmp, body, { mode: 0o600 });
      // Renamed over rather than written in place: a failed write must not
      // truncate the record of who this job disabled, and a reader must never
      // catch the middle of one.
      fs.renameSync(tmp, this.cfg.enforcement_file);
    } catch (err) {
      log.error(`cannot write ${this.cfg.enforcement_file}`, err.code || err.message);
      try { fs.unlinkSync(tmp); } catch { /* the temp file may not exist */ }
    }
  }

  start() {
    if (!this.cfg.enforce_enabled) {
      log.warn('quota and expiry enforcement is switched off in the configuration');
      return;
    }
    if (this.timer) return;
    // Once at start-up, so a restart does not leave an expired account live for
    // a whole interval.
    this.runOnce().catch((err) => log.error('enforcement run failed', err.message));
    this.timer = setInterval(() => {
      this.runOnce().catch((err) => log.error('enforcement run failed', err.message));
    }, this.cfg.enforce_interval_ms);
    if (typeof this.timer.unref === 'function') this.timer.unref();
  }

  stop() {
    if (this.timer) clearInterval(this.timer);
    this.timer = null;
  }

  /**
   * One pass. Returns a summary the panel renders:
   *
   *   { checked, disabled[], reEnabled[], revoked[], quotaSkipped,
   *     stillConnected, baselinesReset, errors[] }
   *
   * `stillConnected` is the honest measure of what flag-only enforcement did not
   * achieve: accounts this job disabled that still hold active credentials.
   */
  async runOnce() {
    if (this.running) return this.lastRun;   // a slow pass must not overlap itself
    this.running = true;

    const summary = {
      startedAt: Math.floor(Date.now() / 1000),
      checked: 0,
      disabled: [],
      reEnabled: [],
      revoked: [],
      quotaSkipped: 0,
      stillConnected: 0,
      baselinesReset: 0,
      errors: [],
      // Distinguishes "nothing to do" from "could not look", which a summary of
      // all zeroes otherwise cannot.
      snapshotAge: null,
    };

    try {
      const snapshot = this.collector && this.collector.snapshot;
      if (!snapshot || !Array.isArray(snapshot.users)) {
        // No successful status read yet. Enforcing against a list we do not have
        // would mean enforcing against an empty one, which reads as "nobody is
        // over quota" — the failure that looks exactly like success.
        summary.errors.push('no status snapshot yet — nothing was enforced this run');
        log.warnOnce('enforce-no-snapshot',
          'enforcement has no status snapshot yet, so nothing was checked');
        return summary;
      }
      summary.snapshotAge = snapshot.stamp
        ? Math.max(0, Math.floor(Date.now() / 1000) - snapshot.stamp) : null;

      const usage = usageFromStore(this.store);
      const now = new Date();
      const nowMs = now.getTime();
      let stateDirty = false;

      for (const user of snapshot.users) {
        summary.checked += 1;

        const expired = isExpired(user.expiresAt, nowMs);

        // ── Quota: three states, not two ──────────────────────────────────────
        let overQuota = false;
        if (user.quotaBytes !== null && user.quotaBytes !== undefined) {
          const lifetime = usage.get(user.name);
          if (typeof lifetime !== 'number' || !Number.isFinite(lifetime)) {
            summary.quotaSkipped += 1;
          } else {
            const start = windowStart(user.quotaReset, now);
            let used = lifetime;

            if (start !== null) {
              const held = Object.hasOwn(this.baselines, user.name)
                ? this.baselines[user.name] : null;

              if (!held || held.windowStart !== start) {
                this.baselines[user.name] = { windowStart: start, bytes: lifetime };
                stateDirty = true;
                used = 0;
              } else if (lifetime < held.bytes) {
                // See the header: the durable total went backwards, so the
                // baseline is describing a history that no longer exists.
                this.baselines[user.name] = { windowStart: start, bytes: lifetime };
                stateDirty = true;
                summary.baselinesReset += 1;
                used = 0;
                log.warn(
                  `usage for "${user.name}" is below its window baseline — the durable ` +
                  'totals were reset or restored. The baseline was re-taken; this window ' +
                  'under-reports rather than enforcing against a figure that no longer exists.',
                );
              } else {
                used = lifetime - held.bytes;
              }
            }
            overQuota = used >= user.quotaBytes;
          }
        }

        const reason = expired ? 'expiry' : (overQuota ? 'quota' : null);
        const previously = Object.hasOwn(this.disabled, user.name) ? this.disabled[user.name] : null;
        // `enabled` is a tri-state in the record parser: true, false, or null for
        // a flag it could not read. Only an explicit `true` counts as on — an
        // unreadable flag must not be treated as "let them in".
        const isEnabled = user.enabled === true;

        if (reason && isEnabled) {
          await this._disable(user, reason, summary);
          continue;
        }

        // ── Re-enable ─────────────────────────────────────────────────────────
        // Only an account THIS JOB disabled, only for a quota, and only now that
        // the window has rolled over and it is back under. Never for an expiry —
        // an expiry does not roll over, and an account whose date was extended is
        // switched back on by the operator who extended it. And never an account
        // the operator disabled: that is what the state file is for.
        if (!reason && !isEnabled && previously && previously.reason === 'quota') {
          await this._reEnable(user, summary);
          continue;
        }

        if (reason && !isEnabled && (user.activeCreds || 0) > 0) {
          summary.stillConnected += 1;
        }

        // Cleared once the reason is gone and the account is on again, so a later
        // manual disable is never mistaken for one of ours.
        if (!reason && isEnabled && previously) {
          delete this.disabled[user.name];
          stateDirty = true;
        }
      }

      if (stateDirty) this._saveState();
    } finally {
      this.running = false;
      this.lastRun = summary;
    }

    if (summary.stillConnected > 0) {
      log.warn(
        `${summary.stillConnected} disabled account(s) still hold active credentials. ` +
        'Disabling is a policy flag; it does not end a session that is already up. ' +
        'Revoke those credentials, or set enforce_quota_revoke / enforce_expiry_revoke.',
      );
    }
    if (summary.quotaSkipped > 0) {
      log.warnOnce('enforce-quota-skipped',
        `no usage reading for ${summary.quotaSkipped} account(s) that have a quota — ` +
        'those were not checked. A missing reading is not a zero.');
    }
    return summary;
  }

  async _disable(user, reason, summary) {
    try {
      const { details } = await this.privileged.userDisable(user.name, { actor: ACTOR });
      this.disabled[user.name] = { reason, at: Math.floor(Date.now() / 1000) };
      this._saveState();
      summary.disabled.push({ name: user.name, reason });

      // The helper looked and reported whether disabling actually cut access.
      // Passed through rather than re-derived here.
      const stillActive = Number.parseInt(details.active_credentials ?? '0', 10) || 0;
      if (stillActive > 0) summary.stillConnected += 1;

      this.audit.write({
        actor: ACTOR, ip: null, verb: 'user-disable', target: user.name,
        result: 'ok', message: `enforce.${reason}`,
        detail: { reason, activeCredentials: stillActive },
      });

      const revoke = reason === 'quota'
        ? this.cfg.enforce_quota_revoke
        : this.cfg.enforce_expiry_revoke;
      if (revoke && stillActive > 0) await this._revokeAll(user, reason, summary);
    } catch (err) {
      summary.errors.push(`${user.name}: ${err.message}`);
      this.audit.write({
        actor: ACTOR, ip: null, verb: 'user-disable', target: user.name,
        result: 'error', code: err.code ?? null, message: err.message,
      });
    }
  }

  /**
   * Revoke every active credential this user holds.
   *
   * The credential list comes from the snapshot, so the ids are the ones the
   * services themselves reported — and the owning service is resolved by the
   * helper from the register, not passed from here. Nothing in this file learns
   * which protocol any of them is.
   */
  async _revokeAll(user, reason, summary) {
    const snapshot = this.collector.snapshot;
    const mine = [];
    for (const adapter of snapshot.adapters || []) {
      for (const cred of adapter.creds || []) {
        if (cred.user === user.name && cred.state === 'active') {
          mine.push({ id: cred.id, service: adapter.tag });
        }
      }
    }

    for (const cred of mine) {
      try {
        await this.privileged.credRevoke(cred.id, cred.service, { actor: ACTOR });
        summary.revoked.push({ name: user.name, cred: cred.id });
        this.audit.write({
          actor: ACTOR, ip: null, verb: 'cred-revoke', target: cred.id,
          result: 'ok', message: `enforce.${reason}`, detail: { user: user.name },
        });
      } catch (err) {
        summary.errors.push(`${cred.id}: ${err.message}`);
        this.audit.write({
          actor: ACTOR, ip: null, verb: 'cred-revoke', target: cred.id,
          result: 'error', code: err.code ?? null, message: err.message,
        });
      }
    }
  }

  async _reEnable(user, summary) {
    try {
      await this.privileged.userEnable(user.name, { actor: ACTOR });
      delete this.disabled[user.name];
      this._saveState();
      summary.reEnabled.push(user.name);
      this.audit.write({
        actor: ACTOR, ip: null, verb: 'user-enable', target: user.name,
        result: 'ok', message: 'enforce.quota_window_reset',
      });
    } catch (err) {
      summary.errors.push(`${user.name}: ${err.message}`);
      this.audit.write({
        actor: ACTOR, ip: null, verb: 'user-enable', target: user.name,
        result: 'error', code: err.code ?? null, message: err.message,
      });
    }
  }
}

module.exports = { Enforcer, usageFromStore, windowStart, isExpired, ACTOR };
