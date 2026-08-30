'use strict';

// panel/lib/audit.js — the panel's write log.
//
// Every write is logged: actor, verb, target, result. For a VPN that is not
// optional, and "every write" includes the ones that did not happen — a refused
// attempt is the record that matters most, because a successful revocation looks
// the same whoever asked for it while a REFUSED one is the first sign that
// someone is trying.
//
// ── There are two audit logs, and that is deliberate ──────────────────────────
//
//   this one            /var/lib/vpn55/panel/audit.log, owned by the panel user
//   helper/vpnctl's     /var/log/vpn55/vpnctl.log, root-only
//
// They are not redundant. This one is written by the process an attacker would
// already control, so it is a record of what the panel BELIEVES happened — rich,
// useful, and worth exactly nothing once the panel is compromised, because
// anything that can write it can rewrite it. The helper's log is written by root
// after the argument checks and cannot be edited from the panel at all: it is
// narrower (seven verbs, no HTTP context) and it is the one that still means
// something afterwards.
//
// A panel that kept only the first would be able to hide its own actions. A
// helper that kept only the second could not say which administrator, from which
// address, asked for it. Both, and neither is the backup of the other.
//
// ── Format ────────────────────────────────────────────────────────────────────
// One JSON object per line. JSONL rather than the project's TSV because these
// records carry free-text messages and a variable set of fields, and because the
// consumer is the panel's own reader. Every value is JSON-encoded, so a newline
// inside a message cannot forge a second record — which is the failure mode a
// hand-rolled delimited log has and this one does not.

const fs = require('node:fs');
const path = require('node:path');

const MAX_BYTES = 8 * 1024 * 1024;   // rotate at 8 MB
const KEEP = 3;                      // audit.log.1 … audit.log.3

class Audit {
  constructor({ file, warn = console.warn }) {
    this.file = file;
    this.warn = warn;
    this._ensured = false;
  }

  _ensure() {
    if (this._ensured) return true;
    try {
      fs.mkdirSync(path.dirname(this.file), { recursive: true, mode: 0o700 });
      this._ensured = true;
      return true;
    } catch (err) {
      this.warn(`[audit] cannot create ${path.dirname(this.file)}: ${err.code || err.message}`);
      return false;
    }
  }

  _rotate() {
    let size = 0;
    try {
      size = fs.statSync(this.file).size;
    } catch {
      return;   // no file yet, nothing to rotate
    }
    if (size < MAX_BYTES) return;

    try {
      // Oldest first, so nothing is overwritten before it has been shifted.
      for (let i = KEEP - 1; i >= 1; i--) {
        const from = `${this.file}.${i}`;
        const to = `${this.file}.${i + 1}`;
        if (fs.existsSync(from)) fs.renameSync(from, to);
      }
      fs.renameSync(this.file, `${this.file}.1`);
    } catch (err) {
      this.warn(`[audit] rotation failed: ${err.code || err.message}`);
    }
  }

  /**
   * Write one record.
   *
   * Never throws, and never blocks a write action from completing. An unwritable
   * audit log is a serious condition and it is reported loudly — but refusing a
   * revocation because the log could not be written gets the priority backwards
   * for a control whose job is cutting off access. The right response to a
   * broken log is an operator fixing it, not access staying live.
   */
  write(record) {
    const line = JSON.stringify({
      ts: new Date().toISOString(),
      actor: record.actor || null,
      ip: record.ip || null,
      verb: record.verb || null,
      target: record.target ?? null,
      result: record.result || 'unknown',
      code: record.code ?? null,
      message: record.message || null,
      ...(record.detail ? { detail: record.detail } : {}),
    });

    if (!this._ensure()) return;
    this._rotate();

    try {
      fs.appendFileSync(this.file, line + '\n', { mode: 0o600 });
    } catch (err) {
      this.warn(`[audit] cannot append to ${this.file}: ${err.code || err.message}`);
    }
  }

  /**
   * The most recent `limit` records, newest first.
   *
   * Reads the whole current file, which is bounded by MAX_BYTES above. A
   * streaming tail would be better at 8 MB and is not worth the code at this
   * size; if the cap ever grows, this is the function that has to change with it.
   */
  tail(limit = 200) {
    let text = '';
    try {
      text = fs.readFileSync(this.file, 'utf8');
    } catch (err) {
      if (err.code !== 'ENOENT') this.warn(`[audit] cannot read: ${err.code || err.message}`);
      return [];
    }
    const out = [];
    const lines = text.split('\n');
    for (let i = lines.length - 1; i >= 0 && out.length < limit; i--) {
      const line = lines[i].trim();
      if (!line) continue;
      try {
        out.push(JSON.parse(line));
      } catch {
        // A truncated final line after a crash. Skipped rather than reported —
        // one unparseable record must not make the whole log unreadable.
      }
    }
    return out;
  }
}

module.exports = { Audit, MAX_BYTES, KEEP };
