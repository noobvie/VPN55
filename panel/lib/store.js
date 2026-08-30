'use strict';
//
// panel/lib/store.js — the panel's own durable state, written atomically.
//
// This holds exactly two things the panel cannot rebuild by asking the host:
// accumulated traffic totals and the event history. Everything else is read
// fresh from the adapters every poll, because on-disk server config is the
// source of truth and a second copy of it here would drift from it.
//
// ⚠ The totals are DURABLE STATE, not a cache. Losing this file resets every
// user's lifetime usage to zero — the counters on the host only ever hold the
// current session. It belongs in a backup; it does not belong in /tmp.
//
// Atomic write: temp file in the same directory, fsync, rename. A rename within
// a directory is atomic, so a reader either sees the whole previous version or
// the whole new one — never the truncated middle of a crashed write, which is
// exactly what a plain overwrite of a JSON file produces under power loss.

const fs = require('node:fs');
const path = require('node:path');
const log = require('./log');

const VERSION = 1;

function emptyState() {
  return {
    version: VERSION,
    // key: `${tag}\u0000${credId}`
    counters: Object.create(null),
    // key: tag
    services: Object.create(null),
    events: [],
    lastPollAt: null,
  };
}

class Store {
  constructor(dir, filename = 'state.json') {
    this.dir = dir;
    this.file = path.join(dir, filename);
    this.state = emptyState();
    this.dirty = false;
  }

  ensureDir() {
    fs.mkdirSync(this.dir, { recursive: true, mode: 0o750 });
  }

  load() {
    let raw;
    try {
      raw = fs.readFileSync(this.file, 'utf8');
    } catch (err) {
      if (err.code === 'ENOENT') {
        log.info('no saved state yet — traffic totals start from this run', this.file);
        return this.state;
      }
      throw err;
    }

    let parsed;
    try {
      parsed = JSON.parse(raw);
    } catch (err) {
      // Refusing beats silently starting from zero. A corrupt state file that
      // is quietly replaced takes every historical total with it and reports
      // nothing; a refusal is recoverable, because the file is still there.
      throw new Error(
        `${this.file}: unreadable (${err.message}). Traffic totals live here and ` +
        'are not recoverable from the host, so this is not being replaced ' +
        'automatically. Move it aside deliberately to start counting again.');
    }

    if (parsed === null || typeof parsed !== 'object' || Array.isArray(parsed)) {
      throw new Error(`${this.file}: top level must be an object`);
    }
    if (parsed.version !== VERSION) {
      throw new Error(
        `${this.file}: written by state version ${parsed.version}, this build ` +
        `understands ${VERSION}`);
    }

    this.state = {
      version: VERSION,
      counters: Object.assign(Object.create(null), parsed.counters || {}),
      services: Object.assign(Object.create(null), parsed.services || {}),
      events: Array.isArray(parsed.events) ? parsed.events : [],
      lastPollAt: typeof parsed.lastPollAt === 'number' ? parsed.lastPollAt : null,
    };
    log.info(`loaded state — ${Object.keys(this.state.counters).length} counter(s), ` +
             `${this.state.events.length} event(s)`);
    return this.state;
  }

  markDirty() {
    this.dirty = true;
  }

  /** Atomic replace. Returns true when something was written. */
  flush(force = false) {
    if (!this.dirty && !force) return false;
    this.ensureDir();
    const tmp = `${this.file}.${process.pid}.tmp`;
    const body = JSON.stringify(this.state);
    let fd;
    try {
      fd = fs.openSync(tmp, 'wx', 0o640);
      fs.writeSync(fd, body);
      fs.fsyncSync(fd);
    } finally {
      if (fd !== undefined) fs.closeSync(fd);
    }
    fs.renameSync(tmp, this.file);
    this.dirty = false;
    return true;
  }
}

module.exports = { Store, emptyState, VERSION };
