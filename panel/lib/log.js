'use strict';
//
// panel/lib/log.js — leveled logging to stdout/stderr.
//
// The panel runs under systemd, so stdout and stderr ARE the log. Nothing here
// opens a file, rotates anything, or needs a directory to exist before the
// process can complain about a directory not existing.
//
// One rule with teeth: a missing translation key logs (i18n.js calls warnOnce).
// Silent blanks are worse than an untranslated string, and the only way anyone
// finds out about one is if this file says so.

const LEVELS = { error: 0, warn: 1, info: 2, debug: 3 };

let threshold = LEVELS.info;

function setLevel(name) {
  if (Object.prototype.hasOwnProperty.call(LEVELS, name)) threshold = LEVELS[name];
}

function emit(level, msg, extra) {
  if (LEVELS[level] > threshold) return;
  const line = `${new Date().toISOString()} ${level.toUpperCase().padEnd(5)} ${msg}`;
  const stream = level === 'error' || level === 'warn' ? process.stderr : process.stdout;
  if (extra === undefined) stream.write(line + '\n');
  else stream.write(`${line} ${safe(extra)}\n`);
}

function safe(value) {
  try {
    return typeof value === 'string' ? value : JSON.stringify(value);
  } catch {
    return String(value);
  }
}

// Deduplicated warnings. A poll loop that warns every 15 seconds about the same
// permanent condition buries the one that just started.
const seen = new Set();
function warnOnce(key, msg, extra) {
  if (seen.has(key)) return;
  seen.add(key);
  emit('warn', msg, extra);
}
function clearOnce(key) {
  seen.delete(key);
}

module.exports = {
  setLevel,
  error: (m, e) => emit('error', m, e),
  warn: (m, e) => emit('warn', m, e),
  info: (m, e) => emit('info', m, e),
  debug: (m, e) => emit('debug', m, e),
  warnOnce,
  clearOnce,
};
