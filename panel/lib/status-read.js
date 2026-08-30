'use strict';
//
// panel/lib/status-read.js — the panel's ONE privileged read.
//
// ── Why this is not part of privileged.js ────────────────────────────────────
//
// privileged.js says of itself that it is the only caller of helper/vpnctl, and
// that is a property worth keeping true: it is what makes "what can a
// compromised panel change?" answerable by reading one short list of verbs.
// This module calls a different program, under a different sudo rule, and
// changes nothing. Folding the two together would mean the write helper's file
// header stopped being true, and would put the read path — which every build
// from Phase 5 onward needs, including one with no write actions at all —
// behind the same review surface as the seven verbs that alter the host.
//
// Two modules, two sudoers lines, two sentences. The split is the documentation.
//
// ── What it runs ─────────────────────────────────────────────────────────────
//
//     sudo -n -- /usr/local/lib/vpn55/vpn55.sh --status
//
// A FIXED argv with no interpolation of anything, which is what lets the sudoers
// rule pin the entire command line. That pinning is the whole control, and it is
// load-bearing in a way that is easy to miss: the same binary with NO argument
// is the interactive installer, which is unrestricted root. A sudoers rule
// written against the path alone — `vpn55 ALL=(root) NOPASSWD: /usr/…/vpn55.sh`
// — grants that too. deploy/sudoers.d/vpn55-panel pins the argument; see the
// comment there, and do not relax it.
//
// ── "Read-only" as far as it actually goes ───────────────────────────────────
//
// This changes no server configuration, adds no user, and touches no key. It is
// not literally inert, and saying so would be the kind of claim that is believed
// until it is not: each adapter's `_status` sweeps its own expired credential
// spool as it reports, which is how the hand-off window in
// docs/security-model.md §6.1 is enforced at all. Nothing that is in service
// changes. Something already past its expiry may be tidied away.

const { spawn } = require('node:child_process');
const fs = require('node:fs');
const path = require('node:path');

const { programProblems } = require('./privileged-path');

// The one argument. Named as a constant because it appears in the spawn, in the
// preflight message and in the string the service logs at startup, and those
// three drifting apart is how a sudoers rule ends up pinning a command nobody
// runs.
const STATUS_ARG = '--status';

const MAX_OUTPUT_BYTES = 8 * 1024 * 1024;

/**
 * `kind` is a short stable word, not a sentence: the collector records it as an
 * event and the UI translates it. The human-readable message rides alongside for
 * the log, where a sentence is what is wanted.
 */
class StatusError extends Error {
  constructor(message, { kind = 'failed', detail = null } = {}) {
    super(message);
    this.name = 'StatusError';
    this.kind = kind;
    this.detail = detail;
  }
}

const KINDS = Object.freeze([
  'missing',      // the installer is not where the config says it is
  'permission',   // sudo refused, or the file cannot be executed
  'timeout',      // it did not finish inside status_timeout_ms
  'exit',         // it ran and failed
  'empty',        // it succeeded and said nothing, which is not a valid stream
  'failed',       // anything else
]);

class StatusReader {
  constructor({ config, warn = () => {} }) {
    this.installer = config.installer;
    this.useSudo = config.use_sudo;
    this.timeoutMs = config.status_timeout_ms;
    this.warn = warn;
  }

  /** The exact command line, for the startup log and for error messages. */
  statusCommandLine() {
    return this.useSudo
      ? `sudo -n -- ${this.installer} ${STATUS_ARG}`
      : `${this.installer} ${STATUS_ARG}`;
  }

  /**
   * Everything that can be checked before the first poll, checked before the
   * first poll. A panel that starts and then fails every fifteen seconds looks
   * like a broken host; a panel that refuses to start and says which file is
   * wrong is the same information, delivered where someone is looking.
   *
   * The writability half — "can this process replace the file it is about to ask
   * root to run?" — moved to privileged-path.js in Phase 6, when the write helper
   * became a second program needing the identical check. Returns an array of
   * problem sentences; empty means good.
   */
  preflight() {
    return programProblems(this.installer, {
      settingName: 'installer',
      label: `${this.installer} ${STATUS_ARG}`,
    });
  }

  /**
   * Run it. Resolves with { text, durationMs }.
   *
   * stderr is NOT part of the stream: vpn55.sh prints its human output there
   * and its records on stdout, so mixing them would put a banner in the middle
   * of the data. It is kept for the error message and otherwise dropped.
   */
  readStatus() {
    return new Promise((resolve, reject) => {
      const started = Date.now();

      let cmd = this.installer;
      let args = [STATUS_ARG];
      if (this.useSudo) {
        cmd = 'sudo';
        // -n: never prompt. A rule that asks for a password would block this
        // process against a terminal that does not exist, and the symptom would
        // be a hung poll rather than a misconfigured sudoers.
        args = ['-n', '--', this.installer, STATUS_ARG];
      }

      const child = spawn(cmd, args, {
        // No shell: there is no string for one to parse, so there is nothing to
        // quote and nothing to get wrong.
        shell: false,
        // A fixed, minimal environment, and LC_ALL is part of the fixture rather
        // than an omission. C is the BYTE-TRANSPARENT locale: it makes no
        // character-class or collation decisions, so UTF-8 in the child's output
        // — a Vietnamese setup page, a translated config comment — arrives here
        // as exactly the bytes it left as, and Buffer.toString('utf8') at the
        // other end reassembles it.
        //
        // Pinned rather than inherited, because inheriting means the child's
        // behaviour depends on how the systemd unit happened to be started, and
        // that is not a thing anyone will think to check. Not C.UTF-8 either:
        // it is absent on musl and on older glibc, and a locale that does not
        // exist is a warning on stderr from every tool that notices.
        env: {
          PATH: '/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin',
          LC_ALL: 'C',
        },
        stdio: ['ignore', 'pipe', 'pipe'],
      });

      let out = '';
      let err = '';
      let truncated = false;
      let settled = false;

      const finish = (fn) => (...a) => {
        if (settled) return;
        settled = true;
        clearTimeout(timer);
        fn(...a);
      };

      const timer = setTimeout(() => {
        if (settled) return;
        settled = true;
        child.kill('SIGKILL');
        reject(new StatusError(
          `the status read did not finish within ${this.timeoutMs} ms`,
          { kind: 'timeout' }));
      }, this.timeoutMs);
      if (typeof timer.unref === 'function') timer.unref();

      child.stdout.on('data', (b) => {
        if (out.length >= MAX_OUTPUT_BYTES) { truncated = true; return; }
        out += b.toString('utf8');
      });
      child.stderr.on('data', (b) => {
        if (err.length >= 64 * 1024) return;
        err += b.toString('utf8');
      });

      child.on('error', finish((e) => {
        // ENOENT here is sudo missing, not the installer — the installer's
        // absence was already caught by preflight and would surface as an exit
        // code from sudo. Saying which of the two is missing saves the next
        // person a wrong guess.
        const what = this.useSudo && e.code === 'ENOENT' ? 'sudo' : this.installer;
        reject(new StatusError(`cannot run ${what}: ${e.code || e.message}`, {
          kind: e.code === 'ENOENT' ? 'missing' : 'permission',
        }));
      }));

      child.on('close', finish((code, signal) => {
        const durationMs = Date.now() - started;
        const tail = err.trim().split('\n').slice(-6).join(' | ');

        if (truncated) {
          this.warn(`[status] output exceeded ${MAX_OUTPUT_BYTES} bytes and was truncated`);
        }

        if (signal) {
          return reject(new StatusError(`the status read was killed by ${signal}`,
            { kind: 'failed', detail: tail }));
        }

        if (code !== 0) {
          // sudo's own refusal exits 1 with its complaint on stderr and no
          // records at all. That is a sudoers problem, not a host problem, and
          // it is worth naming because the two look identical from the UI.
          const looksLikeSudo = /sudo:/i.test(err) || /a password is required/i.test(err);
          return reject(new StatusError(
            looksLikeSudo
              ? `sudo refused: ${tail || 'no detail'}. The rule must permit exactly ` +
                `"${this.installer} ${STATUS_ARG}" with NOPASSWD.`
              : `the status read exited ${code}`,
            { kind: looksLikeSudo ? 'permission' : 'exit', detail: tail }));
        }

        if (out.trim() === '') {
          // Exit 0 and nothing on stdout is not an empty host — every run emits
          // at least a stamp record. Treating it as "no adapters" would render a
          // working host as an empty one.
          return reject(new StatusError(
            'the status read succeeded but produced no records at all',
            { kind: 'empty', detail: tail }));
        }

        if (tail) this.warn(`[status] stderr: ${tail}`);
        resolve({ text: out, durationMs });
      }));
    });
  }
}

module.exports = { StatusReader, StatusError, KINDS, STATUS_ARG, MAX_OUTPUT_BYTES };
