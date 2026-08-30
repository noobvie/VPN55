'use strict';

// panel/lib/privileged.js — the ONLY caller of helper/vpnctl.
//
// Nothing else in panel/ may shell out to a privileged command. Keeping that
// surface in one file is what makes "what can a compromised panel do?" a
// question with a short, auditable answer: it can call the eight verbs below,
// with arguments the helper will check again, and nothing else. Seven of them
// change the host; the eighth, `cred-config`, reads one credential's own
// configuration back and is the only verb that decides for itself who may ask
// — see docs/security-model.md §6F and the comment on it in helper/vpnctl.
//
// ── What this module is, and what it is not ───────────────────────────────────
//
// It BUILDS ARGV. It does not sanitize on the helper's behalf. The helper
// validates its own arguments and must not trust this caller — see
// docs/security-model.md §3. The checks here exist so a mistake in the panel
// produces a clear error in the panel's own log instead of a bare exit code from
// a subprocess. If every check in this file were deleted, the security model
// would be unchanged; if the checks in vpnctl were deleted, there would be none.
//
// That distinction is worth holding on to, because the tempting refactor — "the
// caller already validated, the helper can skip it" — is exactly the change that
// turns a defence in depth into a single point of failure, and it looks like
// removing duplication.
//
// ── Three properties of the call itself ───────────────────────────────────────
//
//  1. NO SHELL. spawn() with an argv ARRAY and `shell: false` (the default).
//     There is no string for a shell to parse, so there is nothing to escape and
//     nothing to get wrong. A single `shell: true` here would undo the whole
//     design, which is why CI greps for it.
//
//  2. NO INHERITED ENVIRONMENT. The child gets a fixed, minimal env. vpnctl
//     pins its own paths too — but a caller that forwards `process.env` is one
//     compromised npm postinstall away from setting something the helper reads,
//     and "the callee defends itself" is not a reason to hand it the weapon.
//
//  3. ONE AT A TIME. Calls are serialised through a promise chain. The bash side
//     takes a flock on the registry so concurrent writes are already safe, but
//     serialising here means the panel never has ten root processes in flight
//     because a button was double-clicked, and it makes the audit log's ordering
//     the real ordering.

const { spawn } = require('node:child_process');

const { programProblems } = require('./privileged-path');

// Mirrored from helper/vpnctl. A second copy of the verb list is a thing that
// can drift, so CI asserts these two lists are identical rather than trusting
// that they are — the check costs three lines and the drift would be a verb the
// panel can reach and nobody reviewed.
const VERBS = Object.freeze([
  'user-add',
  'user-remove',
  'user-enable',
  'user-disable',
  'cred-add',
  'cred-revoke',
  'service-restart',
  // Phase 8, and the only one here that reads rather than writes. It is last
  // rather than beside cred-add so that "what can a compromised panel CHANGE?"
  // is still answered by the first seven lines of this list.
  'cred-config',
]);

const MAX_OUTPUT_BYTES = 256 * 1024;

// Convenience mirrors of the helper's validators. See the header: these produce
// better error messages, they are not the control.
const RE_USER = /^[a-z][a-z0-9_-]{1,31}$/;
const RE_CRED = /^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/;
const RE_TAG = /^[a-z][a-z0-9_]{0,31}$/;
const RE_ACTOR = /^[a-z][a-z0-9_-]{1,31}$/;
const RE_OPTION_KEY = /^[a-z][a-z0-9_]{0,31}$/;
const RE_ARTIFACT = /^[a-z][a-z0-9_]{0,31}$/;
// Deliberately the same closed shape vpnctl enforces, and for the same reason:
// on the far side of the call this tag becomes part of a path under
// lib/locales/. A mirror here is a better error message, never the control.
const RE_LOCALE = /^[a-z]{2,3}(-[a-z0-9]{2,8})?$/;

class HelperError extends Error {
  constructor(message, { code = 6, verb = null, target = null, details = {} } = {}) {
    super(message);
    this.name = 'HelperError';
    this.code = code;
    this.verb = verb;
    this.target = target;
    this.details = details;
  }
}

/**
 * Parse the helper's stdout.
 *
 *   result    <ok|error>  <verb>  <target>  <code>  <message>
 *   detail    <key>  <value>
 *   artifact  <id> <label> <filename> <text|base64> <qr> <note>   (cred-config)
 *
 * The first field is the record type, so an unknown record type is SKIPPED
 * rather than misread. That is the contract the whole project's record shapes
 * are built on, and it is what lets the helper grow a new detail without
 * breaking a reader that predates it.
 *
 * `artifact` is a LIST — repeated, order-significant, and therefore not
 * expressible as a `detail`, where a repeated key would silently keep only the
 * last one. It carries no secret: it is the label, file name and encoding of
 * each configuration a credential still has. The bytes travel in
 * `detail body_b64`, and only ever for the one artifact that was asked for.
 */
function parseRecords(stdout) {
  const details = Object.create(null);
  const artifacts = [];
  let result = null;

  for (const line of String(stdout).split('\n')) {
    if (!line) continue;
    const f = line.split('\t');
    if (f[0] === 'artifact' && f[1]) {
      artifacts.push({
        id: f[1],
        label: f[2] || f[1],
        filename: f[3] || '',
        // The contract's own word, carried rather than interpreted. `text`
        // promises the decoded bytes are text, which is what makes a QR
        // meaningful; anything else says they are not.
        encoding: f[4] === 'base64' ? 'base64' : 'text',
        qr: f[5] === '1',
        note: f[6] || '',
      });
    } else if (f[0] === 'result') {
      result = {
        status: f[1] || 'error',
        verb: f[2] || null,
        target: f[3] === '-' ? null : (f[3] || null),
        code: Number.parseInt(f[4], 10),
        message: f[5] || '',
      };
      if (!Number.isInteger(result.code)) result.code = 6;
    } else if (f[0] === 'detail' && f[1]) {
      details[f[1]] = f[2] ?? '';
    }
  }
  return { result, details, artifacts };
}

class Privileged {
  constructor({ config, warn = console.warn }) {
    this.helper = config.helper;
    this.useSudo = config.use_sudo;
    this.timeoutMs = config.helper_timeout_ms;
    this.warn = warn;
    // The serialisation chain. Every call appends to it; a rejected call must
    // not poison the chain for the next one, hence the `.catch` when chaining.
    this._queue = Promise.resolve();
  }

  /** The exact command line, for the startup log and for error messages. */
  commandLine() {
    return this.useSudo ? `sudo -n -- ${this.helper} <verb>` : `${this.helper} <verb>`;
  }

  /**
   * Checked before the first write rather than at the first write.
   *
   * The important half is not "does the file exist" — it is whether this process
   * can REPLACE the file it is about to ask root to run. A NOPASSWD rule on a
   * writable path is not a narrow privilege; it is root with a delay. The check
   * is shared with the status reader, because the two programs need exactly the
   * same guarantee and a copied check is a check that gets fixed in one place.
   *
   * Returns problem sentences; empty means good.
   */
  preflight() {
    return programProblems(this.helper, { settingName: 'helper' });
  }

  /**
   * Run one verb. Resolves with { result, details } on success; rejects with a
   * HelperError carrying the helper's own code and message on failure.
   *
   * `args` are passed as separate argv words, verbatim. They are never
   * concatenated into a string anywhere in this file.
   */
  call(verb, args = [], { actor = null } = {}) {
    if (!VERBS.includes(verb)) {
      return Promise.reject(new HelperError(`refusing an unknown verb: ${verb}`, { code: 2, verb }));
    }
    for (const a of args) {
      if (typeof a !== 'string') {
        return Promise.reject(new HelperError('helper arguments must be strings', { code: 3, verb }));
      }
      // A leading dash would be read as an option by the helper's own parser.
      // Every legitimate argument here starts alphanumeric, so this can only
      // ever catch a panel-side bug — but the bug it catches is "the caller
      // smuggled an option through a value", which is worth catching early.
      if (a.startsWith('-')) {
        return Promise.reject(new HelperError('a helper argument may not start with a dash', { code: 3, verb }));
      }
      if (/[\0\n\r\t]/.test(a)) {
        return Promise.reject(new HelperError('a helper argument may not contain a control character', { code: 3, verb }));
      }
    }
    if (actor !== null && !RE_ACTOR.test(actor)) {
      return Promise.reject(new HelperError('invalid actor name', { code: 3, verb }));
    }

    const run = () => this._spawn(verb, args, actor);
    // The chain continues whether the previous call resolved or rejected.
    const next = this._queue.then(run, run);
    this._queue = next.then(() => undefined, () => undefined);
    return next;
  }

  _spawn(verb, args, actor) {
    return new Promise((resolve, reject) => {
      const argv = [];
      if (actor) argv.push('--actor', actor);
      argv.push(verb, ...args);

      let cmd = this.helper;
      let cmdArgs = argv;
      if (this.useSudo) {
        cmd = 'sudo';
        // -n: never prompt. A sudo rule that asks for a password would otherwise
        // block this process on a terminal that does not exist, and the failure
        // would look like a hung request rather than a misconfigured sudoers.
        cmdArgs = ['-n', '--', this.helper, ...argv];
      }

      const child = spawn(cmd, cmdArgs, {
        // No shell: see property 1 in the header.
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
        //
        // No inherited environment otherwise: see property 2. PATH is here
        // because sudo has to be found. LC_ALL survives the hop because sudo's
        // default env_keep passes LC_* through even under env_reset.
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

      const timer = setTimeout(() => {
        if (settled) return;
        settled = true;
        child.kill('SIGKILL');
        reject(new HelperError('the privileged helper timed out', { code: 6, verb }));
      }, this.timeoutMs);
      if (typeof timer.unref === 'function') timer.unref();

      const cap = (buf, into) => {
        if (into.length + buf.length > MAX_OUTPUT_BYTES) {
          truncated = true;
          return into + buf.slice(0, Math.max(0, MAX_OUTPUT_BYTES - into.length));
        }
        return into + buf;
      };

      child.stdout.on('data', (b) => { out = cap(b.toString('utf8'), out); });
      child.stderr.on('data', (b) => { err = cap(b.toString('utf8'), err); });

      child.on('error', (e) => {
        if (settled) return;
        settled = true;
        clearTimeout(timer);
        reject(new HelperError(`cannot run the privileged helper: ${e.code || e.message}`, { code: 6, verb }));
      });

      child.on('close', (status) => {
        if (settled) return;
        settled = true;
        clearTimeout(timer);

        if (truncated) this.warn(`[privileged] output from ${verb} was truncated at ${MAX_OUTPUT_BYTES} bytes`);
        if (err.trim()) this.warn(`[privileged] ${verb}: ${err.trim().split('\n').slice(-4).join(' | ')}`);

        const { result, details, artifacts } = parseRecords(out);

        // The helper emits exactly one result record on every path, including
        // its own unexpected exit. Nothing here means the helper never ran or
        // was killed — sudo refusing, for instance, which prints to stderr and
        // exits 1 with no record at all. Reporting that as a generic failure
        // would send whoever debugs it looking inside vpnctl, so it says which
        // half is missing.
        if (!result) {
          return reject(new HelperError(
            status === 0
              ? 'the privileged helper produced no result record'
              : `the privileged helper did not run (exit ${status})`,
            { code: 6, verb, details },
          ));
        }

        if (result.status !== 'ok') {
          return reject(new HelperError(result.message || 'the privileged action failed', {
            code: result.code,
            verb,
            target: result.target,
            details,
          }));
        }
        resolve({ result, details, artifacts });
      });
    });
  }

  // ── The eight verbs, one method each ───────────────────────────────────────
  // Named methods rather than a generic `call(verb, …)` at the call sites, so
  // that grepping the panel for what it can do as root returns this list and not
  // a variable.

  userAdd(name, fields = {}, opts = {}) {
    if (!RE_USER.test(name)) return Promise.reject(new HelperError('invalid user name', { code: 3, verb: 'user-add' }));
    const args = [name];
    for (const key of ['quota_bytes', 'expires_at', 'conn_limit', 'quota_reset']) {
      if (!Object.hasOwn(fields, key)) continue;
      const v = fields[key];
      // null and '' both mean the registry's null — unlimited / never. They are
      // sent as an empty value rather than omitted, because omitting is "leave
      // it alone" and the caller asked for "clear it".
      args.push(`${key}=${v === null || v === undefined ? '' : String(v)}`);
    }
    return this.call('user-add', args, opts);
  }

  userRemove(name, opts = {}) {
    if (!RE_USER.test(name)) return Promise.reject(new HelperError('invalid user name', { code: 3, verb: 'user-remove' }));
    return this.call('user-remove', [name], opts);
  }

  userEnable(name, opts = {}) {
    if (!RE_USER.test(name)) return Promise.reject(new HelperError('invalid user name', { code: 3, verb: 'user-enable' }));
    return this.call('user-enable', [name], opts);
  }

  userDisable(name, opts = {}) {
    if (!RE_USER.test(name)) return Promise.reject(new HelperError('invalid user name', { code: 3, verb: 'user-disable' }));
    return this.call('user-disable', [name], opts);
  }

  credAdd(name, service, options = {}, opts = {}) {
    if (!RE_USER.test(name)) return Promise.reject(new HelperError('invalid user name', { code: 3, verb: 'cred-add' }));
    if (!RE_TAG.test(service)) return Promise.reject(new HelperError('invalid service tag', { code: 3, verb: 'cred-add' }));
    const args = [name, service];
    for (const [k, v] of Object.entries(options)) {
      if (!RE_OPTION_KEY.test(k)) {
        return Promise.reject(new HelperError(`invalid option key '${k}'`, { code: 3, verb: 'cred-add' }));
      }
      // The VALUE is opaque here by contract — this module must not know what
      // any adapter's options mean. It becomes one argv word and the adapter
      // decides whether it is acceptable.
      args.push(`${k}=${v === null || v === undefined ? '' : String(v)}`);
    }
    return this.call('cred-add', args, opts);
  }

  credRevoke(credId, service = null, opts = {}) {
    if (!RE_CRED.test(credId)) return Promise.reject(new HelperError('invalid credential id', { code: 3, verb: 'cred-revoke' }));
    const args = [credId];
    if (service) {
      if (!RE_TAG.test(service)) return Promise.reject(new HelperError('invalid service tag', { code: 3, verb: 'cred-revoke' }));
      args.push(service);
    }
    return this.call('cred-revoke', args, opts);
  }

  serviceRestart(service, opts = {}) {
    if (!RE_TAG.test(service)) return Promise.reject(new HelperError('invalid service tag', { code: 3, verb: 'service-restart' }));
    return this.call('service-restart', [service], opts);
  }

  /**
   * One credential's own configuration, for the person who holds it.
   *
   * The USER is an argument, and that is the point of this method rather than
   * an accident of its signature. The helper checks the register and refuses
   * unless that person holds that credential — so the portal's own ownership
   * check is a courtesy that produces a better error message, and the answer to
   * "can a user read somebody else's config by changing an id in a URL" does not
   * depend on any code in this process being right.
   *
   * Resolves with { result, details, artifacts }: `artifacts` is everything the
   * credential still has, and `details.body_b64` is the base64 of the one that
   * was asked for. `locale` is the language the handed-over text is written in —
   * the person receiving a configuration and the operator who issued it are
   * usually not the same person and often do not read the same language.
   */
  credConfig(user, credId, artifact = null, locale = null, opts = {}) {
    if (!RE_USER.test(user)) return Promise.reject(new HelperError('invalid user name', { code: 3, verb: 'cred-config' }));
    if (!RE_CRED.test(credId)) return Promise.reject(new HelperError('invalid credential id', { code: 3, verb: 'cred-config' }));
    const args = [user, credId];
    // Positional, so naming a locale means naming an artifact. The empty string
    // is how "the adapter's own default" is said in an argv word that has to be
    // there — vpnctl treats it exactly as an omitted argument.
    if (artifact || locale) {
      if (artifact && !RE_ARTIFACT.test(artifact)) {
        return Promise.reject(new HelperError('invalid artifact id', { code: 3, verb: 'cred-config' }));
      }
      args.push(artifact || '');
    }
    if (locale) {
      if (!RE_LOCALE.test(locale)) {
        return Promise.reject(new HelperError('invalid locale', { code: 3, verb: 'cred-config' }));
      }
      args.push(locale);
    }
    return this.call('cred-config', args, opts);
  }
}

module.exports = { Privileged, HelperError, VERBS, parseRecords, MAX_OUTPUT_BYTES };
