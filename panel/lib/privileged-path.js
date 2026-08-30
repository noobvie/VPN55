'use strict';
//
// panel/lib/privileged-path.js — one question, asked about both privileged
// programs: can the panel replace the thing it is about to ask root to run?
//
// There are two of them and they arrived a phase apart — `vpn55.sh --status`
// in Phase 5 and `helper/vpnctl` in Phase 6 — so the check lives here rather
// than in either module. It is exactly the sort of check that gets written once,
// copied once, and then fixed in one copy.
//
// ── Why it matters more than it looks ────────────────────────────────────────
//
// A NOPASSWD sudo rule on a file this process can rewrite is not a restricted
// privilege. It is root, reachable by writing a script into that path and
// waiting for the next call. The same is true of every directory on the way to
// it: being able to replace a directory is being able to replace what is inside
// it. So the whole chain up to `/` is checked, not just the file.
//
// `fs.accessSync(W_OK)` is the honest form of the question — it accounts for
// ownership, group membership, and the ACLs and capabilities that a hand-rolled
// mode-bit comparison silently misses. The one case it answers uselessly is
// root, for whom everything is writable; that case gets its own sentence,
// because a panel running as root has a different and larger problem.
//
// This is a BACKSTOP for a deployment mistake, not a substitute for getting the
// ownership right. deploy/sudoers.d/vpn55-panel says how.

const fs = require('node:fs');
const path = require('node:path');

/**
 * @param {string} target   the program a sudo rule names
 * @param {string} [label]  what to call it in the message
 * @returns {string[]}      problem sentences; empty means good
 */
function writabilityProblems(target, label = target) {
  const problems = [];

  const isRoot = typeof process.getuid === 'function' && process.getuid() === 0;
  if (isRoot) {
    problems.push(
      'the panel is running as root. It is meant to be an unprivileged service ' +
      'that reaches root only through a pinned sudo rule, so that a flaw in it ' +
      'is not a flaw in the host (docs/security-model.md §1, level 3). Give it ' +
      'its own user in the systemd unit.');
    return problems;
  }

  const chain = [target];
  let dir = path.dirname(path.resolve(target));
  for (;;) {
    chain.push(dir);
    const up = path.dirname(dir);
    if (up === dir) break;
    dir = up;
  }

  for (const entry of chain) {
    let writable = false;
    try {
      fs.accessSync(entry, fs.constants.W_OK);
      writable = true;
    } catch {
      writable = false;
    }
    if (!writable) continue;
    problems.push(
      `${entry} is writable by the user this panel runs as. The sudo rule lets ` +
      `this process run ${label} as root, so being able to replace it — or any ` +
      'directory above it — is being able to run anything as root. Own it ' +
      'root:root and take the write bit off (deploy/sudoers.d/vpn55-panel).');
  }
  return problems;
}

/**
 * The file exists, is a regular file, and nothing on the way to it is writable
 * by this process. `settingName` is the panel.conf key, because "which line do I
 * edit" is the next thing whoever reads the message needs.
 */
function programProblems(target, { settingName, label = target }) {
  const problems = [];

  let st;
  try {
    st = fs.statSync(target);
  } catch (err) {
    problems.push(
      `${target}: ${err.code === 'ENOENT' ? 'not found' : err.code || err.message}. ` +
      `This is the \`${settingName}\` setting in panel.conf, and it must be the path ` +
      'the sudoers rule names — not the copy in the source tree.');
    return problems;
  }

  if (!st.isFile()) {
    problems.push(`${target} is not a regular file`);
    return problems;
  }

  problems.push(...writabilityProblems(target, label));
  return problems;
}

module.exports = { writabilityProblems, programProblems };
