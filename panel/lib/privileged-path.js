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
// ── And the same is true of the code that file SOURCES ───────────────────────
//
// ⚠ Neither program is one file. `helper/vpnctl` sources eight libraries out of
// lib/ and then every lib/proto_*.sh adapter beside them, as root, before any
// verb does anything; `vpn55.sh` sources the same tree. Being able to write
// lib/ui.sh is being able to run anything as root, by exactly the argument two
// paragraphs up — but lib/ is a SIBLING of helper/, not an ancestor of the
// binary, so walking the target's parents does not reach it. It was not checked
// at all until that was noticed, which meant a group-writable install tree
// passed this check and reported the deployment as fine.
//
// So the caller names the directory its program sources from, and every `*.sh`
// in it is checked as well. The caller names it rather than this file deriving
// it, because the two programs resolve it differently — vpnctl from its parent
// (`helper/../lib`) and vpn55.sh from its own directory — and a guess here that
// silently resolved to a directory that does not exist would check nothing
// while looking like it had checked something.
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

/** Is this process root? Then everything is writable and the answer is useless. */
function runningAsRoot() {
  return typeof process.getuid === 'function' && process.getuid() === 0;
}

const ROOT_PROBLEM =
  'the panel is running as root. It is meant to be an unprivileged service ' +
  'that reaches root only through a pinned sudo rule, so that a flaw in it ' +
  'is not a flaw in the host (docs/security-model.md §1, level 3). Give it ' +
  'its own user in the systemd unit.';

/** A path and every directory above it, up to `/`. */
function ancestry(target) {
  const resolved = path.resolve(target);
  const chain = [resolved];
  let dir = path.dirname(resolved);
  for (;;) {
    chain.push(dir);
    const up = path.dirname(dir);
    if (up === dir) break;
    dir = up;
  }
  return chain;
}

/**
 * Which of these paths this process can write. Deduplicated by resolved path so
 * that two chains sharing ancestors — and lib/ shares all but one of vpnctl's —
 * do not report the same directory twice.
 *
 * @param {string[]} paths
 * @param {Set<string>} [seen]  carried across calls to keep that dedup honest
 */
function writableAmong(paths, seen = new Set()) {
  const found = [];
  for (const p of paths) {
    const abs = path.resolve(p);
    if (seen.has(abs)) continue;
    seen.add(abs);
    try {
      fs.accessSync(abs, fs.constants.W_OK);
    } catch {
      continue;
    }
    found.push(abs);
  }
  return found;
}

/** The sentence for a writable program, or a directory on the way to it. */
function programSentence(entry, label) {
  return `${entry} is writable by the user this panel runs as. The sudo rule ` +
    `lets this process run ${label} as root, so being able to replace it — or ` +
    'any directory above it — is being able to run anything as root. Own it ' +
    'root:root and take the write bit off (deploy/sudoers.d/vpn55-panel).';
}

/**
 * @param {string} target   the program a sudo rule names
 * @param {string} [label]  what to call it in the message
 * @returns {string[]}      problem sentences; empty means good
 */
function writabilityProblems(target, label = target) {
  if (runningAsRoot()) return [ROOT_PROBLEM];
  return writableAmong(ancestry(target)).map((entry) => programSentence(entry, label));
}

/**
 * The shell libraries `label` sources as root: the directory, everything above
 * it, and every `*.sh` in it.
 *
 * The files are listed individually rather than trusting the directory's mode,
 * because a root-owned 0755 directory holding one group-writable file is a
 * deployment that passes every check which only looks at directories — and that
 * one file is sourced into a root shell.
 *
 * A directory that does not exist is reported rather than skipped: the caller
 * named it because its program sources from it, so its absence is a broken
 * install, not nothing to check.
 *
 * @param {string} dir
 * @param {string} label
 * @param {Set<string>} [seen]
 */
function sourcedLibraryProblems(dir, label, seen = new Set()) {
  if (runningAsRoot()) return [ROOT_PROBLEM];

  let entries;
  try {
    entries = fs.readdirSync(dir, { withFileTypes: true });
  } catch (err) {
    return [
      `${dir}: ${err.code === 'ENOENT' ? 'not found' : err.code || err.message}. ` +
      `${label} sources its shell libraries from there and cannot run without them.`,
    ];
  }

  const files = entries
    .filter((e) => e.isFile() && e.name.endsWith('.sh'))
    .map((e) => path.join(dir, e.name))
    .sort();

  return writableAmong([...ancestry(dir), ...files], seen).map((entry) =>
    `${entry} is writable by the user this panel runs as, and ${label} sources ` +
    'the shell libraries in that directory as root before it does anything ' +
    'else. Being able to write one of them is being able to run anything as ' +
    'root, exactly as if the program itself were writable. Own it root:root ' +
    'and take the write bit off (deploy/sudoers.d/vpn55-panel).');
}

/**
 * The file exists, is a regular file, nothing on the way to it is writable by
 * this process, and neither is any library it sources as root. `settingName` is
 * the panel.conf key, because "which line do I edit" is the next thing whoever
 * reads the message needs.
 *
 * `sourcedFrom` is the directory of shell libraries the program sources — the
 * same directory it resolves at run time. Omitting it checks the program alone,
 * which is the right answer only for a program that sources nothing.
 */
function programProblems(target, { settingName, label = target, sourcedFrom = null }) {
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

  // Asked once, before either walk: to root every path is writable, so the two
  // walks below would otherwise report every directory on the box.
  if (runningAsRoot()) return [ROOT_PROBLEM];

  const seen = new Set();
  problems.push(
    ...writableAmong(ancestry(target), seen).map((entry) => programSentence(entry, label)));

  if (sourcedFrom) {
    problems.push(...sourcedLibraryProblems(sourcedFrom, label, seen));
  }

  return problems;
}

module.exports = { writabilityProblems, sourcedLibraryProblems, programProblems };
