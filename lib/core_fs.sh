# shellcheck shell=bash
#
# lib/core_fs.sh — the small filesystem primitives every adapter needs.
#
# ── Why this file exists, and why it did not exist before Phase 3 ────────────
# The WireGuard adapter carried its own atomic writer, its own in-place
# replacer, its own shred and its own key=value settings reader. Writing the
# second adapter meant writing all four again, and the third would have made it
# three copies of code whose whole job is to be careful — which is the kind of
# code that must not exist in triplicate, because the copy nobody looked at is
# the one that drops the chmod.
#
# So they moved here at the Phase 3 checkpoint, while there were two
# implementations to reconcile rather than three.
#
# Nothing in this file knows what a protocol is. It sits deliberately a level
# BELOW core_net and core_pki: it does not read VPN55 state, it takes paths.
#
# ── Not adopted by core_users.sh or core_net.sh, on purpose ─────────────────
# Both of those carry their own six-line atomic writer, and the comment in
# core_users explains why: a core lib that only works when another core lib was
# sourced first breaks in whichever caller sources them the other way round.
# That reasoning still holds for the core libs. It does NOT hold for the
# adapters, which vpn55.sh loads only after every core lib is in place — so
# the adapters are exactly the callers that can safely depend on this one.
#
# ── errexit ──────────────────────────────────────────────────────────────────
# Every function here is reached from a ||-guarded lib body, where errexit is
# off for the whole body. Every create/copy/move/delete is therefore guarded on
# its own line. See CLAUDE.md.
#
# Sourced, not executed.

[[ -n "${VPN55_FS_LOADED:-}" ]] && return 0
VPN55_FS_LOADED=1

# ─── Time ─────────────────────────────────────────────────────────────────────
# One timestamp format across the whole project. UTC with an explicit Z, because
# a stored local time is a time nobody can compare later.
fs_now()       { date -u +%Y-%m-%dT%H:%M:%SZ; }
fs_now_epoch() { date -u +%s; }

# ─── Directories ──────────────────────────────────────────────────────────────
# fs_ensure_dir <path> [mode]
#   Create it if absent, then assert the mode either way. Asserting on the
#   already-exists path is the point: a directory created once under a loose
#   umask keeps that mode forever otherwise, and a 0755 key directory is
#   readable by every local user on the box.
fs_ensure_dir() {
    local dir="${1:-}" mode="${2:-0700}"
    [[ -n "$dir" ]] || { error "fs_ensure_dir: no path"; return 1; }

    if [[ ! -d "$dir" ]]; then
        mkdir -p "$dir" || { error "cannot create $dir"; return 1; }
    fi
    chmod "$mode" "$dir" || { error "cannot set mode ${mode} on $dir"; return 1; }
    return 0
}

# ─── Writing ──────────────────────────────────────────────────────────────────
# fs_write_atomic <dest> [mode]  — content on stdin.
#   Writes a temp file beside the destination and renames it over. A reader
#   never sees a half-written file, and a failed write never truncates the file
#   that was already there.
#
#   The temp file is created under umask 077 so its content is never briefly
#   world-readable between the write and the chmod. That window is small, and
#   it is the window in which a private key sits on disk at 0644.
fs_write_atomic() {
    local dest="${1:-}" mode="${2:-0600}" tmp
    [[ -n "$dest" ]] || { error "fs_write_atomic: no destination"; return 1; }
    tmp="${dest}.tmp.$$"

    ( umask 077; cat > "$tmp"; ) || { error "cannot write $tmp"; rm -f "$tmp" 2>/dev/null || true; return 1; }
    chmod "$mode" "$tmp" || { error "cannot set mode on $tmp"; rm -f "$tmp" 2>/dev/null || true; return 1; }
    mv -f "$tmp" "$dest" || { error "cannot replace $dest"; rm -f "$tmp" 2>/dev/null || true; return 1; }
    return 0
}

# fs_replace_in_place <dest> [mode] — content on stdin.
#   Overwrites through the destination's existing inode, so its current owner
#   and mode survive. Use this where something else set the ownership on
#   purpose and a rename would silently reset it to root:root.
#
#   Pass a mode to RE-ASSERT it afterwards. That is not the same as preserving
#   it: preserving keeps whatever the file already had, including a mode that
#   something else loosened. For a file holding a server private key, "keep
#   whatever it has" is not good enough, so those callers name the mode they
#   require and get it enforced on every write.
#
#   It is NOT atomic — a reader can catch it mid-write. That is the trade, and
#   it is only the right one for files a daemon reads at start-up rather than
#   continuously.
fs_replace_in_place() {
    local dest="${1:-}" mode="${2:-}" tmp
    [[ -n "$dest" ]] || { error "fs_replace_in_place: no destination"; return 1; }
    tmp="${dest}.tmp.$$"

    ( umask 077; cat > "$tmp"; ) || { error "cannot write $tmp"; rm -f "$tmp" 2>/dev/null || true; return 1; }
    cat "$tmp" > "$dest" || { error "cannot update $dest"; rm -f "$tmp" 2>/dev/null || true; return 1; }
    rm -f "$tmp" || { error "cannot remove $tmp"; return 1; }
    if [[ -n "$mode" ]]; then
        chmod "$mode" "$dest" || { error "cannot set mode ${mode} on $dest"; return 1; }
    fi
    return 0
}

# fs_write_if_changed <dest> <mode> <content>
#   Writes only when the bytes differ, and reports which happened:
#     VPN55_FS_CHANGED=0   identical, nothing was touched
#     VPN55_FS_CHANGED=1   written
#
#   This is what makes "run the installer three times, nothing changes after
#   the first" true rather than aspirational: no write means no reload, no
#   restart and no log line, so the second run is genuinely inert instead of
#   merely ending in the same state.
#
# ── ⚠ The content is an ARGUMENT, never stdin, and that is load-bearing ──────
# The obvious shape for this is `producer | fs_write_if_changed "$dest" 0600`.
# It is wrong, and wrong in the worst available direction. Bash runs the right
# side of a pipe in a SUBSHELL, so the VPN55_FS_CHANGED this function sets is
# discarded when that subshell exits and every caller reads the stale 0 —
# meaning **"nothing changed" is reported on precisely the run that changed
# everything**.
#
# What then does not happen: the daemon reload, the systemd daemon-reload, the
# `sysctl -p`. Each of those was made conditional on this flag *because* it is
# expensive to do unnecessarily, and each silently stops happening at all. The
# only symptom is a service running against a config file that has already been
# replaced on disk — which reads as "the config is wrong" and sends the operator
# to inspect a file that is perfectly correct.
#
# Passing the content as an argument removes the pipe and with it the subshell.
# The cost is that the caller must capture its producer's output first, which is
# an improvement anyway: a producer that fails halfway can be caught before its
# partial output is written, where the pipe form would have written it.
# shellcheck disable=SC2034  # set here, read by callers in other files
VPN55_FS_CHANGED=0
fs_write_if_changed() {
    local dest="${1:-}" mode="${2:-0600}" want="${3-}" current

    [[ -n "$dest" ]] || { error "fs_write_if_changed: no destination"; return 1; }
    if [[ $# -lt 3 ]]; then
        error "fs_write_if_changed <dest> <mode> <content> — the content is an"
        error "argument, not stdin. Piping into this silently loses its answer."
        return 1
    fi

    # A destination that does not exist is ALWAYS a write, even when the content
    # is empty. Comparing "" against the "" of a nonexistent file would
    # otherwise take the unchanged branch and report success without ever
    # creating it.
    if [[ -f "$dest" ]]; then
        current="$(cat "$dest" 2>/dev/null || true)"
        # Command substitution strips trailing newlines from both sides, so this
        # compares the meaningful content rather than the file's final byte.
        if [[ "$want" == "$current" ]]; then
            VPN55_FS_CHANGED=0
            return 0
        fi
    fi

    printf '%s\n' "$want" | fs_write_atomic "$dest" "$mode" || return 1
    # shellcheck disable=SC2034  # read by callers in other files; see above
    VPN55_FS_CHANGED=1
    return 0
}

# ─── Deleting ─────────────────────────────────────────────────────────────────
# fs_shred <path>
#   Overwrite and unlink where shred exists, plain unlink where it does not.
#
#   Neither is a guarantee. On a copy-on-write or log-structured filesystem —
#   btrfs, ZFS, any SSD doing wear levelling — the overwrite lands on new blocks
#   and the originals stay readable to anyone who can reach the device. Saying
#   that plainly is better than implying an erase the storage layer never
#   performed.
fs_shred() {
    local f="${1:-}"
    [[ -n "$f" && -f "$f" ]] || return 0
    if command -v shred >/dev/null 2>&1; then
        shred -u "$f" 2>/dev/null && return 0
    fi
    rm -f "$f" || { error "cannot remove $f"; return 1; }
    return 0
}

# fs_shred_glob <dir> <pattern>
#   Shred every match. A missing directory is not an error — teardown runs on
#   hosts where the thing was never installed.
fs_shred_glob() {
    local dir="${1:-}" pattern="${2:-*}" f
    [[ -n "$dir" && -d "$dir" ]] || return 0
    for f in "$dir"/$pattern; do
        [[ -f "$f" ]] || continue
        fs_shred "$f" || true
    done
    return 0
}

# fs_remove <path>
#   A guarded single-file delete, so callers stop writing the guard out at every
#   site. Absent is success: teardown must be re-runnable.
fs_remove() {
    local f="${1:-}"
    [[ -n "$f" ]] || { error "fs_remove: no path"; return 1; }
    [[ -e "$f" || -L "$f" ]] || return 0
    rm -f "$f" || { error "cannot remove $f"; return 1; }
    return 0
}

# fs_remove_tree <path>
#   Recursive delete, with a guard against the arguments that turn a teardown
#   into an outage. An empty variable expands to `rm -rf` with no operand and a
#   path of `/` needs no explanation; both have shipped in real installers.
fs_remove_tree() {
    local d="${1:-}" trimmed
    [[ -n "$d" ]] || { error "fs_remove_tree: no path"; return 1; }

    # Trailing slashes are stripped in a LOOP, not once. `${d%/}` removes a
    # single one, so "/" collapses to "" and is caught — but "//" collapses to
    # "/", which was not in the list below and went straight through to
    # `rm -rf //`. GNU rm happens to refuse that under its own --preserve-root
    # failsafe; being saved by the behaviour of one implementation of one tool
    # is not the same as being guarded.
    trimmed="$d"
    while [[ "$trimmed" == */ && "$trimmed" != "/" ]]; do
        trimmed="${trimmed%/}"
    done
    [[ "$trimmed" == "/" ]] && trimmed=""

    # Every entry here is a directory whose removal is an outage rather than a
    # teardown. The list covers the FHS top level rather than only the paths
    # this project happens to touch today: the guard is worth having precisely
    # for the call nobody predicted, and a list that tracks current callers is
    # a list that is one refactor behind.
    case "$trimmed" in
        ""|.|..|*/..|/etc|/usr|/usr/local|/usr/lib|/usr/share|/var|/var/lib|/var/log|/var/tmp|/opt|/srv|/tmp|/root|/home|/boot|/lib|/lib64|/bin|/sbin|/dev|/proc|/sys|/run)
            error "fs_remove_tree: refusing to remove '${d}'"
            return 1 ;;
    esac
    [[ -e "$d" ]] || return 0
    rm -rf "$d" || { error "cannot remove $d"; return 1; }
    return 0
}

# fs_rmdir_if_empty <path> — a quiet no-op when it has contents or is absent.
fs_rmdir_if_empty() {
    local d="${1:-}"
    [[ -n "$d" && -d "$d" ]] || return 0
    rmdir "$d" 2>/dev/null || true
    return 0
}

# fs_dir_is_empty <path> — true for an empty or absent directory.
fs_dir_is_empty() {
    local d="${1:-}" entry
    [[ -n "$d" && -d "$d" ]] || return 0
    for entry in "$d"/* "$d"/.[!.]*; do
        [[ -e "$entry" || -L "$entry" ]] && return 1
    done
    return 0
}

# ─── Symlinks ─────────────────────────────────────────────────────────────────
# fs_link <target> <link>
#   Idempotent symlink. Repoints a link that points elsewhere; refuses to
#   replace a REGULAR file, because that file belongs to whoever put it there
#   and clobbering it is not this project's call to make.
fs_link() {
    local target="${1:-}" link="${2:-}" cur
    [[ -n "$target" && -n "$link" ]] || { error "fs_link <target> <link>"; return 1; }

    if [[ -L "$link" ]]; then
        cur="$(readlink "$link" 2>/dev/null || true)"
        if [[ "$cur" == "$target" ]]; then
            return 0
        fi
        rm -f "$link" || { error "cannot replace the symlink $link"; return 1; }
    elif [[ -e "$link" ]]; then
        error "$link already exists and is not a symlink — refusing to replace it."
        return 1
    fi

    ln -s "$target" "$link" || { error "cannot link $link -> $target"; return 1; }
    return 0
}

# ─── key=value settings files ─────────────────────────────────────────────────
# One line per setting, mode 0600. Deliberately not read with `source`: a
# settings file that is sourced is a settings file that executes whatever gets
# written into it, and these sit in directories that also hold private keys.

# fs_conf_get <file> <key>
#   Value on stdout; returns 1 when the key is absent, which is what lets a
#   caller tell "unset" apart from "set to empty".
fs_conf_get() {
    local file="${1:-}" key="${2:-}" line
    [[ -n "$file" && -n "$key" ]] || return 1
    [[ -r "$file" ]] || return 1
    line="$(grep -m1 "^${key}=" "$file" 2>/dev/null)" || return 1
    printf '%s' "${line#*=}"
}

# fs_conf_set <file> <key> <value>
#   Rewrites the file with that one key replaced. A newline in a value would
#   split one setting into two on the next read, so it is refused rather than
#   escaped — nothing here needs multi-line values.
fs_conf_set() {
    local file="${1:-}" key="${2:-}" value="${3:-}" remaining=""
    [[ -n "$file" ]] || { error "fs_conf_set: no file"; return 1; }
    [[ -n "$key"  ]] || { error "fs_conf_set: no key"; return 1; }
    case "$key" in
        *[!A-Za-z0-9_]*) error "fs_conf_set: '${key}' is not a valid setting name"; return 1 ;;
    esac
    case "$value" in
        *$'\n'*) error "setting '${key}' may not contain a newline"; return 1 ;;
    esac

    if [[ -f "$file" ]]; then
        remaining="$(grep -v "^${key}=" "$file" 2>/dev/null || true)"
    fi
    {
        if [[ -n "$remaining" ]]; then
            printf '%s\n' "$remaining"
        fi
        printf '%s=%s\n' "$key" "$value"
    } | fs_write_atomic "$file" 0600 || { error "cannot write $file"; return 1; }
    return 0
}

# fs_conf_default <file> <key> <fallback> — the stored value, or the fallback.
# The common read shape, so callers stop writing `|| printf` at every site.
fs_conf_default() {
    local file="${1:-}" key="${2:-}" fallback="${3:-}" value
    if value="$(fs_conf_get "$file" "$key")"; then
        printf '%s' "$value"
    else
        printf '%s' "$fallback"
    fi
    return 0
}

# ─── Randomness ───────────────────────────────────────────────────────────────
# fs_random_hex <bytes> — lowercase hex from the kernel CSPRNG.
#
# There is deliberately no $RANDOM fallback. $RANDOM is a 15-bit generator
# seeded from the pid and the clock; a credential id or a passphrase built from
# it is guessable, and a fallback that silently downgrades the entropy source is
# worse than a failure the caller can see.
fs_random_hex() {
    local bytes="${1:-16}" out
    if [[ ! "$bytes" =~ ^[0-9]+$ ]] || (( bytes < 1 )); then
        error "fs_random_hex <bytes>"
        return 1
    fi
    out="$(head -c "$bytes" /dev/urandom 2>/dev/null | od -An -tx1 | tr -d ' \n')" || out=""
    [[ -n "$out" ]] || { error "cannot read randomness from /dev/urandom"; return 1; }
    printf '%s' "$out"
}

# fs_random_pass [bytes] — a passphrase with no shell or markup metacharacters.
#
# It ends up inside an XML plist, inside a PowerShell one-liner and as a shell
# argument, so the alphabet is restricted to what is safe in all three rather
# than escaped separately for each. base64 with '+' and '/' folded away and the
# '=' padding dropped leaves [A-Za-z0-9], which needs no quoting anywhere.
fs_random_pass() {
    local bytes="${1:-18}" out
    if [[ ! "$bytes" =~ ^[0-9]+$ ]] || (( bytes < 1 )); then
        error "fs_random_pass [bytes]"
        return 1
    fi
    out="$(head -c "$bytes" /dev/urandom 2>/dev/null | base64 2>/dev/null | tr -d '\n=' | tr '+/' 'Ab')" || out=""
    [[ -n "$out" ]] || { error "cannot read randomness from /dev/urandom"; return 1; }
    printf '%s' "$out"
}

# fs_uuid — an RFC 4122 version-4 UUID, uppercase.
#
# Written from /dev/urandom rather than shelling out to uuidgen: util-linux is
# not universally installed, and a config profile generator that dies on a
# minimal image because a UUID tool is missing is a poor trade for six lines.
fs_uuid() {
    local h
    h="$(fs_random_hex 16)" || return 1
    # Version 4 in the 13th nibble, variant 10xx in the 17th.
    local v="4" r
    r="${h:16:1}"
    case "$r" in
        [0-3]) r="8" ;;
        [4-7]) r="9" ;;
        [89ab]) r="a" ;;
        *) r="b" ;;
    esac
    printf '%s-%s-%s%s-%s%s-%s' \
        "${h:0:8}" "${h:8:4}" "$v" "${h:13:3}" "$r" "${h:17:3}" "${h:20:12}" \
        | tr 'a-f' 'A-F'
}

# ─── XML ──────────────────────────────────────────────────────────────────────
# fs_xml_escape <string>
#
# Lives here rather than in whichever adapter emits a plist, because Phase 4
# will want it too and because an escaper that exists once is an escaper that
# gets reviewed once.
#
# Two things in five lines that are each easy to get wrong:
#
#   1. The ampersand MUST be substituted first. Doing it later would re-escape
#      the ampersands the other four rules just introduced, turning &lt; into
#      &amp;lt; and printing the markup instead of applying it.
#
#   2. Every replacement escapes its own `&` as `\&`. Since bash 5.2 an
#      unescaped `&` in the REPLACEMENT half of ${var//pat/repl} expands to the
#      matched text — so `${s//</&lt;}` yields `<lt;`, silently emitting a raw
#      `<` into the XML. The bug is invisible in the `&` rule, where the match
#      happens to be `&` and the wrong answer equals the right one, which is
#      exactly how it survives a spot check. `\&` is a literal ampersand on
#      5.2 and on every earlier bash, so this is correct on both.
fs_xml_escape() {
    local s="${1:-}"
    s="${s//&/\&amp;}"
    s="${s//</\&lt;}"
    s="${s//>/\&gt;}"
    s="${s//\"/\&quot;}"
    s="${s//\'/\&apos;}"
    printf '%s' "$s"
}
