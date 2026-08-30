# shellcheck shell=bash
# =============================================================================
# VPN55 — lib/core_source.sh
#
# Where the code itself comes from, and how it is replaced.
#
# This is the only lib that talks to the network, and it exists because of two
# facts that are easy to state and expensive to discover.
#
# ── 1. `bash <(curl …)` has no directory ─────────────────────────────────────
# The README's one-line install runs this project from a process substitution,
# where BASH_SOURCE[0] is /dev/fd/63 and its dirname is /dev/fd. Every `.` of
# lib/… then resolves under /dev/fd and fails. A single file cannot source an
# eighteen-file project it did not bring with it, so the entry point has to
# fetch the tree before it can do anything at all. That is what src_fetch is
# for, and vpn55.sh's bootstrap is its first caller.
#
# ── 2. bash runs the copy it parsed at launch ────────────────────────────────
# Pulling new code into the running tree does NOT hot-reload it. The in-memory
# copy of vpn55.sh and of every lib sourced at startup keeps executing, so an
# update that carried on in the same process would apply the OLD code while
# reporting the new version. src_update therefore keys on the REVISION of the
# whole tree — not on vpn55.sh's timestamp, because the change that matters is
# usually in a lib — and relaunches rather than continuing. Same guard as Office
# Tools' opt_5_update_repo, which is where the failure was first paid for.
#
# ── The transport is a BASE URL, never the project's website ─────────────────
# VPN55_MIRROR is a base URL under which the repository's files appear at their
# repository paths. That is true of raw.githubusercontent.com, of Codeberg's raw
# host, of a plain directory served by any web server, and of an onion service —
# so an operator whose usual host is blocked changes one variable rather than
# waiting for a new script. docs/distribution.md §1.
#
# ⚠ Fetching the manifest over the same channel as the files makes it a
# CONSISTENCY check, not a security control: a mirror that can serve a modified
# lib can serve a manifest that agrees with it. What proves provenance is the
# minisign signature over SHA256SUMS, verified out of band against the public
# key in the README — docs/distribution.md §5. Nothing here claims otherwise,
# and the wording an operator sees must not either.
#
# Sourced, not executed.
# =============================================================================

[[ -n "${VPN55_SOURCE_LOADED:-}" ]] && return 0
VPN55_SOURCE_LOADED=1

# The base URL for source assets. Defaults to the code host, never the project
# site — the site can be blocked in the target market and the code host cannot.
# The repository path is case-sensitive on the raw host; the capitals are
# load-bearing.
: "${VPN55_MIRROR:=https://raw.githubusercontent.com/noobvie/VPN55/main}"

# Where an installed copy lives. Pinned, because the panel's sudo rules name
# this path, and a rule naming a path the operator chose is a rule that does not
# match — deploy/sudoers.d/vpn55-panel.
: "${VPN55_HOME:=/usr/local/lib/vpn55}"

# The list of files that make up a runnable copy, with their digests. Generated
# by tools/manifest.sh and checked by CI, so it cannot quietly fall behind.
: "${VPN55_MANIFEST:=MANIFEST.sha256}"

: "${VPN55_FETCH_TIMEOUT:=30}"

# ─── Talking without lib/ui.sh ────────────────────────────────────────────────
# vpn55.sh's bootstrap sources THIS file alone, out of a temp directory,
# before the tree it is about to fetch exists — so ui.sh may legitimately not be
# loaded yet. Everything human goes through these three: the real logging when
# it is there, a plain line when it is not.
_src_say() {
    if declare -F info >/dev/null 2>&1; then info "$*"; else printf '[INFO]  %s\n' "$*" >&2; fi
}
_src_err() {
    if declare -F error >/dev/null 2>&1; then error "$*"; else printf '[ERROR] %s\n' "$*" >&2; fi
}
_src_warn() {
    if declare -F warn >/dev/null 2>&1; then warn "$*"; else printf '[WARN]  %s\n' "$*" >&2; fi
}

# ─── Primitives ───────────────────────────────────────────────────────────────
src_asset_url() {
    local path="${1:-}"
    printf '%s/%s' "${VPN55_MIRROR%/}" "${path#/}"
}

# src_fetch_to <url> <dest>
#   One file. curl or wget, whichever the host has. A failure is a failure —
#   never a zero-byte file left behind for the next step to parse as content.
src_fetch_to() {
    local url="${1:-}" dest="${2:-}"
    [[ -n "$url" && -n "$dest" ]] || { _src_err "src_fetch_to: need a url and a destination"; return 1; }

    if command -v curl >/dev/null 2>&1; then
        curl -fsSL --max-time "$VPN55_FETCH_TIMEOUT" -o "$dest" -- "$url" && return 0
    elif command -v wget >/dev/null 2>&1; then
        wget -q --timeout="$VPN55_FETCH_TIMEOUT" -O "$dest" -- "$url" && return 0
    else
        _src_err "neither curl nor wget is installed — cannot fetch ${url}"
        return 1
    fi

    rm -f "$dest" || _src_warn "could not clean up the partial download at ${dest}"
    _src_err "could not fetch ${url}"
    return 1
}

# src_sha256 <file> — prints the digest alone, or fails.
src_sha256() {
    local f="${1:-}" out=""
    [[ -f "$f" ]] || { _src_err "src_sha256: no such file: ${f}"; return 1; }

    if   command -v sha256sum >/dev/null 2>&1; then out="$(sha256sum -- "$f")"
    elif command -v shasum    >/dev/null 2>&1; then out="$(shasum -a 256 -- "$f")"
    elif command -v openssl   >/dev/null 2>&1; then out="$(openssl dgst -sha256 -r -- "$f")"
    else
        _src_err "no sha256 tool on this host (sha256sum, shasum or openssl)"
        return 1
    fi
    printf '%s' "${out%% *}"
}

# ─── Revision ─────────────────────────────────────────────────────────────────
# What identifies the code in a tree. A git checkout answers with its commit; an
# installed copy answers with the digest of its manifest, which changes when ANY
# listed file does. Both are content-keyed, which is the property the update
# guard needs — a check against vpn55.sh's own timestamp would miss a change
# that landed entirely in a sourced lib, and that is where changes usually land.
src_revision() {
    local dir="${1:-${VPN55_ROOT:-.}}" sha=""

    if [[ -d "$dir/.git" ]] && command -v git >/dev/null 2>&1; then
        sha="$(git -C "$dir" rev-parse --short=12 HEAD 2>/dev/null)" || sha=""
        if [[ -n "$sha" ]]; then
            printf 'git:%s' "$sha"
            return 0
        fi
    fi
    if [[ -f "$dir/$VPN55_MANIFEST" ]]; then
        sha="$(src_sha256 "$dir/$VPN55_MANIFEST" 2>/dev/null)" || sha=""
        if [[ -n "$sha" ]]; then
            printf 'mf:%s' "${sha:0:12}"
            return 0
        fi
    fi
    printf 'unknown'
    return 0
}

# src_is_git_checkout [dir] — a development tree, which this lib never rewrites.
src_is_git_checkout() {
    local dir="${1:-${VPN55_ROOT:-.}}"
    [[ -d "$dir/.git" ]]
}

# ─── Manifest ─────────────────────────────────────────────────────────────────
# Format is sha256sum's own: `<digest>  <path>`, one per line, paths relative to
# the repository root, never absolute and never containing `..`. Both of those
# are checked on the way in: a manifest is a list of places a fetch is about to
# write, so an unchecked path in it is an arbitrary file write as root.
_src_manifest_paths() {
    local manifest="${1:-}"
    awk '
        /^[[:space:]]*(#|$)/ { next }
        { print $2 }
    ' "$manifest"
}

_src_manifest_digest_for() {
    local manifest="${1:-}" want="${2:-}"
    awk -v want="$want" '
        /^[[:space:]]*(#|$)/ { next }
        $2 == want { print $1; exit }
    ' "$manifest"
}

# A plain relative path made of characters a repository actually uses. The
# character class does the real work — it admits no whitespace at all, newline
# included — which matters when a mirror serves something that is not a manifest
# at all, such as an HTML error page.
#
# It is written as one regex on purpose. The first version of this compared
# against $(printf '\n'), and command substitution strips trailing newlines: the
# pattern was the empty string, `*""*` matches everything, and the test rejected
# every path there is. Nothing downstream could tell that apart from a hostile
# manifest, so the whole fetch failed with a message accusing the mirror.
_src_path_is_safe() {
    local p="${1:-}"
    [[ -n "$p" ]]        || return 1
    [[ "$p" != /* ]]     || return 1
    [[ "$p" != *".."* ]] || return 1
    [[ "$p" =~ ^[A-Za-z0-9._/-]+$ ]]
}

# src_manifest_verify <dir> [manifest]
#   Every listed file present and matching. It prints WHICH files are wrong
#   rather than a count, because "3 files differ" is not something an operator
#   can act on.
src_manifest_verify() {
    local dir="${1:-}" manifest="${2:-}" rc=0 path want got
    [[ -n "$dir" ]] || { _src_err "src_manifest_verify: no directory"; return 1; }
    manifest="${manifest:-$dir/$VPN55_MANIFEST}"
    [[ -f "$manifest" ]] || { _src_err "no manifest at ${manifest}"; return 1; }

    while IFS= read -r path; do
        [[ -n "$path" ]] || continue
        if ! _src_path_is_safe "$path"; then
            _src_err "manifest lists an unsafe path: ${path}"
            rc=1
            continue
        fi
        if [[ ! -f "$dir/$path" ]]; then
            _src_err "missing: ${path}"
            rc=1
            continue
        fi
        want="$(_src_manifest_digest_for "$manifest" "$path")"
        got="$(src_sha256 "$dir/$path")" || { rc=1; continue; }
        if [[ "$want" != "$got" ]]; then
            _src_err "digest mismatch: ${path}"
            rc=1
        fi
    done < <(_src_manifest_paths "$manifest")

    return "$rc"
}

# ─── Fetch ────────────────────────────────────────────────────────────────────
# src_fetch <dest>
#   Downloads a complete, verified tree and puts it at <dest>. It stages into a
#   temp directory and only swaps at the end, so a fetch that dies halfway — a
#   dropped connection, a mirror that 404s on the twelfth file — leaves the
#   existing installation exactly as it was. A half-overwritten install root is
#   the one outcome an operator cannot recover from over the tunnel they just
#   broke.
src_fetch() {
    local dest="${1:-}" stage="" manifest="" path url rc=0
    [[ -n "$dest" ]] || { _src_err "src_fetch: no destination"; return 1; }

    if src_is_git_checkout "$dest"; then
        _src_err "${dest} is a git checkout — update it with git, not from a mirror."
        return 1
    fi

    stage="$(mktemp -d "${TMPDIR:-/tmp}/vpn55-src.XXXXXX")" \
        || { _src_err "cannot create a staging directory"; return 1; }

    manifest="$stage/$VPN55_MANIFEST"
    _src_say "Fetching the file list from ${VPN55_MIRROR}"
    if ! src_fetch_to "$(src_asset_url "$VPN55_MANIFEST")" "$manifest"; then
        _src_err "could not fetch ${VPN55_MANIFEST}. If this mirror is blocked, set"
        _src_err "VPN55_MIRROR to another base URL and try again."
        rm -rf "$stage" || _src_warn "could not clean up ${stage}"
        return 1
    fi

    local count=0
    while IFS= read -r path; do
        [[ -n "$path" ]] || continue
        if ! _src_path_is_safe "$path"; then
            _src_err "refusing a manifest entry that is not a plain relative path: ${path}"
            rc=1
            break
        fi
        mkdir -p "$stage/$(dirname -- "$path")" || { _src_err "cannot stage a directory for ${path}"; rc=1; break; }
        url="$(src_asset_url "$path")"
        if ! src_fetch_to "$url" "$stage/$path"; then
            rc=1
            break
        fi
        count=$(( count + 1 ))
    done < <(_src_manifest_paths "$manifest")

    if [[ "$rc" -ne 0 ]]; then
        rm -rf "$stage" || _src_warn "could not clean up ${stage}"
        _src_err "the download did not complete — nothing at ${dest} was touched."
        return 1
    fi
    _src_say "Fetched ${count} files; checking them against the list"

    if ! src_manifest_verify "$stage" "$manifest"; then
        rm -rf "$stage" || _src_warn "could not clean up ${stage}"
        _src_err "the downloaded files do not match the list this mirror served."
        _src_err "Nothing at ${dest} was touched. Try another VPN55_MIRROR."
        return 1
    fi

    # Executability does not survive an HTTP fetch. The two entry points are the
    # ones a person or a sudo rule invokes by path, so they are restored by
    # name; nothing else in the tree is ever executed directly.
    local exe
    for exe in vpn55.sh helper/vpnctl; do
        if [[ -f "$stage/$exe" ]]; then
            chmod 0755 "$stage/$exe" \
                || { _src_err "cannot make ${exe} executable"; rm -rf "$stage" || true; return 1; }
        fi
    done

    # The swap. The old tree moves aside first, so a failure to put the new one
    # in place leaves something to move back rather than no installation at all.
    local backup=""
    if [[ -d "$dest" ]]; then
        backup="${dest}.old.$$"
        mv -- "$dest" "$backup" || { _src_err "cannot move ${dest} aside"; rm -rf "$stage" || true; return 1; }
    else
        mkdir -p -- "$(dirname -- "$dest")" || { _src_err "cannot create the parent of ${dest}"; rm -rf "$stage" || true; return 1; }
    fi

    if ! mv -- "$stage" "$dest"; then
        _src_err "cannot install the new tree at ${dest}"
        if [[ -n "$backup" ]]; then
            mv -- "$backup" "$dest" || _src_err "the previous copy is still at ${backup} — move it back by hand."
        fi
        rm -rf "$stage" || _src_warn "could not clean up ${stage}"
        return 1
    fi

    chmod 0755 "$dest" || _src_warn "could not set the mode on ${dest}"
    if [[ -n "$backup" ]]; then
        rm -rf "$backup" || _src_warn "the previous copy is still at ${backup}"
    fi

    _src_say "Installed at ${dest} — revision $(src_revision "$dest")"
    return 0
}

# ─── Update ───────────────────────────────────────────────────────────────────
# src_update [dir]
#   Refreshes the tree this process is running from, and STOPS if anything
#   changed.
#
#   The return code is the interface here, because the caller has to do
#   something different in each case and a boolean cannot carry it:
#     0   already current — carrying on is safe
#     10  updated — the caller must relaunch and must do nothing else first
#     1   the update failed; the tree is unchanged
#
#   Continuing after an update would apply the code parsed at launch while
#   reporting the version just downloaded. That is not a cosmetic mismatch: the
#   functions that write configuration and firewall rules are exactly the ones
#   that get fixed, so the run that "applied the fix" is the run that did not.
src_update() {
    local dir="${1:-${VPN55_ROOT:-}}" before after
    [[ -n "$dir" ]] || { _src_err "src_update: no directory"; return 1; }

    if src_is_git_checkout "$dir"; then
        _src_err "${dir} is a git checkout. Update it with git:"
        _src_err "    git -C ${dir} pull --ff-only"
        _src_err "then start vpn55.sh again."
        return 1
    fi

    before="$(src_revision "$dir")"
    src_fetch "$dir" || return 1
    after="$(src_revision "$dir")"

    if [[ "$before" == "$after" ]]; then
        _src_say "Already current — revision ${after}."
        return 0
    fi

    _src_warn "Code changed: ${before} → ${after}"
    _src_warn "Bash is still running the copy it parsed at launch, including every"
    _src_warn "library sourced then. Continuing would apply the OLD code."
    return 10
}

# src_relaunch <dir> — hands control to the copy just installed.
#   The sentinel is what stops a loop: the new process can see that an update
#   already happened in this session and does not offer another before it has
#   shown the operator anything.
src_relaunch() {
    local dir="${1:-${VPN55_ROOT:-}}" rev
    if [[ ! -x "$dir/vpn55.sh" ]]; then
        _src_err "the new copy is not executable at ${dir}/vpn55.sh — run:"
        _src_err "    bash ${dir}/vpn55.sh"
        return 1
    fi
    rev="$(src_revision "$dir")"
    _src_say "Relaunching ${dir}/vpn55.sh"
    VPN55_RELAUNCHED="$rev" exec "$dir/vpn55.sh"
}
