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

# ─── Signatures ───────────────────────────────────────────────────────────────
#
# ── The hole this closes ────────────────────────────────────────────────────
#
# src_update fetches MANIFEST.sha256 from VPN55_MIRROR and then checks the tree
# against it. Both halves come from the same place, so a hostile mirror serves a
# tree AND a matching manifest and the check passes: it proves the download was
# not CORRUPTED, and says nothing about who wrote it.
#
# That is not a hypothetical for this project. docs/circumvention.md §8 names it
# exactly — an ISP injecting a fake mirror list is the attack a plain mirror page
# has no answer to, and VPN55 runs as root.
#
# A signature over the manifest closes it, because the signing key is on no
# mirror. What it cannot close is `curl … | bash`: by the time this code runs it
# is already root. tools/release.sh says the same at more length, and neither
# file may imply otherwise.
#
# ── Two verifiers, and why there are two ────────────────────────────────────
#
# minisign is the authority whenever it is installed. It is NOT installed on a
# fresh VPS, and this code runs before anything has been installed — so refusing
# without it would mean the check never runs on a first install, which is the
# install where it matters most.
#
# Hence a fallback through openssl, which is on every host this supports. It is
# the same check on the same bytes: a minisign signature is plain Ed25519, and
# openssl has done raw Ed25519 since 1.1.1.
#
# ⚠ It fails CLOSED, at every branch. Neither tool present, a malformed key, an
# algorithm this does not know, a truncated signature, a key id that is not
# ours — every one of them returns non-zero. A verifier that returns success
# when it could not check is worse than no verifier, because the caller stops
# thinking about it.
#
# ── The minisign format, since this parses it by hand ───────────────────────
#
#   public key file   line 1  untrusted comment
#                     line 2  base64( "Ed" | keyid[8] | pubkey[32] )
#
#   signature file    line 1  untrusted comment
#                     line 2  base64( alg[2] | keyid[8] | sig[64] )
#                     line 3  "trusted comment: <text>"
#                     line 4  base64( globalsig[64] )
#
#   alg  "Ed"  the signature is over the file's own bytes
#        "ED"  the signature is over BLAKE2b-512 of the file's bytes
#
# The GLOBAL signature on line 4 covers sig[64] concatenated with the trusted
# comment text. It is not decoration: unchecked, the trusted comment — the half
# minisign prints as vouched-for — can be rewritten by anyone. So it is verified
# whenever lines 3 and 4 are present.

# The project's public key, base64, exactly as it appears in the README: the
# SECOND line of vpn55.pub, without the comment line above it.
#
# ⚠ THE KEY IS NOT DECLARED HERE ANY MORE. It lives in vpn55.sh, which exports
# it, and this line only picks it up so the lib still works when it is sourced
# on its own — which CI does, and which is also the state the bootstrap sources
# it in. The move was not tidying: vpn55.sh's bootstrap FETCHES this file from
# the mirror and sources it as root, so a key declared in this file would be a
# key the mirror supplies, checked by a verifier the same mirror supplies. Put
# it back here and the signature scheme verifies nothing on a first install.
#
# ⚠ EMPTY until the release key exists (tools/release.sh explains how it is made
# and why it stays offline). Empty makes every verification below REFUSE rather
# than pass, which is the correct state for a project that cannot yet prove who
# it is. Filling it in — in vpn55.sh — is a launch-blocking step.
: "${VPN55_PUBKEY:=}"

# Which verifier will be used, as one word: minisign, openssl or none. The
# caller prints it, so an operator can see what actually checked the file rather
# than assuming it was the good one.
src_sig_backend() {
    if command -v minisign >/dev/null 2>&1; then printf 'minisign'; return 0; fi
    if command -v openssl >/dev/null 2>&1 \
       && openssl list -public-key-algorithms 2>/dev/null | grep -qi 'ed25519'; then
        printf 'openssl'
        return 0
    fi
    printf 'none'
    return 0
}

# _src_b64_bytes <base64-string> <outfile>
_src_b64_bytes() {
    printf '%s\n' "${1:-}" | openssl base64 -d -A > "${2:-}" 2>/dev/null
}

# _src_slice <infile> <skip> <count> <outfile>
_src_slice() {
    dd if="${1:-}" of="${4:-}" bs=1 skip="${2:-0}" count="${3:-0}" 2>/dev/null
}

# _src_verify_ed25519 <pubkey-raw-32> <message-file> <sig-raw-64>
#
# The SubjectPublicKeyInfo wrapper for Ed25519 is a fixed twelve bytes — the
# algorithm takes no parameters and the key is always 32 bytes, so the DER around
# it never varies and is written literally rather than assembled.
_src_verify_ed25519() {
    local pub="${1:-}" msg="${2:-}" sig="${3:-}" der rc=0
    der="$(mktemp)" || return 1
    printf '\x30\x2a\x30\x05\x06\x03\x2b\x65\x70\x03\x21\x00' > "$der" \
        || { rm -f "$der"; return 1; }
    cat "$pub" >> "$der" || { rm -f "$der"; return 1; }
    openssl pkeyutl -verify -pubin -inkey "$der" -keyform DER \
        -rawin -in "$msg" -sigfile "$sig" >/dev/null 2>&1 || rc=1
    rm -f "$der" || true
    return "$rc"
}

# src_minisign_verify <file> <sigfile> [pubkey-base64]
#
# Returns 0 ONLY when the signature is genuine. Every other outcome, including
# "could not check", is non-zero.
src_minisign_verify() {
    local file="${1:-}" sigfile="${2:-}" pub="${3:-${VPN55_PUBKEY:-}}"

    [[ -n "$file" && -f "$file" ]] \
        || { _src_err "nothing to verify at '${file}'"; return 1; }
    [[ -n "$sigfile" && -f "$sigfile" ]] \
        || { _src_err "no signature file at '${sigfile}'"; return 1; }

    if [[ -z "$pub" ]]; then
        _src_err "no VPN55 public key is built into this copy, so nothing can be verified."
        _src_err "That is expected before the project's release key exists. Until it does,"
        _src_err "check the published checksums by hand against a source you trust."
        return 1
    fi

    if command -v minisign >/dev/null 2>&1; then
        minisign -Vm "$file" -x "$sigfile" -P "$pub" >/dev/null 2>&1 && return 0
        _src_err "the signature on ${file##*/} is NOT valid for the VPN55 release key."
        return 1
    fi

    command -v openssl >/dev/null 2>&1 || {
        _src_err "neither minisign nor openssl is on this host, so the signature cannot be checked."
        return 1
    }

    local work rc=0
    work="$(mktemp -d)" || return 1

    local sig_b64 tcomment gsig_b64
    sig_b64="$(sed -n '2p' "$sigfile" | tr -d '\r\n')"
    tcomment="$(sed -n '3p' "$sigfile" | sed 's/\r$//')"
    gsig_b64="$(sed -n '4p' "$sigfile" | tr -d '\r\n')"

    _src_b64_bytes "$pub" "$work/pub.bin" || rc=1
    _src_b64_bytes "$sig_b64" "$work/sig.bin" || rc=1
    if [[ "$rc" -ne 0 ]]; then
        _src_err "the key or the signature is not valid base64."
        rm -rf "$work" || true
        return 1
    fi

    # 2 + 8 + 32 and 2 + 8 + 64. A short read here is a truncated file, and a
    # truncated file must never verify.
    local publen siglen
    publen="$(wc -c < "$work/pub.bin" | tr -d ' ')"
    siglen="$(wc -c < "$work/sig.bin" | tr -d ' ')"
    if [[ "$publen" != "42" || "$siglen" != "74" ]]; then
        _src_err "the key or the signature is the wrong length (key ${publen}, signature ${siglen})."
        rm -rf "$work" || true
        return 1
    fi

    local alg
    _src_slice "$work/sig.bin" 0 2 "$work/alg.bin"
    alg="$(tr -d '\000' < "$work/alg.bin")"

    # The key id ties the signature to THIS key. Without the check, a signature
    # made by any other key would be verified against ours and merely fail —
    # the same outcome, reported as the wrong problem.
    _src_slice "$work/pub.bin" 2 8 "$work/pub.keyid"
    _src_slice "$work/sig.bin" 2 8 "$work/sig.keyid"
    if ! cmp -s "$work/pub.keyid" "$work/sig.keyid"; then
        _src_err "${sigfile##*/} was signed by a different key than this copy of VPN55 trusts."
        rm -rf "$work" || true
        return 1
    fi

    _src_slice "$work/pub.bin" 10 32 "$work/pub.raw"
    _src_slice "$work/sig.bin" 10 64 "$work/sig.raw"

    # What was actually signed.
    case "$alg" in
        Ed) cp "$file" "$work/msg" || rc=1 ;;
        ED) openssl dgst -blake2b512 -binary -out "$work/msg" "$file" 2>/dev/null || rc=1 ;;
        *)
            _src_err "unknown signature algorithm '${alg}' — this copy of VPN55 cannot check it."
            rm -rf "$work" || true
            return 1 ;;
    esac
    if [[ "$rc" -ne 0 ]]; then
        _src_err "cannot prepare ${file##*/} for verification."
        rm -rf "$work" || true
        return 1
    fi

    if ! _src_verify_ed25519 "$work/pub.raw" "$work/msg" "$work/sig.raw"; then
        _src_err "the signature on ${file##*/} is NOT valid for the VPN55 release key."
        rm -rf "$work" || true
        return 1
    fi

    # The trusted comment, when the file carries one. Checked rather than
    # trusted: it is the line minisign displays as vouched-for.
    if [[ -n "$tcomment" && -n "$gsig_b64" ]]; then
        case "$tcomment" in
            "trusted comment: "*) ;;
            *)
                _src_err "the signature file's third line is not a trusted comment."
                rm -rf "$work" || true
                return 1 ;;
        esac
        if ! _src_b64_bytes "$gsig_b64" "$work/gsig.raw"; then
            _src_err "the global signature is not valid base64."
            rm -rf "$work" || true
            return 1
        fi
        cat "$work/sig.raw" > "$work/gmsg" || rc=1
        printf '%s' "${tcomment#trusted comment: }" >> "$work/gmsg" || rc=1
        if [[ "$rc" -ne 0 ]] \
           || ! _src_verify_ed25519 "$work/pub.raw" "$work/gmsg" "$work/gsig.raw"; then
            _src_err "the trusted comment on ${sigfile##*/} is not covered by a valid signature."
            rm -rf "$work" || true
            return 1
        fi
    fi

    rm -rf "$work" || true
    return 0
}

# ─── The rendezvous file ──────────────────────────────────────────────────────
#
# docs/circumvention.md §8 asked whether a signed Nostr event carrying the
# current mirror, the endpoints and the vpn55.sh hash should ship in v1. The
# decision recorded there is: not in v1 — but the SIGNED STATEMENT it was built
# around ships now, over the channels that already exist.
#
# The reasoning in one line: the value in §8 is the signature, not Nostr. A
# signed statement of "here is the current mirror, and here is what vpn55.sh
# should hash to" defeats the injected-mirror attack on a mirror page, on the
# .onion, and pasted into a chat — with no relays, no second signing key on a
# second curve, and no second key custody story.
#
# ── The format ──────────────────────────────────────────────────────────────
#
# key = value, one per line, '#' comments, repeated keys allowed:
#
#   serial   monotonic. A reader keeps the highest it has seen and refuses to
#            go backwards, or an attacker replays a genuine older file to pin
#            somebody to a mirror that has since been burned.
#   expires  YYYY-MM-DD. Bounds that same attack for a reader with no history.
#   version  the release this describes
#   mirror   a base URL for VPN55_MIRROR. Repeatable, in preference order
#   endpoint a tunnel address (see net_endpoints_*). Repeatable
#   sha256   "<digest>  <path>", the same shape sha256sum writes
#   onion    the documentation .onion, if there is one
#
# Nothing here is secret. It is signed so that it cannot be FORGED, not so that
# it cannot be read — publishing it widely is the entire point.
: "${VPN55_RENDEZVOUS:=rendezvous.txt}"

# src_rendezvous_values <file> <key> — every value for that key, one per line.
src_rendezvous_values() {
    local file="${1:-}" key="${2:-}"
    [[ -n "$file" && -r "$file" && -n "$key" ]] || return 1
    awk -F'=' -v k="$key" '
        /^[[:space:]]*#/ { next }
        {
            name = $1
            gsub(/^[[:space:]]+|[[:space:]]+$/, "", name)
            if (name != k) next
            sub(/^[^=]*=/, "")
            gsub(/^[[:space:]]+|[[:space:]]+$/, "")
            if (length($0)) print
        }
    ' "$file"
}

# src_rendezvous_check <file> <sigfile> [today]
#
# Verifies the signature FIRST and reads nothing until it passes. The order is
# the whole point: parsing an unverified file and then checking it is how a
# malformed-input bug in the parser becomes reachable by anyone who can serve a
# file, and this parser runs as root.
src_rendezvous_check() {
    local file="${1:-}" sigfile="${2:-}" today="${3:-}"

    src_minisign_verify "$file" "$sigfile" || {
        _src_err "not using ${file##*/}: it is not signed by the VPN55 release key."
        return 1
    }

    local expires
    expires="$(src_rendezvous_values "$file" expires | head -n1)"
    if [[ -n "$expires" ]]; then
        [[ -n "$today" ]] || today="$(date -u +%Y-%m-%d)"
        # Lexical comparison is correct for zero-padded ISO dates and needs no
        # date parsing, which is the part that differs between busybox and GNU.
        if [[ "$expires" < "$today" ]]; then
            _src_err "${file##*/} expired on ${expires} — it is genuine but stale."
            _src_err "A signed file that is out of date is how somebody is pinned to a"
            _src_err "mirror that has since been blocked. Find a current one."
            return 1
        fi
    fi
    return 0
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

    # ── The manifest's signature, BEFORE a single file is read from it ──────
    #
    # The manifest and the tree come from the same mirror, so checking one
    # against the other proves the download was not corrupted and nothing else:
    # a hostile mirror serves both halves and passes. The signing key is on no
    # mirror, which is what makes this the check that means something.
    #
    # It runs here rather than after the download because the manifest is
    # PARSED to decide what to fetch — every path below comes out of it, and
    # _src_path_is_safe is guarding a file this host has not authenticated.
    # Verifying first makes that guard a second line rather than the only one.
    #
    # ⚠ Two behaviours, and the difference is VPN55_PUBKEY:
    #
    #   key present  a bad or missing signature ABORTS. Nothing is downloaded
    #                and nothing at $dest is touched.
    #   key empty    a loud warning, and the fetch continues.
    #
    # The second is where the project is today: there is no release key yet
    # (tools/release.sh explains how it is made). It is deliberately not a
    # refusal, because that would make --update impossible before launch — but
    # it is deliberately not silent either, and filling VPN55_PUBKEY in is the
    # single change that turns enforcement on everywhere at once.
    local sigfile="${manifest}.minisig"
    if src_fetch_to "$(src_asset_url "${VPN55_MANIFEST}.minisig")" "$sigfile" 2>/dev/null \
       && [[ -s "$sigfile" ]]; then
        if [[ -n "${VPN55_PUBKEY:-}" ]]; then
            if src_minisign_verify "$manifest" "$sigfile"; then
                _src_say "File list signature verified (via $(src_sig_backend))."
            else
                _src_err "${VPN55_MIRROR} served a file list that is NOT signed by the"
                _src_err "VPN55 release key. This is what a tampered mirror looks like."
                _src_err "Nothing was downloaded and nothing at ${dest} was touched."
                rm -rf "$stage" || _src_warn "could not clean up ${stage}"
                return 1
            fi
        else
            _src_warn "This copy has no release key built in, so the file list's signature"
            _src_warn "cannot be checked. Continuing on the mirror's word alone."
        fi
    else
        if [[ -n "${VPN55_PUBKEY:-}" ]]; then
            _src_err "${VPN55_MIRROR} served no signature for ${VPN55_MANIFEST}."
            _src_err "A release is always signed, so this mirror is either out of date or"
            _src_err "not serving VPN55. Nothing at ${dest} was touched."
            rm -rf "$stage" || _src_warn "could not clean up ${stage}"
            return 1
        fi
        _src_warn "No signature alongside ${VPN55_MANIFEST}; the file list is unverified."
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

    # ── Is what arrived actually a runnable VPN55? ──────────────────────────
    #
    # src_manifest_verify checks the files the manifest NAMES, and cannot miss
    # one it does not name. So a manifest that simply omits lib/ui.sh downloads
    # and verifies perfectly, and installs a tree vpn55.sh cannot start from —
    # at which point the bootstrap fetches it again, and again, forever, as
    # root. A stale or half-synced mirror is enough; it does not take a hostile
    # one. The loop is guarded in vpn55.sh as well, but the honest place to
    # refuse is here, before anything is installed, with a message that names
    # the mirror rather than the symptom.
    #
    # Only the two files whose absence is unrecoverable are required. Anything
    # else missing is a broken install that at least reports itself.
    local required
    for required in vpn55.sh lib/ui.sh "$VPN55_MANIFEST"; do
        if [[ ! -f "$stage/$required" ]]; then
            _src_err "${VPN55_MIRROR} served a file list with no ${required} in it."
            _src_err "That is not a runnable copy of VPN55, so nothing was installed and"
            _src_err "nothing at ${dest} was touched. Try another VPN55_MIRROR."
            rm -rf "$stage" || _src_warn "could not clean up ${stage}"
            return 1
        fi
    done

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

    # ── Sweep any orphan left by an interrupted swap ────────────────────────
    #
    # The two moves below are not one atomic step. Killed between them — a
    # reboot, an out-of-memory kill, Ctrl-C on a slow disk — $dest does not
    # exist and $dest.old.<pid> does, and nothing has ever removed it: the next
    # run bootstraps a fresh tree and walks straight past it. On a box updated
    # a few times that way it is several complete copies of the project sitting
    # in /usr/local/lib, one per accident.
    #
    # Swept here rather than in the failure branch below, because the case that
    # leaves one behind is the case where no failure branch runs.
    local orphan
    for orphan in "${dest}".old.*; do
        [[ -d "$orphan" ]] || continue
        _src_warn "removing ${orphan} — left by an interrupted update"
        rm -rf "$orphan" || _src_warn "could not remove ${orphan}"
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
#
#   VPN55_RELAUNCHED marks the new process as one that has already replaced its
#   own tree once in this lineage. vpn55.sh's bootstrap READS it: a relaunch
#   that lands back in the bootstrap means the tree just installed has no
#   lib/ui.sh, and fetching the same incomplete tree a second time would loop
#   forever. It is exported for that reason — a plain shell variable does not
#   survive the exec, and the earlier version of this line set one that nothing
#   anywhere read while the comment above it claimed it stopped a loop.
src_relaunch() {
    local dir="${1:-${VPN55_ROOT:-}}" rev
    if [[ ! -x "$dir/vpn55.sh" ]]; then
        _src_err "the new copy is not executable at ${dir}/vpn55.sh — run:"
        _src_err "    bash ${dir}/vpn55.sh"
        return 1
    fi
    rev="$(src_revision "$dir")"
    _src_say "Relaunching ${dir}/vpn55.sh"
    export VPN55_RELAUNCHED="$rev"
    exec "$dir/vpn55.sh"
}
