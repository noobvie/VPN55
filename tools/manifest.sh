#!/usr/bin/env bash
#
# tools/manifest.sh — write (or check) MANIFEST.sha256.
#
# The manifest is the list of files that make up a runnable copy of VPN55, with
# a sha256 for each. Two things depend on it:
#
#   * vpn55.sh's bootstrap fetches it first and then fetches exactly what it
#     lists, from VPN55_MIRROR. A file that is not in the manifest does not
#     reach a server installed that way — which is why the payload here is the
#     runtime tree and the docs, and not the development tooling.
#
#   * src_revision hashes it. That digest is the identity of the code, and it is
#     what the self-update guard compares before and after. A manifest that
#     lagged behind the tree would make an update look like a no-op.
#
# So it is generated, never hand-edited, and CI fails when the checked-in copy
# does not match what this script produces. Run it after any change to a
# shipped file:
#
#   tools/manifest.sh            # rewrite MANIFEST.sha256
#   tools/manifest.sh --check    # exit 1 if it is out of date
#
# ⚠ This is not a signature. Anyone who can change a file can change the line
# about it, and a mirror serving both can serve a consistent lie. Provenance
# comes from minisign over SHA256SUMS — tools/release.sh, docs/distribution.md §5.
#
set -euo pipefail

ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
MANIFEST="MANIFEST.sha256"

# What ships. Directories are taken whole; anything not named here is
# development-only and stays out of a server install.
#
# tests/ IS shipped: the acceptance harness is meant to run on the throwaway VPS
# a release is verified on, and telling an operator to clone the repository to
# get it would contradict the entire point of a mirror-installable tree.
SHIP_FILES=(
    vpn55.sh
    LICENSE
    README.md
    DISCLAIMER.md
    ATTRIBUTIONS.md
)
SHIP_DIRS=(
    lib
    helper
    panel
    deploy
    docs
    tests
)

# Never shipped, wherever they appear: editor droppings, VCS metadata, node
# modules, and the runtime state that must only ever exist on a server.
is_excluded() {
    case "$1" in
        */.git/*|.git/*)               return 0 ;;
        */node_modules/*)              return 0 ;;
        *.swp|*~|*/.DS_Store)          return 0 ;;
        docs/media/*)                  return 0 ;;
        panel/data/*|panel/sessions/*) return 0 ;;
        *) return 1 ;;
    esac
}

collect() {
    local f d
    for f in "${SHIP_FILES[@]}"; do
        [ -f "$ROOT/$f" ] && printf '%s\n' "$f"
    done
    for d in "${SHIP_DIRS[@]}"; do
        [ -d "$ROOT/$d" ] || continue
        # -print0 is not used because every path here is checked against a
        # conservative character class below; a path this script cannot print
        # safely is a path the fetcher would refuse anyway.
        find "$ROOT/$d" -type f -print | sed "s|^$ROOT/||"
    done
}

digest() {
    local f="$1"
    if   command -v sha256sum >/dev/null 2>&1; then sha256sum -- "$f" | cut -d' ' -f1
    elif command -v shasum    >/dev/null 2>&1; then shasum -a 256 -- "$f" | cut -d' ' -f1
    else openssl dgst -sha256 -r -- "$f" | cut -d' ' -f1
    fi
}

generate() {
    local path rc=0
    while IFS= read -r path; do
        [ -n "$path" ] || continue
        is_excluded "$path" && continue
        # The fetcher only accepts plain relative paths made of these
        # characters. Catching it here means a badly named file fails on the
        # machine that added it, not on someone's server halfway through a
        # download.
        case "$path" in
            /*|*..*) printf 'unshippable path: %s\n' "$path" >&2; rc=1; continue ;;
        esac
        if ! printf '%s' "$path" | grep -qE '^[A-Za-z0-9._/-]+$'; then
            printf 'unshippable path: %s\n' "$path" >&2
            rc=1
            continue
        fi
        printf '%s  %s\n' "$(digest "$ROOT/$path")" "$path"
    done < <(collect | LC_ALL=C sort -u)
    return "$rc"
}

main() {
    local generated
    generated="$(cd "$ROOT" && generate)" || {
        printf 'manifest: refusing to write an incomplete list\n' >&2
        exit 1
    }

    if [ "${1:-}" = "--check" ]; then
        if [ ! -f "$ROOT/$MANIFEST" ]; then
            printf '%s is missing. Run tools/manifest.sh.\n' "$MANIFEST" >&2
            exit 1
        fi
        if printf '%s\n' "$generated" | diff -u "$ROOT/$MANIFEST" - >/dev/null; then
            printf 'ok  %s matches the tree (%s files)\n' \
                "$MANIFEST" "$(printf '%s\n' "$generated" | wc -l | tr -d ' ')"
            exit 0
        fi
        printf '%s is out of date. Run tools/manifest.sh and commit it.\n\n' "$MANIFEST" >&2
        printf '%s\n' "$generated" | diff -u "$ROOT/$MANIFEST" - >&2 || true
        exit 1
    fi

    printf '%s\n' "$generated" > "$ROOT/$MANIFEST"
    printf 'wrote %s — %s files\n' "$MANIFEST" \
        "$(printf '%s\n' "$generated" | wc -l | tr -d ' ')"
}

main "$@"
