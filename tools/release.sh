#!/usr/bin/env bash
#
# tools/release.sh — cut a signed release.
#
# ── Why signing is a launch-blocking item and not a nice-to-have ─────────────
# The moment the website is blocked and users start hunting for a mirror is
# exactly the moment someone publishes a trojaned "VPN55". To a user who just
# wants it to work, a censored project and a compromised one look identical —
# and this one runs as root. Signatures have to exist BEFORE the project is
# worth impersonating, because afterwards there is no way to tell the two apart.
#
# ── What signing fixes, and what it does not ────────────────────────────────
# It fixes the MIRROR problem: someone who found VPN55 somewhere other than the
# canonical repository can prove that what they found is what was published.
#
# It does NOT fix `curl … | bash`. By the time the script could check a
# signature it is already running as root. Nothing in this file, the README or
# the website may imply otherwise; saying so would be worse than not signing,
# because it would sell a guarantee that is not there.
#
# ── Usage ────────────────────────────────────────────────────────────────────
#   tools/release.sh 2026.09.09          # build + sign artifacts
#   tools/release.sh 2026.09.09 --tag    # …and create a signed git tag
#
# Requires: minisign, and a secret key. Generate it ONCE, keep it offline, and
# publish the public half in the README:
#
#   minisign -G -p vpn55.pub -s vpn55.key
#
set -euo pipefail

ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
DIST="$ROOT/dist"
SECKEY="${VPN55_MINISIGN_KEY:-$HOME/.minisign/vpn55.key}"
MANIFEST_NAME="MANIFEST.sha256"

die() { printf '\033[31m[ERROR]\033[0m %s\n' "$*" >&2; exit 1; }
say() { printf '\033[36m[..]\033[0m %s\n' "$*" >&2; }
ok()  { printf '\033[32m[ok]\033[0m %s\n' "$*" >&2; }

VERSION="${1:-}"
[ -n "$VERSION" ] || die "usage: tools/release.sh <version> [--tag]"
# ── The version IS the release date ─────────────────────────────────────────
# CalVer, YYYY.MM.DD, matching VPN55_VERSION in vpn55.sh. A second cut on the
# same day appends a counter: 2026.09.09.1. The range check is not pedantry —
# 2026.13.09 would sort between two real releases and pass a regex happily.
printf '%s' "$VERSION" | grep -qE '^[0-9]{4}\.[0-9]{2}\.[0-9]{2}(\.[0-9]+)?$' \
    || die "version is a release date: YYYY.MM.DD (or YYYY.MM.DD.N for a second cut the same day); got '$VERSION'"
V_MONTH=$(printf '%s' "$VERSION" | cut -d. -f2)
V_DAY=$(printf '%s' "$VERSION" | cut -d. -f3)
[ "$((10#$V_MONTH))" -ge 1 ] && [ "$((10#$V_MONTH))" -le 12 ] \
    || die "month '$V_MONTH' is not a month; got '$VERSION'"
[ "$((10#$V_DAY))" -ge 1 ] && [ "$((10#$V_DAY))" -le 31 ] \
    || die "day '$V_DAY' is not a day; got '$VERSION'"
DO_TAG=0
[ "${2:-}" = "--tag" ] && DO_TAG=1

cd "$ROOT"

# ── A release is cut from a clean, committed tree ────────────────────────────
# A signature over a working copy signs something that exists on exactly one
# machine. Anyone verifying it later has nothing to compare against.
command -v git >/dev/null 2>&1 || die "git is required"
[ -z "$(git status --porcelain)" ] || die "working tree is dirty — commit or stash first"

# ── The manifest and the tarball must agree ─────────────────────────────────
# The tarball is built FROM the manifest, so what a release contains and what a
# mirror serves are the same list by construction rather than by discipline.
say "checking the file manifest"
"$ROOT/tools/manifest.sh" --check || die "MANIFEST.sha256 is out of date — run tools/manifest.sh and commit"

say "checking the installer's version string"
if ! grep -q "VPN55_VERSION=\"${VERSION}\"" "$ROOT/vpn55.sh"; then
    printf '\033[33m[warn]\033[0m vpn55.sh says %s\n' \
        "$(grep -m1 '^VPN55_VERSION=' "$ROOT/vpn55.sh")" >&2
    printf '        The release is %s. A version string that disagrees with its\n' "$VERSION" >&2
    printf '        own tag is how a bug report arrives against the wrong code.\n' >&2
    die "set VPN55_VERSION=\"${VERSION}\" in vpn55.sh, commit, and try again"
fi

# ── The signing key, checked BEFORE anything is built ───────────────────────
# This used to sit after the tarball, which meant a release without minisign got
# most of the way through and then refused — and, worse, that the manifest was
# signed after the tarball had already been packed, so the signature could not
# be in it. Both are fixed by asking the question first.
if ! command -v minisign >/dev/null 2>&1; then
    printf '\033[33m[warn]\033[0m minisign is not installed — a release cannot be signed.\n' >&2
    printf '        An unsigned release is the state this project cannot launch in.\n' >&2
    printf '        Install minisign and run this again.\n' >&2
    exit 1
fi
[ -f "$SECKEY" ] || die "no secret key at $SECKEY (set VPN55_MINISIGN_KEY)"

# ── The file list's own signature ───────────────────────────────────────────
#
# SHA256SUMS covers the dist/ artifacts. MANIFEST.sha256 is a different thing:
# it lives IN THE REPOSITORY and is what src_fetch downloads to decide which
# files make up a runnable copy — so it is the file a hostile mirror would
# rewrite. vpn55.sh's bootstrap checks this signature before it sources a single
# fetched line, and lib/core_source.sh checks it again before it parses a
# manifest entry.
#
# It is written to the repository root because that is where the mirror serves
# it from, next to the manifest it covers — and it therefore has to be
# COMMITTED, which is step 3 of the checklist below.
#
# ⚠ It is signed HERE, before the tarball is staged, so that a copy of it goes
# INTO the tarball. Signed afterwards, as it was, a user installing from the
# tarball had an unsigned file list while a user installing from a mirror had a
# signed one — the same release answering the provenance question two different
# ways depending on how it was obtained.
say "signing $MANIFEST_NAME"
minisign -Sm "$ROOT/$MANIFEST_NAME" -s "$SECKEY" \
    -c "VPN55 $VERSION file list" \
    -t "VPN55 $VERSION file list — verify with the public key in the README" \
    || die "cannot sign $MANIFEST_NAME"
ok "$MANIFEST_NAME.minisig"

rm -rf "$DIST"
mkdir -p "$DIST"

STAGE="$DIST/vpn55-$VERSION"
mkdir -p "$STAGE"

say "staging the tree from MANIFEST.sha256"
COUNT=0
while read -r _digest path; do
    [ -n "${path:-}" ] || continue
    mkdir -p "$STAGE/$(dirname -- "$path")"
    cp -p -- "$ROOT/$path" "$STAGE/$path"
    COUNT=$(( COUNT + 1 ))
done < <(grep -vE '^[[:space:]]*(#|$)' "$ROOT/MANIFEST.sha256")
cp -p -- "$ROOT/MANIFEST.sha256" "$STAGE/MANIFEST.sha256"
# The manifest cannot list itself, and it cannot list its own signature either —
# so both are copied by name. A tarball without the second one is a tarball
# whose file list nobody can check.
cp -p -- "$ROOT/$MANIFEST_NAME.minisig" "$STAGE/$MANIFEST_NAME.minisig"
chmod 0755 "$STAGE/vpn55.sh" "$STAGE/helper/vpnctl" 2>/dev/null || true
ok "staged $COUNT files"

say "building the tarball"
TARBALL="vpn55-$VERSION.tar.gz"
# Reproducible-ish: fixed owner, fixed mtime, sorted names. Two builds of the
# same commit should produce the same bytes, so a third party can rebuild and
# compare rather than having to trust this machine.
tar --sort=name \
    --owner=0 --group=0 --numeric-owner \
    --mtime="@$(git log -1 --format=%ct)" \
    -czf "$DIST/$TARBALL" -C "$DIST" "vpn55-$VERSION"
rm -rf "$STAGE"
ok "$TARBALL"

# ── Checksums, then ONE signature over the checksum file ────────────────────
# Signing the list rather than each artifact means adding an artifact later
# cannot quietly arrive unsigned: it either appears in SHA256SUMS, or it is not
# part of the release.
say "checksums"
( cd "$DIST" && sha256sum "$TARBALL" > SHA256SUMS )
( cd "$ROOT" && sha256sum vpn55.sh MANIFEST.sha256 "$MANIFEST_NAME.minisig" >> "$DIST/SHA256SUMS" )
cat "$DIST/SHA256SUMS" >&2

say "signing SHA256SUMS"
minisign -Sm "$DIST/SHA256SUMS" -s "$SECKEY" \
    -c "VPN55 $VERSION" \
    -t "VPN55 $VERSION — verify with the public key in the README"
ok "SHA256SUMS.minisig"

# ── The rendezvous file ─────────────────────────────────────────────────────
#
# docs/circumvention.md §8 asked whether a signed Nostr event carrying the
# current mirror and the vpn55.sh hash ships in v1. The decision recorded there
# is no — but the SIGNED STATEMENT it was built around ships now, over the
# channels that already exist.
#
# The value in §8 is the signature, not Nostr. "Here is the current mirror, and
# here is what vpn55.sh should hash to", signed by the key already used for
# SHA256SUMS, defeats an injected mirror list on the website, on the .onion and
# pasted into a chat — with no relays, no second signing key on a second curve,
# and no second custody story for a key that would have to come back online to
# re-publish. Nostr can carry this file later; it does not have to sign it.
#
# It is a SEPARATE signature from SHA256SUMS on purpose. SHA256SUMS answers
# "is this download intact"; this answers "where should I be downloading from",
# and that is the question someone asks when they cannot reach the usual place —
# which is exactly when they cannot fetch a tarball to check either.
say "rendezvous file"

# The serial is the commit count: monotonic by construction, never resets, and
# needs no state file that could be forgotten between releases. A reader keeps
# the highest it has seen and refuses to go backwards, so an attacker cannot
# replay a genuine older file to pin somebody to a mirror that has been burned.
SERIAL="$(git rev-list --count HEAD)"

ISSUED="$(date -u +%Y-%m-%d)"
RV_DAYS="${VPN55_RENDEZVOUS_DAYS:-90}"
# GNU first, BSD second. A wrong date here is not cosmetic: it is the bound on
# how long a replayed file stays believable.
EXPIRES="$(date -u -d "+${RV_DAYS} days" +%Y-%m-%d 2>/dev/null \
        || date -u -v"+${RV_DAYS}d" +%Y-%m-%d 2>/dev/null || true)"
[ -n "$EXPIRES" ] || die "cannot compute an expiry date — neither GNU nor BSD date is here"

RV="$DIST/rendezvous.txt"
{
    printf '# VPN55 rendezvous — signed. Check the signature BEFORE believing any of it:\n'
    printf '#     minisign -Vm rendezvous.txt -P <public key from the README>\n'
    printf '#\n'
    printf '# Everything here is public. It is signed so it cannot be forged, not so it\n'
    printf '# cannot be read — the point is to spread it as widely as possible.\n'
    printf 'serial  = %s\n' "$SERIAL"
    printf 'issued  = %s\n' "$ISSUED"
    printf 'expires = %s\n' "$EXPIRES"
    printf 'version = %s\n' "$VERSION"
    for m in ${VPN55_RENDEZVOUS_MIRRORS:-https://raw.githubusercontent.com/noobvie/VPN55/main}; do
        printf 'mirror  = %s\n' "$m"
    done
    # `[ … ] && printf` is an AND-list that returns 1 whenever the variable is
    # unset — which is the default — and this script runs under `set -e`. As a
    # bare statement it would abort the release at its last step.
    if [ -n "${VPN55_RENDEZVOUS_ONION:-}" ]; then
        printf 'onion   = %s\n' "$VPN55_RENDEZVOUS_ONION"
    fi
    # The digest of the ONE file a user runs. Someone who reached a mirror this
    # file did not name can still check what they downloaded against this line.
    ( cd "$ROOT" && sha256sum vpn55.sh ) | while read -r d f; do
        printf 'sha256  = %s  %s\n' "$d" "$f"
    done
} > "$RV"
cat "$RV" >&2

minisign -Sm "$RV" -s "$SECKEY" \
    -c "VPN55 rendezvous $VERSION" \
    -t "VPN55 rendezvous serial ${SERIAL}, issued ${ISSUED}, expires ${EXPIRES}" \
    || die "cannot sign the rendezvous file"
ok "rendezvous.txt + rendezvous.txt.minisig"

if [ "$DO_TAG" = "1" ]; then
    # The tarball signature proves the artifact. The tag signature proves the
    # COMMIT — which is what anyone rebuilding from source is actually trusting.
    say "signing the git tag"
    git tag -s "v$VERSION" -m "VPN55 v$VERSION" || die "tag failed — is a GPG signing key configured?"
    ok "v$VERSION"
fi

cat >&2 <<NEXT

Artifacts in $DIST:
$(cd "$DIST" && ls -1 | sed 's/^/    /')

Before publishing:
  1. Verify from a DIFFERENT machine, as a user would:
         minisign -Vm SHA256SUMS -P <public key from the README>
         sha256sum -c SHA256SUMS
  2. Publish the public key in the README — not only on the website. The
     README lives on the host that cannot be blocked; the website can.
  3. Commit MANIFEST.sha256.minisig, then push the tag and the artifacts and
     update every mirror listed in the README. That signature is what every
     `--update` checks before it parses the file list, so a mirror serving the
     manifest without it is a mirror that will be refused. The README is the
     root of trust, not the site.
  4. Post the release and the current working mirror to the announcement
     channel. That is how someone whose DNS is poisoned finds you again.
  5. Publish rendezvous.txt AND rendezvous.txt.minisig everywhere the project
     can be reached — the website, the .onion, every mirror, and pasted into
     the announcement channel. It is small on purpose: two short files that
     survive being copied into a chat message by someone who cannot reach any
     of the above. Publishing the signature alongside it is not optional; the
     file on its own is a mirror list anyone can rewrite.
NEXT
