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
#   tools/release.sh 1.0.0              # build + sign artifacts
#   tools/release.sh 1.0.0 --tag        # …and create a signed git tag
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

die() { printf '\033[31m[ERROR]\033[0m %s\n' "$*" >&2; exit 1; }
say() { printf '\033[36m[..]\033[0m %s\n' "$*" >&2; }
ok()  { printf '\033[32m[ok]\033[0m %s\n' "$*" >&2; }

VERSION="${1:-}"
[ -n "$VERSION" ] || die "usage: tools/release.sh <version> [--tag]"
printf '%s' "$VERSION" | grep -qE '^[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.]+)?$' \
    || die "version must look like 1.0.0 or 1.0.0-rc1; got '$VERSION'"
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
( cd "$ROOT" && sha256sum vpn55.sh MANIFEST.sha256 >> "$DIST/SHA256SUMS" )
cat "$DIST/SHA256SUMS" >&2

if ! command -v minisign >/dev/null 2>&1; then
    printf '\033[33m[warn]\033[0m minisign is not installed — the release is UNSIGNED.\n' >&2
    printf '        An unsigned release is the state this project cannot launch in.\n' >&2
    printf '        Install minisign, then:  minisign -Sm %s/SHA256SUMS -s %s\n' "$DIST" "$SECKEY" >&2
    exit 1
fi
[ -f "$SECKEY" ] || die "no secret key at $SECKEY (set VPN55_MINISIGN_KEY)"

say "signing SHA256SUMS"
minisign -Sm "$DIST/SHA256SUMS" -s "$SECKEY" \
    -c "VPN55 $VERSION" \
    -t "VPN55 $VERSION — verify with the public key in the README"
ok "SHA256SUMS.minisig"

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
  3. Push the tag and the artifacts, then update every mirror listed in the
     README. The README is the root of trust, not the site.
  4. Post the release and the current working mirror to the announcement
     channel. That is how someone whose DNS is poisoned finds you again.
NEXT
