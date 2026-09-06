#!/usr/bin/env bash
#
# tests/signature-verify.sh — src_minisign_verify, and the rendezvous reader.
#
# Runs anywhere, changes nothing, needs no root and no VPS. Needs openssl with
# Ed25519, which is every host this project supports.
#
# ── Why this file exists ─────────────────────────────────────────────────────
#
# src_minisign_verify parses the minisign format by hand and checks the
# signature through openssl, because minisign is not installed on a fresh VPS
# and that is the install where the check matters most.
#
# Hand-rolled signature plumbing has one failure mode that matters, and it is
# not "rejects a good signature" — that gets noticed on the first release. It is
# **returning success when it did not actually check anything**. Every negative
# case below exists for that: a good signature verifying is one assertion out of
# a dozen, and the other eleven are the file's real purpose.
#
# ── The keys are made here, with openssl ─────────────────────────────────────
#
# minisign is not required to RUN this. A minisign signature is a plain Ed25519
# signature inside a documented envelope, so the test mints an Ed25519 key with
# openssl and assembles the envelope itself:
#
#   public key  base64( "Ed" | keyid[8] | pubkey[32] )
#   signature   base64( alg[2] | keyid[8] | sig[64] )
#               "trusted comment: <text>"
#               base64( globalsig[64] over sig[64] | comment-text )
#
# That is the same construction the real tool writes. If this file and minisign
# ever disagree about it, the format changed and both halves need re-reading —
# so the envelope is built explicitly here rather than borrowed from the code
# under test, which would make the test agree with the bug.

set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LIB="${HERE}/../lib/core_source.sh"

[[ -r "$LIB" ]] || { printf 'cannot read %s\n' "$LIB" >&2; exit 1; }

command -v openssl >/dev/null 2>&1 || { printf 'openssl is required\n' >&2; exit 1; }
openssl list -public-key-algorithms 2>/dev/null | grep -qi ed25519 \
    || { printf 'this openssl has no Ed25519\n' >&2; exit 1; }

pass=0; fail=0
ok()  { pass=$(( pass + 1 )); printf '  ok    %s\n' "$1"; }
bad() { fail=$(( fail + 1 )); printf '  FAIL  %s\n' "$1"; }

# Silenced: every refusal below is the expected result, and printing each one
# would bury the summary under a wall of correct complaints.
_src_err() { :; }
_src_say() { :; }
_src_warn() { :; }

for fn in src_sig_backend _src_b64_bytes _src_slice _src_verify_ed25519 \
          src_minisign_verify src_rendezvous_values src_rendezvous_check; do
    body="$(sed -n "/^${fn}() {/,/^}/p" "$LIB")"
    [[ -n "$body" ]] || { printf 'could not lift %s\n' "$fn" >&2; exit 1; }
    eval "$body" || exit 1
done

WORK="$(mktemp -d)" || exit 1
trap 'rm -rf "$WORK"' EXIT

# ─── Mint a key and build the minisign envelope ──────────────────────────────

mk_key() { # <name>
    local n="$1"
    openssl genpkey -algorithm ed25519 -out "$WORK/$n.key" >/dev/null 2>&1 || return 1
    openssl pkey -in "$WORK/$n.key" -pubout -outform DER -out "$WORK/$n.der" >/dev/null 2>&1 || return 1
    # The raw 32-byte key is the tail of the 44-byte SPKI: a fixed 12-byte
    # prefix, exactly the one _src_verify_ed25519 writes back on.
    dd if="$WORK/$n.der" of="$WORK/$n.raw" bs=1 skip=12 count=32 2>/dev/null || return 1
    # A key id. Its only job is to be stable and to differ between keys.
    head -c 8 /dev/urandom > "$WORK/$n.keyid" || return 1
    { printf '\x45\x64'; cat "$WORK/$n.keyid" "$WORK/$n.raw"; } > "$WORK/$n.pubbin" || return 1
    openssl base64 -A -in "$WORK/$n.pubbin" -out "$WORK/$n.pub64" || return 1
    return 0
}

sign_file() { # <keyname> <file> <sigfile> [trusted comment] [alg Ed|ED]
    local n="$1" f="$2" out="$3" tc="${4:-VPN55 test}" alg="${5:-Ed}"
    local msg="$WORK/.signmsg"
    if [[ "$alg" == "ED" ]]; then
        openssl dgst -blake2b512 -binary -out "$msg" "$f" || return 1
    else
        cp "$f" "$msg" || return 1
    fi
    openssl pkeyutl -sign -inkey "$WORK/$n.key" -rawin -in "$msg" -out "$WORK/.sig.raw" >/dev/null 2>&1 || return 1

    local algbytes
    if [[ "$alg" == "ED" ]]; then algbytes='\x45\x44'; else algbytes='\x45\x64'; fi
    # shellcheck disable=SC2059
    { printf "$algbytes"; cat "$WORK/$n.keyid" "$WORK/.sig.raw"; } > "$WORK/.sig.bin" || return 1

    # The global signature covers sig[64] || the trusted comment text.
    { cat "$WORK/.sig.raw"; printf '%s' "$tc"; } > "$WORK/.gmsg" || return 1
    openssl pkeyutl -sign -inkey "$WORK/$n.key" -rawin -in "$WORK/.gmsg" -out "$WORK/.gsig.raw" >/dev/null 2>&1 || return 1

    {
        printf 'untrusted comment: signature from a test key\n'
        openssl base64 -A -in "$WORK/.sig.bin"; printf '\n'
        printf 'trusted comment: %s\n' "$tc"
        openssl base64 -A -in "$WORK/.gsig.raw"; printf '\n'
    } > "$out" || return 1
    return 0
}

mk_key good  || { printf 'cannot mint the test key\n' >&2; exit 1; }
mk_key other || { printf 'cannot mint the second key\n' >&2; exit 1; }
PUB="$(cat "$WORK/good.pub64")"
PUB_OTHER="$(cat "$WORK/other.pub64")"

printf 'VPN55 rendezvous test payload\n' > "$WORK/msg.txt"
sign_file good "$WORK/msg.txt" "$WORK/msg.txt.minisig" || { printf 'cannot sign\n' >&2; exit 1; }

v() { if src_minisign_verify "$1" "$2" "${3-$PUB}" 2>/dev/null; then printf accept; else printf reject; fi; }
t() { if [[ "$2" == "$3" ]]; then ok "$1"; else bad "$1 (got $2, wanted $3)"; fi; }

printf '\nBackend\n'
printf '        this run verifies through: %s\n' "$(src_sig_backend)"

printf '\nA genuine signature\n'
t "a good signature over the real file"  "$(v "$WORK/msg.txt" "$WORK/msg.txt.minisig")" accept

# The prehashed form. Real minisign emits it for large files, so a verifier that
# only handles the legacy form passes every test here and fails on a release.
cp "$WORK/msg.txt" "$WORK/pre.txt"
sign_file good "$WORK/pre.txt" "$WORK/pre.txt.minisig" "VPN55 prehashed" ED
t "a prehashed (ED) signature"           "$(v "$WORK/pre.txt" "$WORK/pre.txt.minisig")" accept

printf '\nIt must refuse\n'

# The one that matters most: the payload changed after signing.
printf 'VPN55 rendezvous test payload TAMPERED\n' > "$WORK/bad.txt"
cp "$WORK/msg.txt.minisig" "$WORK/bad.txt.minisig"
t "a modified file with a real signature" "$(v "$WORK/bad.txt" "$WORK/bad.txt.minisig")" reject

# A file signed by a real key that is not ours. This is the injected-mirror
# attack: the attacker signs their own, correctly, with their own key.
sign_file other "$WORK/msg.txt" "$WORK/wrongkey.minisig" || exit 1
t "signed by a different key"             "$(v "$WORK/msg.txt" "$WORK/wrongkey.minisig")" reject
t "verified against the wrong public key" "$(v "$WORK/msg.txt" "$WORK/msg.txt.minisig" "$PUB_OTHER")" reject

# The trusted comment rewritten. The signature over the CONTENT is still valid,
# so a verifier that stops there accepts it — and minisign prints that line as
# the vouched-for one.
sed 's/^trusted comment: .*/trusted comment: VPN55 — mirror moved to evil.example/' \
    "$WORK/msg.txt.minisig" > "$WORK/tc.minisig"
t "trusted comment rewritten"             "$(v "$WORK/msg.txt" "$WORK/tc.minisig")" reject

# Structural damage. Each of these must refuse rather than crash or pass.
head -c 40 "$WORK/msg.txt.minisig" > "$WORK/trunc.minisig"
t "a truncated signature file"            "$(v "$WORK/msg.txt" "$WORK/trunc.minisig")" reject

sed '2s/.*/bm90LWJhc2U2NC1hdC1hbGw@@@/' "$WORK/msg.txt.minisig" > "$WORK/garbage.minisig"
t "a signature line that is not base64"   "$(v "$WORK/msg.txt" "$WORK/garbage.minisig")" reject

# An algorithm this build does not know must refuse, not guess.
{
    printf 'untrusted comment: x\n'
    { printf '\x58\x58'; dd if="$WORK/good.keyid" bs=1 count=8 2>/dev/null; head -c 64 /dev/zero; } | openssl base64 -A
    printf '\n'
} > "$WORK/alg.minisig"
t "an unknown algorithm"                  "$(v "$WORK/msg.txt" "$WORK/alg.minisig")" reject

t "no signature file at all"              "$(v "$WORK/msg.txt" "$WORK/nope.minisig")" reject
t "no such payload file"                  "$(v "$WORK/nope.txt" "$WORK/msg.txt.minisig")" reject

# The state the project ships in TODAY: no public key compiled in. It must
# refuse everything rather than wave it through, or the check is decoration
# until somebody remembers to fill the key in.
t "an empty public key refuses"           "$(v "$WORK/msg.txt" "$WORK/msg.txt.minisig" "")" reject

# ─── The rendezvous reader ───────────────────────────────────────────────────
#
# src_rendezvous_check takes no public key: it uses the one built into the
# shipped copy, which is what a real caller has. So the test key goes into
# VPN55_PUBKEY here.
#
# It is set at THIS point and not at the top on purpose. Left unset, every case
# below refuses — including the two that are supposed to refuse, which would
# then be passing for the wrong reason and would keep passing if the signature
# check were deleted. A negative test that cannot tell you why it passed is not
# a test.
VPN55_PUBKEY="$PUB"

printf '\nThe rendezvous file\n'

cat > "$WORK/rv.txt" <<'RV'
# VPN55 rendezvous
serial  = 4
issued  = 2026-09-02
expires = 2099-01-01
version = 2026.09.02
mirror  = https://raw.githubusercontent.com/noobvie/VPN55/main
mirror  = https://mirror2.example/vpn55
endpoint = 203.0.113.10
endpoint = 198.51.100.7
sha256  = 0000000000000000000000000000000000000000000000000000000000000000  vpn55.sh
RV
sign_file good "$WORK/rv.txt" "$WORK/rv.txt.minisig" || exit 1

t "two mirrors, in order" \
  "$(src_rendezvous_values "$WORK/rv.txt" mirror | tr '\n' ' ')" \
  "https://raw.githubusercontent.com/noobvie/VPN55/main https://mirror2.example/vpn55 "
t "two endpoints" \
  "$(src_rendezvous_values "$WORK/rv.txt" endpoint | tr '\n' ' ')" \
  "203.0.113.10 198.51.100.7 "
t "a comment is not a value" "$(src_rendezvous_values "$WORK/rv.txt" '# VPN55 rendezvous' | wc -l | tr -d ' ')" 0
t "the digest keeps its two-space shape" \
  "$(src_rendezvous_values "$WORK/rv.txt" sha256)" \
  "0000000000000000000000000000000000000000000000000000000000000000  vpn55.sh"

r() { if src_rendezvous_check "$1" "$2" "${3:-2026-09-02}" 2>/dev/null; then printf accept; else printf reject; fi; }
t "a signed, in-date file"   "$(r "$WORK/rv.txt" "$WORK/rv.txt.minisig")" accept

# Expiry. A genuine but stale file is how somebody is pinned to a mirror that
# has since been blocked — the signature is real, which is what makes it work.
sed 's/^expires.*/expires = 2026-08-01/' "$WORK/rv.txt" > "$WORK/old.txt"
sign_file good "$WORK/old.txt" "$WORK/old.txt.minisig" || exit 1
t "a genuine but expired file"  "$(r "$WORK/old.txt" "$WORK/old.txt.minisig")" reject
t "expiring today is still in date" \
  "$(r "$WORK/old.txt" "$WORK/old.txt.minisig" 2026-08-01)" accept

# An unsigned rendezvous is the whole attack. It must never be read.
cp "$WORK/rv.txt" "$WORK/unsigned.txt"
sed 's|mirror  = https://mirror2.example/vpn55|mirror  = https://evil.example/vpn55|' \
    "$WORK/rv.txt" > "$WORK/swapped.txt"
cp "$WORK/rv.txt.minisig" "$WORK/swapped.txt.minisig"
t "a rendezvous with a swapped mirror" "$(r "$WORK/swapped.txt" "$WORK/swapped.txt.minisig")" reject
t "a rendezvous with no signature"     "$(r "$WORK/unsigned.txt" "$WORK/none.minisig")" reject

printf '\n%s passed, %s failed\n' "$pass" "$fail"
(( fail == 0 )) || exit 1
exit 0
