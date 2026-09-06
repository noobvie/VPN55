#!/usr/bin/env bash
#
# tests/awg-params.sh — the AmneziaWG obfuscation parameters.
#
# Runs anywhere, changes nothing, needs no root and no VPS — the same posture as
# tests/vpnctl-ownership.sh, and for the same reason: nobody installs a tunnel on
# a throwaway server to find out whether a bounds check is off by one.
#
# ── Why this is worth a file of its own ──────────────────────────────────────
#
# The nine parameters are the one thing in this project whose failure mode is
# invisible. A wrong value does not degrade the tunnel and does not log: the
# handshake is simply never recognised, at both ends, and the operator cannot
# tell that apart from a firewall problem, a NAT problem or a wrong endpoint.
# tests/vps-acceptance.sh would not catch an off-by-one here either — it would
# look like the server not working.
#
# So the constraints are checked HERE, against the real functions, lifted out of
# lib/proto_wireguard.sh and evaluated rather than re-typed. A test that
# re-states the logic it checks passes on the day the real thing is deleted.
#
# ── The two halves ───────────────────────────────────────────────────────────
#
#   1. Boundary table        does _awg_validate reject each violation, and does
#                            it accept the value one step inside the edge? A
#                            validator that accepted everything would pass half
#                            2 on its own, so this half has to exist.
#   2. Generator conformance  does _awg_generate only ever emit sets its own
#                            validator accepts, and does it REDRAW around the
#                            S1+56 rule rather than nudge? A nudged value piles
#                            up beside the forbidden point, which is itself the
#                            fingerprint the parameters exist to destroy — so
#                            the distribution is the assertion, not the comment.
#
# ── The entropy pool, and why it is a file on fd 3 ───────────────────────────
#
# fs_random_hex is stubbed from a pre-drawn pool because the real one forks
# head/od/tr per call and _awg_generate makes at least thirteen calls.
#
# It must be a FILE ON A FILE DESCRIPTOR, never a shell variable with an offset.
# _awg_rand is called as `$( )`, and a subshell gets a COPY of every variable —
# so a variable offset never advances, every draw returns identical bytes, and
# the H1-H4 loop never completes. A file offset is shared across fork, so fd 3
# keeps handing out fresh bytes inside the subshell. This is not a footnote:
# writing it the other way is what proved that loop needed the bound it now has.

set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ADAPTER="${HERE}/../lib/proto_wireguard.sh"

[[ -r "$ADAPTER" ]] || { printf 'cannot read %s\n' "$ADAPTER" >&2; exit 1; }

RUNS="${AWG_TEST_RUNS:-200}"
[[ "$RUNS" =~ ^[0-9]+$ ]] && (( RUNS >= 1 )) \
    || { printf 'AWG_TEST_RUNS must be a positive integer\n' >&2; exit 1; }

pass=0; fail=0
ok()  { pass=$(( pass + 1 )); printf '  ok    %s\n' "$1"; }
bad() { fail=$(( fail + 1 )); printf '  FAIL  %s\n' "$1"; }

# ─── The world the functions run in ──────────────────────────────────────────
# error() is silenced: every rejection below is EXPECTED, and printing each one
# would bury the two lines that matter under a wall of correct complaints.
error() { :; }
debug() { :; }

POOL=""
_pool_drop() {
    exec 3<&- 2>/dev/null || true
    [[ -n "$POOL" ]] && rm -f "$POOL"
    POOL=""
}
trap _pool_drop EXIT

_pool_make() {
    POOL="$(mktemp "${TMPDIR:-/tmp}/awg-pool.XXXXXX")" || return 1
    # 13 draws x 4 bytes per set, plus slack for the two redraw loops.
    head -c $(( RUNS * 160 + 65536 )) /dev/urandom \
        | od -An -tx1 -v | tr -d ' \n' > "$POOL" || return 1
    exec 3< "$POOL" || return 1
    return 0
}

fs_random_hex() {
    local n=$(( ${1:-16} * 2 )) h=""
    read -r -N "$n" -u 3 h || return 1
    [[ "${#h}" -eq "$n" ]] || return 1
    printf '%s' "$h"
}

# The real functions, verbatim. Anchored on `^name() {` .. `^}` — each closes at
# column 0 and nothing nested inside them does.
_lift() {
    local fn="$1" body
    body="$(sed -n "/^${fn}() {/,/^}/p" "$ADAPTER")" || return 1
    [[ -n "$body" ]] || { printf 'could not lift %s out of %s\n' "$fn" "$ADAPTER" >&2; return 1; }
    eval "$body" || return 1
    return 0
}
_lift _awg_rand     || exit 1
_lift _awg_validate || exit 1
_lift _awg_generate || exit 1

# ─── 1. The boundary table ───────────────────────────────────────────────────
# Every rule the adapter documents, checked on BOTH sides of its edge. The
# accept rows are as load-bearing as the reject rows: a validator that refused
# everything would satisfy the reject column on its own.

BASE=(6 12 200 100 90 11 12 13 14)
swap() { local -a a=("${BASE[@]}"); a[$1]="$2"; printf '%s ' "${a[@]}"; }

chk() {
    local want="$1" label="$2"; shift 2
    local got
    if _awg_validate "$@" 2>/dev/null; then got=accept; else got=reject; fi
    if [[ "$got" == "$want" ]]; then ok "$label"; else bad "$label (got ${got}, wanted ${want})"; fi
}

printf '\nBoundary table\n'
chk accept "a known-good set"                        "${BASE[@]}"

chk reject "Jc = 0             floor is 1"           $(swap 0 0)
chk accept "Jc = 1"                                  $(swap 0 1)
chk accept "Jc = 128"                                $(swap 0 128)
chk reject "Jc = 129           ceiling is 128"       $(swap 0 129)

chk reject "Jmin = 0           floor is 1"           $(swap 1 0)
chk accept "Jmax = 1280"                             $(swap 2 1280)
chk reject "Jmax = 1281        ceiling is 1280"      $(swap 2 1281)
chk reject "Jmin == Jmax       a range is a range"   6 200 200 100 90 11 12 13 14
chk reject "Jmin > Jmax"                             6 201 200 100 90 11 12 13 14

chk accept "S1 = 1132          1280 - 148, the init"     6 12 1280 1132 90 11 12 13 14
chk reject "S1 = 1133"                                   6 12 1280 1133 90 11 12 13 14
chk accept "S2 = 1188          1280 - 92, the response"  6 12 1280 100 1188 11 12 13 14
chk reject "S2 = 1189"                                   6 12 1280 100 1189 11 12 13 14

# The rule the whole thing turns on. len(init) = 148 + S1 and len(resp) = 92 + S2,
# so S1 + 56 == S2 makes both packets exactly the same length: a fresh
# fixed-length signature in place of the one just removed. Both neighbours must
# still pass, or the check is a range rather than a point.
chk reject "S1 + 56 == S2      equal packet lengths" 6 12 200 100 156 11 12 13 14
chk accept "S1 + 56 == S2 - 1"                       6 12 200 100 157 11 12 13 14
chk accept "S1 + 56 == S2 + 1"                       6 12 200 100 155 11 12 13 14

chk reject "H1 = 4             1-4 are WireGuard's"  $(swap 5 4)
chk accept "H1 = 5"                                  $(swap 5 5)
chk accept "H1 = 4294967295    the field is uint32"  $(swap 5 4294967295)
chk reject "H1 = 4294967296"                         $(swap 5 4294967296)
chk reject "H1 == H4           must be distinct"     6 12 200 100 90 14 12 13 14
chk reject "H2 == H3"                                6 12 200 100 90 11 12 12 14

chk reject "a negative value"                        6 12 200 100 90 11 12 13 -1
chk reject "a non-numeric value"                     6 12 200 100 90 11 12 13 abc
chk reject "an empty field"                          6 12 200 100 90 11 12 13 ""
chk reject "too few fields"                          6 12 200 100 90 11 12 13

# ─── 2. Generator conformance ────────────────────────────────────────────────
printf '\nGenerator — %s sets\n' "$RUNS"
_pool_make || { printf 'cannot build the entropy pool\n' >&2; exit 1; }

gen_fail=0; self_reject=0; forbidden=0
declare -A near=()
line=""; jc=""; jmin=""; jmax=""; s1=""; s2=""; h1=""; h2=""; h3=""; h4=""; d=0
for (( i = 0; i < RUNS; i++ )); do
    line="$(_awg_generate 2>/dev/null)" || { gen_fail=$(( gen_fail + 1 )); continue; }
    IFS=$'\t' read -r jc jmin jmax s1 s2 h1 h2 h3 h4 <<< "$line"
    _awg_validate "$jc" "$jmin" "$jmax" "$s1" "$s2" "$h1" "$h2" "$h3" "$h4" 2>/dev/null \
        || { self_reject=$(( self_reject + 1 )); printf '        self-rejected: %s\n' "$line"; }
    (( s1 + 56 == s2 )) && forbidden=$(( forbidden + 1 ))
    d=$(( s2 - s1 - 56 )); (( d < 0 )) && d=$(( -d ))
    (( d <= 3 )) && near[$d]=$(( ${near[$d]:-0} + 1 ))
done

if (( gen_fail == 0 )); then ok "every set generated"
else bad "${gen_fail}/${RUNS} sets failed to generate"; fi

if (( self_reject == 0 )); then ok "every generated set passes its own validator"
else bad "${self_reject}/${RUNS} sets were rejected by _awg_validate"; fi

if (( forbidden == 0 )); then ok "no set landed on S1 + 56 == S2"
else bad "${forbidden}/${RUNS} sets landed on the forbidden point"; fi

# REDRAW, not nudge. An implementation that adjusted a rejected S2 by one would
# leave distance 0 empty — which the check above already confirms — while piling
# every one of those adjustments onto distance 1. So the assertion is that
# distance 1 is not a SPIKE relative to its neighbours. It is deliberately a
# loose bound: the counts are small at this sample size, and a test that fails
# on ordinary variance gets disabled, which is worse than not having it.
n1="${near[1]:-0}"; n2="${near[2]:-0}"; n3="${near[3]:-0}"
printf '        |S2 - (S1+56)| = 1:%s  2:%s  3:%s\n' "$n1" "$n2" "$n3"
neighbours=$(( n2 + n3 ))
if (( n1 <= neighbours + 3 )); then
    ok "S2 is redrawn, not nudged — no pile-up beside the forbidden point"
else
    bad "S2 clusters at distance 1 (${n1} against ${neighbours} at 2 and 3) — that is a nudge, and a nudge is a fingerprint"
fi

_pool_drop

# ─── 3. A randomness source that has gone constant ───────────────────────────
# The regression this file was written for. _awg_generate draws H1-H4 until it
# holds four DISTINCT values; that loop exits when _awg_rand FAILS, but not when
# _awg_rand succeeds and keeps returning the same number — which is exactly what
# a constant source does. Unbounded, it spins forever inside an install, with no
# output, nothing logged, and nothing to time out.
#
# So the assertion here is not "it produces a good set". It is "it gives up".
# The outer timeout is the real test: without the try counter this never
# returns, and the run hangs rather than failing.
printf '\nA randomness source that has gone constant\n'
if command -v timeout >/dev/null 2>&1; then
    const_rc=0
    timeout 20 bash -c '
        set -uo pipefail
        error() { :; }; debug() { :; }
        # Always the same eight hex characters. Every constraint _awg_rand
        # itself checks is satisfied; only the values never change.
        fs_random_hex() { printf "%s" "aaaaaaaa"; }
        eval "$(sed -n "/^_awg_rand() {/,/^}/p"     "$1")"
        eval "$(sed -n "/^_awg_validate() {/,/^}/p" "$1")"
        eval "$(sed -n "/^_awg_generate() {/,/^}/p" "$1")"
        _awg_generate >/dev/null 2>&1
    ' _ "$ADAPTER" || const_rc=$?

    if (( const_rc == 0 )); then
        bad "a constant source produced a set — four identical H values is not a set"
    elif (( const_rc == 124 )); then
        bad "_awg_generate HUNG on a constant source — the H1-H4 draw loop is unbounded again"
    else
        ok "_awg_generate gives up instead of spinning forever"
    fi
else
    printf '        skipped — no timeout(1) on this host\n'
fi

printf '\n%s passed, %s failed\n' "$pass" "$fail"
(( fail == 0 )) || exit 1
exit 0
