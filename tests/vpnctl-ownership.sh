#!/usr/bin/env bash
#
# tests/vpnctl-ownership.sh — cred-revoke's ownership assertion.
#
# Runs anywhere, changes nothing, needs no root and no VPS. That is the whole
# point of it: tests/vps-acceptance.sh answers "does this work on a host", and
# nobody runs a destructive script on a throwaway server to find out whether an
# argument parser fails open.
#
# ── What is under test, and why it is worth a file of its own ────────────────
#
# `cred-revoke` used to take a credential id and revoke it, with no holder to
# compare against. The self-serve portal's rotation calls it, so the portal's
# own ownership layer — panel/portal/logic.js — was the ONLY check on the
# destructive half of a rotation, while the comment in that file said it was
# the friendlier of two. `user=` closes that, and this file is what says so
# afterwards.
#
# The function body is LIFTED OUT OF helper/vpnctl and evaluated, rather than
# re-typed here. A test that re-states the logic it is checking passes on the
# day the real thing is deleted.
#
# The collaborators are stubbed because none of them is what is being tested:
# users_cred_find stands in for the register, and the adapter call always
# succeeds, so every refusal below comes from the verb itself.

set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VPNCTL="${HERE}/../helper/vpnctl"

[[ -r "$VPNCTL" ]] || { printf 'cannot read %s\n' "$VPNCTL" >&2; exit 1; }

# ─── The world the verb runs in ──────────────────────────────────────────────

E_OK=0; E_USAGE=2; E_ARG=3; E_PRIV=4; E_TARGET=5; E_FAILED=6
export E_OK E_USAGE E_ARG E_PRIV E_TARGET E_FAILED
VPNCTL_TARGET=""

ctl_fail()   { printf 'FAIL(%s) %s\n' "$1" "$2"; exit "$1"; }
ctl_ok()     { printf 'OK %s\n' "$1"; exit 0; }
ctl_detail() { :; }

# The same shapes vpnctl's own validators accept. Kept deliberately simple: a
# stricter copy here would fail cases the real verb allows, which is a test
# reporting a bug in itself.
ctl_valid_cred() { [[ "$1" =~ ^[A-Za-z0-9._-]{1,64}$ ]]; }
ctl_valid_tag()  { [[ "$1" =~ ^[a-z][a-z0-9-]{1,31}$ ]]; }
ctl_valid_user() { [[ "$1" =~ ^[a-z][a-z0-9_-]{1,31}$ ]]; }

_ctl_load_libs()       { return 0; }
_ctl_load_adapters()   { return 0; }
_ctl_require_adapter() { return 0; }

# name<TAB>service<TAB>created<TAB>state — field 1 is the HOLDER, field 2 the
# adapter tag. Returns 1 for an id in no record at all, which is what the real
# users_cred_find does and is the case the assertion must refuse rather than
# wave through.
users_cred_find() {
    case "$1" in
        nam-1)  printf 'nam\twg\t2026-01-01\tactive\n' ;;
        linh-1) printf 'linh\twg\t2026-01-01\tactive\n' ;;
        *) return 1 ;;
    esac
}

# Always succeeds, so a refusal below is never the adapter's.
vpn_adapter_call() { printf 'revoked\twg\t%s\timmediate\t0\n' "$3"; }

# ─── The function itself, out of the shipped file ────────────────────────────

eval "$(sed -n '/^verb_cred_revoke() {$/,/^}$/p' "$VPNCTL")"
if [[ $(type -t verb_cred_revoke) != function ]]; then
    printf 'could not lift verb_cred_revoke out of %s — has it been renamed?\n' "$VPNCTL" >&2
    exit 1
fi

# ─── Cases ───────────────────────────────────────────────────────────────────

pass=0; fail=0

expect() { # expect <description> <wanted_rc> <args…>
    local what="$1" want="$2"; shift 2
    local out rc
    out="$( verb_cred_revoke "$@" 2>&1 )"; rc=$?
    if [[ "$rc" == "$want" ]]; then
        printf '  ok    %s\n' "$what"; pass=$((pass + 1))
    else
        printf '  FAIL  %s\n          wanted rc %s, got %s: %s\n' "$what" "$want" "$rc" "$out"
        fail=$((fail + 1))
    fi
}

printf '\n  Without an assertion — the admin panel and the enforcement sweep\n'
expect "revokes a registered credential"                 "$E_OK"     nam-1
expect "revokes with an explicit service tag"            "$E_OK"     nam-1 wg
expect "an unregistered id with a tag still revokes"     "$E_OK"     ghost-9 wg
expect "an unregistered id with no tag is refused"       "$E_TARGET" ghost-9

printf '\n  With user= — the self-serve portal\n'
expect "the holder may revoke their own"                 "$E_OK"     nam-1 user=nam
expect "…with a tag as well"                             "$E_OK"     nam-1 wg user=nam
expect "…in either argument order"                       "$E_OK"     nam-1 user=nam wg
expect "ANOTHER USER'S CREDENTIAL IS REFUSED"            "$E_TARGET" linh-1 user=nam
expect "an unregistered id cannot be asserted"           "$E_TARGET" ghost-9 user=nam
expect "…not even when a tag is supplied"                "$E_TARGET" ghost-9 wg user=nam

printf '\n  Malformed arguments\n'
expect "an invalid user name is rejected"                "$E_ARG"    nam-1 'user=../root'
# The regression this file was written for: keying the check on the VALUE being
# non-empty made a bare `user=` skip the check and revoke.
expect "an empty user= is not a wildcard"                "$E_ARG"    nam-1 'user='
expect "two user= are refused"                           "$E_USAGE"  nam-1 user=nam user=linh
expect "two tags are refused"                            "$E_USAGE"  nam-1 wg ovpn
expect "a fourth argument is refused"                    "$E_USAGE"  nam-1 wg user=nam extra
expect "an invalid credential id is rejected"            "$E_ARG"    'a b' user=nam

printf '\n  %s passed, %s failed\n\n' "$pass" "$fail"
[[ $fail -eq 0 ]]
