# shellcheck shell=bash
#
# lib/core_adapters.sh — the adapter registry, and the only way to reach a
# protocol module.
#
# Nothing in this file may learn which protocols exist. Each lib/proto_*.sh
# announces itself with a tag and a display label; every consumer iterates the
# registry and dispatches by tag. Adding a fourth adapter is dropping in a file
# — there is no list anywhere to extend, which is the property that makes the
# contract real rather than aspirational.
#
# ── Why this is a lib and not a copy in each entry point ──────────────────────
# It began as ~30 lines inside vpn55.sh. Phase 6 gave it a second consumer:
# helper/vpnctl needs to turn `service-restart <tag>` into a call on a registered
# adapter, and needs to REFUSE a tag that no adapter registered. Two copies of a
# registry is two copies of "which tags are legitimate" — and the copy that
# drifts is the one enforcing an authorisation boundary as root. So there is one.
#
# Sourced, not executed. Every consumer runs it inside a ||-guarded call, so
# errexit is off throughout — nothing here relies on the caller's `set -e`.

[[ -n "${VPN55_ADAPTERS_LOADED:-}" ]] && return 0
VPN55_ADAPTERS_LOADED=1

VPN55_ADAPTER_TAGS=()
VPN55_ADAPTER_LABELS=()

# vpn_adapter_register <tag> <display label>
#
# Called by each adapter at the bottom of its own file. The tag is the `<proto>`
# in every contract verb: registering `alpha` means the registry will call
# `vpn_alpha_status` and friends through vpn_adapter_call.
vpn_adapter_register() {
    local tag="${1:-}" label="${2:-}"
    if [[ ! "$tag" =~ ^[a-z][a-z0-9_]{0,31}$ ]]; then
        error "adapter tag '${tag}' is not a valid identifier — ignoring it."
        return 1
    fi
    # Re-sourcing an adapter file must not double-register it. A duplicate tag
    # would print the same service twice in a menu and, worse, make a tag
    # ambiguous in an authorisation check.
    local existing
    for existing in ${VPN55_ADAPTER_TAGS[@]+"${VPN55_ADAPTER_TAGS[@]}"}; do
        if [[ "$existing" == "$tag" ]]; then
            return 0
        fi
    done
    VPN55_ADAPTER_TAGS+=("$tag")
    VPN55_ADAPTER_LABELS+=("${label:-$tag}")
    return 0
}

# vpn_adapter_known <tag> — true when an adapter registered under that tag.
#
# This is the authorisation check helper/vpnctl makes before it restarts
# anything: a tag is only a service name if an adapter claimed it. Without this,
# "restart the service named X" is "restart any unit on the box named X", which
# is a different verb entirely.
vpn_adapter_known() {
    local tag="${1:-}" existing
    [[ -n "$tag" ]] || return 1
    for existing in ${VPN55_ADAPTER_TAGS[@]+"${VPN55_ADAPTER_TAGS[@]}"}; do
        if [[ "$existing" == "$tag" ]]; then
            return 0
        fi
    done
    return 1
}

# vpn_adapter_label <tag> — the display label, or the tag itself when unknown.
#
# ⚠ The index loop is COUNT-GUARDED, and it must stay that way. The obvious
# defensive idiom `${!arr[@]+"${!arr[@]}"}` — the one used a few lines above
# for VALUES, where it is correct — is silently WRONG for INDICES. With an
# operator attached, bash reads the leading `!` as indirect expansion rather
# than as "the keys of": it takes the array's joined value as a variable NAME,
# fails with "alpha beta: invalid variable name", and the loop body never runs
# at all. Not on an empty array — on a POPULATED one, which is the case that
# matters. Verified on bash 5.2.
#
# The value form ${arr[@]+"${arr[@]}"} is unaffected and stays as it is.
vpn_adapter_label() {
    local tag="${1:-}" i
    [[ ${#VPN55_ADAPTER_TAGS[@]} -gt 0 ]] || { printf '%s' "$tag"; return 1; }
    for i in "${!VPN55_ADAPTER_TAGS[@]}"; do
        if [[ "${VPN55_ADAPTER_TAGS[$i]}" == "$tag" ]]; then
            printf '%s' "${VPN55_ADAPTER_LABELS[$i]}"
            return 0
        fi
    done
    printf '%s' "$tag"
    return 1
}

# vpn_adapter_call <tag> <verb> [args…]
#
# The ONLY way anything outside lib/proto_*.sh reaches a protocol module. The
# function name is composed from a validated tag and a verb the caller wrote
# literally — never from caller text — so this cannot be turned into a call on
# an arbitrary function.
vpn_adapter_call() {
    local tag="${1:-}" verb="${2:-}"
    shift 2 || true
    local fn="vpn_${tag}_${verb}"
    if ! declare -F "$fn" >/dev/null 2>&1; then
        error "adapter '${tag}' does not implement '${verb}'."
        return 1
    fi
    "$fn" "$@"
}

# vpn_adapter_load [dir] — source every lib/proto_*.sh and let each register.
#
# Defaults to the directory this file is in, so a caller does not have to know
# where the libraries live in order to load the adapters that sit beside them.
vpn_adapter_load() {
    local dir="${1:-}"
    if [[ -z "$dir" ]]; then
        dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)" || {
            error "cannot resolve the library directory"
            return 1
        }
    fi

    # Save and restore rather than unconditionally clearing: `shopt -u nullglob`
    # at the end would turn the option OFF for a caller that had it on.
    local had_nullglob=0
    if shopt -q nullglob; then had_nullglob=1; fi
    shopt -s nullglob

    local f
    for f in "$dir"/proto_*.sh; do
        # shellcheck disable=SC1090  # discovered by glob; there is no fixed path to declare
        . "$f" || warn "could not load adapter file ${f##*/}"
    done

    [[ "$had_nullglob" -eq 1 ]] || shopt -u nullglob
    return 0
}
