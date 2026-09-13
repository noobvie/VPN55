# shellcheck shell=bash
#
# lib/core_setup.sh — the one-shot: check the host, install every tunnel, deploy
# the panel, hand the operator a working credential and a URL.
#
# ── Why this exists ───────────────────────────────────────────────────────────
#
# The menu is eight rows, which is not the problem. The problem is that a first
# run required understanding four of them, driving them in the right order, and
# answering each adapter's own questions separately — the same public address
# typed three times, the same resolver chosen three times — and then reading a
# README to deploy the interface that manages the result. An operator who
# stopped anywhere in the middle had a part-built server and no way to tell.
#
# This asks the small set of questions once and does the rest.
#
# ── How the adapters are driven without knowing what they are ─────────────────
#
# Two mechanisms, both already part of the contract, neither of which teaches
# this file a protocol name:
#
#   1. VPN55_ENDPOINT and VPN55_DNS_CHOICE. Each adapter reads its own
#      adapter-specific variable first and falls back to these, so one answer
#      here reaches all three. A value already stored by a previous run still
#      wins over both — re-running setup never silently moves an endpoint that
#      is baked into certificates already issued.
#
#   2. Stdin closed for the install calls. ask_value takes its default when
#      there is no terminal, and ask_proceed needs VPN55_ASSUME_YES to agree —
#      which is the documented unattended mode, not a trick. So each adapter
#      still PRINTS its explanation of a choice like transport or key custody,
#      and then takes the default it would have offered.
#
# The consequence worth stating: a prompt whose default is EMPTY fails loudly
# under #2 rather than hanging. That is why the endpoint is settled here, before
# any adapter runs, and why an empty answer to it is refused.
#
# ── Partial success is a real outcome, and is reported as one ─────────────────
#
# One adapter failing does not stop the run. A host where two protocols work and
# the third does not is worth far more than a host where an early failure took
# the other two and the panel with it — and the operator finds out either way,
# because the summary names what failed and what to run to see why.
#
# Sourced, not executed; errexit is off in here as it is everywhere in lib/.

[[ -n "${VPN55_SETUP_LOADED:-}" ]] && return 0
VPN55_SETUP_LOADED=1

: "${VPN55_SETUP_OPERATOR:=operator}"
: "${VPN55_SETUP_ADMIN:=admin}"

# Filled in by setup_preflight, read by setup_run.
VPN55_SETUP_PANEL_OK=0
VPN55_SETUP_PANEL_DONE=0
VPN55_SETUP_FAILED=""
VPN55_SETUP_INSTALLED=""

# ─── The requirements report ──────────────────────────────────────────────────
# One line per check, PASS or FAIL, with the reason on the same line. A wall of
# diagnostic output is how a missing requirement gets scrolled past; a column of
# PASS with one FAIL in it is not.

_setup_row() {
    local state="${1:-}" label="${2:-}" detail="${3:-}"
    case "$state" in
        pass) printf '  %s[ ok ]%s  %-26s %s\n' "$GREEN"  "$RESET" "$label" "$detail" >&2 ;;
        warn) printf '  %s[ -- ]%s  %-26s %s\n' "$YELLOW" "$RESET" "$label" "$detail" >&2 ;;
        *)    printf '  %s[FAIL]%s  %-26s %s\n' "$RED"    "$RESET" "$label" "$detail" >&2 ;;
    esac
}

# Returns 1 when something that cannot be worked around is missing. A missing
# Node.js is NOT one of those: the tunnels are the product and the panel is the
# convenience, so it downgrades to "panel skipped" rather than stopping a run
# that would otherwise give the operator three working protocols.
setup_preflight() {
    local hard=0 detail tag label

    section "Requirements"

    if distro_is_root; then
        _setup_row pass "root" "running as uid 0"
    else
        _setup_row fail "root" "run this with sudo, or as root"
        hard=1
    fi

    # distro_detect SETS variables and prints nothing, so the detail comes from
    # what it set rather than from its output.
    if distro_detect >/dev/null 2>&1; then
        _setup_row pass "operating system" "${VPN55_OS_NAME:-unknown} ${VPN55_OS_VERSION:-}"
    else
        _setup_row fail "operating system" "not recognised — see the distro matrix in README.md"
        hard=1
    fi

    if distro_has_systemd; then
        _setup_row pass "systemd" "present"
    else
        _setup_row fail "systemd" "every service here is a unit; there is no other path"
        hard=1
    fi

    if distro_is_container; then
        _setup_row warn "virtualisation" "$(distro_virt 2>/dev/null || printf 'container') — a tunnel needs /dev/net/tun"
    else
        _setup_row pass "virtualisation" "$(distro_virt 2>/dev/null || printf 'bare metal or full VM')"
    fi

    if distro_have openssl; then
        _setup_row pass "openssl" "present"
    else
        _setup_row fail "openssl" "certificate protocols cannot run without it"
        hard=1
    fi

    # ⚠ Checked HERE rather than at deploy time. The panel unit and the sudoers
    # rule both name /usr/local/lib/vpn55 as a literal, so a run from a git
    # checkout cannot deploy the panel — and finding that out at step five,
    # after three protocols are installed, is finding it out too late to act on.
    if [[ -n "${VPN55_ROOT:-}" && "${VPN55_ROOT}" != "${VPN55_HOME}" ]]; then
        VPN55_SETUP_PANEL_OK=0
        _setup_row warn "install location" "running from ${VPN55_ROOT}, not ${VPN55_HOME} — panel will be skipped"
    elif pnl_node_ok; then
        VPN55_SETUP_PANEL_OK=1
        _setup_row pass "node.js" "v$(pnl_node_version) — the panel can be deployed"
    else
        VPN55_SETUP_PANEL_OK=0
        detail="$(pnl_node_version 2>/dev/null || printf 'not installed')"
        [[ "$detail" == "not installed" ]] || detail="v${detail}"
        _setup_row warn "node.js" "${detail} — need ${VPN55_PANEL_NODE_MIN}+, so the panel will be skipped"
    fi

    # A private address here is not fatal — a host behind NAT with a forwarded
    # port is a legitimate arrangement — but it is never what the operator
    # should accept without being told.
    if detail="$(net_public_endpoint 2>/dev/null)"; then
        _setup_row pass "public address" "$detail"
    else
        _setup_row warn "public address" "could not be detected — you will be asked for it"
    fi

    if net_pool_check_conflicts >/dev/null 2>&1; then
        _setup_row pass "address pool" "${VPN55_NET_PARENT} is free"
    else
        _setup_row warn "address pool" "${VPN55_NET_PARENT} overlaps something routed here"
    fi

    for tag in ${VPN55_ADAPTER_TAGS[@]+"${VPN55_ADAPTER_TAGS[@]}"}; do
        label="$(vpn_adapter_label "$tag")" || label="$tag"
        if vpn_adapter_call "$tag" available >/dev/null 2>&1; then
            _setup_row pass "$label" "can run on this host"
        else
            _setup_row warn "$label" "unavailable here — it will be skipped"
        fi
    done

    ui_rule
    if [[ "$hard" -eq 1 ]]; then
        error "Something above cannot be worked around. Nothing has been changed."
        return 1
    fi
    return 0
}

# ─── The questions ────────────────────────────────────────────────────────────
# Asked once, each with a default that is right for most hosts: the endpoint,
# the resolver, the operator's name, the administrator's name, and — from
# _adapter_deliver — the language their files are written in. Anything else an
# adapter needs, it explains and defaults on its own.
_setup_ask() {
    local detected="" rc=0

    section "Settings"

    detected="$(net_public_endpoint)" || rc=$?
    if [[ "$rc" -eq 2 ]]; then
        warn "Detected ${detected}, which is a private address — clients on the"
        warn "internet cannot dial it. Enter the address they reach this host on."
        detected=""
    fi

    info "This address goes into every client configuration and into the server"
    info "certificate, so changing it later means reissuing both. A hostname is the"
    info "better answer if the address might ever move."
    ask_value VPN55_ENDPOINT "Public address or hostname clients will dial" "$detected" || return 1
    [[ -n "$VPN55_ENDPOINT" ]] || { error "There is no default for this — setup cannot continue without it."; return 1; }

    net_resolvers_explain || true
    ask_value VPN55_DNS_CHOICE "DNS (system/cloudflare/quad9/custom)" "system" || return 1

    # custom needs a second answer that only the adapters know what to do with,
    # and this file has no business asking for resolver addresses it cannot
    # validate against the adapter that will use them.
    if [[ "$VPN55_DNS_CHOICE" == "custom" ]]; then
        warn "'custom' needs resolver addresses per protocol, which setup does not ask for."
        warn "Falling back to 'system'; change it later from the tunnel services screen."
        VPN55_DNS_CHOICE="system"
    fi

    info "You are the first user of this server, so setup registers you and issues"
    info "you a credential for every protocol it installs."
    ask_value VPN55_SETUP_OPERATOR "Your name in the user registry" "$VPN55_SETUP_OPERATOR" || return 1
    users_validate_name "$VPN55_SETUP_OPERATOR" || return 1

    if [[ "$VPN55_SETUP_PANEL_OK" -eq 1 ]]; then
        ask_value VPN55_SETUP_ADMIN "Administrator name for the panel" "$VPN55_SETUP_ADMIN" || return 1
        [[ -n "$VPN55_SETUP_ADMIN" ]] || { error "The panel needs an administrator name."; return 1; }
    fi

    export VPN55_ENDPOINT VPN55_DNS_CHOICE
    return 0
}

# ─── Installing every adapter ─────────────────────────────────────────────────
# Stdin is closed per call rather than for the whole function: the operator is
# still at a terminal, and a later step — delivering their configuration — has
# every reason to use it.
_setup_install_all() {
    local tag label ok=0

    for tag in ${VPN55_ADAPTER_TAGS[@]+"${VPN55_ADAPTER_TAGS[@]}"}; do
        label="$(vpn_adapter_label "$tag")" || label="$tag"

        if ! vpn_adapter_call "$tag" available >/dev/null 2>&1; then
            info "Skipping ${label} — it cannot run on this host."
            continue
        fi

        if VPN55_ASSUME_YES=1 vpn_adapter_call "$tag" install < /dev/null; then
            ok=$(( ok + 1 ))
            VPN55_SETUP_INSTALLED="${VPN55_SETUP_INSTALLED}${tag} "
        else
            error "${label} did not install. The other services are unaffected."
            VPN55_SETUP_FAILED="${VPN55_SETUP_FAILED}${label}, "
        fi
    done

    [[ "$ok" -gt 0 ]]
}

# ─── The operator's own credential ────────────────────────────────────────────
# Issued before the panel URL is printed, and that ordering is the point: the
# panel listens on the tunnel only, so an operator who cannot get on the tunnel
# cannot open it. This is what makes the URL in the summary a URL they can use.
_setup_operator_creds() {
    local tag cred locale label

    users_exists "$VPN55_SETUP_OPERATOR" || users_add "$VPN55_SETUP_OPERATOR" \
        || { error "could not register '${VPN55_SETUP_OPERATOR}'"; return 1; }

    locale="$(_artifact_locale)" || locale="$VPN55_DEFAULT_LOCALE"

    for tag in $VPN55_SETUP_INSTALLED; do
        label="$(vpn_adapter_label "$tag")" || label="$tag"
        section "Your ${label} configuration"
        cred="$(vpn_adapter_call "$tag" cred_add "$VPN55_SETUP_OPERATOR")" || {
            warn "Could not issue you a ${label} credential. Everything else is unaffected;"
            warn "issue one later from the tunnel services screen."
            continue
        }
        [[ -n "$cred" ]] || {
            warn "${label} reported success but returned no credential id."
            continue
        }
        success "Credential '${cred}' issued to '${VPN55_SETUP_OPERATOR}'."
        _adapter_deliver "$tag" "$cred" "$locale" || true
    done
    return 0
}

# ─── The summary ──────────────────────────────────────────────────────────────
# The last thing on the screen, because it is the only part an operator will
# scroll back to. Everything they need to actually use the server, and every
# thing that did not work.
_setup_summary() {
    local url fp

    section "Done"

    ui_kv "Public address" "$VPN55_ENDPOINT"
    ui_kv "Services installed" "${VPN55_SETUP_INSTALLED:-none}"
    if [[ -n "$VPN55_SETUP_FAILED" ]]; then
        ui_kv "Did NOT install" "${VPN55_SETUP_FAILED%, }"
    fi
    ui_kv "Registered to you" "$VPN55_SETUP_OPERATOR"

    # ⚠ Gated on the flag panel_install actually returned, not on pnl_installed:
    # a deploy that placed the unit and then failed at the vhost leaves that file
    # behind, and printing a URL for a panel that is not serving is worse than
    # printing nothing.
    if [[ "$VPN55_SETUP_PANEL_DONE" -eq 1 ]]; then
        url="$(panel_url 2>/dev/null || printf 'unavailable')"
        ui_rule
        info "The admin panel is reachable OVER THE TUNNEL ONLY — it has no public"
        info "port at all. Connect with the configuration saved above, then open:"
        ui_kv "Panel" "$url"
        ui_kv "Administrator" "$VPN55_SETUP_ADMIN"
        if [[ -n "$VPN55_PANEL_ADMIN_PASS" ]]; then
            ui_kv "Password" "$VPN55_PANEL_ADMIN_PASS"
            warn "That password is shown ONCE and is not recoverable — this host keeps"
            warn "only a hash of it. Save it now. To replace it later:"
            warn "  node ${VPN55_PANEL_SRC}/scripts/admin.js passwd ${VPN55_SETUP_ADMIN}"
        fi
        if fp="$(pnl_cert_fingerprint 2>/dev/null)"; then
            info "The certificate is self-signed, so the browser warns once. Check it"
            info "against this before you accept it:"
            ui_kv "SHA-256" "$fp"
        fi
    fi

    ui_rule
    info "Add another user:      run this installer again and choose Users"
    info "Hand out a config:     Tunnel services → the protocol → issue"

    if [[ -n "$VPN55_SETUP_FAILED" ]]; then
        ui_rule
        warn "Not everything installed. To see why the failed one refused:"
        warn "  journalctl -xe --no-pager | tail -50"
    fi
    return 0
}

# ─── The one-shot ─────────────────────────────────────────────────────────────
setup_run() {
    distro_require_root || return 1

    section "Set up this server"
    info "This installs every tunnel service this host can run, deploys the admin"
    info "panel, registers you as its first user and hands you a configuration."
    info "It asks a few short questions and defaults sensibly on everything else."

    setup_preflight || return 1

    if ! ask_proceed "Set this server up now"; then
        info "Nothing was changed."
        return 0
    fi

    _setup_ask || return 1

    if ! _setup_install_all; then
        error "No tunnel service installed, so there is nothing for the panel to"
        error "listen on and setup stops here. The failures are above."
        return 1
    fi

    _setup_operator_creds || true

    if [[ "$VPN55_SETUP_PANEL_OK" -eq 1 ]]; then
        if panel_install "$VPN55_SETUP_ADMIN"; then
            VPN55_SETUP_PANEL_DONE=1
        else
            VPN55_SETUP_FAILED="${VPN55_SETUP_FAILED}admin panel, "
            warn "The panel did not deploy. Every tunnel above is unaffected and"
            warn "working; re-run setup once the reason above is fixed."
        fi
    else
        info "Skipping the panel — see the requirements table above for why."
    fi

    _setup_summary || true
    return 0
}
