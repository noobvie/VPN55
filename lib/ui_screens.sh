# shellcheck shell=bash
#
# lib/ui_screens.sh — the screens that are not about one tunnel service.
#
# Split out of vpn55.sh in Phase 9: the host report, the network prerequisites,
# the user registry, the panel explainer, the network-state teardown, and the
# self-update screen. The per-service screens are in lib/ui_adapter.sh; the
# machine-readable verbs are in lib/cli.sh; vpn55.sh keeps the bootstrap, the
# main menu and the argument dispatch and nothing else.
#
# ⚠ errexit does NOT protect these bodies. Every screen is called as `fn || true`
# from vpn55.sh's menu, which disables errexit for the whole call — see
# CLAUDE.md. Guard anything that writes.
# ─── Screens ──────────────────────────────────────────────────────────────────
screen_doctor() {
    section "Host report"
    distro_report || return 1
    ui_rule
    net_report || true
    ui_rule
    pki_report || true
    ui_rule
    bak_report || true
    ui_rule
    ui_kv "Registered users" "$(users_count)"
    ui_kv "Protocol adapters" "${#VPN55_ADAPTER_TAGS[@]} loaded"
    ui_kv "VPN55 state" "$VPN55_ETC"
    ui_kv "Installed at" "$VPN55_ROOT"
    ui_kv "Revision" "$(src_revision "$VPN55_ROOT")"
    ui_kv "Source base URL" "$VPN55_MIRROR"
    return 0
}

screen_network() {
    section "Network"
    net_report || true

    if ! ask_proceed "Apply VPN55's network prerequisites now"; then
        info "Nothing was changed."
        return 0
    fi

    # Checked before anything is written: a parent range that collides with an
    # existing route is a routing failure that presents as a firewall failure,
    # and it is far cheaper to catch here than in week three.
    if ! net_pool_check_conflicts; then
        if ! ask_proceed "Continue anyway"; then
            info "Nothing was changed."
            return 0
        fi
    fi

    net_forwarding_enable || return 1
    net_fw_backend >/dev/null || return 1
    success "Network prerequisites applied."
    return 0
}

_users_menu_add() {
    local name="" quota="" expires="" conn="" reset=""
    ask_value name "User name" || return 1
    [[ -n "$name" ]] || { error "A name is required."; return 1; }

    info "Leave a limit blank for unlimited — that is the default and it is not a placeholder."
    ask_value quota   "Traffic quota in bytes" || return 1
    ask_value expires "Expires (YYYY-MM-DD)"   || return 1
    ask_value conn    "Simultaneous devices"   || return 1
    ask_value reset   "Quota resets (daily/weekly/monthly, blank = lifetime cap)" || return 1

    users_add "$name" \
        "quota_bytes=$quota" \
        "expires_at=$expires" \
        "conn_limit=$conn" \
        "quota_reset=$reset"
}

_users_menu_show() {
    local name=""
    ask_value name "User name" || return 1
    users_show "$name"
}

_users_menu_toggle() {
    local name="" state=""
    ask_value name "User name" || return 1
    state="$(users_get "$name" enabled)" || return 1
    if [[ "$state" == "1" ]]; then
        users_disable "$name" && success "User '${name}' disabled."
    else
        users_enable "$name" && success "User '${name}' enabled."
    fi
}

_users_menu_remove() {
    local name=""
    ask_value name "User name" || return 1
    users_exists "$name" || { error "No such user '${name}'."; return 1; }
    ask_proceed "Remove '${name}' from the registry" || { info "Nothing was changed."; return 0; }
    users_remove "$name"
}

_users_menu_list() {
    local rows
    rows="$(users_list)"
    if [[ -z "$rows" ]]; then
        info "No users in the registry yet."
        return 0
    fi

    local name created enabled quota expires conn reset creds
    ui_rule
    while IFS=$'\t' read -r name created enabled quota expires conn reset creds; do
        [[ -n "$name" ]] || continue
        ui_kv "$name" "$( [[ "$enabled" == "1" ]] && printf 'enabled' || printf 'DISABLED' ) · \
quota ${quota:-unlimited} · resets ${reset:-never} · expires ${expires:-never} · \
devices ${conn:-unlimited} · ${creds} credential(s) · created ${created}"
    done <<< "$rows"
    ui_rule
    return 0
}

screen_users() {
    while true; do
        section "Users — the identity registry"
        cat >&2 <<'MENU'
  1) List users
  2) Add a user
  3) Show one user
  4) Enable / disable a user
  5) Remove a user

  0) Back
MENU
        local key=""
        ask_key key "Select [0-5]" || return 0
        case "$key" in
            1) _users_menu_list   || true ;;
            2) _users_menu_add    || true ;;
            3) _users_menu_show   || true ;;
            4) _users_menu_toggle || true ;;
            5) _users_menu_remove || true ;;
            0|q|Q) return 0 ;;
            *) warn "Unknown option '${key}'." ;;
        esac
        press_enter || true
    done
}


screen_panel() {
    section "Admin panel"
    info "The panel is a separate service: its own port, its own systemd unit, its"
    info "own nginx vhost and its own unprivileged user. It never shares a process"
    info "with anything public-facing."
    info ""
    info "It reaches this host through exactly two programs, behind two separate"
    info "sudo rules:"
    info ""
    info "  read   'vpn55.sh --status' — the same adapter output the status"
    info "         screens here print. The sudo rule PINS that argument, because"
    info "         this file with no argument is the menu you are looking at,"
    info "         which is unrestricted root."
    info "  write  helper/vpnctl — seven verbs and nothing else: user-add,"
    info "         user-remove, user-enable, user-disable, cred-add, cred-revoke,"
    info "         service-restart. It validates its own arguments and never"
    info "         trusts the panel, so a panel compromise costs exactly those"
    info "         seven verbs rather than root."
    info ""
    info "Deploying it is manual for now: panel/README.md and deploy/. Create the"
    info "first administrator at the console, as root, before starting it:"
    info ""
    info "  node /usr/local/lib/vpn55/panel/scripts/admin.js add <name>"
    info ""
    info "Nothing was installed or changed."
    return 0
}

screen_uninstall() {
    section "Remove VPN55 network state"
    warn "This reverses every firewall rule VPN55 added and removes its sysctl file."
    warn "It does NOT touch the user registry — that is deleted separately, on purpose."

    if ! ask_proceed "Remove VPN55's network state now"; then
        info "Nothing was changed."
        return 0
    fi

    net_fw_revoke_all   || warn "some firewall rules could not be removed — check ${VPN55_FW_STATE}"
    net_forwarding_disable || warn "could not remove the forwarding sysctl file"
    success "VPN55 network state removed."

    # The program itself is not removed here, and saying so is the point. This
    # screen is named "network state" and means it — but an operator who has
    # just run the most destructive option on the menu reasonably assumes VPN55
    # is gone, and nothing anywhere else tells them the tree is still on disk.
    # There is deliberately no verb for it: a script deleting the directory it
    # is executing from has to survive its own libraries vanishing mid-run, and
    # two `rm` lines an operator can read are a better trade than that.
    if [[ "$VPN55_ROOT" != "$PWD" ]] && [[ -f "$VPN55_ROOT/vpn55.sh" ]]; then
        info ""
        info "VPN55 itself is still installed at ${VPN55_ROOT}, and it stays there —"
        info "this screen removes network state, not the program. To remove that too,"
        info "after you are finished with this menu:"
        info "    rm -rf ${VPN55_ROOT}"
        info "    rm -f  /etc/sudoers.d/vpn55-panel"
    fi

    # The certificate authority outlives any single service on purpose: more
    # than one protocol can be built on it, so removing one must not invalidate
    # the other's credentials. That means nothing else ever deletes it, and this
    # is the only place an operator can. It gets its own confirmation because it
    # is the one action here with no way back at all.
    if pki_ca_exists; then
        ui_rule
        warn "This host still has a certificate authority."
        if pki_in_use; then
            info "A service is still registered against it, so it is being kept."
            info "Remove that service first if you want the authority gone too."
            return 0
        fi
        warn "Nothing is using it any more. Destroying it is PERMANENT: every"
        warn "certificate it ever signed becomes worthless, including any already"
        warn "handed out, and nothing on this host can reissue them."
        # The claim here used to be "there is no backup", which was true and is
        # no longer. It is replaced rather than deleted: an operator standing in
        # front of this prompt is one keystroke from the irreversible thing, and
        # "you can take one first" is the most useful sentence available.
        if [[ -n "$(bak_list 2>/dev/null)" ]]; then
            info "Backups exist on this host — 'vpn55.sh --backup-list' shows them."
            info "A restore from one brings this authority back."
        else
            warn "There is NO backup of it on this host. 'vpn55.sh --backup' takes"
            warn "one now, and takes about a second."
        fi
        if ask_proceed "Destroy the certificate authority as well"; then
            pki_destroy || warn "the certificate authority could not be removed"
        else
            info "The certificate authority was left in place."
        fi
    fi
    return 0
}


# ─── Keeping the code current ─────────────────────────────────────────────────
# The whole of the guard is in lib/core_source.sh; this is the operator-facing
# half. Return code 10 from src_update means "new code is on disk and this
# process is still the old one" — the only correct response to which is to stop
# being this process.
screen_update() {
    local rc=0
    section "Update VPN55"
    ui_kv "Installed at" "$VPN55_ROOT"
    ui_kv "Revision"     "$(src_revision "$VPN55_ROOT")"
    ui_kv "Source"       "$VPN55_MIRROR"

    if src_is_git_checkout "$VPN55_ROOT"; then
        info "This is a git checkout. Update it with git, not from a mirror:"
        info "    git -C ${VPN55_ROOT} pull --ff-only"
        return 0
    fi
    if ! ask_proceed "Fetch the current code and replace this installation"; then
        info "Nothing was changed."
        return 0
    fi

    src_update "$VPN55_ROOT" || rc=$?
    case "$rc" in
        0)  return 0 ;;
        10)
            # src_relaunch execs and never returns — unless it refuses, which it
            # does when the new vpn55.sh is not executable. Returning there would
            # drop the operator back into a menu whose in-memory code is the OLD
            # tree while the NEW one is on disk: precisely the state return code
            # 10 exists to prevent, arriving by the back door. The menu's arm is
            # `screen_update || true`, so a `return 1` here is swallowed and the
            # next thing they pick writes firewall rules with the old code.
            #
            # So this exits the process instead. The message src_relaunch printed
            # says how to start the new copy by hand.
            src_relaunch "$VPN55_ROOT"
            error "VPN55 has been updated but this process is still the old code."
            error "It will not continue. Start the new copy with the command above."
            exit 1 ;;
        *)  return 1 ;;
    esac
}

