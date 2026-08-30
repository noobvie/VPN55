# shellcheck shell=bash
#
# lib/proto_ipsec.sh — IKEv2/IPsec adapter (strongSwan, swanctl-era). Phase 3.
#
# The adapter contract — every protocol module implements exactly this surface,
# and nothing outside lib/proto_*.sh may know which protocol it is talking to.
#
#   vpn_<proto>_available      # can this host run it? (kernel, container, pkgs)
#   vpn_<proto>_capabilities   # what this adapter needs and how it revokes
#   vpn_<proto>_install        # idempotent; safe to re-run
#   vpn_<proto>_uninstall      # fully reverses install, incl. NAT + firewall
#   vpn_<proto>_cred_add       # <user> [k=v …] -> creates credential, returns id
#   vpn_<proto>_cred_remove    # <cred_id> -> revokes (see revocation trap)
#   vpn_<proto>_cred_list      # machine-readable, one record per line
#   vpn_<proto>_artifacts      # <cred_id> -> what a client can be given
#   vpn_<proto>_client_config  # <cred_id> [artifact] -> that artifact on stdout
#   vpn_<proto>_status         # service state + per-cred rx/tx + last handshake
#
# ── This adapter is why three of those verbs exist ───────────────────────────
# Phase 2 shipped a contract with eight verbs, shaped — without anyone deciding
# to — around what WireGuard happens to be. Writing this file broke three of
# those assumptions, and the contract was widened rather than special-cased:
#
#   _capabilities  because _cred_add's second positional argument was a
#                  WireGuard public key, and vpn55.sh was prompting for one
#                  by name. An adapter now DECLARES the options it takes.
#   _artifacts     because a credential here is not one text file. It is a
#                  configuration profile, a binary key bundle, a CA
#                  certificate and a page of instructions, and only one of
#                  those is small enough to put in a QR code.
#   handshake = -  because strongSwan does not remember when a client last
#                  connected. WireGuard can answer "never"; this can only
#                  answer "I have no reading", and those are different facts.
#
# The full list of what changed and why is in the Phase 3 checkpoint section of
# docs/security-model.md.
#
# ── Written from scratch, and it had to be ───────────────────────────────────
# hwdsl2/setup-ipsec-vpn is the best-maintained IKEv2 installer in existence and
# it is CC BY-SA 3.0 — a viral CONTENT licence applied to software. Reading it
# is fine; copying one line of it would oblige VPN55 to relicense. algo is
# AGPL-3.0, with the same consequence. There is no permissively-licensed IKEv2
# installer anywhere, so nothing in this file is reshaped from anything and
# ATTRIBUTIONS.md gets no entry for this phase. See docs/prior-art.md §2.
#
# ── Design decisions, and why ────────────────────────────────────────────────
#
# 1. swanctl, not ipsec.conf. The legacy starter stack is deprecated upstream
#    and its config cannot express half of what is below. Where a host has the
#    legacy unit installed as well, this stops it — two charons on one box fight
#    over the same sockets and the loser's failure is silent.
#
# 2. ONE connection block, not one per user. A road-warrior responder accepts
#    any client certificate its CA signed, so a credential leaves no trace in
#    the daemon's config at all. That is the opposite of the WireGuard adapter,
#    which reads its peer list straight out of the server config — so this file
#    keeps its own credential index. It is an INDEX, not a user list: identity
#    stays in core_users, and the record here holds only what the certificate
#    cannot.
#
# 3. Addresses are handed out by the daemon, not by net_pool_alloc. strongSwan
#    owns a virtual-IP pool and there is no supported way to pin an address to
#    an identity without dragging in a database plugin. So this adapter CLAIMS
#    its /24 through net_pool_claim — that is what stops another protocol from
#    handing out the same addresses — and then delegates allocation inside it.
#    The consequence is honest rather than hidden: a credential has no stable
#    address, so _cred_list reports "-" and _status reports the live one.
#
# 4. UDP encapsulation is forced. It costs a few bytes per packet and it means
#    the firewall needs two UDP ports and no raw-ESP rule — and raw ESP is
#    exactly what a carrier-grade NAT drops, which is most mobile networks in
#    the target market.
#
# 5. IPv6 is NOT carried, and NOT captured. The WireGuard adapter claims ::/0 so
#    a dual-stack client fails closed; that trick does not exist here, because
#    without a v6 virtual address the client installs no v6 route and simply
#    keeps its native one. The server cannot block traffic that never reaches
#    it. So this is surfaced as a status note rather than papered over — see
#    _ipsec_notes.
#
# ── Revocation: one verb, a genuinely different operation ────────────────────
# WireGuard deletes a peer and the device is off the tunnel before the function
# returns. Here, revocation is a CRL entry, and a CRL entry does nothing to a
# session that has already authenticated. What this adapter does about that:
#
#   - publishes the revocation to the CRL and reloads the daemon's credentials,
#     which refuses the next authentication,
#   - terminates the credential's live IKE SAs, which ends the current session,
#   - and reports which of those it actually managed, rather than assuming.
#
# When both succeed the effect really is immediate and it says so. When either
# could not be confirmed — the daemon is down, the terminate failed — the honest
# answer is the re-authentication interval, and that is what it returns. The
# panel prints the number; it does not decide it.
#
# Sourced, not executed. errexit does not cover a ||-guarded function body, so
# every command here that creates, copies, moves or deletes is guarded on its
# own line — see CLAUDE.md.

[[ -n "${VPN55_IPSEC_LOADED:-}" ]] && return 0
VPN55_IPSEC_LOADED=1

: "${VPN55_ETC:=/etc/vpn55}"

# The adapter's own tag. It is the <proto> in every contract verb, the owner tag
# it claims its pool slot and its firewall rules under, and the owner tag its
# credentials carry in the registry. One string, four uses, so they cannot drift.
VPN55_IPSEC_TAG="ipsec"

# Pool slot 2. The slot table lives in CLAUDE.md § Networking and nowhere else —
# core_net deliberately does not know which protocol owns which slot.
VPN55_IPSEC_SLOT=2

: "${VPN55_IPSEC_STATE:=$VPN55_ETC/ipsec}"
: "${VPN55_IPSEC_CONF:=$VPN55_IPSEC_STATE/settings.conf}"
: "${VPN55_IPSEC_CREDS:=$VPN55_IPSEC_STATE/creds}"
: "${VPN55_IPSEC_SPOOL:=$VPN55_IPSEC_STATE/spool}"

: "${VPN55_SWANCTL_ETC:=/etc/swanctl}"
: "${VPN55_SWANCTL_CONF:=$VPN55_SWANCTL_ETC/conf.d/vpn55.conf}"

# The IKE identity and connection name inside the daemon's config.
VPN55_IPSEC_CONN="vpn55"

VPN55_IPSEC_SYSCTL="/etc/sysctl.d/99-vpn55-ipsec.conf"
VPN55_IPSEC_HOOK="ipsec-reload"

# How long a client's artifacts stay retrievable after issue, in hours. Same
# compromise, and the same number, as the WireGuard key spool: long enough for a
# real hand-off, short enough that the exit node is not a permanent store of
# every user's identity. 0 disables the spool entirely — the artifacts are
# emitted once by _cred_add and never again.
: "${VPN55_IPSEC_KEY_TTL_HOURS:=24}"

# Re-authentication interval. This is the ONLY guaranteed upper bound on how
# long a revoked credential can keep an already-established tunnel, so it is a
# security setting wearing a performance setting's clothes.
#
# 24h is a deliberate middle. Apple's clients drop and re-establish the tunnel
# at re-authentication rather than doing it seamlessly, so a short interval is a
# visible daily-times-N interruption; 0 turns re-authentication off entirely and
# makes the fallback bound UNLIMITED, which _cred_remove then has to report as
# -1. In practice the terminate path makes revocation immediate and this bound
# never comes into play — it is what is left when the daemon was down at the
# moment someone was revoked.
: "${VPN55_IPSEC_REAUTH_HOURS:=24}"

# How the daemon treats a certificate whose revocation status it cannot check.
#   strict   the certificate must have a valid, unexpired revocation list.
#            Fail-closed, and the right default for a product whose revocation
#            story is a CRL. Its cost is real: if the CRL lapses, EVERY user is
#            refused, not just revoked ones. core_pki's weekly timer and
#            30-day window exist to make that unreachable, and _status warns
#            long before it could happen.
#   ifuri    check only when the certificate names a distribution point.
#   relaxed  do not check.
: "${VPN55_IPSEC_REVOCATION:=strict}"

# Proposals. The defaults deliberately exclude the weak sets that some built-in
# clients offer FIRST — notably 1024-bit Diffie-Hellman and SHA-1 — because
# accepting those to make an out-of-the-box connection work would quietly hand
# every user of that platform the weakest thing their client knows how to ask
# for. The instructions artifact ships the one command that makes such a client
# offer something modern instead, which is the fix that does not cost everyone
# else anything.
: "${VPN55_IPSEC_IKE_PROPOSALS:=aes256-sha256-modp2048,aes256gcm16-prfsha256-modp2048,aes256-sha384-modp3072,aes256gcm16-prfsha384-ecp384}"
: "${VPN55_IPSEC_ESP_PROPOSALS:=aes256gcm16-modp2048,aes256gcm16,aes256-sha256-modp2048,aes256-sha256,aes256gcm16-ecp384}"

# Opt-in package purge on uninstall. Off by default, for the same reason as the
# other adapter: removing a package is not what "reverse the install" means to
# an operator who wants the tunnel gone.
: "${VPN55_IPSEC_PURGE_PACKAGES:=0}"

# ─── Settings ─────────────────────────────────────────────────────────────────
_ipsec_state_dir() {
    fs_ensure_dir "$VPN55_IPSEC_STATE" 0700 || return 1
    fs_ensure_dir "$VPN55_IPSEC_CREDS" 0700 || return 1
    fs_ensure_dir "$VPN55_IPSEC_SPOOL" 0700 || return 1
    return 0
}

_ipsec_set()  { fs_conf_set "$VPN55_IPSEC_CONF" "${1:-}" "${2:-}"; }

_ipsec_endpoint()   { fs_conf_default "$VPN55_IPSEC_CONF" endpoint   ""; }
_ipsec_server_cn()  { fs_conf_default "$VPN55_IPSEC_CONF" server_cn  ""; }
_ipsec_dns()        { fs_conf_default "$VPN55_IPSEC_CONF" dns        ""; }
_ipsec_unit()       { fs_conf_default "$VPN55_IPSEC_CONF" unit       ""; }
_ipsec_reauth()     { fs_conf_default "$VPN55_IPSEC_CONF" reauth_hours "$VPN55_IPSEC_REAUTH_HOURS"; }
_ipsec_revocation() { fs_conf_default "$VPN55_IPSEC_CONF" revocation "$VPN55_IPSEC_REVOCATION"; }

_ipsec_subnet()  { net_pool_subnet  "$VPN55_IPSEC_SLOT"; }

_ipsec_installed() { [[ -f "$VPN55_SWANCTL_CONF" ]]; }

_ipsec_active() {
    local unit
    unit="$(_ipsec_unit)"
    [[ -n "$unit" ]] || return 1
    distro_service_is_active "$unit"
}

# Worst-case seconds a revoked credential could keep an established tunnel when
# the live terminate could not be confirmed. -1 means there is no bound at all,
# which is what re-authentication being switched off actually means.
_ipsec_revoke_bound() {
    local hours
    hours="$(_ipsec_reauth)"
    if [[ ! "$hours" =~ ^[0-9]+$ ]] || [[ "$hours" -eq 0 ]]; then
        printf -- '-1'
    else
        printf '%s' "$(( hours * 3600 ))"
    fi
}

# ─── Availability ─────────────────────────────────────────────────────────────
# Three things have to be true, and each failure gets its own explanation
# because they have three different fixes.
_ipsec_xfrm_usable() {
    ip xfrm state >/dev/null 2>&1
}

vpn_ipsec_available() {
    if ! pki_available; then
        error "Certificate operations are unavailable, and this protocol is built on them."
        return 1
    fi

    if _ipsec_xfrm_usable; then
        debug "kernel IPsec transform interface is usable"
        return 0
    fi

    error "This host cannot run IKEv2: the kernel's IPsec transform interface is not usable."
    if distro_is_container; then
        error "It is a $(distro_virt) container. IPsec transforms are a kernel"
        error "feature and a container shares the host's kernel, so this has to be"
        error "enabled on the HOST — an installer inside the container cannot do it."
        error "Ask the provider to allow it, or use a KVM instance."
    else
        error "Load the IPsec modules for $(uname -r) — xfrm_user, esp4, ah4 and"
        error "af_key — or use a kernel that has them built in, then re-run."
    fi
    return 1
}

# ─── Capabilities ─────────────────────────────────────────────────────────────
# What a caller needs to know about this adapter WITHOUT knowing which protocol
# it is. Records:
#
#   revoke    <latency>  <worst_case_seconds>
#   custody   <who>      <one-line disclosure to show when issuing>
#   filtering <level>    <one-line explanation of how it fares under a censor>
#   restart   <effect>   <what a restart costs the people connected right now>
#   option    <key>  <prompt>  <required 0|1>  <help>
#
# The filtering record was added in Phase 5. A reader that must warn a user which
# services survive a filtered network cannot work that out for itself without
# learning which protocol it is holding — which is exactly the thing it may not
# do. So the adapter states it: `resistant`, `partial` or `exposed`, plus a
# sentence in its own words. The LEVEL is the stable identifier a UI keys its
# translations on; the sentence is adapter-authored data, rendered as-is like a
# note record.
#
# The revoke record is the one that earns its place. Before this existed, the
# installer could only tell an operator that a revocation was delayed AFTER
# they had confirmed it — which is the wrong order for the one question they
# were actually asking.
#
# There are no options: this adapter takes nothing but a user name. Declaring
# that emptiness is the point — it is what stopped vpn55.sh from prompting
# every protocol for a public key it has no use for.
vpn_ipsec_capabilities() {
    printf 'revoke\tcrl\t%s\n' "$(_ipsec_revoke_bound)"
    printf 'custody\tserver\t%s\n' \
        "The server generates this credential's private key, packages it into the client artifacts, and erases it ${VPN55_IPSEC_KEY_TTL_HOURS}h after issue."
    # Fixed, and not computed, because nothing on this adapter moves it. It is
    # here because devices connect to it with nothing installed, which is a real
    # advantage — and it is not the advantage a filtered network needs.
    printf 'filtering\texposed\t%s\n' \
        "This service cannot be disguised. It negotiates on well-known ports and its packets are recognisable on the wire, and no setting offered here changes either. It is here for devices that connect with no app installed; on a filtered network, expect it to be blocked first."

    printf 'restart\tsessions-dropped\t%s\n' \
        "Restarting tears down every security association: all connected devices are dropped and reconnect on their own. It is also the only way to make a revocation take effect at once."
    return 0
}

# ─── Packages and the service unit ────────────────────────────────────────────
_ipsec_packages() {
    _distro_need_detect || return 1
    case "$VPN55_OS_FAMILY" in
        debian) printf '%s\n' strongswan-swanctl charon-systemd ;;
        rhel)   printf '%s\n' strongswan ;;
        arch)   printf '%s\n' strongswan ;;
        *)      error "no package set known for OS family '${VPN55_OS_FAMILY}'"; return 1 ;;
    esac
}

# Which unit runs the swanctl-era daemon, resolved by looking rather than by
# assuming — because the same NAME means different things on different distros.
# On Debian and Arch, strongswan.service IS the swanctl daemon. On Fedora and
# EL, strongswan.service is the LEGACY starter and strongswan-swanctl.service is
# the one we want. Preferring the explicit name first is correct on all four.
_ipsec_resolve_unit() {
    local u
    # Answered before the loop so the caller's error message can be honest. On a
    # host with no systemd there is no unit to find, and reporting that as
    # "strongSwan has only the legacy stack" would send an operator looking for
    # a package problem that does not exist.
    if ! distro_has_systemd; then
        error "This host is not running systemd, and this adapter manages its"
        error "daemon through a systemd unit. That is a packaging limitation of"
        error "VPN55, not of strongSwan."
        return 1
    fi
    for u in strongswan-swanctl.service strongswan.service charon-systemd.service; do
        if systemctl list-unit-files "$u" >/dev/null 2>&1 \
           && systemctl cat "$u" >/dev/null 2>&1; then
            printf '%s' "$u"
            return 0
        fi
    done
    return 1
}

# The legacy starter and the swanctl daemon both want charon's sockets. Running
# both means one of them loses, and it loses silently — the tunnel simply never
# comes up while both units report as started.
_ipsec_stop_legacy() {
    local legacy="strongswan-starter.service"
    distro_has_systemd || return 0
    systemctl cat "$legacy" >/dev/null 2>&1 || return 0

    if distro_service_is_active "$legacy" || distro_service_is_enabled "$legacy"; then
        info "Stopping the legacy IPsec unit — it and the swanctl daemon cannot coexist."
        distro_service_disable "$legacy" || warn "could not disable ${legacy}"
    fi
    return 0
}

_ipsec_install_packages() {
    local -a want=() missing=()
    mapfile -t want < <(_ipsec_packages) || return 1

    local pkg
    for pkg in "${want[@]}"; do
        distro_pkg_installed "$pkg" || missing+=("$pkg")
    done

    if [[ ${#missing[@]} -eq 0 ]]; then
        debug "packages already present: ${want[*]}"
    else
        info "Installing: ${missing[*]}"
        distro_pkg_refresh || warn "package index refresh failed — continuing with the cached one"
        if ! distro_pkg_install "${missing[@]}"; then
            if [[ "$VPN55_OS_FAMILY" == "rhel" ]]; then
                error "strongSwan is not in the base repositories on this distribution."
                error "It lives in EPEL. Enable it and re-run:"
                error "  dnf install -y epel-release"
            fi
            return 1
        fi
    fi

    command -v swanctl >/dev/null 2>&1 \
        || { error "'swanctl' is still missing after installing packages."; return 1; }
    return 0
}

# ─── The daemon's configuration ───────────────────────────────────────────────
# Written to conf.d/ rather than over swanctl.conf, so an operator's own
# settings are not silently replaced by an installer.
_ipsec_ensure_include() {
    local main="$VPN55_SWANCTL_ETC/swanctl.conf" body
    fs_ensure_dir "$VPN55_SWANCTL_ETC/conf.d" 0750 || return 1

    if [[ ! -f "$main" ]]; then
        printf '%s\n' 'include conf.d/*.conf' | fs_write_atomic "$main" 0640 \
            || { error "cannot create $main"; return 1; }
        return 0
    fi

    body="$(cat "$main" 2>/dev/null || true)"

    # The test is for a LIVE include, not for the text appearing anywhere in the
    # file. The stock file ships the line with an explanatory comment beside it,
    # and on any distribution that ships it commented out a substring match
    # finds `# include conf.d/*.conf`, concludes the include is present, and
    # adds nothing — after which VPN55's entire configuration is written to a
    # file the daemon never reads. Everything then looks installed and no tunnel
    # can be established, with nothing in any log to say why.
    if grep -qE '^[[:space:]]*include[[:space:]]+.*conf\.d/' "$main" 2>/dev/null; then
        return 0
    fi

    # Appended, not rewritten: whatever else is in that file belongs to whoever
    # put it there. The mode is re-asserted rather than merely preserved, since
    # this file sits in a directory that also holds private keys.
    printf '%s\ninclude conf.d/*.conf\n' "$body" | fs_replace_in_place "$main" 0640 \
        || { error "cannot add the conf.d include to $main"; return 1; }
    info "Added 'include conf.d/*.conf' to ${main}."
    return 0
}

_ipsec_render_conf() {
    local endpoint subnet dns cn reauth revocation
    endpoint="$(_ipsec_endpoint)"
    cn="$(_ipsec_server_cn)"
    dns="$(_ipsec_dns)"
    reauth="$(_ipsec_reauth)"
    revocation="$(_ipsec_revocation)"
    subnet="$(_ipsec_subnet)" || return 1

    [[ -n "$endpoint" ]] || { error "no endpoint recorded"; return 1; }
    [[ -n "$cn" ]] || { error "no server certificate recorded"; return 1; }

    # There is deliberately no generated-on timestamp anywhere in this file. A
    # date line would make the second install produce different bytes, and
    # "install three times, nothing changes after the first" would be false in
    # exactly the way that is hardest to notice.
    cat <<CONF
# VPN55 — managed IKEv2 responder. Written by lib/proto_ipsec.sh; edits are lost.
#
# One connection accepts every client certificate this CA signed. There is no
# per-user block here on purpose: a road-warrior responder does not need one,
# and a config that grew an entry per credential would be a second user list
# drifting away from the registry in /etc/vpn55/users.
#
# There are no firewall rules in this file either. The open ports, the forward
# path and the NAT rule are applied through VPN55's firewall ledger under the
# tag '${VPN55_IPSEC_TAG}', so an uninstall reverses exactly what was added.

connections {
    ${VPN55_IPSEC_CONN} {
        version = 2
        proposals = ${VPN55_IPSEC_IKE_PROPOSALS}
        local_addrs = %any
        remote_addrs = %any
        pools = ${VPN55_IPSEC_CONN}

        # Forced UDP encapsulation. Raw ESP is what carrier-grade NAT drops, and
        # the target market reaches this over mobile networks.
        encap = yes
        fragmentation = yes

        # The client is not asked which CA to use — its profile already carries
        # exactly one identity, and the certificate-request payload would only
        # advertise this server's issuer to anyone who probes the port.
        send_certreq = no
        send_cert = always

        # One credential is one device. A second connection presenting the same
        # certificate replaces the first rather than running beside it, which is
        # also what makes a per-user device limit enforceable later.
        unique = replace

        dpd_delay = 30s
CONF

    # 0 means "never re-authenticate", and swanctl already reads a missing key
    # that way — so the line is omitted rather than written as 0, keeping the
    # rendered file honest about what was actually configured.
    if [[ "$reauth" =~ ^[0-9]+$ ]] && [[ "$reauth" -gt 0 ]]; then
        printf '        reauth_time = %sh\n' "$reauth"
    fi

    cat <<CONF

        local {
            auth = pubkey
            certs = ${cn}.crt
            id = ${endpoint}
        }

        remote {
            auth = pubkey
            cacerts = vpn55-ca.crt

            # 'strict' means a certificate whose revocation status cannot be
            # established is REFUSED. That is the point of having a revocation
            # list at all, and it is also why core_pki keeps the list fresh on a
            # timer: an expired list refuses everyone, not just the revoked.
            revocation = ${revocation}
        }

        children {
            ${VPN55_IPSEC_CONN} {
                # IPv4 only, and that is a real limitation rather than an
                # oversight — see the header. Claiming ::/0 without a v6 pool
                # would not capture v6 traffic, it would only look as though it
                # had.
                local_ts = 0.0.0.0/0
                esp_proposals = ${VPN55_IPSEC_ESP_PROPOSALS}
                dpd_action = clear
                start_action = none
                rekey_time = 1h
            }
        }
    }
}

pools {
    ${VPN55_IPSEC_CONN} {
        addrs = ${subnet}
CONF

    if [[ -n "$dns" ]]; then
        printf '        dns = %s\n' "${dns//,/, }"
    fi

    cat <<'CONF'
    }
}
CONF
    return 0
}

# swanctl reads credentials out of its own directories. These are symlinks into
# the PKI rather than copies, so there is one file on disk per key and the CRL
# the daemon loads is always the one core_pki just regenerated — a copy would
# quietly go stale the first time the timer ran.
_ipsec_link_creds() {
    local cn
    cn="$(_ipsec_server_cn)"
    [[ -n "$cn" ]] || { error "no server certificate recorded"; return 1; }

    fs_ensure_dir "$VPN55_SWANCTL_ETC/x509"    0750 || return 1
    fs_ensure_dir "$VPN55_SWANCTL_ETC/x509ca"  0750 || return 1
    fs_ensure_dir "$VPN55_SWANCTL_ETC/x509crl" 0750 || return 1
    fs_ensure_dir "$VPN55_SWANCTL_ETC/private" 0700 || return 1

    fs_link "$(pki_ca_path)"          "$VPN55_SWANCTL_ETC/x509ca/vpn55-ca.crt"   || return 1
    fs_link "$(pki_cert_path "$cn")"  "$VPN55_SWANCTL_ETC/x509/${cn}.crt"        || return 1
    fs_link "$(pki_key_path "$cn")"   "$VPN55_SWANCTL_ETC/private/${cn}.key"     || return 1
    fs_link "$(pki_crl_path)"         "$VPN55_SWANCTL_ETC/x509crl/vpn55.crl"     || return 1
    return 0
}

_ipsec_unlink_creds() {
    local cn
    cn="$(_ipsec_server_cn)"
    fs_remove "$VPN55_SWANCTL_ETC/x509ca/vpn55-ca.crt" || true
    fs_remove "$VPN55_SWANCTL_ETC/x509crl/vpn55.crl"   || true
    if [[ -n "$cn" ]]; then
        fs_remove "$VPN55_SWANCTL_ETC/x509/${cn}.crt"    || true
        fs_remove "$VPN55_SWANCTL_ETC/private/${cn}.key" || true
    fi
    return 0
}

_ipsec_reload() {
    _ipsec_active || return 0
    swanctl --load-all >/dev/null 2>&1 || { error "the daemon rejected the new configuration"; return 1; }
    return 0
}

_ipsec_reload_creds() {
    _ipsec_active || return 0
    swanctl --load-creds >/dev/null 2>&1
}

# The hook core_pki runs after every revocation-list refresh. It is a standalone
# shell script because the timer that runs it must keep working when the
# installer checkout has been moved or deleted.
_ipsec_install_hook() {
    local unit
    unit="$(_ipsec_unit)"
    [[ -n "$unit" ]] || return 0

    {
        printf '#!/bin/sh\n'
        printf '# VPN55 — republish the revocation list to the running IKE daemon.\n'
        printf '#\n'
        printf '# A stopped daemon is not a failure: it loads everything at start-up, so\n'
        printf '# there is nothing to publish to. Exiting 0 there keeps a real failure\n'
        printf '# visible instead of drowning it in a weekly false alarm.\n'
        printf 'command -v swanctl >/dev/null 2>&1 || exit 0\n'
        printf 'systemctl is-active --quiet %s 2>/dev/null || exit 0\n' "$unit"
        printf 'exec swanctl --load-creds\n'
    } | pki_hook_install "$VPN55_IPSEC_HOOK" || return 1
    return 0
}

# ─── Kernel settings ──────────────────────────────────────────────────────────
# Reverse-path filtering drops a decrypted packet whose source is a tunnel
# address arriving on the WAN interface, because the return path is an IPsec
# policy rather than a route. The symptom is a tunnel that establishes perfectly
# and carries no traffic, which sends people to look at the firewall.
#
# The trap inside the trap: Linux evaluates rp_filter as max(all, <interface>),
# so setting it on the interface alone changes NOTHING while `all` is 1. Both
# have to be written or neither matters.
_ipsec_write_sysctl() {
    local wan body
    wan="$(net_wan_iface)" || wan=""

    # Built into a variable, not piped: fs_write_if_changed on the right of a
    # pipe runs in a subshell and its VPN55_FS_CHANGED never comes back, so the
    # `sysctl -p` below would never run. The file would be written correctly and
    # the setting would not take effect until the next reboot — presenting as a
    # tunnel that establishes and then carries nothing, which is exactly the
    # symptom this file exists to prevent.
    body="$( {
        printf '# Written by VPN55 (lib/proto_ipsec.sh). Removed when the service is removed.\n'
        printf '#\n'
        printf '# Reverse-path filtering has to be off for decrypted IPsec traffic: the\n'
        printf '# return path for a tunnel address is a transform policy, not a route, so\n'
        printf '# a strict check discards packets that are perfectly legitimate.\n'
        printf '#\n'
        printf '# The kernel takes max(all, <interface>), so BOTH lines are required —\n'
        printf '# setting only the interface leaves the filter fully on.\n'
        printf 'net.ipv4.conf.all.rp_filter = 0\n'
        printf 'net.ipv4.conf.default.rp_filter = 0\n'
        if [[ -n "$wan" ]]; then
            printf 'net.ipv4.conf.%s.rp_filter = 0\n' "$wan"
        fi
        printf '\n'
        printf '# ICMP redirects can rewrite the routing of a host that terminates tunnels.\n'
        printf 'net.ipv4.conf.all.accept_redirects = 0\n'
        printf 'net.ipv4.conf.all.send_redirects = 0\n'
    } )" || { error "cannot render the kernel settings"; return 1; }

    fs_write_if_changed "$VPN55_IPSEC_SYSCTL" 0644 "$body" \
        || { error "cannot write $VPN55_IPSEC_SYSCTL"; return 1; }

    if [[ "$VPN55_FS_CHANGED" == "1" ]]; then
        sysctl -p "$VPN55_IPSEC_SYSCTL" >/dev/null 2>&1 \
            || warn "could not apply ${VPN55_IPSEC_SYSCTL} — a reboot will apply it"
    fi
    return 0
}

# ─── Settings bootstrap ───────────────────────────────────────────────────────
# Settled once, then never asked again. Precedence is: an existing stored value,
# then an environment override, then the interactive prompt, then the default.
# That order is what makes the second install silent.
_ipsec_settings_bootstrap() {
    _ipsec_state_dir || return 1

    local endpoint
    endpoint="$(fs_conf_default "$VPN55_IPSEC_CONF" endpoint "")"
    if [[ -z "$endpoint" ]]; then
        endpoint="${VPN55_IPSEC_ENDPOINT:-}"
    fi
    if [[ -z "$endpoint" ]]; then
        local detected="" rc=0
        detected="$(net_public_endpoint)" || rc=$?
        if [[ "$rc" -eq 2 ]]; then
            warn "Detected ${detected}, which is private — clients cannot dial it."
            detected=""
        fi
        info "This address is baked into the server certificate, so changing it later"
        info "means reissuing that certificate. A hostname is the better answer if the"
        info "address might ever move."
        ask_value endpoint "Public address or hostname clients will dial" "$detected" || return 1
    fi
    [[ -n "$endpoint" ]] || {
        error "No endpoint. Set VPN55_IPSEC_ENDPOINT, or run this interactively and enter one."
        return 1
    }

    # It becomes a certificate common name as well as an IKE identity, so it has
    # to satisfy the stricter of the two rules rather than only look plausible.
    pki_validate_cn "$endpoint" || {
        error "'${endpoint}' cannot be used as a certificate identity."
        return 1
    }

    _ipsec_set endpoint "$endpoint" || return 1

    local reauth revocation
    reauth="$(fs_conf_default "$VPN55_IPSEC_CONF" reauth_hours "$VPN55_IPSEC_REAUTH_HOURS")"
    [[ "$reauth" =~ ^[0-9]+$ ]] || {
        error "Re-authentication interval must be a whole number of hours; got '${reauth}'."
        return 1
    }
    _ipsec_set reauth_hours "$reauth" || return 1

    revocation="$(fs_conf_default "$VPN55_IPSEC_CONF" revocation "$VPN55_IPSEC_REVOCATION")"
    case "$revocation" in
        strict|ifuri|relaxed) ;;
        *) error "Revocation policy must be strict, ifuri or relaxed; got '${revocation}'."; return 1 ;;
    esac
    _ipsec_set revocation "$revocation" || return 1

    # ── DNS ──
    # Resolved ONCE and stored, exactly as the other adapter does it: the pool
    # hands these to every client, and re-resolving on a later re-run would
    # silently change what already-issued credentials point at.
    local dns_choice dns_custom dns
    dns_choice="$(fs_conf_default "$VPN55_IPSEC_CONF" dns_choice "")"
    if [[ -z "$dns_choice" ]]; then
        dns_choice="${VPN55_IPSEC_DNS_CHOICE:-system}"
        net_resolvers_explain
        ask_value dns_choice "DNS (system/cloudflare/quad9/custom)" "$dns_choice" || return 1
        if [[ "$dns_choice" == "custom" ]]; then
            ask_value dns_custom "Resolver addresses, comma-separated" "${VPN55_IPSEC_DNS:-}" || return 1
        fi
        dns="$(net_resolvers_resolve "$dns_choice" "${dns_custom:-}")" || return 1
    else
        dns="$(fs_conf_default "$VPN55_IPSEC_CONF" dns "")"
        if [[ -z "$dns" ]]; then
            dns="$(net_resolvers_resolve "$dns_choice" "")" || return 1
        fi
    fi
    _ipsec_set dns_choice "$dns_choice" || return 1
    _ipsec_set dns        "$dns"        || return 1

    debug "settings: endpoint=${endpoint} dns=${dns} reauth=${reauth}h revocation=${revocation}"
    return 0
}

# ─── The server certificate ───────────────────────────────────────────────────
# The CA is shared with the other certificate protocol, so it is created only if
# absent — and never recreated, because that would invalidate everything the
# other one has issued too.
_ipsec_server_cert_ensure() {
    local endpoint current
    endpoint="$(_ipsec_endpoint)"
    current="$(_ipsec_server_cn)"

    pki_init || return 1
    pki_ca_create "VPN55 Certificate Authority" || return 1

    if [[ "$current" == "$endpoint" ]] && [[ "$(pki_cert_state "$endpoint")" == "valid" ]]; then
        debug "server certificate for ${endpoint} is present and valid"
        return 0
    fi

    if [[ -n "$current" && "$current" != "$endpoint" ]]; then
        warn "The endpoint changed from '${current}' to '${endpoint}'."
        warn "A server certificate names the address it serves, so the old one is"
        warn "revoked and a new one issued. Already-issued CLIENT credentials are"
        warn "unaffected — they trust the CA, not this certificate."
        pki_cert_revoke "$current" || warn "could not revoke the previous server certificate"
    fi

    # The extra OID is id-kp-ipsecIKE. Some built-in clients will not accept a
    # server certificate for IKE without it even when serverAuth is present, and
    # the refusal surfaces on the device as an unexplained failure. It is passed
    # in from here rather than hardcoded in core_pki, which has no business
    # knowing why one of its consumers needs it.
    VPN55_PKI_SERVER_EKU="serverAuth,1.3.6.1.5.5.8.2.2" \
        pki_server_cert_issue "$endpoint" "$endpoint" >/dev/null || return 1

    _ipsec_set server_cn "$endpoint" || return 1
    success "Server certificate issued for ${endpoint}."
    return 0
}

# ─── Install ──────────────────────────────────────────────────────────────────
vpn_ipsec_install() {
    distro_require_root || return 1
    vpn_ipsec_available || return 1

    section "IKEv2/IPsec"

    _ipsec_settings_bootstrap || return 1
    _ipsec_install_packages   || return 1

    local unit
    unit="$(_ipsec_resolve_unit)" || {
        error "strongSwan is installed but no swanctl service unit was found."
        error "Looked for strongswan-swanctl.service, strongswan.service and"
        error "charon-systemd.service. This host may only have the deprecated"
        error "starter stack, which this adapter does not use."
        return 1
    }
    _ipsec_set unit "$unit" || return 1
    _ipsec_stop_legacy || true

    # Claim before anything is written. Idempotent for the same owner and slot,
    # a hard error on any conflict — which is what stops a second adapter
    # quietly handing out addresses in this /24.
    net_pool_claim "$VPN55_IPSEC_TAG" "$VPN55_IPSEC_SLOT" || return 1
    net_forwarding_enable || return 1

    _ipsec_server_cert_ensure || return 1
    _ipsec_ensure_include     || return 1
    _ipsec_link_creds         || return 1
    _ipsec_write_sysctl       || return 1

    # Rendered into a variable first, for two reasons. fs_write_if_changed must
    # not sit on the right of a pipe or the "did it change" answer is lost in a
    # subshell and the daemon is never reloaded. And a renderer that fails
    # PARTWAY — after emitting some of the file — would have had its partial
    # output written by the pipe form before anyone noticed; capturing it means
    # the failure is caught while the old config is still in place.
    local changed=0 rendered
    rendered="$(_ipsec_render_conf)" || return 1
    fs_write_if_changed "$VPN55_SWANCTL_CONF" 0640 "$rendered" \
        || { error "cannot write $VPN55_SWANCTL_CONF"; return 1; }
    if [[ "$VPN55_FS_CHANGED" == "1" ]]; then changed=1; fi

    local subnet
    subnet="$(_ipsec_subnet)" || return 1

    # Two UDP ports and no raw-ESP rule, because encapsulation is forced. 500 is
    # where the negotiation starts; 4500 is where it moves the moment either end
    # is behind NAT, which is almost always.
    net_fw_open_port    "$VPN55_IPSEC_TAG" udp 500  || return 1
    net_fw_open_port    "$VPN55_IPSEC_TAG" udp 4500 || return 1
    net_fw_allow_subnet "$VPN55_IPSEC_TAG" "$subnet" || return 1
    net_fw_masquerade   "$VPN55_IPSEC_TAG" "$subnet" || return 1

    _ipsec_install_hook || warn "could not install the revocation-list reload hook"
    pki_crl_timer_install || warn "the revocation list will not refresh on a schedule"

    if ! distro_service_is_enabled "$unit"; then
        distro_service_enable "$unit" || return 1
    elif ! _ipsec_active; then
        distro_service_start "$unit" || return 1
    elif [[ "$changed" == "1" ]]; then
        _ipsec_reload || return 1
    else
        # Even with no config change the credentials are reloaded: the CRL
        # symlink may point at a list regenerated since the daemon last read it.
        _ipsec_reload_creds || true
    fi

    _ipsec_spool_sweep || true

    success "IKEv2 is up on ${subnet} — udp/500 and udp/4500, endpoint $(_ipsec_endpoint)."
    info "Revocation policy: $(_ipsec_revocation). Client key custody: server-generated."
    local reauth
    reauth="$(_ipsec_reauth)"
    if [[ "$reauth" == "0" ]]; then
        warn "Re-authentication is off. A revoked credential whose live session could"
        warn "not be terminated would keep its tunnel indefinitely."
    fi
    return 0
}

# ─── Uninstall ────────────────────────────────────────────────────────────────
vpn_ipsec_uninstall() {
    distro_require_root || return 1

    local unit
    unit="$(_ipsec_unit)"

    section "Removing IKEv2/IPsec"

    # Registry first, while the credential index is still readable. A credential
    # left marked active for a protocol that no longer exists is the "user
    # exists in two protocols and no longer in the third" failure arriving by
    # the back door.
    local cred user row
    while IFS= read -r cred; do
        [[ -n "$cred" ]] || continue
        if row="$(users_cred_find "$cred" 2>/dev/null)"; then
            user="${row%%$'\t'*}"
            users_cred_revoke "$user" "$cred" >/dev/null 2>&1 \
                || warn "could not mark credential '${cred}' revoked for '${user}'"
        fi
        pki_cert_revoke "$cred" >/dev/null 2>&1 || true
        _ipsec_spool_clear "$cred" || true
    done < <(_ipsec_cred_ids)

    if [[ -n "$unit" ]]; then
        distro_service_disable "$unit" || warn "could not disable ${unit}"
    fi

    fs_remove "$VPN55_SWANCTL_CONF" || return 1
    _ipsec_unlink_creds || true

    net_fw_revoke_tag "$VPN55_IPSEC_TAG" || warn "some firewall rules could not be removed — check ${VPN55_FW_STATE}"
    net_pool_release  "$VPN55_IPSEC_TAG" || warn "could not release the pool claim"

    if [[ -f "$VPN55_IPSEC_SYSCTL" ]]; then
        fs_remove "$VPN55_IPSEC_SYSCTL" || return 1
        # The values stay applied until the next boot. Restoring them here would
        # mean guessing what they were before, and guessing wrong turns a clean
        # uninstall into a host that drops legitimate traffic.
        info "Reverse-path filtering stays as it is until the next reboot."
    fi

    pki_hook_remove "$VPN55_IPSEC_HOOK" || true

    # The certificate authority is SHARED with the other certificate protocol
    # and is deliberately left in place. Removing it here would invalidate every
    # credential that one has issued. The refresh timer goes only when nothing
    # is registered against the CA any more.
    if ! pki_in_use; then
        pki_crl_timer_remove || warn "could not remove the revocation-list timer"
        info "No certificate protocol is left. The certificate authority is still"
        info "in ${VPN55_PKI} — remove it from the uninstall screen if you want it gone."
    else
        info "The certificate authority is shared and stays — another protocol uses it."
    fi

    fs_shred_glob "$VPN55_IPSEC_SPOOL" '*' || true
    fs_remove_tree "$VPN55_IPSEC_STATE" || return 1

    local remaining
    remaining="$(net_pool_claims 2>/dev/null || true)"
    if [[ -z "$remaining" ]]; then
        net_forwarding_disable || warn "could not remove the forwarding sysctl file"
    else
        info "IP forwarding left on — another tunnel service still holds a pool slot."
    fi

    if [[ "$VPN55_IPSEC_PURGE_PACKAGES" == "1" ]]; then
        local -a pkgs=()
        mapfile -t pkgs < <(_ipsec_packages) || pkgs=()
        if [[ ${#pkgs[@]} -gt 0 ]]; then
            distro_pkg_remove "${pkgs[@]}" || warn "package removal failed — remove them by hand if you want them gone"
        fi
    else
        info "Packages left installed. Set VPN55_IPSEC_PURGE_PACKAGES=1 to remove them too."
    fi

    success "IKEv2 removed — NAT, forward and port rules revoked from the ledger."
    return 0
}

# ─── The credential index ─────────────────────────────────────────────────────
# One file per credential, key=value, mode 0600. This exists because the daemon
# config holds no per-user entry to read a peer list out of — see design note 2.
_ipsec_cred_file() { printf '%s/%s' "$VPN55_IPSEC_CREDS" "${1:-}"; }

_ipsec_cred_exists() {
    local cred="${1:-}"
    [[ -n "$cred" ]] || return 1
    [[ -f "$(_ipsec_cred_file "$cred")" ]]
}

_ipsec_cred_get() {
    local cred="${1:-}" key="${2:-}"
    fs_conf_default "$(_ipsec_cred_file "$cred")" "$key" ""
}

_ipsec_cred_ids() {
    [[ -d "$VPN55_IPSEC_CREDS" ]] || return 0
    local f
    for f in "$VPN55_IPSEC_CREDS"/*; do
        [[ -f "$f" ]] || continue
        printf '%s\n' "${f##*/}"
    done
    return 0
}

# Ids are opaque and carry no user name: this one becomes a certificate common
# name, a file name in the spool and a line in every log the panel writes, and a
# name in any of those is a name that outlives the account.
_ipsec_new_cred_id() {
    local raw
    raw="$(fs_random_hex 6)" || return 1
    printf 'ipsec-%s' "$raw"
}

# ─── The artifact spool ───────────────────────────────────────────────────────
# Everything a client needs, kept only until the TTL expires. Held as text —
# the key bundle is base64 — so one sweep and one set of permissions covers all
# of it, and so an artifact survives a caller that reads it through command
# substitution, which would otherwise truncate binary at the first NUL.
_ipsec_spool_path() { printf '%s/%s.%s' "$VPN55_IPSEC_SPOOL" "${1:-}" "${2:-}"; }

_ipsec_spool_held() {
    local cred="${1:-}"
    [[ -n "$cred" ]] || return 1
    [[ -s "$(_ipsec_spool_path "$cred" mobileconfig)" ]]
}

_ipsec_spool_clear() {
    local cred="${1:-}" ext
    [[ -n "$cred" ]] || return 0
    for ext in mobileconfig p12b64 pass meta; do
        fs_shred "$(_ipsec_spool_path "$cred" "$ext")" || true
    done
    return 0
}

# Swept on every read path rather than by a timer. A timer is another unit to
# install and another thing to fail silently; the sweep costs one find.
_ipsec_spool_sweep() {
    [[ -d "$VPN55_IPSEC_SPOOL" ]] || return 0
    local ttl="$VPN55_IPSEC_KEY_TTL_HOURS"
    [[ "$ttl" =~ ^[0-9]+$ ]] || ttl=24

    if [[ "$ttl" -eq 0 ]]; then
        fs_shred_glob "$VPN55_IPSEC_SPOOL" '*' || true
        return 0
    fi

    local f
    while IFS= read -r f; do
        [[ -n "$f" ]] || continue
        debug "spool: shredding expired ${f##*/}"
        fs_shred "$f" || true
    done < <(find "$VPN55_IPSEC_SPOOL" -maxdepth 1 -type f -mmin "+$(( ttl * 60 ))" 2>/dev/null || true)
    return 0
}

# ─── Credentials ──────────────────────────────────────────────────────────────
# vpn_ipsec_cred_add <user> [key=value …]
#
# This adapter declares no options in _capabilities, so any key=value pair is a
# caller mistake rather than something to ignore quietly — ignoring it would
# mean a panel silently dropping a field an operator filled in.
#
# Prints the credential id on stdout and nothing else. The artifacts go to the
# spool; the caller reads them back through _artifacts and _client_config, which
# is the same path the panel and the portal use.
vpn_ipsec_cred_add() {
    local user="${1:-}"
    shift || true

    _ipsec_installed || { error "IKEv2 is not installed on this host."; return 1; }
    [[ -n "$user" ]] || { error "vpn_ipsec_cred_add <user>"; return 1; }
    users_exists "$user" || { error "No such user '${user}' in the registry."; return 1; }

    local opt
    for opt in "$@"; do
        [[ -n "$opt" ]] || continue
        error "This protocol takes no credential options; got '${opt%%=*}'."
        error "Ask it what it accepts with the 'capabilities' verb."
        return 1
    done

    local enabled
    enabled="$(users_get "$user" enabled 2>/dev/null)" || enabled="1"
    if [[ "$enabled" != "1" ]]; then
        error "User '${user}' is disabled — enable them before issuing a credential."
        return 1
    fi

    _ipsec_state_dir || return 1

    local cred=""
    local _try
    for _try in 1 2 3 4 5; do
        cred="$(_ipsec_new_cred_id)" || return 1
        if _ipsec_cred_exists "$cred"; then
            cred=""
            continue
        fi
        users_cred_add "$user" "$cred" "$VPN55_IPSEC_TAG" >/dev/null 2>&1 && break
        cred=""
    done
    [[ -n "$cred" ]] || { error "could not register a unique credential id after five tries."; return 1; }

    # ── Order matters, and it is the opposite of the obvious one ────────────
    # The index entry is written BEFORE the certificate exists, because the two
    # failure modes are not symmetrical:
    #
    #   index entry, no certificate  — visible, harmless, removable. It lists in
    #                                  _cred_list, holds no artifacts, and
    #                                  _cred_remove cleans it up.
    #   certificate, no index entry  — INVISIBLE and permanent. Nothing on this
    #                                  host knows the credential exists, so
    #                                  nothing will ever revoke it, and it
    #                                  authenticates until the CA expires.
    #
    # Writing the certificate first and the index second gets this exactly
    # backwards: any failure in between mints a credential that cannot be taken
    # away. So the cheap, reversible record goes down first, and it is rolled
    # back if the expensive irreversible one fails.
    {
        printf 'user=%s\n'    "$user"
        printf 'created=%s\n' "$(fs_now)"
        printf 'custody=server\n'
    } | fs_write_atomic "$(_ipsec_cred_file "$cred")" 0600 \
        || { error "cannot record the credential index entry"; return 1; }

    if ! pki_client_cert_issue "$cred" >/dev/null; then
        fs_remove "$(_ipsec_cred_file "$cred")" || true
        users_cred_revoke "$user" "$cred" >/dev/null 2>&1 || true
        error "Could not issue a certificate for '${cred}'."
        return 1
    fi

    if ! _ipsec_build_artifacts "$cred" "$user"; then
        error "The certificate was issued but its client artifacts could not be built."
        error "Revoke '${cred}' and issue another rather than handing out a partial one."
        return 1
    fi

    # The private key has done its job — it is inside the bundle now. Keeping it
    # would mean the CA directory accumulated one plaintext client key per user,
    # which is exactly what docs/security-model.md §2 says this project does not
    # do.
    pki_client_key_discard "$cred" || warn "could not erase the client private key for '${cred}'"

    _ipsec_spool_sweep || true

    printf '%s' "$cred"
    return 0
}

# vpn_ipsec_cred_remove <cred_id>
#
# Prints, on stdout, one record in the shape every adapter uses:
#
#   revoked  <tag>  <cred_id>  <latency>  <seconds>
#
# latency is a closed vocabulary — `immediate` when access is gone with no
# window, `crl` when an established session survives until it re-authenticates.
# seconds is the worst case, or -1 when there is no bound at all.
#
# Which one this returns is MEASURED, not assumed. The common path really is
# immediate, and reporting it as delayed would train an operator to ignore the
# warning on the day it is true.
vpn_ipsec_cred_remove() {
    local cred="${1:-}"
    [[ -n "$cred" ]] || { error "vpn_ipsec_cred_remove <cred_id>"; return 1; }
    _ipsec_installed || { error "IKEv2 is not installed on this host."; return 1; }
    _ipsec_cred_exists "$cred" || { error "No credential '${cred}' on this server."; return 1; }

    pki_cert_revoke "$cred" || { error "could not revoke the certificate for '${cred}'"; return 1; }

    # pki_cert_revoke regenerates the list and fires the reload hook, so the
    # daemon already refuses the next authentication. What is left is the
    # session that authenticated before any of that happened.
    local published=0
    if _ipsec_active; then
        if _ipsec_reload_creds; then
            published=1
        else
            warn "The revocation list was regenerated but the daemon did not reload it."
        fi
    fi

    local terminated=1 ike_id
    if [[ "$published" == "1" ]]; then
        while IFS= read -r ike_id; do
            [[ -n "$ike_id" ]] || continue
            if ! swanctl --terminate --ike-id "$ike_id" >/dev/null 2>&1; then
                warn "could not terminate the live session ${ike_id} for '${cred}'"
                terminated=0
            fi
        done < <(_ipsec_sa_records | awk -F'\t' -v c="$cred" '$1 == c { print $2 }')
    else
        terminated=0
    fi

    fs_remove "$(_ipsec_cred_file "$cred")" || warn "could not remove the index entry for '${cred}'"
    _ipsec_spool_clear "$cred" || true

    local row user
    if row="$(users_cred_find "$cred" 2>/dev/null)"; then
        user="${row%%$'\t'*}"
        users_cred_revoke "$user" "$cred" >/dev/null 2>&1 \
            || warn "the certificate is revoked but the registry still shows '${cred}' active"
    fi

    if [[ "$published" == "1" && "$terminated" == "1" ]]; then
        printf 'revoked\t%s\t%s\timmediate\t0\n' "$VPN55_IPSEC_TAG" "$cred"
        success "Credential '${cred}' revoked — the certificate is on the revocation"
        success "list and any live session was terminated."
    else
        local bound
        bound="$(_ipsec_revoke_bound)"
        printf 'revoked\t%s\t%s\tcrl\t%s\n' "$VPN55_IPSEC_TAG" "$cred" "$bound"
        warn "Credential '${cred}' is revoked, but the live session could not be ended."
        if [[ "$bound" == "-1" ]]; then
            warn "Re-authentication is switched off on this server, so there is NO"
            warn "guaranteed limit on how long an existing tunnel can continue."
            warn "Restart the service to end every session at once."
        else
            warn "An established tunnel can continue for up to $(( bound / 3600 ))h, until it"
            warn "re-authenticates and is refused. Restart the service to end it now."
        fi
    fi
    return 0
}

# ─── Restart ──────────────────────────────────────────────────────────────────
# The seventh helper verb. Not `_install` re-run: a re-apply rewrites config and
# may change nothing, while this always cycles the daemon — which is the point
# when a service is wedged, and the reason the two must not be conflated.
#
# It matters more here than on a keypair protocol, because it is the ONLY way to
# make a revocation take effect immediately: the revocation list is consulted at
# re-authentication, so a session established before the revocation continues
# until then. Restarting tears down every security association at once. That is
# why the revocation path already tells the operator to do this, and why the
# panel needs a verb for it rather than an instruction to go and use ssh.
vpn_ipsec_restart() {
    distro_require_root || return 1
    _ipsec_installed || { error "IKEv2 is not installed on this host."; return 1; }

    local unit
    unit="$(_ipsec_unit)"
    if [[ -z "$unit" ]]; then
        printf 'restarted\t%s\tfailed\tsessions-dropped\t%s\n' \
            "$VPN55_IPSEC_TAG" "no service unit is recorded for this install"
        error "This install recorded no service unit — re-run the install to repair it."
        return 1
    fi

    if ! distro_service_restart "$unit"; then
        printf 'restarted\t%s\tfailed\tsessions-dropped\t%s\n' \
            "$VPN55_IPSEC_TAG" "the service did not restart; it may now be stopped"
        return 1
    fi

    # A restart that systemd accepted is not a daemon that is running. This one
    # exits on a configuration error it only reads at start-up, so the state has
    # to be re-read rather than inferred from the exit status of the request.
    if ! _ipsec_active; then
        printf 'restarted\t%s\tfailed\tsessions-dropped\t%s\n' \
            "$VPN55_IPSEC_TAG" "the restart was accepted but the daemon is not running"
        error "The daemon restarted and then stopped. Check: journalctl -u ${unit}"
        return 1
    fi

    printf 'restarted\t%s\tok\tsessions-dropped\t%s\n' \
        "$VPN55_IPSEC_TAG" "every security association was torn down; clients re-establish on their own"
    success "IKEv2 restarted — every session was ended and any revocation is now in force."
    return 0
}

# One record per line, the contract's shape:
#
#   cred_id  user  state  address  created  custody  artifacts_held
#
# address is "-": the daemon owns address allocation here, so a credential has
# no address until it connects. That is a real difference from the other
# adapter, not a missing feature, and "-" is the contract's word for "no
# reading" rather than a zero dressed up as one.
vpn_ipsec_cred_list() {
    _ipsec_spool_sweep || true

    local cred user created state row held
    while IFS= read -r cred; do
        [[ -n "$cred" ]] || continue
        user="$(_ipsec_cred_get "$cred" user)"
        created="$(_ipsec_cred_get "$cred" created)"

        state="unregistered"
        if row="$(users_cred_find "$cred" 2>/dev/null)"; then
            state="${row##*$'\t'}"
        fi
        if _ipsec_spool_held "$cred"; then held=1; else held=0; fi

        printf '%s\t%s\t%s\t-\t%s\tserver\t%s\n' \
            "$cred" "$user" "$state" "$created" "$held"
    done < <(_ipsec_cred_ids)
    return 0
}

# ─── Client artifacts ─────────────────────────────────────────────────────────
# vpn_ipsec_artifacts <cred_id> — one record per line:
#
#   artifact  <id>  <label>  <filename>  <encoding>  <qr>  <note>
#
#   encoding   text | base64. A caller reading a config through command
#              substitution cannot carry binary — NULs are dropped and trailing
#              newlines are eaten — so anything not text is base64 on the wire
#              and the caller decodes.
#   qr         1 only where a QR code is genuinely useful. A configuration
#              profile is several kilobytes of XML; encoding it produces a code
#              no phone camera will resolve, and offering one is worse than
#              offering nothing because it looks like it should work.
#
# The list reflects what is available RIGHT NOW. Once the spool TTL passes, the
# two artifacts that contain the private key are gone and stop being listed,
# which is what makes the "held" column in _cred_list mean something.
vpn_ipsec_artifacts() {
    local cred="${1:-}"
    [[ -n "$cred" ]] || { error "vpn_ipsec_artifacts <cred_id>"; return 1; }
    _ipsec_cred_exists "$cred" || { error "No credential '${cred}' on this server."; return 1; }
    _ipsec_spool_sweep || true

    if [[ -s "$(_ipsec_spool_path "$cred" mobileconfig)" ]]; then
        printf 'artifact\tmobileconfig\tApple configuration profile\tvpn55-%s.mobileconfig\ttext\t0\t%s\n' \
            "$cred" "iOS and macOS. Open it on the device and install it — everything is inside, including the identity."
    fi
    if [[ -s "$(_ipsec_spool_path "$cred" p12b64)" ]]; then
        printf 'artifact\tp12\tCertificate bundle\tvpn55-%s.p12\tbase64\t0\t%s\n' \
            "$cred" "Windows and Android. Passphrase-protected; the passphrase is in the instructions."
    fi
    printf 'artifact\tca\tCertificate authority\tvpn55-ca.crt\ttext\t0\t%s\n' \
        "Not secret. Windows needs this in its trusted root store before the connection will verify."
    if [[ -s "$(_ipsec_spool_path "$cred" meta)" ]]; then
        printf 'artifact\tinstructions\tSetup instructions\tvpn55-%s.txt\ttext\t0\t%s\n' \
            "$cred" "Per-platform steps, the server address and the bundle passphrase."
    fi
    return 0
}

# vpn_ipsec_client_config <cred_id> [artifact_id] [locale]
#
# With no artifact named, the first one _artifacts lists is returned — which is
# the most directly usable, not the most complete.
#
# The locale is the third positional argument on every adapter. It reaches here
# from a caller that does not know which protocol it is talking to, which is
# exactly right: a language tag is not protocol vocabulary. It is ignored by the
# artifacts that are not prose — a configuration profile and a certificate
# bundle are bytes for a parser, and there is no Vietnamese spelling of either.
vpn_ipsec_client_config() {
    local cred="${1:-}" artifact="${2:-}" locale="${3:-}"
    [[ -n "$cred" ]] || { error "vpn_ipsec_client_config <cred_id> [artifact] [locale]"; return 1; }
    _ipsec_installed || { error "IKEv2 is not installed on this host."; return 1; }
    _ipsec_cred_exists "$cred" || { error "No credential '${cred}' on this server."; return 1; }
    _ipsec_spool_sweep || true

    if [[ -z "$artifact" ]]; then
        artifact="$(vpn_ipsec_artifacts "$cred" | awk -F'\t' 'NR == 1 { print $2 }')"
        [[ -n "$artifact" ]] || { error "'${cred}' has no artifacts left to hand out."; return 1; }
    fi

    case "$artifact" in
        ca)
            cat "$(pki_ca_path)" || { error "cannot read the certificate authority"; return 1; }
            return 0 ;;
        mobileconfig|p12|instructions) ;;
        *)
            error "'${artifact}' is not an artifact this protocol produces."
            error "Ask it what it has with the 'artifacts' verb."
            return 1 ;;
    esac

    local ext="$artifact"
    [[ "$artifact" == "p12" ]] && ext="p12b64"
    # The prose artifact has no spool file of its own any more: what is kept is
    # the handful of facts it is rendered from, on the same TTL. So the
    # existence check below still asks the right question, and the error it
    # gives when the answer is no is still true.
    [[ "$artifact" == "instructions" ]] && ext="meta"

    local path
    path="$(_ipsec_spool_path "$cred" "$ext")"
    if [[ ! -s "$path" ]]; then
        error "The '${artifact}' artifact for '${cred}' is no longer available."
        error "It carried the private key, which was erased ${VPN55_IPSEC_KEY_TTL_HOURS}h after issue."
        error "There is no way to rebuild it — revoke this credential and issue a new one."
        return 1
    fi

    if [[ "$artifact" == "instructions" ]]; then
        _ipsec_build_instructions "$cred" "$locale" \
            || { error "cannot build the setup instructions for '${cred}'"; return 1; }
        return 0
    fi

    cat "$path" || { error "cannot read the ${artifact} artifact for '${cred}'"; return 1; }
    return 0
}

# ─── Building the artifacts ───────────────────────────────────────────────────
_ipsec_build_artifacts() {
    local cred="${1:-}" user="${2:-}"
    local p12 pass rc=0

    p12="$(_ipsec_spool_path "$cred" p12)"
    pass="$(pki_bundle_p12 "$cred" "$p12")" || return 1
    [[ -n "$pass" ]] || { error "no passphrase returned for the bundle"; return 1; }

    base64 < "$p12" | fs_write_atomic "$(_ipsec_spool_path "$cred" p12b64)" 0600 || rc=1
    fs_shred "$p12" || true
    [[ "$rc" -eq 0 ]] || { error "cannot spool the certificate bundle"; return 1; }

    printf '%s\n' "$pass" | fs_write_atomic "$(_ipsec_spool_path "$cred" pass)" 0600 \
        || { error "cannot spool the bundle passphrase"; return 1; }

    _ipsec_build_mobileconfig "$cred" "$user" "$pass" \
        | fs_write_atomic "$(_ipsec_spool_path "$cred" mobileconfig)" 0600 \
        || { error "cannot spool the configuration profile"; return 1; }

    # The instructions are prose for whoever receives this credential, and
    # nobody knows at issue time which of the three languages that person
    # reads. So the FACTS are spooled and the page is rendered at handover,
    # in the language asked for then. The passphrase already has its own
    # spool entry on the same clock, so this file holds only the name.
    printf 'user\t%s\n' "$user" \
        | fs_write_atomic "$(_ipsec_spool_path "$cred" meta)" 0600 \
        || { error "cannot spool the credential's details"; return 1; }

    return 0
}

# The CA's own common name, which a configuration profile has to name so the
# client knows which issuer to accept for the server.
_ipsec_ca_cn() {
    local subject
    subject="$(openssl x509 -in "$(pki_ca_path)" -noout -subject 2>/dev/null)" || return 1
    subject="${subject##*CN = }"
    subject="${subject##*CN=}"
    printf '%s' "${subject%%,*}"
}

# A configuration profile is a plist. Everything interpolated into it goes
# through fs_xml_escape — the CA common name and the endpoint are operator-
# supplied, and an unescaped ampersand in either produces a profile the device
# rejects as corrupt with no indication of why.
#
# ⚠ This file contains the certificate bundle AND its passphrase in the clear.
# It is exactly as sensitive as the private key, which is why it lives in the
# same spool under the same TTL and never in a world-readable place.
_ipsec_build_mobileconfig() {
    local cred="${1:-}" user="${2:-}" pass="${3:-}"
    local endpoint ca_cn ca_b64 p12_b64
    local uuid_top uuid_ca uuid_p12 uuid_vpn

    endpoint="$(_ipsec_endpoint)"
    ca_cn="$(_ipsec_ca_cn)" || ca_cn="VPN55 Certificate Authority"

    ca_b64="$(openssl x509 -in "$(pki_ca_path)" -outform DER 2>/dev/null | base64)" \
        || { error "cannot encode the certificate authority"; return 1; }
    p12_b64="$(cat "$(_ipsec_spool_path "$cred" p12b64)" 2>/dev/null)" \
        || { error "cannot read the spooled bundle"; return 1; }

    uuid_top="$(fs_uuid)" || return 1
    uuid_ca="$(fs_uuid)"  || return 1
    uuid_p12="$(fs_uuid)" || return 1
    uuid_vpn="$(fs_uuid)" || return 1

    local e_endpoint e_cred e_user e_ca_cn e_pass
    e_endpoint="$(fs_xml_escape "$endpoint")"
    e_cred="$(fs_xml_escape "$cred")"
    e_user="$(fs_xml_escape "$user")"
    e_ca_cn="$(fs_xml_escape "$ca_cn")"
    e_pass="$(fs_xml_escape "$pass")"

    cat <<PROFILE
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>PayloadType</key>
  <string>Configuration</string>
  <key>PayloadVersion</key>
  <integer>1</integer>
  <key>PayloadIdentifier</key>
  <string>org.vpn55.${e_endpoint}.${e_cred}</string>
  <key>PayloadUUID</key>
  <string>${uuid_top}</string>
  <key>PayloadDisplayName</key>
  <string>VPN55</string>
  <key>PayloadDescription</key>
  <string>IKEv2 VPN for ${e_user}. Contains the certificate authority and this device's identity.</string>
  <key>PayloadOrganization</key>
  <string>VPN55</string>
  <key>PayloadRemovalDisallowed</key>
  <false/>
  <key>PayloadContent</key>
  <array>

    <dict>
      <key>PayloadType</key>
      <string>com.apple.security.root</string>
      <key>PayloadVersion</key>
      <integer>1</integer>
      <key>PayloadIdentifier</key>
      <string>org.vpn55.${e_endpoint}.${e_cred}.ca</string>
      <key>PayloadUUID</key>
      <string>${uuid_ca}</string>
      <key>PayloadDisplayName</key>
      <string>${e_ca_cn}</string>
      <key>PayloadCertificateFileName</key>
      <string>vpn55-ca.crt</string>
      <key>PayloadContent</key>
      <data>
${ca_b64}
      </data>
    </dict>

    <dict>
      <key>PayloadType</key>
      <string>com.apple.security.pkcs12</string>
      <key>PayloadVersion</key>
      <integer>1</integer>
      <key>PayloadIdentifier</key>
      <string>org.vpn55.${e_endpoint}.${e_cred}.identity</string>
      <key>PayloadUUID</key>
      <string>${uuid_p12}</string>
      <key>PayloadDisplayName</key>
      <string>VPN55 identity — ${e_cred}</string>
      <key>PayloadCertificateFileName</key>
      <string>vpn55-${e_cred}.p12</string>
      <key>Password</key>
      <string>${e_pass}</string>
      <key>PayloadContent</key>
      <data>
${p12_b64}
      </data>
    </dict>

    <dict>
      <key>PayloadType</key>
      <string>com.apple.vpn.managed</string>
      <key>PayloadVersion</key>
      <integer>1</integer>
      <key>PayloadIdentifier</key>
      <string>org.vpn55.${e_endpoint}.${e_cred}.vpn</string>
      <key>PayloadUUID</key>
      <string>${uuid_vpn}</string>
      <key>PayloadDisplayName</key>
      <string>VPN55</string>
      <key>UserDefinedName</key>
      <string>VPN55</string>
      <key>VPNType</key>
      <string>IKEv2</string>
      <key>IKEv2</key>
      <dict>
        <key>RemoteAddress</key>
        <string>${e_endpoint}</string>
        <key>RemoteIdentifier</key>
        <string>${e_endpoint}</string>
        <key>LocalIdentifier</key>
        <string>${e_cred}</string>
        <key>AuthenticationMethod</key>
        <string>Certificate</string>
        <key>PayloadCertificateUUID</key>
        <string>${uuid_p12}</string>
        <key>ServerCertificateIssuerCommonName</key>
        <string>${e_ca_cn}</string>
        <key>ExtendedAuthEnabled</key>
        <integer>0</integer>
        <key>EnablePFS</key>
        <true/>
        <key>DisableMOBIKE</key>
        <integer>0</integer>
        <key>DisableRedirect</key>
        <integer>0</integer>
        <key>UseConfigurationAttributeInternalIPSubnet</key>
        <integer>0</integer>
        <key>EnableCertificateRevocationCheck</key>
        <integer>0</integer>
        <key>IKESecurityAssociationParameters</key>
        <dict>
          <key>EncryptionAlgorithm</key>
          <string>AES-256</string>
          <key>IntegrityAlgorithm</key>
          <string>SHA2-256</string>
          <key>DiffieHellmanGroup</key>
          <integer>14</integer>
          <key>LifeTimeInMinutes</key>
          <integer>1440</integer>
        </dict>
        <key>ChildSecurityAssociationParameters</key>
        <dict>
          <key>EncryptionAlgorithm</key>
          <string>AES-256</string>
          <key>IntegrityAlgorithm</key>
          <string>SHA2-256</string>
          <key>DiffieHellmanGroup</key>
          <integer>14</integer>
          <key>LifeTimeInMinutes</key>
          <integer>1440</integer>
        </dict>
      </dict>
      <key>IPv4</key>
      <dict>
        <key>OverridePrimary</key>
        <integer>1</integer>
      </dict>
    </dict>

  </array>
</dict>
</plist>
PROFILE
    return 0
}

# _ipsec_build_instructions <cred> [locale] — the setup page, in one language.
#
# The prose lives in lib/locales/<tag>/<locale>.txt and is looked up by SECTION
# NAME, never by matching its English text: a phrase map keyed on English word
# order misses every translator who reorders a sentence, and the two files still
# look parallel afterwards.
#
# Two things in the English text are load-bearing and are stated there rather
# than buried, which is also why they must survive translation intact:
#
#   - Windows' built-in client offers a WEAK proposal set by default (1024-bit
#     Diffie-Hellman, SHA-1) and this server does not accept it. The connection
#     fails with no useful message until the policy command is run, so that
#     command is marked required rather than optional.
#   - IPv6 does not enter this tunnel and the server cannot make it. Anyone
#     using this to avoid being observed is entitled to know that before they
#     rely on it, not after.
_ipsec_build_instructions() {
    local cred="${1:-}" locale="${2:-}"
    local tag="$VPN55_IPSEC_TAG"
    local meta user pass endpoint ca_cn

    meta="$(_ipsec_spool_path "$cred" meta)"
    [[ -s "$meta" ]] || { error "no spooled details for '${cred}'"; return 1; }
    user="$(awk -F'\t' '$1 == "user" { print $2; exit }' "$meta")"

    # The passphrase has its own spool entry, written and swept on the same
    # clock as the bundle it unlocks. Reading it back here is what keeps the
    # page renderable in a second language without ever holding it twice.
    pass="$(cat "$(_ipsec_spool_path "$cred" pass)" 2>/dev/null)" || pass=""

    endpoint="$(_ipsec_endpoint)"
    ca_cn="$(_ipsec_ca_cn)" || ca_cn="VPN55 Certificate Authority"

    i18n_render "$tag" "$locale" main \
        "cred=${cred}" "user=${user}" "pass=${pass}" \
        "endpoint=${endpoint}" "ca_cn=${ca_cn}" || return 1
    return 0
}

# ─── Live security associations ───────────────────────────────────────────────
# Parsed from `swanctl --list-sas --raw`. The raw form is used rather than the
# human one because the human one is laid out for reading and gets re-laid-out
# between releases; the raw form is a serialised message and is stable.
#
# One record per line, TAB separated:
#
#   cred  ike_id  state  remote_host  remote_port  virtual_ip  established_epoch  bytes_in  bytes_out
#
# Bytes are summed across the credential's child SAs. They reset on every rekey
# — that is the counter-reset trap the collector already handles, and it is why
# this reports the instantaneous reading rather than trying to accumulate here.
_ipsec_sa_records() {
    _ipsec_active || return 0
    command -v swanctl >/dev/null 2>&1 || return 0

    local now
    now="$(fs_now_epoch)"

    # Bounded. This is on the panel's polling path, and swanctl talks to the
    # daemon over a unix socket — a daemon that is wedged rather than stopped
    # leaves the read blocking forever, and the panel stops rendering ANY
    # protocol's status rather than showing this one as unavailable. `timeout`
    # is coreutils and effectively always present; where it is not, the
    # unbounded call is still better than no status at all.
    local -a run=()
    if command -v timeout >/dev/null 2>&1; then
        run=(timeout 5)
    fi

    "${run[@]}" swanctl --list-sas --raw 2>/dev/null | awk -v now="$now" '
        # The raw form nests with braces. Depth 1 is one IKE SA, depth 3 is one
        # of its child SAs — and `uniqueid` and `state` appear at BOTH levels,
        # so a parser that matched on the key alone would report a child SA'"'"'s
        # id and then terminate the wrong session.
        BEGIN { TAB = sprintf("%c", 9); depth = 0 }

        function flush() {
            if (cred != "") {
                print cred TAB ike TAB state TAB rhost TAB rport TAB vip TAB est TAB bin TAB bout
            }
            cred = ""; ike = ""; state = ""; rhost = "-"; rport = "-"
            vip = "-"; est = "-"; bin = 0; bout = 0; seen = 0
        }

        {
            line = $0
            sub(/^[ \t]+/, "", line)
            sub(/[ \t]+$/, "", line)
            if (line == "") next

            if (line ~ /\{$/) {
                depth++
                if (depth == 1) flush()
                next
            }
            if (line == "}") {
                depth--
                if (depth == 0) flush()
                next
            }

            eq = index(line, "=")
            if (eq == 0) next
            key = substr(line, 1, eq - 1)
            val = substr(line, eq + 1)

            if (depth == 1) {
                if (key == "uniqueid")    ike = val
                else if (key == "state")  state = val
                else if (key == "remote-host") rhost = val
                else if (key == "remote-port") rport = val
                else if (key == "established") est = (val + 0 >= 0 ? now - val : "-")
                else if (key == "remote-id") {
                    # The identity is the client certificate subject, which this
                    # adapter issues as exactly CN=<cred_id>. A client that sends
                    # the subjectAltName instead sends the bare id, so both forms
                    # are accepted rather than guessed between.
                    v = val
                    sub(/^CN=/, "", v)
                    sub(/^.*, *CN=/, "", v)
                    cred = v
                }
                else if (key == "remote-vips") {
                    v = val
                    gsub(/[\[\]]/, "", v)
                    n = index(v, ",")
                    if (n > 0) v = substr(v, 1, n - 1)
                    if (v != "") vip = v
                }
            } else if (depth == 3) {
                if (key == "bytes-in")       bin += val + 0
                else if (key == "bytes-out") bout += val + 0
            }
        }

        END { if (depth >= 1) flush() }
    ' || true
    return 0
}

# ─── Status ───────────────────────────────────────────────────────────────────
# The uniform shape. Field 1 is the record type, so a reader never has to guess
# from the field count, and field 2 is always the adapter tag so the panel can
# concatenate every adapter's output into one stream.
#
#   service   <tag>  <state>  <enabled>  <listen>  <since>  <cred_count>
#   cred      <tag>  <cred_id>  <user>  <state>  <address>  <rx>  <tx>  <handshake>  <endpoint>
#   note      <tag>  <severity>  <message>
#
#   state      absent | stopped | running   (closed vocabulary, all protocols)
#   listen     a display string, not a single port — this one serves two
#   rx / tx    bytes as the protocol reports them RIGHT NOW, or "-" when there
#              is no reading. "-" is NOT zero and must not be treated as a
#              counter reset by the collector.
#   handshake  unix epoch of the last proof this credential was live.
#              0  = never, as a fact.
#              -  = no reading. This adapter cannot tell the two apart for a
#                   credential that is not connected right now: the daemon keeps
#                   no history, so "never connected" and "connected yesterday"
#                   look identical from here. Reporting 0 for both would state a
#                   fact this adapter does not have.
#   endpoint   the peer's current remote address, or "-". LIVE state only, never
#              retained — docs/security-model.md §2 says VPN55 keeps no per-user
#              connection IP history.
vpn_ipsec_status() {
    _ipsec_spool_sweep || true

    local tag="$VPN55_IPSEC_TAG"
    local state enabled since count unit

    if ! _ipsec_installed; then
        printf 'service\t%s\tabsent\t0\tudp/500,4500\t-\t0\n' "$tag"
        return 0
    fi

    unit="$(_ipsec_unit)"
    if _ipsec_active; then state="running"; else state="stopped"; fi
    if [[ -n "$unit" ]] && distro_service_is_enabled "$unit"; then enabled=1; else enabled=0; fi

    since="-"
    if [[ "$state" == "running" ]] && distro_has_systemd; then
        local stamp
        stamp="$(systemctl show -p ActiveEnterTimestamp --value "$unit" 2>/dev/null || true)"
        if [[ -n "$stamp" ]]; then
            since="$(date -d "$stamp" +%s 2>/dev/null || printf -- '-')"
        fi
    fi

    local ids
    ids="$(_ipsec_cred_ids)"
    count="$(printf '%s' "$ids" | grep -c . || true)"
    printf 'service\t%s\t%s\t%s\tudp/500,4500\t%s\t%s\n' "$tag" "$state" "$enabled" "$since" "${count:-0}"

    _ipsec_notes || true

    [[ -n "$ids" ]] || return 0

    # One read of the live SA table, then a lookup per credential. Calling
    # swanctl once per credential would be one process per user on every poll.
    #
    # _c_ike and _c_state are read only to consume their columns — the SA's own
    # state is not what a credential row reports, since a credential's state
    # comes from the registry. The underscore keeps a linter quiet, and it is
    # also the honest signal that this loop is POSITIONAL: dropping a name here
    # rather than renaming it would shift every value after it by one.
    declare -A sa_host sa_vip sa_est sa_in sa_out
    local c_cred _c_ike _c_state c_host c_port c_vip c_est c_in c_out
    while IFS=$'\t' read -r c_cred _c_ike _c_state c_host c_port c_vip c_est c_in c_out; do
        [[ -n "$c_cred" ]] || continue
        sa_host["$c_cred"]="${c_host}:${c_port}"
        sa_vip["$c_cred"]="$c_vip"
        sa_est["$c_cred"]="$c_est"
        sa_in["$c_cred"]="$c_in"
        sa_out["$c_cred"]="$c_out"
    done < <(_ipsec_sa_records)

    local cred user cstate row
    while IFS= read -r cred; do
        [[ -n "$cred" ]] || continue
        user="$(_ipsec_cred_get "$cred" user)"

        cstate="unregistered"
        if row="$(users_cred_find "$cred" 2>/dev/null)"; then
            cstate="${row##*$'\t'}"
        fi

        printf 'cred\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
            "$tag" "$cred" "$user" "$cstate" \
            "${sa_vip[$cred]:--}" \
            "${sa_in[$cred]:--}" "${sa_out[$cred]:--}" \
            "${sa_est[$cred]:--}" \
            "${sa_host[$cred]:--}"
    done <<< "$ids"
    return 0
}

# Facts the panel should surface that are not per-credential and are not the
# service being up. The record type exists so an adapter can say something
# specific without the panel learning what a revocation list is.
_ipsec_notes() {
    local tag="$VPN55_IPSEC_TAG"

    printf 'note\t%s\tinfo\t%s\n' "$tag" \
        "IPv6 does not travel through this tunnel. A dual-stack device keeps using its own IPv6 path, and the server cannot block traffic that never reaches it."

    local left
    left="$(pki_crl_expires_in)"
    if [[ "$left" =~ ^-?[0-9]+$ ]]; then
        if [[ "$left" -le 0 ]]; then
            printf 'note\t%s\tcrit\t%s\n' "$tag" \
                "The certificate revocation list has EXPIRED. With a strict policy every client is refused, not only revoked ones. Refresh it now."
        elif [[ "$left" -lt 604800 ]]; then
            printf 'note\t%s\twarn\t%s\n' "$tag" \
                "The certificate revocation list expires in $(( left / 86400 )) days. If it lapses, every client is refused."
        fi
    fi

    if [[ "$(_ipsec_reauth)" == "0" ]]; then
        printf 'note\t%s\twarn\t%s\n' "$tag" \
            "Re-authentication is off. If a revoked credential's live session cannot be terminated, its tunnel has no guaranteed end."
    fi
    return 0
}

# ─── Registration ─────────────────────────────────────────────────────────────
# vpn55.sh sources every lib/proto_*.sh by glob and each adapter announces
# itself. The guard is for the case where this file is sourced on its own — a
# test harness, or a panel-side check — where the registry does not exist.
if declare -F vpn_adapter_register >/dev/null 2>&1; then
    vpn_adapter_register "$VPN55_IPSEC_TAG" "IKEv2/IPsec" || true
fi
