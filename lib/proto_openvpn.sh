# shellcheck shell=bash
#
# lib/proto_openvpn.sh — OpenVPN adapter. Phase 4.
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
# ── The contract was not changed for this adapter, and that is the result ────
# Phase 3 widened the contract from eight verbs to ten because a certificate
# protocol broke three assumptions the first adapter had quietly baked in. This
# one needed nothing: _capabilities already carries the revocation latency and
# the custody disclosure, _artifacts already separates "what exists" from "give
# me one", `-` already means "no reading" as distinct from zero, and the `note`
# record already carries a fact the panel must show without understanding it.
#
# One gap was found and is deliberately NOT closed here, because closing it
# belongs to the phase that grows the consumer rather than to this one: an
# adapter's INSTALL-TIME choices are invisible to a protocol-neutral caller.
# The transport mode below, and the other adapter's obfuscation mode, are both
# settled inside the adapter's own bootstrap prompt, so a panel-driven install
# silently takes whatever default the adapter picked. `option` records exist for
# _cred_add and have no _install equivalent. See the note at the end of this
# header block.
#
# ── Reshaped from MIT sources, and which parts ───────────────────────────────
# Unlike Phase 3, this phase HAD liftable prior art. Nyr/openvpn-install and
# angristan/openvpn-install are both MIT (re-verified through the GitHub API on
# 2026-08-29, not from a README badge). What was taken from them is the
# single-file inline-certificate emit, the transport/port handling and three
# platform traps — recorded per-function below and in ATTRIBUTIONS.md.
#
# Deliberately NOT taken: easy-rsa. Both upstreams vendor it as their PKI; this
# adapter reuses lib/core_pki.sh, the same authority the other certificate
# protocol issues from. A second PKI would mean two CAs, two revocation lists
# and two answers to "is this credential still valid".
#
# Also not taken: their firewall handling. Nyr writes iptables rules into a
# generated systemd unit and angristan applies them directly; VPN55 routes every
# rule through one backend and records it in a ledger, so an uninstall reverses
# exactly what was added. Same lesson, our mechanism — as with the first adapter.
#
# ── Design decisions, and why ────────────────────────────────────────────────
#
# 1. TRANSPORT IS THE FIRST QUESTION, not a buried option. TCP/443 is the whole
#    practical reason this protocol is in the set: it is what survives a network
#    that drops UDP or blocks the keypair protocol by signature. It is also
#    slower, and the reason is structural rather than a tuning problem — see
#    _ovpn_transport_bootstrap. Both facts are put in front of the operator at
#    the moment they choose, because afterwards is too late: the transport is
#    baked into every client configuration ever issued.
#
# 2. tls-crypt IS ON, ALWAYS, and is not offered as a choice. Without it this
#    protocol's control-channel handshake is identifiable in the clear, which
#    makes it blockable by signature in the same way the keypair protocol is.
#    With it there is nothing to match. It costs one directive and one key.
#    Where the daemon is new enough, tls-crypt-v2 is used instead, which does
#    the same thing with a per-client key — see _ovpn_tls_mode.
#
# 3. ONE server certificate with a FIXED common name, not the endpoint. The
#    other certificate protocol names its server certificate after the endpoint
#    because IKE matches on that identity. This one does not: a client pins the
#    server with verify-x509-name against a name we choose, and does no hostname
#    check at all. Naming it after the endpoint would put BOTH protocols on the
#    same common name, and core_pki stores an issued certificate at
#    issued/<cn>.crt — one file. Whichever installed second would find a valid
#    certificate for that name and reuse it, so an endpoint installed here first
#    would hand the other protocol a certificate missing the extended-key-usage
#    OID its native clients require, and the failure would surface on a user's
#    phone as an unexplained refusal. A fixed name cannot collide, and it also
#    means changing the endpoint needs no certificate work at all.
#
# 4. Addresses come from net_pool_alloc and are PINNED per credential, through
#    client-config-dir. This protocol can do what the other certificate protocol
#    cannot, so it does: a credential's address is stable, _cred_list reports a
#    real one, and the daemon never allocates dynamically. ccd-exclusive makes
#    that last part true rather than merely argued.
#
# 5. Only the revocation list is published outside the PKI. The certificate
#    authority, the server certificate and its key are read once at start-up
#    while the daemon is still root, so they are referenced by absolute path
#    into a 0700 directory. The revocation list is different: it is re-read on
#    EVERY client connection, long after the daemon has dropped to an
#    unprivileged user, so a copy of it lives in a world-readable directory and
#    is refreshed by a core_pki hook. Referencing the list inside the PKI
#    directly would work until the first connection after start-up and then
#    refuse every user with a permission error nobody would look for.
#
# 6. IPv6 is not carried, and IS captured where the daemon can. The keypair
#    protocol captures it by claiming ::/0 in the client's allowed routes; the
#    other certificate protocol cannot capture it at all. This one sits in
#    between: from 2.5 the server can push block-ipv6, which makes a dual-stack
#    client drop its own IPv6 rather than route it around the tunnel. Where the
#    daemon is older, that is reported as a note rather than papered over.
#
# ── Revocation: measured, not assumed ────────────────────────────────────────
# A revocation here is a list entry, exactly as it is for the other certificate
# protocol, and a list entry does nothing to a session that has already
# authenticated. What this adapter does about that:
#
#   - publishes the revocation to the list the daemon actually reads, which
#     refuses the next connection,
#   - kills the credential's live session through the management interface,
#     which ends the current one,
#   - and reports which of those it managed rather than assuming both.
#
# When the daemon is not running there is no session to end and the list is
# already updated for when it starts, so that case is immediate too. When the
# kill could not be confirmed, the honest answer is the renegotiation interval:
# the server re-verifies a client's certificate against the revocation list when
# it renegotiates the data channel, and it triggers that on its own timer
# whatever the client would prefer.
#
# Sourced, not executed. errexit does not cover a ||-guarded function body, so
# every command here that creates, copies, moves or deletes is guarded on its
# own line — see CLAUDE.md.

[[ -n "${VPN55_OPENVPN_LOADED:-}" ]] && return 0
VPN55_OPENVPN_LOADED=1

: "${VPN55_ETC:=/etc/vpn55}"

# The adapter's own tag. It is the <proto> in every contract verb, the owner tag
# it claims its pool slot and its firewall rules under, and the owner tag its
# credentials carry in the registry. One string, four uses, so they cannot drift.
VPN55_OVPN_TAG="openvpn"

# Pool slot 1. The slot table lives in CLAUDE.md § Networking and nowhere else —
# core_net deliberately does not know which protocol owns which slot.
VPN55_OVPN_SLOT=1

: "${VPN55_OVPN_STATE:=$VPN55_ETC/openvpn}"
: "${VPN55_OVPN_CONF:=$VPN55_OVPN_STATE/settings.conf}"
: "${VPN55_OVPN_CREDS:=$VPN55_OVPN_STATE/creds}"
: "${VPN55_OVPN_SPOOL:=$VPN55_OVPN_STATE/spool}"

# The daemon's configuration is written under OUR OWN instance name rather than
# the conventional one. A host may already run a tunnel this installer did not
# create, and overwriting its config because the file name happened to match is
# not something an installer gets to do.
: "${VPN55_OVPN_INSTANCE:=vpn55}"

# World-readable by design: the revocation list the daemon re-reads after it has
# dropped privileges lives here, and nothing secret ever does. Kept out of
# $VPN55_ETC deliberately — that tree is 0700, and a 0644 file inside a
# directory nobody can traverse is a 0644 file nobody can read.
: "${VPN55_OVPN_PUB:=/var/lib/vpn55/openvpn}"

# The status file the daemon writes and _status reads back.
: "${VPN55_OVPN_LOG_DIR:=/var/log/vpn55}"
: "${VPN55_OVPN_STATUS_INTERVAL:=10}"

# The management socket, in a root-only runtime directory. Anyone who can reach
# this socket can disconnect clients and read the daemon's state, so the control
# is the directory mode — there is no authentication on a management socket that
# is not asked for one.
: "${VPN55_OVPN_RUN_DIR:=/run/vpn55}"

VPN55_OVPN_HOOK="openvpn-crl"

# The server certificate's common name. Fixed, and not the endpoint — design
# note 3. Clients pin it with verify-x509-name; no client checks it against a
# hostname, so it never has to change when the endpoint does.
VPN55_OVPN_SERVER_CN="vpn55-openvpn-server"

# How long a client's artifacts stay retrievable after issue, in hours. Same
# compromise, and the same number, as the other two adapters: long enough for a
# real hand-off, short enough that the exit node is not a permanent store of
# every user's identity. 0 disables the spool entirely.
: "${VPN55_OVPN_KEY_TTL_HOURS:=24}"

# Data-channel key renegotiation, in seconds. The server re-verifies the client
# certificate against the revocation list when it renegotiates, and it triggers
# that on its own timer — so this is the guaranteed upper bound on how long a
# revoked credential can keep an already-established session when the live kill
# could not be confirmed. It is a security setting wearing a performance
# setting's clothes, exactly as the other certificate protocol's
# re-authentication interval is.
#
# 3600 is the daemon's own default and is left alone. Lowering it costs a
# handshake per client per interval; 0 turns renegotiation off entirely and
# makes the fallback bound unlimited, which _cred_remove then reports as -1.
: "${VPN55_OVPN_RENEG_SECONDS:=3600}"

# Data-channel ciphers. AEAD only: the CBC modes some old clients still offer
# first are accepted by nobody here, for the same reason the other certificate
# protocol refuses 1024-bit Diffie-Hellman — quietly accepting the weakest thing
# a platform knows how to ask for, to make it connect out of the box, hands
# every user of that platform the weakest thing.
: "${VPN55_OVPN_DATA_CIPHERS:=AES-256-GCM:AES-128-GCM}"
: "${VPN55_OVPN_AUTH_DIGEST:=SHA256}"
: "${VPN55_OVPN_TLS_MIN:=1.2}"
: "${VPN55_OVPN_TLS_GROUPS:=X25519:prime256v1:secp384r1}"

# Ports the named transports use unless VPN55_OVPN_PORT overrides them.
: "${VPN55_OVPN_TCP_PORT:=443}"
: "${VPN55_OVPN_UDP_PORT:=1194}"

# Opt-in package purge on uninstall. Off by default, for the same reason as the
# other adapters: removing a package is not what "reverse the install" means to
# an operator who wants the tunnel gone.
: "${VPN55_OVPN_PURGE_PACKAGES:=0}"

# ─── Settings ─────────────────────────────────────────────────────────────────
_ovpn_state_dir() {
    fs_ensure_dir "$VPN55_OVPN_STATE" 0700 || return 1
    fs_ensure_dir "$VPN55_OVPN_CREDS" 0700 || return 1
    fs_ensure_dir "$VPN55_OVPN_SPOOL" 0700 || return 1
    return 0
}

_ovpn_set() { fs_conf_set "$VPN55_OVPN_CONF" "${1:-}" "${2:-}"; }

_ovpn_endpoint()  { fs_conf_default "$VPN55_OVPN_CONF" endpoint  ""; }
_ovpn_transport() { fs_conf_default "$VPN55_OVPN_CONF" transport ""; }
_ovpn_port()      { fs_conf_default "$VPN55_OVPN_CONF" port      ""; }
_ovpn_dns()       { fs_conf_default "$VPN55_OVPN_CONF" dns       ""; }
_ovpn_unit()      { fs_conf_default "$VPN55_OVPN_CONF" unit      ""; }
_ovpn_confdir()   { fs_conf_default "$VPN55_OVPN_CONF" confdir   ""; }
_ovpn_svc_user()  { fs_conf_default "$VPN55_OVPN_CONF" svc_user  ""; }
_ovpn_svc_group() { fs_conf_default "$VPN55_OVPN_CONF" svc_group ""; }
_ovpn_tls_mode()  { fs_conf_default "$VPN55_OVPN_CONF" tls_mode  ""; }
_ovpn_reneg()     { fs_conf_default "$VPN55_OVPN_CONF" reneg_seconds "$VPN55_OVPN_RENEG_SECONDS"; }
_ovpn_selinux()   { fs_conf_default "$VPN55_OVPN_CONF" selinux_port "0"; }

_ovpn_subnet()  { net_pool_subnet  "$VPN55_OVPN_SLOT"; }
_ovpn_gateway() { net_pool_gateway "$VPN55_OVPN_SLOT"; }

# Where things live once the unit has been resolved. confdir is the directory
# the chosen service template reads its instance config out of, which is NOT the
# same on every distribution — see _ovpn_resolve_unit.
_ovpn_server_conf() { printf '%s/%s.conf' "$(_ovpn_confdir)" "$VPN55_OVPN_INSTANCE"; }

# The per-client directory lives in OUR tree, not beside the daemon's config,
# and that is a permissions decision rather than a tidiness one. The daemon
# reads these files at connection time, after it has dropped privileges, so the
# directory has to be traversable by an unprivileged user. Putting it under the
# daemon's own config directory would mean asserting a mode on a directory the
# distribution created — and that directory is 0700 on some of them and may hold
# another administrator's server keys. Loosening it to make our files readable
# would expose theirs.
_ovpn_ccd_dir()     { printf '%s/ccd' "$VPN55_OVPN_PUB"; }
_ovpn_tls_key()     { printf '%s/tls-crypt.key' "$VPN55_OVPN_STATE"; }
_ovpn_pub_crl()     { printf '%s/crl.pem' "$VPN55_OVPN_PUB"; }
_ovpn_status_log()  { printf '%s/openvpn-status.log' "$VPN55_OVPN_LOG_DIR"; }
_ovpn_mgmt_sock()   { printf '%s/openvpn.sock' "$VPN55_OVPN_RUN_DIR"; }
_ovpn_dropin_dir()  { printf '/etc/systemd/system/%s.d' "$(_ovpn_unit)"; }
_ovpn_dropin()      { printf '%s/10-vpn55.conf' "$(_ovpn_dropin_dir)"; }

_ovpn_installed() {
    local dir
    dir="$(_ovpn_confdir)"
    [[ -n "$dir" ]] || return 1
    [[ -f "$(_ovpn_server_conf)" ]]
}

_ovpn_active() {
    local unit
    unit="$(_ovpn_unit)"
    [[ -n "$unit" ]] || return 1
    distro_service_is_active "$unit"
}

# Worst-case seconds a revoked credential could keep an established session when
# the live kill could not be confirmed. -1 means there is no bound at all, which
# is what switching renegotiation off actually means.
_ovpn_revoke_bound() {
    local secs
    secs="$(_ovpn_reneg)"
    if [[ ! "$secs" =~ ^[0-9]+$ ]] || [[ "$secs" -eq 0 ]]; then
        printf -- '-1'
    else
        printf '%s' "$secs"
    fi
}

# ─── The daemon's version, and what it gates ──────────────────────────────────
# Three directives in this file exist in one form on 2.4 and another on 2.5, and
# a fourth exists only from 2.5. Writing the newer form on an older daemon is
# not a warning — the daemon refuses to start, and the failure surfaces as a
# service that will not come up rather than as a line anyone can point at.
#
# ⚠ The exit status of `openvpn --version` is NOT 0 on every release, and the
# releases it differs on are exactly the ones this gate exists to tell apart.
# Verified against upstream: 2.4's usage_version() ends in
# openvpn_exit(OPENVPN_EXIT_STATUS_USAGE), which is 1; 2.5 and 2.6 changed it to
# OPENVPN_EXIT_STATUS_GOOD. This project runs under `set -o pipefail`, which a
# ||-guarded function body does NOT disable — so writing this as one pipeline
# makes the pipeline inherit that 1, the version reads as unknown on 2.4 alone,
# every gate below takes its oldest branch, and `_ovpn_install_packages` refuses
# to install at all on the very version it is trying to support. It would pass
# every test run on 2.5 or 2.6. The status is therefore discarded deliberately
# and the ANSWER is judged on the output instead.
_ovpn_version() {
    local raw out
    command -v openvpn >/dev/null 2>&1 || return 1
    raw="$(openvpn --version 2>/dev/null || true)"
    [[ -n "$raw" ]] || return 1
    out="$(printf '%s\n' "$raw" | awk 'NR == 1 { print $2 }')"
    [[ "$out" =~ ^[0-9]+\.[0-9]+ ]] || return 1
    printf '%s' "$out"
}

# _ovpn_version_ge <major> <minor> — true when the installed daemon is at least
# that version. Unknown answers false: assuming the newer form because the
# version could not be read is how a host with no openvpn at all gets a config
# it cannot parse.
_ovpn_version_ge() {
    local want_major="${1:-0}" want_minor="${2:-0}" v major minor
    v="$(_ovpn_version)" || return 1
    major="${v%%.*}"
    minor="${v#*.}"
    minor="${minor%%.*}"
    [[ "$major" =~ ^[0-9]+$ && "$minor" =~ ^[0-9]+$ ]] || return 1
    if [[ "$major" -gt "$want_major" ]]; then return 0; fi
    if [[ "$major" -lt "$want_major" ]]; then return 1; fi
    [[ "$minor" -ge "$want_minor" ]]
}

# ─── Availability ─────────────────────────────────────────────────────────────
# The tunnel device, not a kernel module name. /dev/net/tun is what the daemon
# actually opens, and on a container host the module can be present in the
# host's /lib/modules — so modinfo answers yes — while the device node is not
# passed through and the daemon still cannot start. Checking the node is
# checking the thing that has to work.
_ovpn_tun_usable() {
    [[ -c /dev/net/tun ]]
}

vpn_openvpn_available() {
    if ! pki_available; then
        error "Certificate operations are unavailable, and this protocol is built on them."
        return 1
    fi

    if _ovpn_tun_usable; then
        debug "tunnel device /dev/net/tun is present"
        return 0
    fi

    # Absent but loadable is a normal state on a freshly booted host: the module
    # is autoloaded when something opens the device. Reporting that as "cannot
    # run" would refuse a host that works perfectly.
    local state
    state="$(distro_module_state tun 2>/dev/null)" || state="unavailable"
    case "$state" in
        loaded|builtin|loadable)
            debug "tunnel device is absent but the module is ${state}"
            return 0 ;;
    esac

    error "This host cannot run this protocol: there is no tunnel device."
    if distro_is_container; then
        error "It is a $(distro_virt) container, and /dev/net/tun has to be passed"
        error "through by the HOST — an installer inside the container cannot create"
        error "it. Ask the provider to enable it, or use a KVM instance."
    else
        error "The tun module is not available for $(uname -r). Install the kernel"
        error "modules package for this kernel, or use a kernel that has it built in."
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
# There are no options: this adapter takes nothing but a user name. Declaring
# that emptiness is the point — it is what stops the installer prompting every
# protocol for a field only one of them has a use for.
vpn_openvpn_capabilities() {
    printf 'revoke\tcrl\t%s\n' "$(_ovpn_revoke_bound)"
    printf 'custody\tserver\t%s\n' \
        "The server generates this credential's private key, packages it into the client file, and erases it ${VPN55_OVPN_KEY_TTL_HOURS}h after issue."
    # Two independent properties, and only one is unconditional here. The
    # handshake is always hidden; whether the traffic also ARRIVES somewhere
    # unremarkable is the install-time transport choice, so the level moves.
    local _f_transport _f_port
    _f_transport="$(_ovpn_transport)"
    _f_port="$(_ovpn_port)"
    if [[ "$_f_transport" == "tcp" && "$_f_port" == "443" ]]; then
        printf 'filtering\tresistant\t%s\n' \
            "This service hides its handshake, and carries it over the same port and transport as ordinary web traffic. A filter can separate it from a website neither by shape nor by destination."
    else
        printf 'filtering\tpartial\t%s\n' \
            "This service hides its handshake, so there is no pattern in it to match. It is not on the port ordinary web traffic uses, so a filter that blocks by destination rather than by shape still reaches it. Re-installing it on the web port closes that."
    fi

    printf 'restart\tsessions-dropped\t%s\n' \
        "This daemon has no reload: restarting disconnects every client, and they reconnect on their own. It is also the only way to make a revocation take effect at once."
    return 0
}

# ─── Packages and the service unit ────────────────────────────────────────────
_ovpn_packages() {
    _distro_need_detect || return 1
    case "$VPN55_OS_FAMILY" in
        debian) printf '%s\n' openvpn ;;
        rhel)   printf '%s\n' openvpn ;;
        arch)   printf '%s\n' openvpn ;;
        *)      error "no package set known for OS family '${VPN55_OS_FAMILY}'"; return 1 ;;
    esac
}

_ovpn_install_packages() {
    local -a want=() missing=()
    mapfile -t want < <(_ovpn_packages) || return 1
    # mapfile succeeds even when the process substitution failed, so the
    # emptiness is what has to be tested. Without this the loop below is
    # skipped, nothing is installed, and the failure surfaces two calls later
    # as "openvpn is still missing" - which points at the wrong thing.
    [[ ${#want[@]} -gt 0 ]] || { error "no package set for this host"; return 1; }

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
                error "This package lives in EPEL on some releases of this distribution."
                error "Enable it and re-run:"
                error "  dnf install -y epel-release"
            fi
            return 1
        fi
    fi

    command -v openvpn >/dev/null 2>&1 \
        || { error "'openvpn' is still missing after installing packages."; return 1; }

    # tls-crypt is 2.4. Below that there is no way to hide the control-channel
    # handshake, and shipping the protocol without it would be shipping the
    # thing this adapter exists to avoid.
    if ! _ovpn_version_ge 2 4; then
        error "This host has openvpn $(_ovpn_version 2>/dev/null || printf 'of an unknown version'), and 2.4 is the minimum."
        error "Below 2.4 the control channel cannot be encrypted, so the handshake is"
        error "identifiable in the clear and the protocol can be blocked by signature."
        error "Upgrade the package, or use a distribution release that ships 2.4 or later."
        return 1
    fi
    return 0
}

# Which unit runs the daemon, and which directory it reads an instance config
# out of — resolved by looking rather than by assuming, because the two travel
# together and differ by distribution:
#
#   openvpn-server@<name>.service   reads /etc/openvpn/server/<name>.conf
#   openvpn@<name>.service          reads /etc/openvpn/<name>.conf   (older layout)
#
# The second field printed below is that directory, so _ovpn_server_conf can
# append the instance file name to it without knowing which template won.
#
# Preferring the explicit server-side template first is correct everywhere that
# has it; the legacy template is the fallback for releases that only ship one.
# Prints "<unit>\t<confdir>".
_ovpn_resolve_unit() {
    if ! distro_has_systemd; then
        error "This host is not running systemd, and this adapter manages its daemon"
        error "through a systemd unit. That is a packaging limitation of VPN55, not"
        error "of the daemon."
        return 1
    fi

    if systemctl cat 'openvpn-server@.service' >/dev/null 2>&1; then
        printf 'openvpn-server@%s.service\t/etc/openvpn/server' "$VPN55_OVPN_INSTANCE"
        return 0
    fi
    if systemctl cat 'openvpn@.service' >/dev/null 2>&1; then
        printf 'openvpn@%s.service\t/etc/openvpn' "$VPN55_OVPN_INSTANCE"
        return 0
    fi
    return 1
}

# Which unprivileged identity the daemon drops to after binding its socket.
#
# Reshaped from angristan/openvpn-install (MIT) — the three-way split it
# documents is real and each branch is a distribution that would otherwise fail:
# the RHEL family creates a dedicated user, Arch creates that user in a
# different primary group, and the Debian family creates neither and needs the
# nobody/nogroup pair. Prints "<user>\t<group>", or nothing when the service
# template already drops privileges itself and a second drop in the config would
# be an error rather than a belt-and-braces.
#
# _ovpn_resolve_service_user <resolved_unit>
#
# ⚠ It takes the RESOLVED unit and inspects only that template. A host can ship
# both templates, and checking whichever one happens to come first in a list
# answers for a unit we are not going to run: if the one we run drops privileges
# and the one we read does not, the config gets a second drop and the daemon
# refuses to start; the other way round it silently keeps running as root.
_ovpn_resolve_service_user() {
    local unit="${1:-}" template unit_file
    [[ -n "$unit" ]] || { error "_ovpn_resolve_service_user <unit>"; return 1; }

    # openvpn-server@vpn55.service -> openvpn-server@.service
    template="${unit%@*}@.service"

    for unit_file in "/usr/lib/systemd/system/${template}" \
                     "/lib/systemd/system/${template}"; do
        [[ -f "$unit_file" ]] || continue
        if grep -qE '^[[:space:]]*User=' "$unit_file" 2>/dev/null; then
            debug "${template} drops privileges itself"
            return 0
        fi
        break
    done

    if id openvpn >/dev/null 2>&1; then
        printf 'openvpn\t%s' "$(id -gn openvpn 2>/dev/null || printf 'openvpn')"
        return 0
    fi
    if grep -qs '^nogroup:' /etc/group; then
        printf 'nobody\tnogroup'
    else
        printf 'nobody\tnobody'
    fi
    return 0
}

# ─── The port has to be free, and 443 usually is not ──────────────────────────
# The transport this adapter exists for wants the port every web server on the
# planet already holds. Finding that out from a daemon that will not start is
# the wrong way round: the message is a bind failure in a journal, and the
# operator has just been told the install succeeded.
#
# Checked with `ss`, and only for a listener that is not already ours — a
# re-run of _install must not refuse because the previous run is still up.
#
# A host with no `ss` is reported as "no conflict", which is the wrong direction
# to fail in but the only one available: there is nothing to check with. `ss` is
# part of iproute2 and is present on every distribution in the matrix, so this is
# a note rather than a live risk.
_ovpn_port_conflict() {
    local proto="${1:-}" port="${2:-}" filter rows
    command -v ss >/dev/null 2>&1 || return 1

    if [[ "$proto" == "tcp" ]]; then filter="-Hlnt"; else filter="-Hlnu"; fi
    rows="$(ss "$filter" "sport = :${port}" 2>/dev/null || true)"
    [[ -n "$rows" ]] || return 1

    # `ss -p` needs root to name the process and this always runs as root, so a
    # conflict can say WHAT holds the port and WHICH pid does.
    local detail
    detail="$(ss "${filter}p" "sport = :${port}" 2>/dev/null || true)"

    # Is it ours? Compared by PID against this service's own, never by process
    # NAME. A host can legitimately run a second, unrelated daemon of the same
    # software — that is exactly why this adapter uses its own instance name —
    # and matching on the name would wave that one through, after which our
    # daemon fails to bind and the check that exists to prevent it reported
    # success.
    local ours=""
    if distro_has_systemd && [[ -n "$(_ovpn_unit)" ]]; then
        ours="$(systemctl show -p MainPID --value "$(_ovpn_unit)" 2>/dev/null || true)"
    fi
    if [[ "$ours" =~ ^[0-9]+$ ]] && [[ "$ours" -gt 0 ]]; then
        local holders
        holders="$(printf '%s\n' "$detail" | grep -oE 'pid=[0-9]+' | cut -d= -f2 | sort -u || true)"
        if str_has_line "$holders" "$ours"; then
            debug "port ${proto}/${port} is held by this service's own daemon (pid ${ours})"
            return 1
        fi
    fi

    # The process names are the only quoted strings in that output, so they are
    # taken as such. Matching the surrounding `users:((` as well looks more
    # precise and is not: it captures the opening of the list and drops every
    # name after the first, and one wrong quantifier in the trim yields an EMPTY
    # string — which reports every conflict as unidentified.
    local named
    named="$(printf '%s\n' "$detail" | grep -oE '"[^"]+"' | tr -d '"' | sort -u | paste -sd, - || true)"
    printf '%s' "${named:-an unidentified process}"
    return 0
}

# ─── SELinux ──────────────────────────────────────────────────────────────────
# On an enforcing host the daemon may only bind ports labelled openvpn_port_t.
# Its own default port is; 443 is not, and 443 already carries http_port_t.
#
# The trap inside the trap, and the reason this does not just "fix" it: a port
# carries ONE type. Relabelling 443 to openvpn_port_t would take the label away
# from every web server on the box, so an installer that did that silently would
# repair its own tunnel by breaking the operator's site. So this adds a label
# where the port is unlabelled, and where it is already claimed it explains the
# situation and leaves the decision where it belongs.
#
# The idea of labelling the port at all is from Nyr/openvpn-install (MIT); the
# refusal to relabel a port another service already owns is ours.
_ovpn_selinux_enforcing() {
    command -v getenforce >/dev/null 2>&1 || return 1
    [[ "$(getenforce 2>/dev/null || true)" == "Enforcing" ]]
}

_ovpn_selinux_port_ensure() {
    local proto="${1:-}" port="${2:-}"

    _ovpn_selinux_enforcing || return 0

    if ! command -v semanage >/dev/null 2>&1; then
        warn "SELinux is enforcing and 'semanage' is not installed, so this cannot"
        warn "check whether the daemon is allowed to bind ${proto}/${port}."
        warn "Install it with 'dnf install -y policycoreutils-python-utils' and re-run"
        warn "if the service fails to start."
        return 0
    fi

    if semanage port -l 2>/dev/null | awk -v p="$port" -v pr="$proto" \
        '$1 == "openvpn_port_t" && $2 == pr { for (i = 3; i <= NF; i++) { gsub(/,/, "", $i); if ($i == p) { found = 1 } } } END { exit !found }'; then
        debug "selinux: ${proto}/${port} already carries openvpn_port_t"
        return 0
    fi

    if semanage port -a -t openvpn_port_t -p "$proto" "$port" >/dev/null 2>&1; then
        _ovpn_set selinux_port 1 || return 1
        info "SELinux: labelled ${proto}/${port} for this daemon."
        return 0
    fi

    warn "SELinux is enforcing and ${proto}/${port} is already labelled for another"
    warn "service — a port carries one type, so this cannot be relabelled without"
    warn "taking it away from whatever owns it now."
    warn "The daemon will fail to bind. Either choose a different port, or decide"
    warn "deliberately with:"
    warn "  semanage port -m -t openvpn_port_t -p ${proto} ${port}"
    warn "which will stop the current owner of that port from binding it."
    return 0
}

_ovpn_selinux_port_remove() {
    local proto="${1:-}" port="${2:-}"
    [[ "$(_ovpn_selinux)" == "1" ]] || return 0
    command -v semanage >/dev/null 2>&1 || return 0
    semanage port -d -t openvpn_port_t -p "$proto" "$port" >/dev/null 2>&1 \
        || warn "could not remove the SELinux label from ${proto}/${port}"
    return 0
}

# ─── Settings bootstrap ───────────────────────────────────────────────────────
# Settled once, then never asked again. Precedence is: an existing stored value,
# then an environment override, then the interactive prompt, then the default.
# That order is what makes the second install silent.

# The transport is the FIRST question this adapter asks, and it is asked with
# both costs on the table, because it cannot be revisited afterwards: it is
# written into every client file ever issued, so changing it later is a reinstall
# and a reissue for every user.
_ovpn_transport_bootstrap() {
    local transport port choice

    transport="$(fs_conf_default "$VPN55_OVPN_CONF" transport "")"

    if [[ -z "$transport" ]]; then
        choice="${VPN55_OVPN_TRANSPORT:-tcp443}"
        info "Transport. This is the choice that decides whether the tunnel works on a"
        info "filtered network, and it cannot be changed later without reissuing every"
        info "client file."
        info "  tcp443  TCP on port ${VPN55_OVPN_TCP_PORT}. Indistinguishable from ordinary web traffic"
        info "          at the port level, and it survives a network that drops UDP"
        info "          outright — which is the practical reason to run this protocol"
        info "          at all. It is SLOWER, and not by a tuning margin: a TCP tunnel"
        info "          carrying TCP means two retransmission timers stacked on one"
        info "          path, so a lossy link degrades far worse than it should."
        info "  udp     UDP on port ${VPN55_OVPN_UDP_PORT}. Faster and better behaved under loss."
        info "          A network that blocks or throttles UDP blocks this outright."
        ask_value choice "Transport (tcp443/udp)" "$choice" || return 1

        case "$choice" in
            tcp443|tcp) transport="tcp"; port="$VPN55_OVPN_TCP_PORT" ;;
            udp)        transport="udp"; port="$VPN55_OVPN_UDP_PORT" ;;
            *)
                error "Transport must be 'tcp443' or 'udp'; got '${choice}'."
                return 1 ;;
        esac
    else
        # Switching transport on a live server is not an in-place change. The
        # protocol and the port are both inside every client file already handed
        # out, and those files cannot be rebuilt — their private keys were
        # erased. Refusing is the honest answer; doing it quietly would leave an
        # operator with a healthy-looking server and a user base that cannot
        # connect.
        local wanted="${VPN55_OVPN_TRANSPORT:-}"
        case "$wanted" in
            tcp443|tcp) wanted="tcp" ;;
            udp)        wanted="udp" ;;
            "")         wanted="" ;;
            *) error "Transport must be 'tcp443' or 'udp'; got '${wanted}'."; return 1 ;;
        esac
        if [[ -n "$wanted" && "$wanted" != "$transport" ]]; then
            error "This server is installed on ${transport} and VPN55_OVPN_TRANSPORT asks for ${wanted}."
            error "The transport and port are written into every client file already"
            error "issued, and those files cannot be rebuilt — their private keys were"
            error "erased after hand-off. Remove the service, install again on the other"
            error "transport, and reissue every credential."
            return 1
        fi
        port="$(fs_conf_default "$VPN55_OVPN_CONF" port "")"
    fi

    # The port override applies to either transport, and it is read on every run
    # so an operator can move off a contested port without a reinstall. Moving
    # it does NOT invalidate issued client files any more gently than the
    # transport does — so it is refused for the same reason once credentials
    # exist, and allowed freely before that.
    local wanted_port="${VPN55_OVPN_PORT:-}"
    if [[ -n "$wanted_port" && "$wanted_port" != "$port" ]]; then
        if [[ -n "$(_ovpn_cred_ids)" ]]; then
            error "VPN55_OVPN_PORT asks for ${wanted_port} and this server is on ${port}."
            error "The port is written into every client file already issued, so moving"
            error "it would break every one of them. Revoke them first, or leave it."
            return 1
        fi
        port="$wanted_port"
    fi

    if [[ ! "$port" =~ ^[0-9]+$ ]] || (( port < 1 || port > 65535 )); then
        error "Port '${port}' is not a valid port number."
        return 1
    fi

    _ovpn_set transport "$transport" || return 1
    _ovpn_set port      "$port"      || return 1
    return 0
}

_ovpn_settings_bootstrap() {
    _ovpn_state_dir || return 1

    # Transport first, and not for tidiness: the firewall rule, the port
    # conflict check, the SELinux label and both configuration files all depend
    # on it already being settled.
    _ovpn_transport_bootstrap || return 1

    local endpoint
    endpoint="$(fs_conf_default "$VPN55_OVPN_CONF" endpoint "")"
    if [[ -z "$endpoint" ]]; then
        endpoint="${VPN55_OVPN_ENDPOINT:-}"
    fi
    if [[ -z "$endpoint" ]]; then
        local detected="" rc=0
        detected="$(net_public_endpoint)" || rc=$?
        if [[ "$rc" -eq 2 ]]; then
            warn "Detected ${detected}, which is private — clients cannot dial it."
            detected=""
        fi
        ask_value endpoint "Public address or hostname clients will dial" "$detected" || return 1
    fi
    [[ -n "$endpoint" ]] || {
        error "No endpoint. Set VPN55_OVPN_ENDPOINT, or run this interactively and enter one."
        return 1
    }

    # Not a certificate identity here — design note 3 — so the rule is only what
    # is valid in a host address, which is looser than a common name.
    case "$endpoint" in
        *[![:alnum:].:_-]*)
            error "Endpoint '${endpoint}' contains characters that are not valid in a host address."
            return 1 ;;
    esac
    _ovpn_set endpoint "$endpoint" || return 1

    local reneg
    reneg="$(fs_conf_default "$VPN55_OVPN_CONF" reneg_seconds "$VPN55_OVPN_RENEG_SECONDS")"
    [[ "$reneg" =~ ^[0-9]+$ ]] || {
        error "Renegotiation interval must be a whole number of seconds; got '${reneg}'."
        return 1
    }
    _ovpn_set reneg_seconds "$reneg" || return 1

    # ── DNS ──
    # Resolved ONCE and stored, exactly as the other two adapters do it: the
    # server pushes these to every client, and re-resolving on a later re-run
    # would silently change what already-issued credentials point at.
    local dns_choice dns_custom dns
    dns_choice="$(fs_conf_default "$VPN55_OVPN_CONF" dns_choice "")"
    if [[ -z "$dns_choice" ]]; then
        dns_choice="${VPN55_OVPN_DNS_CHOICE:-system}"
        net_resolvers_explain
        ask_value dns_choice "DNS (system/cloudflare/quad9/custom)" "$dns_choice" || return 1
        if [[ "$dns_choice" == "custom" ]]; then
            ask_value dns_custom "Resolver addresses, comma-separated" "${VPN55_OVPN_DNS:-}" || return 1
        fi
        dns="$(net_resolvers_resolve "$dns_choice" "${dns_custom:-}")" || return 1
    else
        dns="$(fs_conf_default "$VPN55_OVPN_CONF" dns "")"
        if [[ -z "$dns" ]]; then
            dns="$(net_resolvers_resolve "$dns_choice" "")" || return 1
        fi
    fi
    _ovpn_set dns_choice "$dns_choice" || return 1
    _ovpn_set dns        "$dns"        || return 1

    debug "settings: transport=$(_ovpn_transport)/$(_ovpn_port) endpoint=${endpoint} dns=${dns} reneg=${reneg}s"
    return 0
}

# ─── The control-channel key ──────────────────────────────────────────────────
# tls-crypt is on unconditionally. What is decided here is only WHICH form, and
# the answer is the newer one wherever the daemon can read it.
#
# tls-crypt      one key, shared by every client. Encrypts and authenticates the
#                control channel, so there is no handshake to fingerprint and an
#                unauthenticated probe gets nothing back at all.
# tls-crypt-v2   the same, with a per-client key wrapped by a server key. Two
#                things improve: a leaked client file no longer lets anyone
#                else's control channel be decrypted, and a stolen key does not
#                hand an attacker the ability to reach the TLS handshake as
#                every other user.
#
# What tls-crypt-v2 does NOT do, and this is worth writing down because the
# feature's name invites the assumption: revoking a credential does not revoke
# its wrapped key. The daemon supports a separate blocklist for that, keyed on
# metadata this adapter does not set. It does not matter here — the wrapped key
# only buys entry to the TLS handshake, and the revocation list refuses the
# certificate at that handshake — but an operator reading "per-client key"
# should not conclude that revocation works differently than it does.
_ovpn_tls_mode_for_host() {
    if _ovpn_version_ge 2 5; then
        printf 'crypt-v2'
    else
        printf 'crypt'
    fi
}

_ovpn_tls_key_ensure() {
    local mode key
    key="$(_ovpn_tls_key)"

    mode="$(_ovpn_tls_mode)"
    if [[ -n "$mode" && -s "$key" ]]; then
        debug "control-channel key present, mode ${mode}"
        return 0
    fi

    # Where a key exists but the mode was lost, the key is the authority — the
    # two forms are not interchangeable and guessing wrong produces a daemon
    # that starts and a client that cannot connect.
    if [[ -s "$key" && -z "$mode" ]]; then
        if grep -q 'BEGIN OpenVPN tls-crypt-v2 server key' "$key" 2>/dev/null; then
            mode="crypt-v2"
        else
            mode="crypt"
        fi
        _ovpn_set tls_mode "$mode" || return 1
        return 0
    fi

    mode="$(_ovpn_tls_mode_for_host)"

    local rc=0
    if [[ "$mode" == "crypt-v2" ]]; then
        ( umask 077; openvpn --genkey tls-crypt-v2-server "$key" >/dev/null 2>&1; ) || rc=$?
    elif _ovpn_version_ge 2 5; then
        ( umask 077; openvpn --genkey secret "$key" >/dev/null 2>&1; ) || rc=$?
    else
        # 2.4 spells it as two options. 2.6 still accepts that spelling, but
        # only the older daemon needs it, so only the older daemon is given it.
        ( umask 077; openvpn --genkey --secret "$key" >/dev/null 2>&1; ) || rc=$?
    fi
    if [[ "$rc" -ne 0 ]]; then
        error "cannot generate the control-channel key"
        fs_remove "$key" || true
        return 1
    fi
    chmod 0600 "$key" || { error "cannot set mode on $key"; return 1; }

    _ovpn_set tls_mode "$mode" || return 1
    debug "control-channel key generated, mode ${mode}"
    return 0
}

# ─── The server certificate ───────────────────────────────────────────────────
# The authority is SHARED with the other certificate protocol, so it is created
# only if absent and never recreated — recreating it would invalidate everything
# that one has issued too.
_ovpn_server_cert_ensure() {
    pki_init || return 1
    pki_ca_create "VPN55 Certificate Authority" || return 1

    if [[ "$(pki_cert_state "$VPN55_OVPN_SERVER_CN")" == "valid" ]]; then
        debug "server certificate ${VPN55_OVPN_SERVER_CN} is present and valid"
        _ovpn_set server_cn "$VPN55_OVPN_SERVER_CN" || return 1
        return 0
    fi

    # Plain serverAuth, which is core_pki's default. The other certificate
    # protocol adds an extra OID because some native clients demand it; nothing
    # here does, and adding an OID nobody checks is one more thing that can be
    # wrong.
    pki_server_cert_issue "$VPN55_OVPN_SERVER_CN" >/dev/null || return 1
    _ovpn_set server_cn "$VPN55_OVPN_SERVER_CN" || return 1
    success "Server certificate issued for ${VPN55_OVPN_SERVER_CN}."
    return 0
}

# ─── Publishing the revocation list ───────────────────────────────────────────
# Design note 5. The daemon re-reads the list on every client connection, by
# which time it is no longer root, so it reads a copy from a directory it can
# actually traverse. The copy is refreshed by the core_pki hook below, which
# runs after every regeneration — so it cannot go stale the way a copy taken
# once at install would.
_ovpn_publish_crl() {
    local src dst
    src="$(pki_crl_path)"
    dst="$(_ovpn_pub_crl)"

    # A missing list is regenerated rather than reported. The authority can
    # outlive its list — another protocol's uninstall, a hand-edited PKI
    # directory — and refusing the install for something one call fixes would
    # leave an operator to run that call by hand and re-run anyway.
    if [[ ! -f "$src" ]]; then
        warn "There is no revocation list yet — regenerating it."
        pki_crl_refresh || { error "cannot generate a revocation list to publish"; return 1; }
    fi
    [[ -f "$src" ]] || { error "there is still no revocation list to publish"; return 1; }
    fs_ensure_dir "$(dirname "$VPN55_OVPN_PUB")" 0755 || return 1
    fs_ensure_dir "$VPN55_OVPN_PUB" 0755 || return 1

    # Written through a temporary file and renamed, so a connection landing
    # mid-write never reads half a list and refuses a legitimate user.
    fs_write_atomic "$dst" 0644 < "$src" \
        || { error "cannot publish the revocation list to $dst"; return 1; }
    return 0
}

# The hook core_pki runs after every regeneration. It is a standalone shell
# script because the timer that runs it has to keep working when the installer
# checkout has been moved or deleted.
#
# It does NOT restart the daemon, and that is deliberate rather than an omission:
# the list is re-read per connection, so replacing the file is the whole
# publication. Restarting would disconnect every user once a week for nothing.
_ovpn_install_hook() {
    {
        printf '#!/bin/sh\n'
        printf '# VPN55 — republish the revocation list where the tunnel daemon can read it.\n'
        printf '#\n'
        printf '# The daemon re-reads this file on every client connection, after it has\n'
        printf '# dropped privileges — so the copy lives outside the 0700 authority\n'
        printf '# directory and no restart is needed to pick a new one up.\n'
        printf 'set -eu\n'
        printf 'src="%s"\n' "$(pki_crl_path)"
        printf 'dst="%s"\n' "$(_ovpn_pub_crl)"
        printf '[ -f "$src" ] || exit 0\n'
        printf '[ -d "%s" ] || exit 0\n' "$VPN55_OVPN_PUB"
        printf 'tmp="$dst.new.$$"\n'
        printf 'cat "$src" > "$tmp" || { rm -f "$tmp"; echo "vpn55: could not stage $dst" >&2; exit 1; }\n'
        printf 'chmod 0644 "$tmp" || { rm -f "$tmp"; exit 1; }\n'
        printf 'mv -f "$tmp" "$dst" || { rm -f "$tmp"; echo "vpn55: could not replace $dst" >&2; exit 1; }\n'
        printf 'exit 0\n'
    } | pki_hook_install "$VPN55_OVPN_HOOK" || return 1
    return 0
}

# ─── The daemon's configuration ───────────────────────────────────────────────
# There is deliberately no generated-on timestamp anywhere in this file. A date
# line would make the second install produce different bytes, and "install three
# times, nothing changes after the first" would be false in exactly the way that
# is hardest to notice — and here it would also mean a restart, which
# disconnects every user.
_ovpn_render_conf() {
    local transport port subnet dns endpoint reneg tls_mode svc_user svc_group
    transport="$(_ovpn_transport)"
    port="$(_ovpn_port)"
    dns="$(_ovpn_dns)"
    endpoint="$(_ovpn_endpoint)"
    reneg="$(_ovpn_reneg)"
    tls_mode="$(_ovpn_tls_mode)"
    svc_user="$(_ovpn_svc_user)"
    svc_group="$(_ovpn_svc_group)"
    subnet="$(_ovpn_subnet)" || return 1

    [[ -n "$transport" && -n "$port" ]] || { error "no transport recorded"; return 1; }
    [[ -n "$tls_mode" ]] || { error "no control-channel key recorded"; return 1; }

    local ccd
    ccd="$(_ovpn_ccd_dir)"

    cat <<CONF
# VPN55 — managed tunnel responder. Written by lib/proto_openvpn.sh; edits are lost.
#
# There is no per-user block in this file. A road-warrior responder accepts every
# client certificate this authority signed, so a credential leaves no trace in
# the daemon's own configuration — the per-credential index lives in
# ${VPN55_OVPN_CREDS} and identity lives in the registry, not here.
#
# There are no firewall rules in this file either. The open port, the forward
# path and the NAT rule are applied through VPN55's firewall ledger under the
# tag '${VPN55_OVPN_TAG}', so an uninstall reverses exactly what was added.

port ${port}
proto ${transport}
dev tun
topology subnet
CONF

    # The mask is written literally rather than derived because core_net's
    # allocator partitions one /16 into /24s by construction — the slot table in
    # CLAUDE.md § Networking is the only place that is written down. If the
    # allocator ever hands out a different prefix, this line changes with it.
    printf 'server %s 255.255.255.0\n' "${subnet%%/*}"

    if [[ -n "$svc_user" && -n "$svc_group" ]]; then
        printf 'user %s\n'  "$svc_user"
        printf 'group %s\n' "$svc_group"
    fi

    cat <<'CONF'
persist-key
persist-tun
keepalive 10 120
CONF

    # Addresses are pinned per credential through the per-client directory below,
    # and ccd-exclusive turns "the daemon never allocates dynamically" from an
    # argument into a rule: a certificate with no entry in that directory is
    # refused rather than handed a lease out of a range the allocator does not
    # know about.
    printf 'client-config-dir %s\n' "$ccd"
    printf 'ccd-exclusive\n'

    # The authority, the certificate and the key are read once at start-up while
    # this is still root, so they are referenced where they live. The revocation
    # list is not — see design note 5.
    printf 'ca %s\n'          "$(pki_ca_path)"
    printf 'cert %s\n'        "$(pki_cert_path "$VPN55_OVPN_SERVER_CN")"
    printf 'key %s\n'         "$(pki_key_path  "$VPN55_OVPN_SERVER_CN")"
    printf 'crl-verify %s\n'  "$(_ovpn_pub_crl)"

    # Ephemeral Diffie-Hellman over a named curve, so there is no parameter file
    # to generate and none to keep. 'dh none' is 2.4; naming the groups is 2.5.
    printf 'dh none\n'
    if _ovpn_version_ge 2 5; then
        printf 'tls-groups %s\n' "$VPN55_OVPN_TLS_GROUPS"
    fi

    printf 'tls-server\n'
    printf 'tls-version-min %s\n' "$VPN55_OVPN_TLS_MIN"
    printf 'remote-cert-tls client\n'
    printf 'auth %s\n' "$VPN55_OVPN_AUTH_DIGEST"

    # The negotiated-cipher directive was renamed at 2.5 and the old name is not
    # understood by the new daemon in the same way. Both are written under the
    # name the running daemon actually reads.
    if _ovpn_version_ge 2 5; then
        printf 'data-ciphers %s\n' "$VPN55_OVPN_DATA_CIPHERS"
    else
        printf 'ncp-ciphers %s\n' "$VPN55_OVPN_DATA_CIPHERS"
    fi
    printf 'cipher %s\n' "${VPN55_OVPN_DATA_CIPHERS%%:*}"

    printf 'reneg-sec %s\n' "$reneg"

    case "$tls_mode" in
        crypt-v2) printf 'tls-crypt-v2 %s\n' "$(_ovpn_tls_key)" ;;
        *)        printf 'tls-crypt %s\n'    "$(_ovpn_tls_key)" ;;
    esac

    # Full tunnel. bypass-dhcp keeps the client's own DHCP server reachable,
    # without which a client on a home network loses its lease renewal.
    printf 'push "redirect-gateway def1 bypass-dhcp"\n'

    local resolver
    while IFS= read -r resolver; do
        [[ -n "$resolver" ]] || continue
        printf 'push "dhcp-option DNS %s"\n' "$resolver"
    done < <(printf '%s\n' "${dns//,/$'\n'}")

    # Windows resolves through every interface at once unless told not to, so a
    # query can leave over the local link while the tunnel is up. The client
    # ignores the directive where it means nothing.
    printf 'push "block-outside-dns"\n'

    # Design note 6. Without this a dual-stack client keeps its native IPv6 path
    # and the tunnel silently carries only half its traffic.
    if _ovpn_version_ge 2 5; then
        printf 'push "block-ipv6"\n'
    fi

    # One credential is one device: a second connection presenting the same
    # certificate replaces the first rather than running beside it, which is what
    # makes a per-user device limit enforceable later. That is the default, and
    # it is written down rather than relied on.
    printf '# duplicate-cn is deliberately NOT set — one credential, one device.\n'
    printf '# client-to-client is deliberately NOT set — tunnel clients cannot reach\n'
    printf '# each other, only the network beyond the exit.\n'

    # ⚠ The packaged unit ALREADY passes --status and --status-version on the
    # command line, before --config. These two lines override them, and that is
    # load-bearing: the daemon expands --config in place and a later occurrence
    # of either option replaces the earlier one, so ours win because they are
    # read second. If that ever stopped being true, the daemon would write its
    # figures to the unit's runtime path instead and every credential would read
    # as "-" — which _ovpn_status_records handles by looking there too, and
    # _ovpn_notes reports rather than hiding.
    printf 'status %s %s\n' "$(_ovpn_status_log)" "$VPN55_OVPN_STATUS_INTERVAL"
    printf 'status-version 2\n'
    printf 'management %s unix\n' "$(_ovpn_mgmt_sock)"
    printf 'verb 3\n'

    # Only valid on the connectionless transport; the daemon refuses to start
    # with it on the other one.
    if [[ "$transport" == "udp" ]]; then
        printf 'explicit-exit-notify 1\n'
    fi
    return 0
}

# ─── The unit drop-in ─────────────────────────────────────────────────────────
# A drop-in rather than an edit to the packaged unit, because a package upgrade
# rewrites the packaged unit and would take the change with it — silently, and
# the symptom would be a tunnel that stops accepting clients some weeks later.
#
# LimitNPROC is the one that bites. The packaged unit caps the daemon at a
# handful of processes, which is fine until it is not; both upstream installers
# raise it, and the failure without it is a daemon that refuses new connections
# under load with nothing useful in the journal.
_ovpn_write_dropin() {
    local dir body
    dir="$(_ovpn_dropin_dir)"
    fs_ensure_dir "$dir" 0755 || return 1

    body="$(printf '%s\n' \
        "# Written by VPN55 (lib/proto_openvpn.sh). Removed when the service is removed." \
        "#" \
        "# The packaged unit caps the process count low enough to refuse connections" \
        "# under load, and creates no runtime directory for a management socket." \
        "[Service]" \
        "LimitNPROC=infinity" \
        "RuntimeDirectory=${VPN55_OVPN_RUN_DIR##*/}" \
        "RuntimeDirectoryMode=0700")" || { error "cannot render the unit drop-in"; return 1; }

    fs_write_if_changed "$(_ovpn_dropin)" 0644 "$body" \
        || { error "cannot write the unit drop-in"; return 1; }
    return 0
}

_ovpn_log_dir_ensure() {
    local user group log
    fs_ensure_dir "$VPN55_OVPN_LOG_DIR" 0750 || return 1
    user="$(_ovpn_svc_user)"; group="$(_ovpn_svc_group)"
    [[ -n "$user" && -n "$group" ]] || return 0

    # The daemon opens the status file at start-up while it is still root, but
    # re-opens it on an internal restart — a ping-restart, or a SIGUSR1 — by
    # which time it is the unprivileged user. Both the directory AND the file
    # have to be handed over: a root-owned file in a directory the daemon owns
    # is still a file it cannot reopen for writing, and the failure is one line
    # in a journal followed by every credential reading as "-" forever.
    log="$(_ovpn_status_log)"
    chown "${user}:${group}" "$VPN55_OVPN_LOG_DIR" 2>/dev/null \
        || warn "could not hand ${VPN55_OVPN_LOG_DIR} to ${user}:${group}"
    if [[ -f "$log" ]]; then
        chown "${user}:${group}" "$log" 2>/dev/null \
            || warn "could not hand ${log} to ${user}:${group}"
    fi
    return 0
}

# ─── Install ──────────────────────────────────────────────────────────────────
vpn_openvpn_install() {
    distro_require_root || return 1
    vpn_openvpn_available || return 1

    section "OpenVPN"

    _ovpn_settings_bootstrap || return 1
    _ovpn_install_packages   || return 1

    local unit confdir line
    line="$(_ovpn_resolve_unit)" || {
        error "The daemon is installed but no service template was found."
        error "Looked for openvpn-server@.service and openvpn@.service. This host"
        error "may package the daemon without a systemd unit, which this adapter"
        error "does not support."
        return 1
    }
    unit="${line%%$'\t'*}"
    confdir="${line#*$'\t'}"
    _ovpn_set unit    "$unit"    || return 1
    _ovpn_set confdir "$confdir" || return 1

    local svc_line svc_user="" svc_group=""
    svc_line="$(_ovpn_resolve_service_user "$unit")" || svc_line=""
    if [[ -n "$svc_line" ]]; then
        svc_user="${svc_line%%$'\t'*}"
        svc_group="${svc_line#*$'\t'}"
    fi
    _ovpn_set svc_user  "$svc_user"  || return 1
    _ovpn_set svc_group "$svc_group" || return 1

    local transport port
    transport="$(_ovpn_transport)"
    port="$(_ovpn_port)"

    # Before anything is written. A port conflict discovered after the config is
    # in place is a config in place for a daemon that cannot start.
    local holder
    if holder="$(_ovpn_port_conflict "$transport" "$port")"; then
        error "${transport}/${port} is already in use on this host, by ${holder}."
        if [[ "$port" == "443" ]]; then
            error "Port 443 is the one every web server holds, and that is the cost of"
            error "the transport that gets through filtered networks — the two cannot"
            error "share it."
            error "Either move the web server, or set VPN55_OVPN_PORT to a free port and"
            error "re-run. Note that VPN55's own admin panel does NOT need this port:"
            error "it binds to a tunnel address and takes its certificate over DNS."
        else
            error "Set VPN55_OVPN_PORT to a free port and re-run."
        fi
        error "Nothing was installed or changed."
        return 1
    fi

    # Claim before anything is written. Idempotent for the same owner and slot,
    # a hard error on any conflict — which is what stops a second adapter
    # quietly handing out addresses in this /24.
    net_pool_claim "$VPN55_OVPN_TAG" "$VPN55_OVPN_SLOT" || return 1
    net_forwarding_enable || return 1

    _ovpn_server_cert_ensure || return 1
    _ovpn_tls_key_ensure     || return 1
    _ovpn_publish_crl        || return 1
    _ovpn_log_dir_ensure     || return 1

    # Created only when absent, and NOT chmod'd when it is already there. The
    # distribution owns this directory: it is 0700 on some of them and may hold
    # another administrator's server keys, so asserting a mode on it — which is
    # what fs_ensure_dir does — would loosen someone else's permissions as a
    # side effect of installing this.
    if [[ ! -d "$confdir" ]]; then
        mkdir -p "$confdir" || { error "cannot create $confdir"; return 1; }
        chmod 0755 "$confdir" || { error "cannot set mode on $confdir"; return 1; }
    fi
    fs_ensure_dir "$(_ovpn_ccd_dir)" 0755 || return 1

    _ovpn_selinux_port_ensure "$transport" "$port" || return 1

    # Rendered into a variable first, for two reasons. fs_write_if_changed must
    # not sit on the right of a pipe or the "did it change" answer is lost in a
    # subshell and the daemon is never restarted. And a renderer that fails
    # PARTWAY — after emitting some of the file — would have had its partial
    # output written by the pipe form before anyone noticed; capturing it means
    # the failure is caught while the old config is still in place.
    local changed=0 rendered
    rendered="$(_ovpn_render_conf)" || return 1
    fs_write_if_changed "$(_ovpn_server_conf)" 0640 "$rendered" \
        || { error "cannot write $(_ovpn_server_conf)"; return 1; }
    if [[ "$VPN55_FS_CHANGED" == "1" ]]; then changed=1; fi

    _ovpn_write_dropin || return 1
    if [[ "$VPN55_FS_CHANGED" == "1" ]]; then
        changed=1
        distro_daemon_reload || return 1
    fi

    local subnet
    subnet="$(_ovpn_subnet)" || return 1

    net_fw_open_port    "$VPN55_OVPN_TAG" "$transport" "$port" || return 1
    net_fw_allow_subnet "$VPN55_OVPN_TAG" "$subnet" || return 1
    net_fw_masquerade   "$VPN55_OVPN_TAG" "$subnet" || return 1

    _ovpn_install_hook || warn "could not install the revocation-list publishing hook"
    pki_crl_timer_install || warn "the revocation list will not refresh on a schedule"

    # There is no reload for this daemon — a configuration change means a
    # restart, and a restart disconnects everyone. So it only happens when the
    # bytes actually changed, which is what makes a second install run inert
    # rather than merely idempotent-looking.
    if ! distro_service_is_enabled "$unit"; then
        distro_service_enable "$unit" || return 1
    elif ! _ovpn_active; then
        distro_service_start "$unit" || return 1
    elif [[ "$changed" == "1" ]]; then
        warn "The configuration changed, so the service is being restarted — every"
        warn "connected client is disconnected and will reconnect on its own."
        distro_service_restart "$unit" || return 1
    fi

    _ovpn_spool_sweep || true

    success "OpenVPN is up on ${subnet} — ${transport}/${port}, endpoint $(_ovpn_endpoint)."
    info "Control channel: tls-$(_ovpn_tls_mode) (always on). Client key custody: server-generated."
    info "DNS: $(_ovpn_dns)."
    if [[ "$transport" == "tcp" ]]; then
        info "This is the transport that survives a network dropping UDP. It is also"
        info "the slower one, and noticeably so on a lossy link."
    else
        warn "This transport is blocked outright by a network that drops UDP. If your"
        warn "users are on a filtered network, the TCP mode is the one that gets"
        warn "through — switching means a reinstall and reissuing every credential."
    fi
    local reneg
    reneg="$(_ovpn_reneg)"
    if [[ "$reneg" == "0" ]]; then
        warn "Renegotiation is off. A revoked credential whose live session could not"
        warn "be ended would keep its tunnel indefinitely."
    fi
    return 0
}

# ─── Uninstall ────────────────────────────────────────────────────────────────
vpn_openvpn_uninstall() {
    distro_require_root || return 1

    local unit confdir transport port
    unit="$(_ovpn_unit)"
    confdir="$(_ovpn_confdir)"
    transport="$(_ovpn_transport)"
    port="$(_ovpn_port)"

    section "Removing OpenVPN"

    # Registry first, while the credential index is still readable. A credential
    # left marked active for a protocol that no longer exists is the "user exists
    # in two protocols and no longer in the third" failure arriving by the back
    # door.
    local cred user row
    while IFS= read -r cred; do
        [[ -n "$cred" ]] || continue
        if row="$(users_cred_find "$cred" 2>/dev/null)"; then
            user="${row%%$'\t'*}"
            users_cred_revoke "$user" "$cred" >/dev/null 2>&1 \
                || warn "could not mark credential '${cred}' revoked for '${user}'"
        fi
        pki_cert_revoke "$cred" >/dev/null 2>&1 || true
        net_pool_free "$VPN55_OVPN_TAG" "$cred" || warn "could not release the lease for '${cred}'"
        _ovpn_spool_clear "$cred" || true
    done < <(_ovpn_cred_ids)

    if [[ -n "$unit" ]]; then
        distro_service_disable "$unit" || warn "could not disable ${unit}"
    fi

    if [[ -n "$confdir" ]]; then
        fs_remove "$(_ovpn_server_conf)" || return 1
    fi
    # Not inside that `if`: the per-client directory is in VPN55's own tree, so
    # it has to go even on a host where the daemon's config directory was never
    # recorded. Left behind, it is the one piece of removed state a re-install
    # would silently inherit.
    fs_remove_tree "$(_ovpn_ccd_dir)" || return 1

    local dropin dropin_dir
    dropin="$(_ovpn_dropin)"; dropin_dir="$(_ovpn_dropin_dir)"
    if [[ -f "$dropin" ]]; then
        fs_remove "$dropin" || return 1
        fs_rmdir_if_empty "$dropin_dir"
        distro_daemon_reload || true
    fi

    net_fw_revoke_tag "$VPN55_OVPN_TAG" || warn "some firewall rules could not be removed — check ${VPN55_FW_STATE}"
    net_pool_release  "$VPN55_OVPN_TAG" || warn "could not release the pool claim"

    if [[ -n "$transport" && -n "$port" ]]; then
        _ovpn_selinux_port_remove "$transport" "$port" || true
    fi

    pki_hook_remove "$VPN55_OVPN_HOOK" || true

    fs_remove "$(_ovpn_pub_crl)" || true
    fs_rmdir_if_empty "$VPN55_OVPN_PUB"
    fs_rmdir_if_empty "$(dirname "$VPN55_OVPN_PUB")"

    fs_remove "$(_ovpn_status_log)" || true
    fs_rmdir_if_empty "$VPN55_OVPN_LOG_DIR"

    # The certificate authority is SHARED with the other certificate protocol
    # and is deliberately left in place. Removing it here would invalidate every
    # credential that one has issued. The refresh timer goes only when nothing
    # is registered against the authority any more.
    if ! pki_in_use; then
        pki_crl_timer_remove || warn "could not remove the revocation-list timer"
        info "No certificate protocol is left. The certificate authority is still"
        info "in ${VPN55_PKI} — remove it from the uninstall screen if you want it gone."
    else
        info "The certificate authority is shared and stays — another protocol uses it."
    fi

    fs_shred "$(_ovpn_tls_key)" || true
    fs_shred_glob "$VPN55_OVPN_SPOOL" '*' || true
    fs_remove_tree "$VPN55_OVPN_STATE" || return 1

    local remaining
    remaining="$(net_pool_claims 2>/dev/null || true)"
    if [[ -z "$remaining" ]]; then
        net_forwarding_disable || warn "could not remove the forwarding sysctl file"
    else
        info "IP forwarding left on — another tunnel service still holds a pool slot."
    fi

    if [[ "$VPN55_OVPN_PURGE_PACKAGES" == "1" ]]; then
        local -a pkgs=()
        mapfile -t pkgs < <(_ovpn_packages) || pkgs=()
        if [[ ${#pkgs[@]} -gt 0 ]]; then
            distro_pkg_remove "${pkgs[@]}" || warn "package removal failed — remove them by hand if you want them gone"
        fi
    else
        info "Packages left installed. Set VPN55_OVPN_PURGE_PACKAGES=1 to remove them too."
    fi

    success "OpenVPN removed — NAT, forward and port rules revoked from the ledger."
    return 0
}

# ─── The credential index ─────────────────────────────────────────────────────
# One file per credential, key=value, mode 0600. This exists for the same reason
# the other certificate protocol has one: the daemon's config holds no per-user
# entry to read a list out of.
_ovpn_cred_file() { printf '%s/%s' "$VPN55_OVPN_CREDS" "${1:-}"; }

_ovpn_cred_exists() {
    local cred="${1:-}"
    [[ -n "$cred" ]] || return 1
    [[ -f "$(_ovpn_cred_file "$cred")" ]]
}

_ovpn_cred_get() {
    local cred="${1:-}" key="${2:-}"
    fs_conf_default "$(_ovpn_cred_file "$cred")" "$key" ""
}

_ovpn_cred_ids() {
    [[ -d "$VPN55_OVPN_CREDS" ]] || return 0
    local f
    for f in "$VPN55_OVPN_CREDS"/*; do
        [[ -f "$f" ]] || continue
        printf '%s\n' "${f##*/}"
    done
    return 0
}

# Ids are opaque and carry no user name: this one becomes a certificate common
# name, a per-client file name the daemon reads, a line in the status file and a
# line in every log the panel writes — and a name in any of those is a name that
# outlives the account.
_ovpn_new_cred_id() {
    local raw
    raw="$(fs_random_hex 6)" || return 1
    printf 'ovpn-%s' "$raw"
}

# ─── The per-client directory ─────────────────────────────────────────────────
# One file per credential, named for the certificate common name the client
# presents, pinning its address. With ccd-exclusive set in the server config a
# certificate with no file here cannot connect at all, which is what makes the
# allocator the only source of addresses on this protocol.
_ovpn_ccd_file() { printf '%s/%s' "$(_ovpn_ccd_dir)" "${1:-}"; }

_ovpn_ccd_write() {
    local cred="${1:-}" ip="${2:-}" body
    [[ -n "$cred" && -n "$ip" ]] || { error "_ovpn_ccd_write <cred> <ip>"; return 1; }

    fs_ensure_dir "$(_ovpn_ccd_dir)" 0755 || return 1
    body="$(printf '%s\n' \
        "# VPN55 — pinned address for ${cred}. Written by lib/proto_openvpn.sh." \
        "ifconfig-push ${ip} 255.255.255.0")" || return 1

    # 0644, not 0600: the daemon reads this directory after it has dropped
    # privileges, exactly as it does the revocation list. Nothing in here is
    # secret — it is one address.
    fs_write_if_changed "$(_ovpn_ccd_file "$cred")" 0644 "$body" \
        || { error "cannot write the per-client entry for '${cred}'"; return 1; }
    return 0
}

_ovpn_ccd_remove() {
    local cred="${1:-}"
    [[ -n "$cred" ]] || return 0
    fs_remove "$(_ovpn_ccd_file "$cred")" || return 1
    return 0
}

# ─── The artifact spool ───────────────────────────────────────────────────────
# The emitted client file, complete with its private key, kept only until the
# TTL expires. Held as text, so one sweep and one set of permissions covers it
# and it survives a caller reading it through command substitution.
_ovpn_spool_path() { printf '%s/%s.%s' "$VPN55_OVPN_SPOOL" "${1:-}" "${2:-}"; }

_ovpn_spool_held() {
    local cred="${1:-}"
    [[ -n "$cred" ]] || return 1
    [[ -s "$(_ovpn_spool_path "$cred" ovpn)" ]]
}

_ovpn_spool_clear() {
    local cred="${1:-}" ext
    [[ -n "$cred" ]] || return 0
    # 'wk' is the per-client wrapped control-channel key. _ovpn_build_profile
    # shreds it on every path of its own, but a process killed between the
    # mint and the shred leaves one behind, and it is key material.
    for ext in ovpn meta wk; do
        fs_shred "$(_ovpn_spool_path "$cred" "$ext")" || true
    done
    return 0
}

# Swept on every read path rather than by a timer. A timer is another unit to
# install and another thing to fail silently; the sweep costs one find.
_ovpn_spool_sweep() {
    [[ -d "$VPN55_OVPN_SPOOL" ]] || return 0
    local ttl="$VPN55_OVPN_KEY_TTL_HOURS"
    [[ "$ttl" =~ ^[0-9]+$ ]] || ttl=24

    if [[ "$ttl" -eq 0 ]]; then
        fs_shred_glob "$VPN55_OVPN_SPOOL" '*' || true
        return 0
    fi

    local f
    while IFS= read -r f; do
        [[ -n "$f" ]] || continue
        debug "spool: shredding expired ${f##*/}"
        fs_shred "$f" || true
    done < <(find "$VPN55_OVPN_SPOOL" -maxdepth 1 -type f -mmin "+$(( ttl * 60 ))" 2>/dev/null || true)
    return 0
}

# ─── Credentials ──────────────────────────────────────────────────────────────
# vpn_openvpn_cred_add <user> [key=value …]
#
# This adapter declares no options in _capabilities, so any key=value pair is a
# caller mistake rather than something to ignore quietly — ignoring it would
# mean a panel silently dropping a field an operator filled in.
#
# Prints the credential id on stdout and nothing else. The artifacts go to the
# spool; the caller reads them back through _artifacts and _client_config, which
# is the same path the panel and the portal use.
vpn_openvpn_cred_add() {
    local user="${1:-}"
    shift || true

    _ovpn_installed || { error "This protocol is not installed on this host."; return 1; }
    [[ -n "$user" ]] || { error "vpn_openvpn_cred_add <user>"; return 1; }
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

    _ovpn_state_dir || return 1

    local cred=""
    local _try
    for _try in 1 2 3 4 5; do
        cred="$(_ovpn_new_cred_id)" || return 1
        if _ovpn_cred_exists "$cred"; then
            cred=""
            continue
        fi
        users_cred_add "$user" "$cred" "$VPN55_OVPN_TAG" >/dev/null 2>&1 && break
        cred=""
    done
    [[ -n "$cred" ]] || { error "could not register a unique credential id after five tries."; return 1; }

    local ip
    if ! ip="$(net_pool_alloc "$VPN55_OVPN_TAG" "$cred")"; then
        users_cred_revoke "$user" "$cred" >/dev/null 2>&1 || true
        error "No address left in $(_ovpn_subnet)."
        return 1
    fi

    # ── Order matters, and it is the opposite of the obvious one ────────────
    # Every cheap, reversible record goes down BEFORE the certificate, because
    # the two failure modes are not symmetrical:
    #
    #   index entry, no certificate  — visible, harmless, removable. It lists in
    #                                  _cred_list, holds no artifacts, and
    #                                  _cred_remove cleans it up.
    #   certificate, no index entry  — INVISIBLE and permanent. Nothing on this
    #                                  host knows the credential exists, so
    #                                  nothing will ever revoke it, and it
    #                                  authenticates until the authority expires.
    #
    # The per-client entry is in the same group and for a second reason: with
    # ccd-exclusive set, a certificate with no entry cannot connect — so writing
    # it first means the worst case is a credential that is refused, never one
    # that connects with an address the allocator has not leased.
    {
        printf 'user=%s\n'    "$user"
        printf 'address=%s\n' "$ip"
        printf 'created=%s\n' "$(fs_now)"
        printf 'custody=server\n'
    } | fs_write_atomic "$(_ovpn_cred_file "$cred")" 0600 \
        || {
            error "cannot record the credential index entry"
            net_pool_free "$VPN55_OVPN_TAG" "$cred" || true
            users_cred_revoke "$user" "$cred" >/dev/null 2>&1 || true
            return 1
        }

    if ! _ovpn_ccd_write "$cred" "$ip"; then
        fs_remove "$(_ovpn_cred_file "$cred")" || true
        net_pool_free "$VPN55_OVPN_TAG" "$cred" || true
        users_cred_revoke "$user" "$cred" >/dev/null 2>&1 || true
        return 1
    fi

    if ! pki_client_cert_issue "$cred" >/dev/null; then
        _ovpn_ccd_remove "$cred" || true
        fs_remove "$(_ovpn_cred_file "$cred")" || true
        net_pool_free "$VPN55_OVPN_TAG" "$cred" || true
        users_cred_revoke "$user" "$cred" >/dev/null 2>&1 || true
        error "Could not issue a certificate for '${cred}'."
        return 1
    fi

    if ! _ovpn_build_artifacts "$cred" "$user" "$ip"; then
        error "The certificate was issued but the client file could not be built."
        error "Revoke '${cred}' and issue another rather than handing out a partial one."
        return 1
    fi

    # The private key has done its job — it is inside the client file now.
    # Keeping it would mean the authority directory accumulated one plaintext
    # client key per user, which is exactly what docs/security-model.md §2 says
    # this project does not do.
    pki_client_key_discard "$cred" || warn "could not erase the client private key for '${cred}'"

    _ovpn_spool_sweep || true

    printf '%s' "$cred"
    return 0
}

# ─── The management interface ─────────────────────────────────────────────────
# Used for exactly one thing: ending a revoked credential's live session, so
# _cred_remove can report what it actually achieved instead of the worst case.
#
# Bash cannot open a unix socket, so this borrows whichever tool the host has.
# None of them is a dependency: where there is no way to reach the socket, the
# revocation still happens and is simply reported as delayed, which is true.
# Every call is bounded — a wedged daemon leaves the read blocking forever, and
# this sits on the panel's write path.
_ovpn_mgmt_cmd() {
    local cmd="${1:-}" sock payload
    sock="$(_ovpn_mgmt_sock)"
    [[ -S "$sock" ]] || return 1
    [[ -n "$cmd" ]] || return 1

    payload="$(printf '%s\nquit\n' "$cmd")"

    local -a run=()
    if command -v timeout >/dev/null 2>&1; then
        run=(timeout 5)
    fi

    # ⚠ Every branch below discards the PIPELINE's status and judges the answer
    # on the output instead. Under `set -o pipefail` — which a ||-guarded body
    # does not disable — a `printf | tool` whose reader closes first makes the
    # printf die on SIGPIPE and 141 becomes the pipeline's status, so a kill
    # that actually worked would be reported as a failure and the revocation
    # would be downgraded to "delayed". The interface always greets a caller
    # with its version banner, so non-empty output is the honest test of
    # "did this reach the daemon".
    local out=""
    if command -v socat >/dev/null 2>&1; then
        out="$(printf '%s' "$payload" | "${run[@]}" socat - "UNIX-CONNECT:${sock}" 2>/dev/null || true)"
    elif command -v nc >/dev/null 2>&1 && str_contains "$(nc -h 2>&1 || true)" '-U'; then
        # Only the OpenBSD netcat has -U. Probing for the flag rather than for a
        # version string is what keeps this from picking the traditional one and
        # writing the command into a file named for the socket.
        #
        # The probe is NOT `nc -h | grep -q -- '-U'`: grep exits on its first
        # match, nc dies of SIGPIPE, pipefail makes 141 the answer, and the test
        # says "no -U" precisely when the flag IS there. That is the same trap
        # recorded in ui.sh, which is why str_contains exists.
        out="$(printf '%s' "$payload" | "${run[@]}" nc -U "$sock" 2>/dev/null || true)"
    elif command -v python3 >/dev/null 2>&1; then
        out="$(printf '%s' "$payload" | "${run[@]}" python3 -c '
import socket, sys
s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
s.settimeout(4)
s.connect(sys.argv[1])
s.sendall(sys.stdin.buffer.read())
out = b""
try:
    while True:
        chunk = s.recv(4096)
        if not chunk:
            break
        out += chunk
except Exception:
    pass
sys.stdout.buffer.write(out)
' "$sock" 2>/dev/null || true)"
    else
        return 1
    fi

    [[ -n "$out" ]] || return 1
    printf '%s' "$out"
    return 0
}

# True when the credential is no longer holding a session — either because it
# was killed, or because it was not connected in the first place. Those are the
# same outcome and treating them differently would report a revocation as
# delayed on the common path where nobody was connected at all.
_ovpn_kill_session() {
    local cred="${1:-}" out
    out="$(_ovpn_mgmt_cmd "kill ${cred}")" || return 1
    case "$out" in
        *SUCCESS*)               return 0 ;;
        *"common name"*"not found"*) return 0 ;;
        *) return 1 ;;
    esac
}

# ─── Revocation ───────────────────────────────────────────────────────────────
# vpn_openvpn_cred_remove <cred_id>
#
# Prints, on stdout, one record in the shape every adapter uses:
#
#   revoked  <tag>  <cred_id>  <latency>  <seconds>
#
# latency is a closed vocabulary — `immediate` when access is gone with no
# window, `crl` when an established session survives until it renegotiates.
# seconds is the worst case, or -1 when there is no bound at all.
#
# Which one this returns is MEASURED, not assumed. The common path really is
# immediate, and reporting it as delayed would train an operator to ignore the
# warning on the day it is true.
vpn_openvpn_cred_remove() {
    local cred="${1:-}"
    [[ -n "$cred" ]] || { error "vpn_openvpn_cred_remove <cred_id>"; return 1; }
    _ovpn_installed || { error "This protocol is not installed on this host."; return 1; }
    _ovpn_cred_exists "$cred" || { error "No credential '${cred}' on this server."; return 1; }

    pki_cert_revoke "$cred" || { error "could not revoke the certificate for '${cred}'"; return 1; }

    # pki_cert_revoke regenerates the list and fires the publishing hook, so the
    # copy the daemon reads should already be current. It is re-published here
    # anyway rather than assumed: the hook is best-effort by design, and a
    # revocation the daemon cannot see is not a revocation.
    local published=1
    _ovpn_publish_crl || {
        published=0
        warn "The certificate is revoked but the list the daemon reads could not be"
        warn "updated. Until it is, that credential can still connect."
    }

    # The per-client entry goes too. With ccd-exclusive set this is a second,
    # independent refusal that does not depend on the revocation list being
    # readable — belt and braces, and it costs one file.
    _ovpn_ccd_remove "$cred" || warn "could not remove the per-client entry for '${cred}'"

    local ended=1
    if _ovpn_active; then
        if ! _ovpn_kill_session "$cred"; then
            ended=0
        fi
    fi
    # A stopped daemon holds no sessions, so there is nothing to end — that is
    # not a failure and must not be reported as one.

    fs_remove "$(_ovpn_cred_file "$cred")" || warn "could not remove the index entry for '${cred}'"
    _ovpn_spool_clear "$cred" || true
    net_pool_free "$VPN55_OVPN_TAG" "$cred" || warn "could not release the address lease"

    local row user
    if row="$(users_cred_find "$cred" 2>/dev/null)"; then
        user="${row%%$'\t'*}"
        users_cred_revoke "$user" "$cred" >/dev/null 2>&1 \
            || warn "the certificate is revoked but the registry still shows '${cred}' active"
    fi

    if [[ "$published" == "1" && "$ended" == "1" ]]; then
        printf 'revoked\t%s\t%s\timmediate\t0\n' "$VPN55_OVPN_TAG" "$cred"
        success "Credential '${cred}' revoked — the certificate is on the revocation"
        success "list and no session is left holding it."
    else
        local bound
        bound="$(_ovpn_revoke_bound)"
        printf 'revoked\t%s\t%s\tcrl\t%s\n' "$VPN55_OVPN_TAG" "$cred" "$bound"
        warn "Credential '${cred}' is revoked, but the live session could not be ended."
        if [[ "$bound" == "-1" ]]; then
            warn "Renegotiation is switched off on this server, so there is NO guaranteed"
            warn "limit on how long an existing tunnel can continue."
            warn "Restart the service to end every session at once."
        else
            # Rendered in whichever unit does not round to zero. Integer
            # division alone turns any bound under a minute into "up to 0m",
            # which reads as "instant" — the exact opposite of what this
            # sentence exists to say. vpn55.sh makes the same point about the
            # record this function returns; the same care is owed to the
            # sentence printed beside it.
            local human
            if   (( bound >= 7200 )); then human="$(( bound / 3600 )) hours"
            elif (( bound >= 3600 )); then human="an hour"
            elif (( bound >= 120 ));  then human="$(( bound / 60 )) minutes"
            else                           human="${bound} seconds"
            fi
            warn "An established tunnel can continue for up to ${human}, until the"
            warn "server renegotiates its data channel and refuses the certificate."
            warn "Restart the service to end it now."
        fi
    fi
    return 0
}

# ─── Restart ──────────────────────────────────────────────────────────────────
# The seventh helper verb. Not `_install` re-run: a re-apply rewrites config and
# may change nothing, while this always cycles the daemon — which is the point
# when a service is wedged, and the reason the two must not be conflated.
#
# This daemon has no reload at all, so a restart is the only lever there is, and
# it is the only way to make a revocation bite before renegotiation would: the
# revocation list is read on connect, so a session established before the
# revocation continues until it renegotiates. Restarting ends every one of them.
vpn_openvpn_restart() {
    distro_require_root || return 1
    _ovpn_installed || { error "OpenVPN is not installed on this host."; return 1; }

    local unit
    unit="$(_ovpn_unit)"
    if [[ -z "$unit" ]]; then
        printf 'restarted\t%s\tfailed\tsessions-dropped\t%s\n' \
            "$VPN55_OVPN_TAG" "no service unit is recorded for this install"
        error "This install recorded no service unit — re-run the install to repair it."
        return 1
    fi

    if ! distro_service_restart "$unit"; then
        printf 'restarted\t%s\tfailed\tsessions-dropped\t%s\n' \
            "$VPN55_OVPN_TAG" "the service did not restart; it may now be stopped"
        return 1
    fi

    # Accepted is not running. This daemon exits on a configuration error it
    # only reads at start-up, and on a port it cannot bind — the second is the
    # likely one here, since the TCP/443 mode shares a port with anything else
    # that wanted it. Either way the state is re-read rather than inferred.
    if ! _ovpn_active; then
        printf 'restarted\t%s\tfailed\tsessions-dropped\t%s\n' \
            "$VPN55_OVPN_TAG" "the restart was accepted but the daemon is not running"
        error "The daemon restarted and then stopped. Check: journalctl -u ${unit}"
        return 1
    fi

    printf 'restarted\t%s\tok\tsessions-dropped\t%s\n' \
        "$VPN55_OVPN_TAG" "every client was disconnected; they reconnect on their own"
    success "OpenVPN restarted — every session was ended and any revocation is now in force."
    return 0
}

# One record per line, the contract's shape:
#
#   cred_id  user  state  address  created  custody  artifacts_held
vpn_openvpn_cred_list() {
    _ovpn_spool_sweep || true

    local cred user created address state row held
    while IFS= read -r cred; do
        [[ -n "$cred" ]] || continue
        user="$(_ovpn_cred_get "$cred" user)"
        created="$(_ovpn_cred_get "$cred" created)"
        address="$(_ovpn_cred_get "$cred" address)"

        state="unregistered"
        if row="$(users_cred_find "$cred" 2>/dev/null)"; then
            state="${row##*$'\t'}"
        fi
        if _ovpn_spool_held "$cred"; then held=1; else held=0; fi

        printf '%s\t%s\t%s\t%s\t%s\tserver\t%s\n' \
            "$cred" "$user" "$state" "${address:--}" "$created" "$held"
    done < <(_ovpn_cred_ids)
    return 0
}

# ─── Client artifacts ─────────────────────────────────────────────────────────
# vpn_openvpn_artifacts <cred_id> — one record per line:
#
#   artifact  <id>  <label>  <filename>  <encoding>  <qr>  <note>
#
# Two artifacts, and the reason there are only two is the whole point of the
# emit below: one file with everything inline, plus the page telling a human
# what to do with it. Nobody wants four files.
#
# qr is 0 on both. It is not a judgement about how nice a QR code would be — a
# client file carrying an RSA certificate and its key runs to several kilobytes,
# which produces a code no camera resolves. Offering one would be worse than
# offering none, because it looks as though it should have worked.
vpn_openvpn_artifacts() {
    local cred="${1:-}"
    [[ -n "$cred" ]] || { error "vpn_openvpn_artifacts <cred_id>"; return 1; }
    _ovpn_cred_exists "$cred" || { error "No credential '${cred}' on this server."; return 1; }
    _ovpn_spool_sweep || true

    # Both are gated on still existing. The list reflects what is available RIGHT
    # NOW — offering an artifact the spool has already swept would have the
    # caller ask for it and be refused, which is a worse answer than not
    # offering it.
    if [[ -s "$(_ovpn_spool_path "$cred" ovpn)" ]]; then
        printf 'artifact\tprofile\tClient profile\tvpn55-%s.ovpn\ttext\t0\t%s\n' \
            "$cred" "Everything in one file — the server address, the certificates and the key. Import it into the client app on any platform."
    fi
    if [[ -s "$(_ovpn_spool_path "$cred" meta)" ]]; then
        printf 'artifact\tinstructions\tSetup instructions\tvpn55-%s.txt\ttext\t0\t%s\n' \
            "$cred" "Which app to install on each platform, and what to do with the profile."
    fi
    return 0
}

# vpn_openvpn_client_config <cred_id> [artifact_id] [locale]
#
# With no artifact named, the first one _artifacts lists is returned — which is
# the most directly usable, not the most complete.
#
# The locale is the third positional argument on every adapter. It reaches here
# from a caller that does not know which protocol it is talking to, which is
# exactly right: a language tag is not protocol vocabulary. It is ignored by the
# artifacts that are not prose — a profile is bytes for a parser, and there is no
# Vietnamese spelling of a certificate.
vpn_openvpn_client_config() {
    local cred="${1:-}" artifact="${2:-}" locale="${3:-}"
    [[ -n "$cred" ]] || { error "vpn_openvpn_client_config <cred_id> [artifact] [locale]"; return 1; }
    _ovpn_installed || { error "This protocol is not installed on this host."; return 1; }
    _ovpn_cred_exists "$cred" || { error "No credential '${cred}' on this server."; return 1; }
    _ovpn_spool_sweep || true

    if [[ -z "$artifact" ]]; then
        artifact="$(vpn_openvpn_artifacts "$cred" | awk -F'\t' 'NR == 1 { print $2 }')"
        [[ -n "$artifact" ]] || { error "'${cred}' has no artifacts left to hand out."; return 1; }
    fi

    local ext
    case "$artifact" in
        profile)      ext="ovpn" ;;
        instructions) ext="meta" ;;
        *)
            error "'${artifact}' is not an artifact this protocol produces."
            error "Ask it what it has with the 'artifacts' verb."
            return 1 ;;
    esac

    local path
    path="$(_ovpn_spool_path "$cred" "$ext")"
    if [[ ! -s "$path" ]]; then
        error "The '${artifact}' artifact for '${cred}' is no longer available."
        # Only one of the two ever held a key, and saying so about the other
        # would be a plausible-sounding lie in an error message — which is
        # exactly where a reader has no way to check it.
        if [[ "$artifact" == "profile" ]]; then
            error "It carried the private key, which was erased ${VPN55_OVPN_KEY_TTL_HOURS}h after issue."
            error "There is no way to rebuild it — revoke this credential and issue a new one."
        else
            error "It was erased ${VPN55_OVPN_KEY_TTL_HOURS}h after issue, alongside the profile it"
            error "describes. Issue a new credential to get both again."
        fi
        return 1
    fi

    # The prose artifact is rendered now, in the language asked for. The others
    # are bytes and are handed over as they are.
    if [[ "$artifact" == "instructions" ]]; then
        _ovpn_build_instructions "$cred" "$locale" \
            || { error "cannot build the setup instructions for '${cred}'"; return 1; }
        return 0
    fi

    cat "$path" || { error "cannot read the ${artifact} artifact for '${cred}'"; return 1; }
    return 0
}

# ─── Building the artifacts ───────────────────────────────────────────────────
# Each artifact is built into a variable and only then written, never piped
# straight into the writer.
#
# `producer | fs_write_atomic dest` cannot report the PRODUCER's exit status —
# the pipeline's status is the writer's — so a build that fails halfway, after
# emitting the authority certificate and before the private key, is written out
# in full and reported as a success. The caller then hands someone a profile
# that is missing exactly the part that makes it work, and the first sign of it
# is a user who cannot connect. Capturing the output means the failure is caught
# before anything reaches the spool.
_ovpn_build_artifacts() {
    local cred="${1:-}" user="${2:-}" ip="${3:-}"
    local profile

    profile="$(_ovpn_build_profile "$cred")" \
        || { error "cannot build the client profile for '${cred}'"; return 1; }
    [[ -n "$profile" ]] || { error "the client profile came out empty"; return 1; }

    printf '%s\n' "$profile" \
        | fs_write_atomic "$(_ovpn_spool_path "$cred" ovpn)" 0600 \
        || { error "cannot spool the client profile"; return 1; }

    # What is spooled for the instructions is the FACTS, not one rendered
    # language. The page is prose for the person who will read it, and nobody
    # knows at issue time which of the three they read — the operator issuing
    # the credential and the person receiving it are usually not the same
    # person, which is the whole reason the self-serve portal exists.
    # Rendering at handover means every locale comes out of one spool entry,
    # and it is an entry that expires on the same clock as the profile it
    # describes, so the artifact list stays honest about what is left.
    #
    # Only the credential's tunnel address is unrecoverable afterwards; the
    # rest is written here so the renderer needs nothing but this file and
    # the live server config.
    printf 'cred\t%s\nuser\t%s\nip\t%s\n' "$cred" "$user" "$ip" \
        | fs_write_atomic "$(_ovpn_spool_path "$cred" meta)" 0600 \
        || { error "cannot spool the credential's details"; return 1; }
    return 0
}

# The single-file emit, with everything inline.
#
# Reshaped from angristan/openvpn-install (MIT) — the inline-block structure,
# the ordering of the directives, the ignore-unknown-option guards that let one
# file serve both an old and a new client, and the awk that trims everything
# before the certificate's BEGIN line. That last one is not cosmetic: the
# authority writes a human-readable text dump above the certificate, and a
# client that is handed the whole file refuses it.
_ovpn_build_profile() {
    local cred="${1:-}"
    local endpoint transport port reneg tls_mode proto_line

    endpoint="$(_ovpn_endpoint)"
    transport="$(_ovpn_transport)"
    port="$(_ovpn_port)"
    reneg="$(_ovpn_reneg)"
    tls_mode="$(_ovpn_tls_mode)"

    [[ -n "$endpoint" && -n "$transport" && -n "$port" ]] || {
        error "this server's transport settings are incomplete"
        return 1
    }

    # The client names the transport differently from the server: on the
    # connection-oriented one it has to say which end it is.
    if [[ "$transport" == "tcp" ]]; then
        proto_line="tcp-client"
    else
        proto_line="udp"
    fi

    printf '# VPN55 client profile — %s\n' "$cred"
    printf '#\n'
    printf '# Everything this needs is inside this one file, including a PRIVATE KEY.\n'
    printf '# Treat it the way you would treat a password: it is the credential, not a\n'
    printf '# description of one. The server erased its copy and cannot send it again.\n'
    printf 'client\n'
    printf 'dev tun\n'
    printf 'proto %s\n' "$proto_line"
    printf 'remote %s %s\n' "$endpoint" "$port"
    printf 'resolv-retry infinite\n'
    printf 'nobind\n'
    printf 'persist-key\n'
    printf 'persist-tun\n'
    printf 'remote-cert-tls server\n'
    printf 'verify-x509-name %s name\n' "$VPN55_OVPN_SERVER_CN"
    printf 'auth %s\n' "$VPN55_OVPN_AUTH_DIGEST"
    printf 'auth-nocache\n'
    printf 'tls-client\n'
    printf 'tls-version-min %s\n' "$VPN55_OVPN_TLS_MIN"
    printf 'reneg-sec %s\n' "$reneg"

    # The guard comes BEFORE the directives it guards, or an older client stops
    # at the first line it does not recognise instead of skipping it.
    #
    # Two of the three names guarded here are never written in this file: they
    # are PUSHED by the server, and a client that does not understand a pushed
    # option does not ignore it — it refuses the connection. So an old client
    # talking to a new server fails at the last moment, after authenticating,
    # with a message about an option this file does not contain. Listing them
    # here is what makes one profile serve both.
    printf 'ignore-unknown-option block-outside-dns block-ipv6 data-ciphers\n'
    printf 'data-ciphers %s\n' "$VPN55_OVPN_DATA_CIPHERS"
    printf 'cipher %s\n' "${VPN55_OVPN_DATA_CIPHERS%%:*}"
    printf 'verb 3\n'

    if [[ "$transport" == "udp" ]]; then
        printf 'explicit-exit-notify\n'
    fi

    printf '<ca>\n'
    awk '/BEGIN CERTIFICATE/,/END CERTIFICATE/' "$(pki_ca_path)" \
        || { error "cannot read the certificate authority"; return 1; }
    printf '</ca>\n'

    printf '<cert>\n'
    awk '/BEGIN CERTIFICATE/,/END CERTIFICATE/' "$(pki_cert_path "$cred")" \
        || { error "cannot read the certificate for '${cred}'"; return 1; }
    printf '</cert>\n'

    printf '<key>\n'
    cat "$(pki_key_path "$cred")" || { error "cannot read the private key for '${cred}'"; return 1; }
    printf '</key>\n'

    if [[ "$tls_mode" == "crypt-v2" ]]; then
        # A per-client wrapped key, minted here from the server key. It is
        # written to a file because the tool only writes to one, and it is
        # written inside the spool rather than /tmp: on a host with a private
        # temporary directory per service the daemon cannot read /tmp at all,
        # and on any host /tmp is the wrong place for a key.
        local wk rc=0
        wk="$(_ovpn_spool_path "$cred" wk)"
        fs_ensure_dir "$VPN55_OVPN_SPOOL" 0700 || return 1
        ( umask 077; openvpn --tls-crypt-v2 "$(_ovpn_tls_key)" \
            --genkey tls-crypt-v2-client "$wk" >/dev/null 2>&1; ) || rc=$?
        if [[ "$rc" -ne 0 ]]; then
            fs_shred "$wk" || true
            error "cannot mint a per-client control-channel key for '${cred}'"
            return 1
        fi
        printf '<tls-crypt-v2>\n'
        cat "$wk" || { fs_shred "$wk" || true; error "cannot read the per-client control-channel key"; return 1; }
        printf '</tls-crypt-v2>\n'
        fs_shred "$wk" || true
    else
        printf '<tls-crypt>\n'
        cat "$(_ovpn_tls_key)" || { error "cannot read the control-channel key"; return 1; }
        printf '</tls-crypt>\n'
    fi
    return 0
}

# _ovpn_build_instructions <cred> [locale] — the setup page, in one language.
#
# Reads the spooled facts rather than taking them as arguments, so the same call
# produces the same page at any point in the credential's life. The prose lives
# in lib/locales/<tag>/<locale>.txt and is looked up by SECTION NAME, never by
# matching its English text: a phrase map keyed on English word order misses
# every translator who reorders a sentence, and the two files still look
# parallel afterwards.
_ovpn_build_instructions() {
    local cred="${1:-}" locale="${2:-}"
    local tag="$VPN55_OVPN_TAG"
    local meta user ip endpoint transport port

    meta="$(_ovpn_spool_path "$cred" meta)"
    [[ -s "$meta" ]] || { error "no spooled details for '${cred}'"; return 1; }
    user="$(awk -F'\t' '$1 == "user" { print $2; exit }' "$meta")"
    ip="$(awk -F'\t' '$1 == "ip" { print $2; exit }' "$meta")"

    endpoint="$(_ovpn_endpoint)"
    transport="$(_ovpn_transport)"
    port="$(_ovpn_port)"

    i18n_render "$tag" "$locale" main \
        "cred=${cred}" "user=${user}" "ip=${ip}" \
        "endpoint=${endpoint}" "transport=${transport}" "port=${port}" || return 1

    # The transport note is a separate section rather than a sentence spliced
    # into the one above, because the two say opposite things and a translator
    # has to be able to see which one they are working on.
    if [[ "$transport" == "tcp" ]]; then
        i18n_render "$tag" "$locale" transport.tcp || return 1
    else
        i18n_render "$tag" "$locale" transport.udp || return 1
    fi
    return 0
}

# ─── Reading the live state ───────────────────────────────────────────────────
# The daemon writes a status file every ${VPN55_OVPN_STATUS_INTERVAL} seconds.
# It is read rather than the management interface because a file read cannot
# block, and this is on the panel's polling path — the interface is used only
# for the one thing a file cannot do, which is end a session.
#
# ── The columns are looked up by NAME, never by position ─────────────────────
# Version 2 of this format gained a column in the middle at 2.4 (the virtual
# IPv6 address) and could gain another. A parser with hardcoded field numbers
# reads the wrong ones on the version it was not written against, and the
# failure is silent and plausible: byte counts land in the address column and
# every credential shows sensible-looking nonsense. The header row names each
# column, so it is used.
#
# The header names field N of the rows that follow at its own field N+1, because
# the header carries an extra leading label. Getting that off by one puts every
# value one column to the left, which is the same silent failure by another
# route — hence the arithmetic being written down rather than inferred.
#
# The path is resolved rather than assumed, for the reason in _ovpn_render_conf:
# the packaged unit passes its own --status on the command line and our config
# overrides it. Ours is read first; the unit's documented runtime path is tried
# only if ours does not exist, so a wrong assumption about which one wins costs
# nothing instead of costing the whole feature. It is the same instance's file
# either way — %i is our instance name — so the fallback cannot mix up servers.
_ovpn_status_file() {
    local ours unit
    ours="$(_ovpn_status_log)"
    if [[ -r "$ours" ]]; then
        printf '%s' "$ours"
        return 0
    fi
    unit="$(_ovpn_unit)"
    case "$unit" in
        openvpn-server@*)
            # Only this template documents --status-version 2 on its command
            # line. The legacy template writes version 1, which this parser
            # cannot read, so it is deliberately not offered as a fallback.
            local alt="/run/openvpn-server/status-${VPN55_OVPN_INSTANCE}.log"
            if [[ -r "$alt" ]]; then
                printf '%s' "$alt"
                return 0
            fi ;;
    esac
    printf '%s' "$ours"
    return 0
}

_ovpn_status_records() {
    local log
    log="$(_ovpn_status_file)"
    [[ -r "$log" ]] || return 0

    awk -F',' '
        BEGIN { TAB = sprintf("%c", 9) }
        function g(n,   i) {
            i = col[n]
            if (i == "" || i + 0 < 1 || i + 0 > NF) return "-"
            if ($i == "") return "-"
            return $i
        }
        {
            sub(/\r$/, "")
            if ($1 == "HEADER" && $2 == "CLIENT_LIST") {
                for (i = 3; i <= NF; i++) col[$i] = i - 1
                next
            }
            if ($1 == "CLIENT_LIST") {
                if (g("Common Name") == "-") next
                print g("Common Name") TAB g("Bytes Received") TAB g("Bytes Sent") TAB g("Real Address")
            }
        }
    ' "$log" 2>/dev/null || true
    return 0
}

# When the daemon last wrote that file. It is the honest answer to "when was
# this credential last seen alive": the row exists because the daemon observed
# the session at that moment, which is a fact, whereas the session's start time
# would report a client connected and active for three days as last seen three
# days ago.
_ovpn_status_stamp() {
    local log stamp
    log="$(_ovpn_status_file)"
    [[ -r "$log" ]] || { printf -- '-'; return 0; }
    stamp="$(awk -F',' '$1 == "TIME" { sub(/\r$/, "", $3); print $3; exit }' "$log" 2>/dev/null || true)"
    if [[ "$stamp" =~ ^[0-9]+$ ]]; then
        printf '%s' "$stamp"
    else
        printf -- '-'
    fi
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
#   rx / tx    bytes as the daemon reports them RIGHT NOW, and they reset on
#              every reconnection. "-" is NOT zero and must not be treated as a
#              counter reset by the collector.
#   handshake  when the daemon last observed this credential connected, or "-"
#              when it is not connected. Never 0: the daemon keeps no history at
#              all, so "never connected" and "connected yesterday" are the same
#              from here, and reporting 0 would assert a fact this adapter does
#              not have.
#   endpoint   the peer's current remote address, or "-". LIVE state only, never
#              retained — docs/security-model.md §2 says VPN55 keeps no per-user
#              connection IP history.
vpn_openvpn_status() {
    _ovpn_spool_sweep || true

    local tag="$VPN55_OVPN_TAG"
    local state enabled since count unit listen transport port

    transport="$(_ovpn_transport)"
    port="$(_ovpn_port)"
    if [[ -n "$transport" && -n "$port" ]]; then
        listen="${transport}/${port}"
    else
        listen="-"
    fi

    if ! _ovpn_installed; then
        printf 'service\t%s\tabsent\t0\t%s\t-\t0\n' "$tag" "$listen"
        return 0
    fi

    unit="$(_ovpn_unit)"
    if _ovpn_active; then state="running"; else state="stopped"; fi
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
    ids="$(_ovpn_cred_ids)"
    count="$(printf '%s' "$ids" | grep -c . || true)"
    printf 'service\t%s\t%s\t%s\t%s\t%s\t%s\n' "$tag" "$state" "$enabled" "$listen" "$since" "${count:-0}"

    _ovpn_notes || true

    [[ -n "$ids" ]] || return 0

    # One read of the status file, then a lookup per credential. Parsing it once
    # per credential would be a process per user on every poll.
    local seen="-"
    declare -A st_rx st_tx st_ep
    if [[ "$state" == "running" ]]; then
        seen="$(_ovpn_status_stamp)"
        local c_cred c_rx c_tx c_ep
        while IFS=$'\t' read -r c_cred c_rx c_tx c_ep; do
            [[ -n "$c_cred" ]] || continue
            st_rx["$c_cred"]="$c_rx"
            st_tx["$c_cred"]="$c_tx"
            st_ep["$c_cred"]="$c_ep"
        done < <(_ovpn_status_records)
    fi

    local cred user address cstate row handshake
    while IFS= read -r cred; do
        [[ -n "$cred" ]] || continue
        user="$(_ovpn_cred_get "$cred" user)"
        address="$(_ovpn_cred_get "$cred" address)"

        cstate="unregistered"
        if row="$(users_cred_find "$cred" 2>/dev/null)"; then
            cstate="${row##*$'\t'}"
        fi

        # Only a credential the daemon is currently reporting gets a reading.
        # Handing every other one the file's timestamp would say the whole fleet
        # was seen a moment ago.
        if [[ -n "${st_rx[$cred]:-}" ]]; then
            handshake="$seen"
        else
            handshake="-"
        fi

        printf 'cred\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
            "$tag" "$cred" "$user" "$cstate" "${address:--}" \
            "${st_rx[$cred]:--}" "${st_tx[$cred]:--}" \
            "$handshake" "${st_ep[$cred]:--}"
    done <<< "$ids"
    return 0
}

# Facts the panel should surface that are not per-credential and are not the
# service being up. The record type exists so an adapter can say something
# specific without the panel learning what a revocation list is.
_ovpn_notes() {
    local tag="$VPN55_OVPN_TAG" transport held

    transport="$(_ovpn_transport)"
    if [[ "$transport" == "tcp" ]]; then
        printf 'note\t%s\tinfo\t%s\n' "$tag" \
            "This service runs on the transport that survives a network dropping UDP, with the control channel encrypted so there is no handshake to match on. That is the combination worth having on a filtered network, and it is slower than the alternative — noticeably so where the link loses packets."
    else
        printf 'note\t%s\twarn\t%s\n' "$tag" \
            "This service runs on UDP. The control channel is encrypted, so there is no handshake signature to match — but a network that drops UDP outright blocks it anyway. If your users are on a filtered network, the TCP mode is the one that gets through."
    fi

    if ! _ovpn_version_ge 2 5; then
        printf 'note\t%s\twarn\t%s\n' "$tag" \
            "This daemon is older than 2.5, so it cannot tell a client to stop using IPv6 while connected, and it uses one shared control-channel key rather than one per client. A dual-stack device keeps its own IPv6 path and that traffic does not enter the tunnel."
    fi

    # The status file is the only source for every per-credential reading here,
    # so an operator who is looking at stale numbers is entitled to know that is
    # what they are looking at.
    if _ovpn_active; then
        local stamp now age
        stamp="$(_ovpn_status_stamp)"
        if [[ "$stamp" =~ ^[0-9]+$ ]]; then
            now="$(fs_now_epoch)"
            age=$(( now - stamp ))
            if (( age > VPN55_OVPN_STATUS_INTERVAL * 6 )); then
                printf 'note\t%s\twarn\t%s\n' "$tag" \
                    "The live connection figures are ${age}s old — the service is running but has not refreshed them. Treat the per-credential readings as stale."
            fi
        else
            printf 'note\t%s\twarn\t%s\n' "$tag" \
                "The service is running but has written no connection figures yet, so no per-credential reading is available."
        fi
    fi

    local left
    left="$(pki_crl_expires_in)"
    if [[ "$left" =~ ^-?[0-9]+$ ]]; then
        if [[ "$left" -le 0 ]]; then
            printf 'note\t%s\tcrit\t%s\n' "$tag" \
                "The certificate revocation list has EXPIRED. The daemon refuses a client whose revocation status it cannot establish, so every user is refused, not only revoked ones. Refresh it now."
        elif [[ "$left" -lt 604800 ]]; then
            printf 'note\t%s\twarn\t%s\n' "$tag" \
                "The certificate revocation list expires in $(( left / 86400 )) days. If it lapses, every client is refused."
        fi
    fi

    if [[ "$(_ovpn_reneg)" == "0" ]]; then
        printf 'note\t%s\twarn\t%s\n' "$tag" \
            "Data-channel renegotiation is off. If a revoked credential's live session cannot be ended, its tunnel has no guaranteed end."
    fi

    held="$(find "$VPN55_OVPN_SPOOL" -maxdepth 1 -type f -name '*.ovpn' 2>/dev/null | grep -c . || true)"
    if [[ "${held:-0}" -gt 0 ]]; then
        printf 'note\t%s\tinfo\t%s\n' "$tag" \
            "${held} client profile(s) are still retrievable, which means this server is still holding those private keys. Each is erased ${VPN55_OVPN_KEY_TTL_HOURS}h after it was issued."
    fi
    return 0
}

# ─── Registration ─────────────────────────────────────────────────────────────
# vpn55.sh sources every lib/proto_*.sh by glob and each adapter announces
# itself. The guard is for the case where this file is sourced on its own — a
# test harness, or a panel-side check — where the registry does not exist.
if declare -F vpn_adapter_register >/dev/null 2>&1; then
    vpn_adapter_register "$VPN55_OVPN_TAG" "OpenVPN" || true
fi
