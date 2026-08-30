# shellcheck shell=bash
#
# lib/proto_wireguard.sh — WireGuard adapter. Phase 2.
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
# ── Reshaped at the Phase 3 checkpoint ───────────────────────────────────────
# The contract this file was written against had eight verbs and, without anyone
# choosing it, they were shaped around what WireGuard happens to be. Writing the
# second adapter exposed that, and the contract was widened rather than
# special-cased. What changed HERE:
#
#   - _cred_add took a client public key as its second POSITIONAL argument, and
#     vpn55.sh was prompting for one by that name for every protocol. It now
#     takes `key=value` options, and _capabilities declares that this adapter
#     accepts `pubkey` — so the installer can prompt for it without knowing what
#     it is.
#   - _client_config now takes an optional artifact name, and _artifacts says
#     what there is. This adapter has exactly one artifact, which is why the
#     shortcoming was invisible until a protocol with four turned up.
#   - the DNS resolver choice moved to core_net. It was never protocol
#     knowledge; it was just the first place it happened to be written.
#   - the atomic write, in-place replace, shred and settings reader moved to
#     core_fs for the same reason. Three copies of code whose only job is to be
#     careful is three chances for one of them to drop a chmod.
#
# Reshaped from Grin Node Toolkit scripts/lib/grin_wg_access.sh (same author):
# server init, peer add/remove/list, next-address allocation, `wg syncconf`
# instead of a restart, and handshake detection. The distro package matrix comes
# from angristan/wireguard-install (MIT). Both are logged in ATTRIBUTIONS.md.
#
# ── What changed in the reshaping, and why ───────────────────────────────────
# The Grin original is deliberately NOT a VPN: forwarding stays off, there is no
# NAT, and clients split-tunnel to reach one host. This is the opposite product,
# so three things are inverted here:
#
#   1. Full tunnel. AllowedIPs is 0.0.0.0/0, ::/0 — see the IPv6 note below.
#   2. NAT and forwarding are on, and every rule goes through core_net's tagged
#      verbs. There are deliberately NO PostUp/PostDown rules in the interface
#      config, which is where angristan and almost every other installer puts
#      them. A PostUp iptables rule is a second firewall path that the ledger
#      never sees, and CLAUDE.md's one-backend rule exists precisely because a
#      rule added through one backend and torn down through another survives an
#      uninstall. The PostUp/PostDown *lesson* — everything added on up is
#      removed on down — is kept; the mechanism is the ledger in core_net.sh.
#   3. Peers are keyed on an opaque credential id issued by core_users, not on a
#      device name chosen by the operator.
#
# ── Two Phase-2 decisions, recorded in docs/security-model.md §6 ─────────────
#   * KEY CUSTODY: server-generates by default, client-generates on request, and
#     a server-generated private key is spooled for a bounded window and then
#     shredded. Never a permanent plaintext key store. See _wg_spool_sweep.
#   * DNS: the host's own upstream resolvers by default, because a public
#     resolver adds a second observer the user did not choose. Cloudflare, Quad9
#     and a custom pair are offered. Resolved ONCE at install and baked in.
#
# ── IPv6 is captured and dropped, on purpose ─────────────────────────────────
# The client config claims ::/0 while the tunnel carries no IPv6. That is
# deliberate: with ::/0 absent, a dual-stack client keeps its native v6 path and
# every v6-capable site leaves the tunnel in the clear while the user believes
# it does not. Claiming ::/0 makes v6 fail closed instead. Real v6 transport is
# future work; a silent leak is not an acceptable stand-in for it.
#
# Sourced, not executed. errexit does not cover a ||-guarded function body, so
# every command here that creates, copies, moves or deletes is guarded on its
# own line — see CLAUDE.md.

[[ -n "${VPN55_WG_LOADED:-}" ]] && return 0
VPN55_WG_LOADED=1

: "${VPN55_ETC:=/etc/vpn55}"

# The adapter's own tag. It is the <proto> in every contract verb, the owner tag
# it claims its pool slot and its firewall rules under, and the owner tag its
# credentials carry in the registry. One string, four uses, so they cannot drift.
VPN55_WG_TAG="wireguard"

# Pool slot 0. The slot table lives in CLAUDE.md § Networking and nowhere else —
# core_net deliberately does not know which protocol owns which slot.
VPN55_WG_SLOT=0

# ─── The two modes ────────────────────────────────────────────────────────────
# This adapter runs one protocol in one of two modes:
#
#   wireguard   stock WireGuard.
#   amneziawg   AmneziaWG — the same protocol with the fingerprint filed off.
#
# A MODE, not a fourth adapter. Same tag, same pool slot, same firewall tag, same
# credential registry, same contract verbs. What changes is the pair of binaries
# (wg/awg), the config directory, the systemd unit template, the kernel module
# name, and nine extra keys in the [Interface] section at both ends.
#
# Why it exists: WireGuard's handshake initiation is a fixed-size packet with a
# fixed type byte, so blocking it needs no heuristics and produces no false
# positives — it is the cheapest of the three protocols for a censor to kill, and
# shipping it unobfuscated as the flagship for a filtered market ships the one
# that breaks first. AmneziaWG prepends junk packets and replaces the four fixed
# type bytes with values chosen per server. See docs/circumvention.md §5.
: "${VPN55_WG_MODE_DEFAULT:=wireguard}"

: "${VPN55_WG_ETC:=/etc/wireguard}"                       # where wg-quick looks
: "${VPN55_AWG_ETC:=/etc/amnezia/amneziawg}"              # where awg-quick looks
: "${VPN55_WG_STATE:=$VPN55_ETC/wireguard}"               # our settings + spool
: "${VPN55_WG_CONF:=$VPN55_WG_STATE/settings.conf}"
: "${VPN55_WG_SPOOL:=$VPN55_WG_STATE/spool}"

: "${VPN55_WG_IFACE:=wg0}"
: "${VPN55_WG_PORT:=51820}"
: "${VPN55_WG_KEEPALIVE:=25}"

# How long a server-generated private key stays retrievable after issue, in
# hours. Long enough for a real hand-off — issue in the panel now, scan on the
# user's phone this evening — and short enough that the box is not a permanent
# key store. 0 disables spooling entirely: the config is emitted once by
# _cred_add and never again.
: "${VPN55_WG_KEY_TTL_HOURS:=24}"

# Opt-in package purge on uninstall. Off by default: wireguard-tools and
# qrencode are ordinary utilities that something else on the host may be using,
# and removing a package is not what "reverse the install" means to an operator
# who just wants the tunnel gone.
: "${VPN55_WG_PURGE_PACKAGES:=0}"

# ─── Settings file ────────────────────────────────────────────────────────────
# key=value, one per line, mode 0600, through core_fs. The atomic writer, the
# in-place replacer, the shred and this reader all used to live in this file;
# they moved to core_fs at the Phase 3 checkpoint, when the second adapter
# turned out to need identical copies of every one of them.
_wg_state_dir() {
    fs_ensure_dir "$VPN55_WG_STATE" 0700 || return 1
    fs_ensure_dir "$VPN55_WG_SPOOL" 0700 || return 1
    return 0
}

_wg_conf_get() { fs_conf_get "$VPN55_WG_CONF" "${1:-}"; }

_wg_conf_set() {
    local key="${1:-}" value="${2:-}" current
    _wg_state_dir || return 1

    # An unchanged value is not written at all. fs_conf_set rewrites by dropping
    # the old line and appending the new one, so re-setting a value that has not
    # changed silently MOVES it to the end of the file — and the settings file
    # then differs between the first install and the second for no reason. "Run
    # it three times and nothing changes after the first" has to mean nothing,
    # including the order of a file nobody looks at; the alternative is an
    # idempotence test that passes only because it does not read that file.
    if current="$(fs_conf_get "$VPN55_WG_CONF" "$key" 2>/dev/null)" \
       && [[ "$current" == "$value" ]]; then
        return 0
    fi
    fs_conf_set "$VPN55_WG_CONF" "$key" "$value"
}

# Settings with their defaults resolved. Reading through one accessor is what
# lets _install re-render a byte-identical config on the second run.
_wg_iface()     { fs_conf_default "$VPN55_WG_CONF" iface     "$VPN55_WG_IFACE"; }
_wg_port()      { fs_conf_default "$VPN55_WG_CONF" port      "$VPN55_WG_PORT"; }
_wg_keepalive() { fs_conf_default "$VPN55_WG_CONF" keepalive "$VPN55_WG_KEEPALIVE"; }
_wg_endpoint()  { fs_conf_default "$VPN55_WG_CONF" endpoint  ""; }
_wg_dns()       { fs_conf_default "$VPN55_WG_CONF" dns       ""; }
_wg_custody()   { fs_conf_default "$VPN55_WG_CONF" custody   "server"; }
_wg_userspace() { fs_conf_default "$VPN55_WG_CONF" userspace ""; }
_wg_mtu()       { fs_conf_default "$VPN55_WG_CONF" mtu       ""; }

# ── Everything the mode swaps ──
# Read through these, never hardcode `wg` or `/etc/wireguard` again. A missed
# site does not fail loudly: `wg show awg0` on an AmneziaWG host simply reports
# nothing, so status would render every live peer as idle rather than erroring.
_wg_mode() { fs_conf_default "$VPN55_WG_CONF" mode "$VPN55_WG_MODE_DEFAULT"; }

_wg_is_awg() { [[ "$(_wg_mode)" == "amneziawg" ]]; }

# The userspace tool and its wrapper. amneziawg-tools installs `awg`/`awg-quick`
# with the same sub-commands, so every call site is the binary name and nothing
# else.
_wg_tool()  { if _wg_is_awg; then printf 'awg';       else printf 'wg';       fi; }
_wg_quick() { if _wg_is_awg; then printf 'awg-quick'; else printf 'wg-quick'; fi; }

# awg-quick resolves a bare interface name against /etc/amnezia/amneziawg, not
# /etc/wireguard — verified in amneziawg-tools' src/wg-quick/linux.bash. Putting
# the config in the wrong one leaves `awg-quick up` reporting that the interface
# does not exist, which reads as a broken install rather than a wrong path.
_wg_etc()    { if _wg_is_awg; then printf '%s' "$VPN55_AWG_ETC"; else printf '%s' "$VPN55_WG_ETC"; fi; }
_wg_module() { if _wg_is_awg; then printf 'amneziawg'; else printf 'wireguard'; fi; }

_wg_server_conf() { printf '%s/%s.conf' "$(_wg_etc)" "$(_wg_iface)"; }
_wg_server_key()  { printf '%s/%s.key'  "$(_wg_etc)" "$(_wg_iface)"; }
_wg_server_pub()  { printf '%s/%s.pub'  "$(_wg_etc)" "$(_wg_iface)"; }
_wg_unit()        { printf '%s@%s.service' "$(_wg_quick)" "$(_wg_iface)"; }
_wg_dropin_dir()  { printf '/etc/systemd/system/%s@%s.service.d' "$(_wg_quick)" "$(_wg_iface)"; }
_wg_dropin()      { printf '%s/10-vpn55-userspace.conf' "$(_wg_dropin_dir)"; }

_wg_installed() { local c; c="$(_wg_server_conf)"; [[ -f "$c" ]]; }
_wg_active()    { distro_service_is_active "$(_wg_unit)"; }
_wg_now()       { fs_now; }

# What to call this on screen. The tag stays "wireguard" everywhere it matters —
# pool slot, firewall ledger, credential owner — because those are identity and
# must not move when the mode does. This is display only.
_wg_label() { if _wg_is_awg; then printf 'AmneziaWG'; else printf 'WireGuard'; fi; }

_wg_subnet()  { net_pool_subnet  "$VPN55_WG_SLOT"; }
_wg_gateway() { net_pool_gateway "$VPN55_WG_SLOT"; }

# ─── Availability ─────────────────────────────────────────────────────────────
# Three distinct answers collapsed into two by the contract, so the reason goes
# to stderr while the exit code stays binary:
#
#   kernel module usable            -> available
#   no module but a userspace impl  -> available, degraded (slower, higher CPU)
#   neither                         -> unavailable, and say what would fix it
#
# The judgement lives here rather than in core_distro because core_distro
# reports facts and does not decide policy — deciding that boringtun is an
# acceptable substitute is this adapter's call to make.
# boringtun and wireguard-go speak stock WireGuard and cannot produce an
# obfuscated handshake, so they are NOT substitutes in AmneziaWG mode. Offering
# one there would build a tunnel that comes up, carries traffic and is trivially
# fingerprinted — the exact failure the mode exists to prevent, presented as a
# success.
_wg_userspace_impl() {
    local bin
    if _wg_is_awg; then
        for bin in amneziawg-go awg-go; do
            if command -v "$bin" >/dev/null 2>&1; then
                printf '%s' "$bin"
                return 0
            fi
        done
        return 1
    fi
    for bin in boringtun-cli boringtun wireguard-go; do
        if command -v "$bin" >/dev/null 2>&1; then
            printf '%s' "$bin"
            return 0
        fi
    done
    return 1
}

vpn_wireguard_available() {
    local state impl mod
    mod="$(_wg_module)"
    state="$(distro_module_state "$mod" 2>/dev/null)" || state="unavailable"

    case "$state" in
        loaded|builtin)
            debug "${mod} kernel module: ${state}"
            return 0 ;;
        loadable)
            debug "${mod} kernel module: loadable"
            return 0 ;;
    esac

    if impl="$(_wg_userspace_impl)"; then
        warn "No ${mod} kernel module on this host — falling back to ${impl}."
        warn "A userspace tunnel works, but costs noticeably more CPU per gigabit."
        return 0
    fi

    # The advice differs by mode and getting it wrong wastes an operator's
    # afternoon: boringtun is a fine answer for stock WireGuard and a useless one
    # for AmneziaWG, because it speaks the protocol this mode exists to hide.
    local userspace_hint
    if _wg_is_awg; then
        userspace_hint="amneziawg-go"
    else
        userspace_hint="boringtun / wireguard-go"
    fi

    error "This host cannot run ${mod}: no kernel module and no userspace implementation."
    if distro_is_container; then
        error "It is a $(distro_virt) container, and a container shares the host kernel —"
        error "the module has to be loaded on the HOST, which is not something this"
        error "installer can do from inside. That is a hosting limitation, not a bug."
        error "Either ask the provider to load it, install ${userspace_hint} here, or use a KVM instance."
    else
        error "Install the kernel module for $(uname -r), or install ${userspace_hint}"
        error "for a userspace tunnel, then re-run."
    fi
    if _wg_is_awg; then
        error ""
        error "AmneziaWG is in no distribution's repositories — see"
        error "  https://github.com/amnezia-vpn/amneziawg-linux-kernel-module"
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
# The option record is what removed "Client public key" from vpn55.sh. The
# installer used to prompt every protocol for one because this adapter is the
# one that wanted it; now it asks each adapter what it takes and prompts for
# that. The custody line is not decoration either — a user is entitled to know
# whether the server has ever held their private key, and it changes with the
# configured default, so it is computed rather than written down twice.
vpn_wireguard_capabilities() {
    printf 'revoke\timmediate\t0\n'

    # Computed, never written down: the same adapter is the best and the worst
    # of the three on this axis depending on one install-time choice, and a
    # fixed answer here would be wrong half the time.
    if _wg_is_awg; then
        printf 'filtering\tresistant\t%s\n' \
            "This service pads its handshake with junk packets and randomises its header values, using numbers drawn for this server alone. There is no fixed pattern left in it for a filter to match."
    else
        printf 'filtering\texposed\t%s\n' \
            "This service is running unobfuscated. Its first packet is a fixed size with fixed header bytes, so a filter recognises it with no guesswork at all — it is the cheapest tunnel on this host to block. Re-installing it in its obfuscated mode closes that, and nothing else here will."
    fi

    if [[ "$(_wg_custody)" == "client" ]]; then
        printf 'custody\tclient\t%s\n' \
            "This server issues client-generated credentials only: it never sees a private key, and you must supply a public key made on the device."
    else
        printf 'custody\tserver\t%s\n' \
            "The server generates this credential's private key by default, holds it for ${VPN55_WG_KEY_TTL_HOURS}h so the config can be fetched, then erases it. Supply a public key instead and it never holds one at all."
    fi

    printf 'restart\tsessions-dropped\t%s\n' \
        "Restarting brings the interface down and back up: every connected device is dropped and re-handshakes on its own, usually within seconds."

    printf 'option\tpubkey\t%s\t0\t%s\n' \
        "Client public key (blank = the server generates the keypair)" \
        "Generate one on the device with '$(_wg_tool) genkey | tee private.key | $(_wg_tool) pubkey' and paste the PUBLIC half here. The server then never holds the private one."
    return 0
}

# ─── Install ──────────────────────────────────────────────────────────────────
# Package names per distro family. Lifted from angristan/wireguard-install (MIT,
# verified via the GitHub API on 2026-08-27) and mapped onto core_distro's family
# abstraction; see ATTRIBUTIONS.md.
#
# Not lifted: its iptables handling. That is the PostUp/PostDown model this file
# replaces with the core_net ledger, for the reason in the header.
_wg_packages() {
    _distro_need_detect || return 1
    case "$VPN55_OS_FAMILY" in
        debian) printf '%s\n' wireguard wireguard-tools qrencode ;;
        rhel)   printf '%s\n' wireguard-tools qrencode ;;
        arch)   printf '%s\n' wireguard-tools qrencode ;;
        *)      error "no package set known for OS family '${VPN55_OS_FAMILY}'"; return 1 ;;
    esac
}

# AmneziaWG ships in no distribution's repositories. VPN55 deliberately does NOT
# add a third-party apt/yum repository or a PPA on the operator's behalf: adding
# a signing key and a package source to a root-run server is a trust decision
# that belongs to whoever owns the box, and an installer that makes it silently
# is a supply-chain hazard however convenient it is. So the mode checks for the
# tooling, and when it is absent it says exactly what to install and stops —
# rather than half-installing and leaving a server that looks obfuscated.
_awg_require_tools() {
    local tool quick missing=0
    tool="$(_wg_tool)"; quick="$(_wg_quick)"

    command -v "$tool"  >/dev/null 2>&1 || missing=1
    command -v "$quick" >/dev/null 2>&1 || missing=1
    [[ "$missing" -eq 0 ]] || {
        error "AmneziaWG mode needs '${tool}' and '${quick}', and neither is in this"
        error "distribution's repositories. VPN55 will not add a third-party package"
        error "source to your server for you — that is your decision to make."
        error ""
        error "Install amneziawg-tools and the kernel module (or amneziawg-go for a"
        error "userspace tunnel) from the project's own instructions, then re-run:"
        error "  https://github.com/amnezia-vpn/amneziawg-tools"
        error "  https://github.com/amnezia-vpn/amneziawg-linux-kernel-module"
        error ""
        error "Or install in plain WireGuard mode instead — it works everywhere, and"
        error "it is fingerprintable. docs/circumvention.md §5 says what that costs."
        return 1
    }
    return 0
}

_wg_install_packages() {
    if _wg_is_awg; then
        _awg_require_tools || return 1
        # qrencode is the one package the mode still wants from the distro, and
        # it is optional — a missing QR degrades the hand-off, it does not break
        # the tunnel.
        if ! distro_pkg_installed qrencode; then
            info "Installing: qrencode"
            distro_pkg_refresh || warn "package index refresh failed — continuing with the cached one"
            distro_pkg_install qrencode \
                || warn "qrencode is unavailable — client configs will emit as text with no QR."
        fi
        return 0
    fi

    local -a want=() missing=()
    mapfile -t want < <(_wg_packages) || return 1

    local pkg
    for pkg in "${want[@]}"; do
        distro_pkg_installed "$pkg" || missing+=("$pkg")
    done

    # Nothing missing is the second-run case, and it must not touch the package
    # manager at all: an apt-get invocation that changes nothing is still a
    # network call and a lock, which is not "changes nothing".
    if [[ ${#missing[@]} -eq 0 ]]; then
        debug "packages already present: ${want[*]}"
    else
        info "Installing: ${missing[*]}"
        distro_pkg_refresh || warn "package index refresh failed — continuing with the cached one"
        distro_pkg_install "${missing[@]}" || return 1
    fi

    # On EL 8 the module ships out of tree. Best effort only: EL 9 and every
    # other supported release have it in the kernel, and failing the whole
    # install over an optional package on one release is the wrong trade.
    if [[ "$VPN55_OS_FAMILY" == "rhel" ]] && ! distro_module_ready "$(_wg_module)"; then
        if ! distro_pkg_installed kmod-wireguard; then
            info "Kernel module not present — trying the out-of-tree kmod package."
            distro_pkg_install kmod-wireguard \
                || warn "kmod-wireguard is unavailable (it needs ELRepo on EL 8). Continuing."
        fi
    fi

    local cmd
    for cmd in "$(_wg_tool)" "$(_wg_quick)"; do
        command -v "$cmd" >/dev/null 2>&1 \
            || { error "'${cmd}' is still missing after installing packages."; return 1; }
    done
    command -v qrencode >/dev/null 2>&1 \
        || warn "qrencode is missing — client configs will emit as text with no QR code."
    return 0
}

# The DNS resolver choice lives in core_net now — net_resolvers_system,
# net_resolvers_resolve and net_resolvers_explain. It moved there at the
# Phase 3 checkpoint: pushing a resolver at clients is something every tunnel
# protocol does identically, and this file was only its first home, not its
# owner. The systemd-resolved stub trap and the loopback filtering went with
# it, which is the point — that knowledge is now written down once.

# ─── AmneziaWG obfuscation parameters ─────────────────────────────────────────
# Nine values. They are not tuning knobs and they are not secrets — they are the
# shape of the packets on the wire, and the ONE rule that matters is that the
# server and every client must carry the identical nine or the tunnel does not
# come up at all. It does not degrade, it does not warn: the handshake is simply
# never recognised. That is why there is exactly one emitter, _awg_params, and
# both the server config and every client config are rendered from it.
#
#   Jc          how many junk packets precede the handshake
#   Jmin/Jmax   the size range those junk packets are drawn from
#   S1          random prefix on the handshake INIT   (len = 148 + S1)
#   S2          random prefix on the handshake RESPONSE (len =  92 + S2)
#   H1..H4      replacements for WireGuard's four fixed message-type bytes
#               (1 = init, 2 = response, 3 = cookie, 4 = transport)
#
# Sources: the parameter semantics and the numeric bounds below are from the
# AmneziaWG project's own documentation and the amneziawg-tools/kernel-module
# repositories, read on 2026-08-29. NOTHING here is copied from them — see the
# licence note in ATTRIBUTIONS.md. Bounds are enforced rather than trusted,
# because an out-of-range value produces a tunnel that silently never connects.
VPN55_AWG_KEYS="jc jmin jmax s1 s2 h1 h2 h3 h4"

# A uniform-ish integer in [min,max]. Modulo bias is real and irrelevant here:
# these values shape packet padding, they are not key material, and the
# alternative is rejection sampling for no security gain. Anything that IS key
# material in this file goes through the protocol's own genkey/genpsk.
_awg_rand() {
    local lo="${1:-0}" hi="${2:-0}" hex n span
    (( hi >= lo )) || { error "_awg_rand: empty range ${lo}..${hi}"; return 1; }
    hex="$(fs_random_hex 4)" || return 1
    n=$(( 0x${hex} ))
    span=$(( hi - lo + 1 ))
    printf '%s' "$(( lo + n % span ))"
}

# Every constraint, checked. Returning 1 here is always better than writing the
# value out: a bad set is not a degraded tunnel, it is a tunnel that never
# handshakes, and the operator has no way to tell that apart from a firewall
# problem, a NAT problem or a wrong endpoint.
_awg_validate() {
    local jc="${1:-}" jmin="${2:-}" jmax="${3:-}" s1="${4:-}" s2="${5:-}"
    local h1="${6:-}" h2="${7:-}" h3="${8:-}" h4="${9:-}"

    local v
    for v in "$jc" "$jmin" "$jmax" "$s1" "$s2" "$h1" "$h2" "$h3" "$h4"; do
        [[ "$v" =~ ^[0-9]+$ ]] || { error "obfuscation parameters must all be whole numbers; got '${v}'."; return 1; }
    done

    (( jc >= 1 && jc <= 128 )) \
        || { error "Jc must be 1-128 (4-12 is the useful band); got ${jc}."; return 1; }
    (( jmin >= 1 )) \
        || { error "Jmin must be at least 1; got ${jmin}."; return 1; }
    (( jmax <= 1280 )) \
        || { error "Jmax must not exceed 1280 or the junk packets fragment; got ${jmax}."; return 1; }
    (( jmin < jmax )) \
        || { error "Jmin (${jmin}) must be less than Jmax (${jmax}) — the range is a range."; return 1; }

    # The prefix is prepended to a packet of known size, so the ceiling is the
    # MTU less that packet: 1280 - 148 for the init, 1280 - 92 for the response.
    (( s1 <= 1132 )) \
        || { error "S1 must not exceed 1132 (1280 - 148, the init packet); got ${s1}."; return 1; }
    (( s2 <= 1188 )) \
        || { error "S2 must not exceed 1188 (1280 - 92, the response packet); got ${s2}."; return 1; }

    # The one non-obvious rule. len(init) = 148 + S1 and len(resp) = 92 + S2, so
    # S1 + 56 == S2 makes the two packets exactly the same size — handing a
    # censor a fresh fixed-length signature, which is the whole thing these
    # parameters exist to destroy.
    (( s1 + 56 != s2 )) \
        || { error "S1 + 56 must not equal S2: that makes the init and response packets"; \
             error "the same length, which is a new fixed signature rather than none."; return 1; }

    # H1..H4 replace the type bytes. 1-4 are WireGuard's own values, so anything
    # in that range is "no obfuscation" for that message type, and duplicates
    # make two message types indistinguishable to the peer.
    local h
    for h in "$h1" "$h2" "$h3" "$h4"; do
        (( h >= 5 && h <= 2147483647 )) \
            || { error "H1-H4 must be 5-2147483647; 1-4 are WireGuard's own type bytes. Got ${h}."; return 1; }
    done
    if [[ "$h1" == "$h2" || "$h1" == "$h3" || "$h1" == "$h4" \
       || "$h2" == "$h3" || "$h2" == "$h4" || "$h3" == "$h4" ]]; then
        error "H1-H4 must all be different from each other."
        return 1
    fi
    return 0
}

# Generate a set for THIS server.
#
# Deliberately random per install rather than the project's published example
# values. If every VPN55 server shipped one recommended set, those nine numbers
# would themselves become the fingerprint — H1..H4 are literally the packet type
# field, so a shared quadruple is a fixed byte at a fixed offset, which is
# precisely what we just finished removing. A per-server draw costs nothing and
# is the difference between hiding WireGuard and advertising VPN55.
_awg_generate() {
    local jc jmin jmax s1 s2 h1 h2 h3 h4

    jc="$(_awg_rand 4 12)"     || return 1
    jmin="$(_awg_rand 8 24)"   || return 1
    jmax="$(_awg_rand 64 320)" || return 1
    s1="$(_awg_rand 15 150)"   || return 1

    # Redraw S2 rather than nudging it: an adjusted value would cluster around
    # the forbidden one, and the whole point is that a watcher learns nothing
    # from the distribution.
    for _ in 1 2 3 4 5 6 7 8; do
        s2="$(_awg_rand 15 150)" || return 1
        (( s1 + 56 != s2 )) && break
        s2=""
    done
    [[ -n "$s2" ]] || { error "could not draw an S2 distinct from S1 + 56."; return 1; }

    # Four distinct type bytes. The space is 2^31 wide, so a collision is a
    # formality — but an un-checked formality is how two message types end up
    # sharing a byte and the peer silently drops half the handshake.
    local -a htypes=()
    local cand dup existing
    while (( ${#htypes[@]} < 4 )); do
        cand="$(_awg_rand 5 2147483647)" || return 1
        dup=0
        for existing in ${htypes[@]+"${htypes[@]}"}; do
            [[ "$cand" == "$existing" ]] && dup=1
        done
        (( dup )) || htypes+=("$cand")
    done
    h1="${htypes[0]}"; h2="${htypes[1]}"; h3="${htypes[2]}"; h4="${htypes[3]}"

    _awg_validate "$jc" "$jmin" "$jmax" "$s1" "$s2" "$h1" "$h2" "$h3" "$h4" || return 1
    printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
        "$jc" "$jmin" "$jmax" "$s1" "$s2" "$h1" "$h2" "$h3" "$h4"
    return 0
}

# The nine [Interface] lines, from the stored settings. THE single emitter: the
# server config and every client config both call this, so they cannot drift
# apart no matter what is edited later. In stock WireGuard mode it prints
# nothing at all, which is what makes it safe to call unconditionally.
_awg_params() {
    _wg_is_awg || return 0
    local k v
    for k in $VPN55_AWG_KEYS; do
        v="$(fs_conf_default "$VPN55_WG_CONF" "awg_${k}" "")"
        [[ -n "$v" ]] || { error "AmneziaWG mode is on but '${k}' is not set — re-run the install."; return 1; }
        # Jc/Jmin/Jmax/S1/S2/H1..H4 — the config keys are capitalised the way
        # awg-tools writes them, and the alignment matches the rest of the file.
        case "$k" in
            jc)   printf '%-10s = %s\n' "Jc"   "$v" ;;
            jmin) printf '%-10s = %s\n' "Jmin" "$v" ;;
            jmax) printf '%-10s = %s\n' "Jmax" "$v" ;;
            s1)   printf '%-10s = %s\n' "S1"   "$v" ;;
            s2)   printf '%-10s = %s\n' "S2"   "$v" ;;
            h1)   printf '%-10s = %s\n' "H1"   "$v" ;;
            h2)   printf '%-10s = %s\n' "H2"   "$v" ;;
            h3)   printf '%-10s = %s\n' "H3"   "$v" ;;
            h4)   printf '%-10s = %s\n' "H4"   "$v" ;;
        esac
    done
    return 0
}

# Settle the mode and, in AmneziaWG mode, the nine parameters — once, at install.
#
# Regenerating them on a re-run would invalidate every client config already
# handed out, silently, because the peers keep their keys and simply stop
# handshaking. So this is stored-value-first like every other setting, and the
# second _install run must not touch it.
_awg_settings_bootstrap() {
    local mode stored
    mode="$(fs_conf_default "$VPN55_WG_CONF" mode "")"

    if [[ -z "$mode" ]]; then
        mode="${VPN55_WG_MODE:-$VPN55_WG_MODE_DEFAULT}"
        info "Transport mode."
        info "  wireguard   stock WireGuard. Works everywhere, and its handshake is a"
        info "              fixed-size packet with a fixed type byte — the cheapest of"
        info "              the three protocols for a censor to block, with no false"
        info "              positives to deter them."
        info "  amneziawg   the same protocol with junk packets and per-server type"
        info "              bytes, so there is no fixed signature to match. Needs the"
        info "              AmneziaWG tools installed, and clients need an app that"
        info "              speaks it. Nothing else changes: same keys, same addresses."
        ask_value mode "Transport mode (wireguard/amneziawg)" "$mode" || return 1
    else
        # Changing mode on a live server moves the config directory, the unit and
        # the binaries, and — because the parameters are part of the client
        # config — invalidates every credential already issued. Refusing is the
        # honest answer; doing it quietly would leave an operator with a server
        # that looks healthy and a user base that cannot connect.
        local wanted="${VPN55_WG_MODE:-}"
        if [[ -n "$wanted" && "$wanted" != "$mode" ]]; then
            error "This server is installed in '${mode}' mode and VPN55_WG_MODE asks for '${wanted}'."
            error "Switching is not an in-place change: it moves the config directory and"
            error "the systemd unit, and every client configuration already issued stops"
            error "working, because the obfuscation parameters are part of those files."
            error "Remove the service and install again in the other mode, then re-issue"
            error "every credential."
            return 1
        fi
    fi

    case "$mode" in
        wireguard|amneziawg) ;;
        *) error "Transport mode must be 'wireguard' or 'amneziawg'; got '${mode}'."; return 1 ;;
    esac
    _wg_conf_set mode "$mode" || return 1

    [[ "$mode" == "amneziawg" ]] || return 0

    # Present already? Validate and keep. Validating on every run is deliberate:
    # these can be hand-edited, and a hand-edited set that breaks a constraint
    # should be caught here rather than by a user who cannot connect.
    stored="$(fs_conf_default "$VPN55_WG_CONF" awg_jc "")"
    if [[ -n "$stored" ]]; then
        local k vals=() v
        for k in $VPN55_AWG_KEYS; do
            v="$(fs_conf_default "$VPN55_WG_CONF" "awg_${k}" "")"
            [[ -n "$v" ]] || { error "obfuscation parameter '${k}' is missing from ${VPN55_WG_CONF}."; return 1; }
            vals+=("$v")
        done
        _awg_validate "${vals[@]}" || return 1
        debug "obfuscation parameters already set"
        return 0
    fi

    local line
    line="$(_awg_generate)" || return 1

    local -a gen=()
    IFS=$'\t' read -r -a gen <<< "$line"
    [[ "${#gen[@]}" -eq 9 ]] || { error "internal: expected nine obfuscation parameters."; return 1; }

    local i=0 k
    for k in $VPN55_AWG_KEYS; do
        _wg_conf_set "awg_${k}" "${gen[$i]}" || return 1
        i=$(( i + 1 ))
    done

    info "Obfuscation parameters generated for this server."
    info "They are baked into every client configuration and must match exactly —"
    info "a client missing them, or carrying another server's, will not connect."
    return 0
}

# Settle every setting once, then never ask again. Precedence is: an existing
# stored value, then an environment override, then the interactive prompt, then
# the default. That order is what makes the second _install run silent.
_wg_settings_bootstrap() {
    _wg_state_dir || return 1

    # Mode first, and not for tidiness: it decides which binaries run, which
    # directory the server config lives in and which systemd unit is enabled, so
    # every accessor called below this line depends on it already being settled.
    _awg_settings_bootstrap || return 1

    local iface port endpoint keepalive
    iface="$(_wg_conf_get iface 2>/dev/null || printf '%s' "$VPN55_WG_IFACE")"
    port="$(_wg_conf_get port 2>/dev/null || printf '%s' "$VPN55_WG_PORT")"
    keepalive="$(_wg_conf_get keepalive 2>/dev/null || printf '%s' "$VPN55_WG_KEEPALIVE")"
    endpoint="$(_wg_conf_get endpoint 2>/dev/null || printf '')"

    if [[ ! "$iface" =~ ^[a-zA-Z0-9_]{1,15}$ ]]; then
        error "Interface name '${iface}' is invalid — letters, digits and underscore, 15 max."
        return 1
    fi
    if [[ ! "$port" =~ ^[0-9]+$ ]] || (( port < 1 || port > 65535 )); then
        error "Listen port '${port}' is not a valid port number."
        return 1
    fi

    # The environment override, before the prompt. It is named in the failure
    # message below, and a documented switch that nothing reads is worse than no
    # switch at all: the operator does exactly what they were told and gets the
    # same error again. This is the only path an unattended install has on a host
    # behind provider NAT, where the detected address is deliberately discarded.
    if [[ -z "$endpoint" ]]; then
        endpoint="${VPN55_WG_ENDPOINT:-}"
    fi

    # The endpoint clients dial. net_public_endpoint returns 2 and a private
    # address when the host is behind provider NAT — that is not a failure to
    # report as one, it is a question only the operator can answer.
    if [[ -z "$endpoint" ]]; then
        local detected="" rc=0
        detected="$(net_public_endpoint)" || rc=$?
        if [[ "$rc" -eq 2 ]]; then
            warn "Detected ${detected}, which is private — clients cannot dial it."
            detected=""
        fi
        ask_value endpoint "Public address or hostname clients will dial" "$detected" || return 1
        if [[ -z "$endpoint" ]]; then
            error "No endpoint. Set VPN55_WG_ENDPOINT, or run this interactively and enter one."
            return 1
        fi
    fi
    case "$endpoint" in
        *[![:alnum:].:_-]*) error "Endpoint '${endpoint}' contains characters that are not valid in a host address."; return 1 ;;
    esac

    _wg_conf_set iface     "$iface"     || return 1
    _wg_conf_set port      "$port"      || return 1
    _wg_conf_set keepalive "$keepalive" || return 1
    _wg_conf_set endpoint  "$endpoint"  || return 1

    # ── Key custody ──
    # Asked once, and the answer is shown on every config this adapter emits.
    # The disclosure is the point: a user is entitled to know whether the server
    # has ever held their private key, and burying that in documentation is the
    # same as not saying it.
    local custody
    custody="$(_wg_conf_get custody 2>/dev/null || printf '')"
    if [[ -z "$custody" ]]; then
        custody="${VPN55_WG_CUSTODY:-server}"
        info "Key custody — who generates a client's private key?"
        info "  server  the server makes it, builds a complete config and shows a QR."
        info "          Fast, works on a phone in fifteen seconds, and the server has"
        info "          held the key. It is erased ${VPN55_WG_KEY_TTL_HOURS}h after issue."
        info "  client  the user's device makes it and sends only the public half."
        info "          The server never holds it; the user has more steps to follow."
        ask_value custody "Default key custody (server/client)" "$custody" || return 1
    fi
    case "$custody" in
        server|client) ;;
        *) error "Key custody must be 'server' or 'client'; got '${custody}'."; return 1 ;;
    esac
    _wg_conf_set custody "$custody" || return 1

    # ── DNS ──
    local dns_choice dns_custom dns
    dns_choice="$(_wg_conf_get dns_choice 2>/dev/null || printf '')"
    if [[ -z "$dns_choice" ]]; then
        dns_choice="${VPN55_WG_DNS_CHOICE:-system}"
        net_resolvers_explain
        ask_value dns_choice "DNS (system/cloudflare/quad9/custom)" "$dns_choice" || return 1
        if [[ "$dns_choice" == "custom" ]]; then
            ask_value dns_custom "Resolver addresses, comma-separated" "${VPN55_WG_DNS:-}" || return 1
        fi
        dns="$(net_resolvers_resolve "$dns_choice" "${dns_custom:-}")" || return 1
    else
        # Already settled. The stored literal is reused rather than resolved
        # again, and that matters most for the `system` choice: re-resolving
        # would read whatever /etc/resolv.conf says today, so a re-run of
        # _install after the host changed resolvers would quietly start issuing
        # configs pointing somewhere else. "Resolved once at install" has to
        # mean once, or it is not a property anyone can rely on.
        dns="$(_wg_conf_get dns 2>/dev/null || printf '')"
        if [[ -z "$dns" ]]; then
            dns="$(net_resolvers_resolve "$dns_choice" "")" || return 1
        fi
    fi

    _wg_conf_set dns_choice "$dns_choice" || return 1
    _wg_conf_set dns        "$dns"        || return 1

    debug "settings: iface=${iface} port=${port} endpoint=${endpoint} custody=${custody} dns=${dns}"
    return 0
}

_wg_server_key_ensure() {
    local key pub
    key="$(_wg_server_key)"
    pub="$(_wg_server_pub)"

    local etc
    etc="$(_wg_etc)"
    fs_ensure_dir "$etc" 0700 || return 1

    if [[ -s "$key" && -s "$pub" ]]; then
        return 0
    fi

    # Regenerating a server key invalidates every peer at once, so this only ever
    # runs when there is no key at all.
    local tool
    tool="$(_wg_tool)"
    ( umask 077; "$tool" genkey > "$key"; ) || { error "cannot generate the server private key"; return 1; }
    "$tool" pubkey < "$key" > "$pub" || { error "cannot derive the server public key"; return 1; }
    chmod 0600 "$key" || { error "cannot set mode on $key"; return 1; }
    chmod 0644 "$pub" || { error "cannot set mode on $pub"; return 1; }
    success "Server keypair generated."
    return 0
}

_wg_server_pubkey() {
    local pub
    pub="$(_wg_server_pub)"
    [[ -r "$pub" ]] || { error "server public key not found at $pub"; return 1; }
    tr -d '[:space:]' < "$pub"
}

# Render the whole server config: the [Interface] section from settings, then
# every existing [Peer] block copied through byte for byte.
#
# There is deliberately no generation timestamp anywhere in this output. A date
# line would make the second _install run produce a different file, and "install
# three times, nothing changes after the first" would be false in exactly the
# way that is hardest to notice.
_wg_render_conf() {
    local iface port key priv existing
    iface="$(_wg_iface)"; port="$(_wg_port)"
    key="$(_wg_server_key)"
    existing="$(_wg_server_conf)"

    local mode quick
    mode="$(_wg_mode)"; quick="$(_wg_quick)"

    priv="$(tr -d '[:space:]' < "$key" 2>/dev/null)" || priv=""
    [[ -n "$priv" ]] || { error "server private key is missing or empty"; return 1; }

    cat <<CONF
# VPN55 — managed ${mode} interface ${iface}. Edited by lib/proto_wireguard.sh.
#
# SaveConfig is OFF on purpose. With it on, ${quick} rewrites this file on every
# 'down' and strips the "# vpn55-cred" comments that tie each peer to a
# credential in the registry — after which nothing can say who a peer belongs to.
#
# There are no PostUp/PostDown rules here. NAT, the forward path and the open
# port are applied through VPN55's firewall ledger under the tag '${VPN55_WG_TAG}',
# so an uninstall reverses exactly what was added. A rule added here instead
# would be invisible to that ledger and would survive the teardown.

[Interface]
Address    = $(_wg_gateway)/24
ListenPort = ${port}
PrivateKey = ${priv}
SaveConfig = false
CONF

    local mtu
    mtu="$(_wg_mtu)"
    if [[ -n "$mtu" ]]; then
        printf 'MTU        = %s\n' "$mtu"
    fi

    # The obfuscation parameters, from the one emitter that also writes them into
    # every client config. Server and client carrying an identical set is not a
    # nicety here — a mismatch means the handshake is never recognised and the
    # tunnel simply never comes up, with nothing logged on either side.
    # Prints nothing at all in stock WireGuard mode.
    _awg_params || return 1

    local peers=""
    if [[ -f "$existing" ]]; then
        peers="$(awk '/^[[:space:]]*\[Peer\]/ { p = 1 } p' "$existing" 2>/dev/null || true)"
    fi
    if [[ -n "$peers" ]]; then
        # The blank line matters. cred_add writes one before each [Peer], so a
        # render that started straight at the first [Peer] would differ from the
        # file on disk by exactly one newline — and every "re-apply" on a server
        # that has peers would then rewrite the config and re-sync a live tunnel
        # for no reason. Idempotence stops at the first credential if this is
        # dropped, which is the point at which nobody is testing it any more.
        printf '\n%s\n' "$peers"
    fi
    return 0
}

# Write the rendered config only when it differs. The comparison is what makes
# the re-run genuinely inert: no write, no syncconf, no restart, no log line.
# Returns 0 and sets VPN55_WG_CONF_CHANGED to 1 or 0.
VPN55_WG_CONF_CHANGED=0
_wg_write_conf() {
    local dest rendered current
    dest="$(_wg_server_conf)"
    rendered="$(_wg_render_conf)" || return 1

    current=""
    if [[ -f "$dest" ]]; then
        current="$(cat "$dest" 2>/dev/null || true)"
    fi

    if [[ "$rendered" == "$current" ]]; then
        VPN55_WG_CONF_CHANGED=0
        debug "server config unchanged"
        return 0
    fi

    if [[ -f "$dest" ]]; then
        printf '%s\n' "$rendered" | fs_replace_in_place "$dest" 0600 || return 1
    else
        printf '%s\n' "$rendered" | fs_write_atomic "$dest" 0600 || return 1
    fi
    VPN55_WG_CONF_CHANGED=1
    return 0
}

# Apply the on-disk config to a running interface without dropping live peers.
# `wg syncconf` diffs rather than replaces, so existing handshakes survive — a
# restart would knock the operator's own device off in the middle of adding one.
_wg_sync() {
    local iface
    iface="$(_wg_iface)"
    _wg_active || return 0

    local tool quick
    tool="$(_wg_tool)"; quick="$(_wg_quick)"
    if "$tool" syncconf "$iface" <("$quick" strip "$iface") 2>/dev/null; then
        return 0
    fi
    warn "${tool} syncconf failed — restarting the interface instead. Live peers will reconnect."
    distro_service_restart "$(_wg_unit)" || return 1
    return 0
}

# A userspace tunnel is selected through the quick wrapper's environment, and the
# only portable place to set it is a unit drop-in: Debian's wg-quick@.service
# reads /etc/default/wg-quick, the RPM one does not.
#
# Both wrappers read the SAME variable — verified against wireguard-tools and
# amneziawg-tools on 2026-08-29, where each does
# `cmd "${WG_QUICK_USERSPACE_IMPLEMENTATION:-<its own default>}" "$INTERFACE"`.
# So the drop-in is identical in both modes and only its path differs.
_wg_userspace_dropin() {
    local impl dir file
    if ! impl="$(_wg_userspace_impl)"; then
        return 0
    fi
    if distro_module_ready "$(_wg_module)"; then
        return 0
    fi

    dir="$(_wg_dropin_dir)"; file="$(_wg_dropin)"
    fs_ensure_dir "$dir" 0755 || return 1

    # No WG_SUDO here. An earlier revision set it; neither wrapper reads it —
    # checked in both upstreams — and a unit that declares a variable nothing
    # consumes is a false lead for whoever debugs this next.
    local want
    want="$(printf '# Written by VPN55. No kernel module on this host.\n[Service]\nEnvironment=WG_QUICK_USERSPACE_IMPLEMENTATION=%s\n' "$impl")"
    if [[ -f "$file" ]] && [[ "$(cat "$file" 2>/dev/null || true)" == "$want" ]]; then
        return 0
    fi

    printf '%s' "$want" | fs_write_atomic "$file" 0644 || return 1
    chmod 0644 "$file" || { error "cannot set mode on $file"; return 1; }
    distro_daemon_reload || return 1
    _wg_conf_set userspace "$impl" || return 1
    info "Userspace tunnel via ${impl}."
    return 0
}

vpn_wireguard_install() {
    distro_require_root || return 1
    vpn_wireguard_available || return 1

    section "$(_wg_label)"

    _wg_settings_bootstrap || return 1
    _wg_install_packages   || return 1

    # Claim before anything is written. The claim is idempotent for the same
    # owner and slot, and a hard error on any conflict — which is the whole
    # reason a second adapter cannot quietly hand out addresses in this /24.
    net_pool_claim "$VPN55_WG_TAG" "$VPN55_WG_SLOT" || return 1

    net_forwarding_enable || return 1

    _wg_server_key_ensure  || return 1
    _wg_write_conf         || return 1
    _wg_userspace_dropin   || return 1

    local port subnet
    port="$(_wg_port)"
    subnet="$(_wg_subnet)" || return 1

    net_fw_open_port    "$VPN55_WG_TAG" udp "$port" || return 1
    net_fw_allow_subnet "$VPN55_WG_TAG" "$subnet"   || return 1
    net_fw_masquerade   "$VPN55_WG_TAG" "$subnet"   || return 1

    local unit
    unit="$(_wg_unit)"
    if ! distro_service_is_enabled "$unit"; then
        distro_service_enable "$unit" || return 1
    elif ! _wg_active; then
        distro_service_start "$unit" || return 1
    elif [[ "$VPN55_WG_CONF_CHANGED" == "1" ]]; then
        _wg_sync || return 1
    fi

    _wg_spool_sweep || true

    success "$(_wg_label) is up on ${subnet} — udp/${port}, endpoint $(_wg_endpoint)."
    info "Key custody: $(_wg_custody)-generated. DNS: $(_wg_dns)."
    local impl
    impl="$(_wg_userspace)"
    if [[ -n "$impl" ]]; then
        info "Tunnel runs in userspace via ${impl} — no kernel module on this host."
    fi
    return 0
}

# ─── Uninstall ────────────────────────────────────────────────────────────────
# Reverses _install in the reverse order it applied things. What it deliberately
# does NOT do is stated out loud rather than left for the operator to discover:
# packages stay unless asked for, and IP forwarding stays on while any other
# adapter still holds a pool slot.
vpn_wireguard_uninstall() {
    distro_require_root || return 1

    local iface unit
    iface="$(_wg_iface)"; unit="$(_wg_unit)"

    section "Removing $(_wg_label)"

    # Registry first, while the peer list is still readable. A credential left
    # marked active for a protocol that no longer exists is the "user exists in
    # two protocols and no longer in the third" failure, arriving by the back
    # door.
    local cred user row
    while IFS=$'\t' read -r cred user _; do
        [[ -n "$cred" ]] || continue
        if row="$(users_cred_find "$cred" 2>/dev/null)"; then
            user="${row%%$'\t'*}"
            users_cred_revoke "$user" "$cred" >/dev/null 2>&1 \
                || warn "could not mark credential '${cred}' revoked for '${user}'"
        fi
        net_pool_free "$VPN55_WG_TAG" "$cred" || warn "could not release the lease for '${cred}'"
        fs_shred "${VPN55_WG_SPOOL}/${cred}.conf" || true
    done < <(_wg_peers 2>/dev/null || true)

    distro_service_disable "$unit" || warn "could not disable ${unit}"

    # A stopped unit does not always take the interface down — an interface left
    # up after wg-quick has gone keeps forwarding traffic that nothing manages.
    if ip link show "$iface" >/dev/null 2>&1; then
        "$(_wg_quick)" down "$iface" >/dev/null 2>&1 || ip link delete "$iface" >/dev/null 2>&1 || true
    fi

    net_fw_revoke_tag "$VPN55_WG_TAG" || warn "some firewall rules could not be removed — check ${VPN55_FW_STATE}"
    net_pool_release  "$VPN55_WG_TAG" || warn "could not release the pool claim"

    local dropin dropin_dir
    dropin="$(_wg_dropin)"; dropin_dir="$(_wg_dropin_dir)"
    if [[ -f "$dropin" ]]; then
        rm -f "$dropin" || { error "cannot remove $dropin"; return 1; }
        rmdir "$dropin_dir" 2>/dev/null || true
        distro_daemon_reload || true
    fi

    local conf key pub
    conf="$(_wg_server_conf)"; key="$(_wg_server_key)"; pub="$(_wg_server_pub)"
    fs_shred "$conf" || true
    fs_shred "$key"  || true
    if [[ -f "$pub" ]]; then
        rm -f "$pub" || { error "cannot remove $pub"; return 1; }
    fi

    if [[ -d "$VPN55_WG_SPOOL" ]]; then
        local spooled
        for spooled in "$VPN55_WG_SPOOL"/*.conf; do
            [[ -f "$spooled" ]] || continue
            fs_shred "$spooled" || true
        done
        rmdir "$VPN55_WG_SPOOL" 2>/dev/null || true
    fi
    if [[ -f "$VPN55_WG_CONF" ]]; then
        rm -f "$VPN55_WG_CONF" || { error "cannot remove $VPN55_WG_CONF"; return 1; }
    fi
    rmdir "$VPN55_WG_STATE" 2>/dev/null || true

    # Forwarding is host-global and shared. Turning it off while another adapter
    # is still installed would take that protocol's traffic down, and the pool
    # claims are the protocol-neutral way to ask whether anyone else is left.
    local remaining
    remaining="$(net_pool_claims 2>/dev/null || true)"
    if [[ -z "$remaining" ]]; then
        net_forwarding_disable || warn "could not remove the forwarding sysctl file"
    else
        info "IP forwarding left on — another tunnel service still holds a pool slot."
    fi

    # Only ever remove what this adapter installed. In AmneziaWG mode the tooling
    # came from the operator, by hand, from outside any package manager we drove
    # — uninstalling something we did not install is not "reversing the install".
    if [[ "$VPN55_WG_PURGE_PACKAGES" == "1" ]] && ! _wg_is_awg; then
        local -a pkgs=()
        mapfile -t pkgs < <(_wg_packages) || pkgs=()
        if [[ ${#pkgs[@]} -gt 0 ]]; then
            distro_pkg_remove "${pkgs[@]}" || warn "package removal failed — remove them by hand if you want them gone"
        fi
    elif _wg_is_awg; then
        info "The AmneziaWG tooling was installed by hand and is left alone."
    else
        info "Packages left installed. Set VPN55_WG_PURGE_PACKAGES=1 to remove them too."
    fi

    success "$(_wg_label) removed — NAT, forward and port rules revoked from the ledger."
    return 0
}

# ─── Restart ──────────────────────────────────────────────────────────────────
# The seventh helper verb, and the one an operator reaches for when a tunnel is
# wedged. It is deliberately NOT `_install` re-run: a re-apply rewrites config
# and may change nothing, while this is the blunt instrument that always cycles
# the daemon. Conflating them would mean an operator asking to restart a stuck
# service silently gets a config rewrite instead.
#
# The disruption is declared in _capabilities so the caller can warn BEFORE the
# operator confirms — the same ordering the revocation notice needed, for the
# same reason: the disruption is the thing being decided about.
#
# Bringing the interface down drops every session. They come back on their own —
# the transport re-handshakes without the user touching anything — but "comes
# back by itself" is not the same as "was never interrupted", and reporting the
# second would be a lie an operator only discovers mid-call.
vpn_wireguard_restart() {
    distro_require_root || return 1
    _wg_installed || { error "$(_wg_label) is not installed on this host."; return 1; }

    local unit
    unit="$(_wg_unit)"

    if ! distro_service_restart "$unit"; then
        printf 'restarted\t%s\tfailed\tsessions-dropped\t%s\n' \
            "$VPN55_WG_TAG" "the service did not restart; it may now be stopped"
        return 1
    fi

    # `systemctl restart` returning 0 means the job was accepted, not that the
    # interface came up: a wg-quick unit that fails in PostUp exits non-zero and
    # systemd reports the restart as done. Re-reading the state is the only way
    # to answer the question the caller actually asked.
    if ! _wg_active; then
        printf 'restarted\t%s\tfailed\tsessions-dropped\t%s\n' \
            "$VPN55_WG_TAG" "the restart was accepted but the interface is not up"
        error "The service restarted and then stopped. Check: journalctl -u ${unit}"
        return 1
    fi

    printf 'restarted\t%s\tok\tsessions-dropped\t%s\n' \
        "$VPN55_WG_TAG" "the interface is up; peers re-handshake on their own"
    success "$(_wg_label) restarted — the interface is up."
    return 0
}

# ─── Peers ────────────────────────────────────────────────────────────────────
# One record per peer, read out of the server config:
#
#   cred_id  user  public_key  address  created  custody
#
# Emitted at the START of the next [Peer] rather than off the last field of the
# current one, so re-ordering a key inside a block cannot silently drop a peer.
#
# The values are read as awk's $NF, which is only safe because no field here can
# contain whitespace: users_validate_name forbids it in a user name and
# users_validate_cred_id forbids it in a credential id. That is a contract across
# two files — loosen either charset and this parser truncates at the first space.
_wg_peers() {
    local conf
    conf="$(_wg_server_conf)"
    [[ -f "$conf" ]] || return 0

    awk '
        function flush() {
            if (cred != "") print cred "\t" user "\t" pub "\t" ip "\t" created "\t" custody
        }
        /^[[:space:]]*\[Peer\]/      { flush(); cred=user=pub=ip=created=custody=""; inpeer=1; next }
        /^[[:space:]]*\[Interface\]/ { flush(); cred=user=pub=ip=created=custody=""; inpeer=0; next }
        inpeer && /^#[[:space:]]*vpn55-cred[[:space:]]*=/    { cred=$NF }
        inpeer && /^#[[:space:]]*vpn55-user[[:space:]]*=/    { user=$NF }
        inpeer && /^#[[:space:]]*vpn55-added[[:space:]]*=/   { created=$NF }
        inpeer && /^#[[:space:]]*vpn55-custody[[:space:]]*=/ { custody=$NF }
        inpeer && /^[[:space:]]*PublicKey[[:space:]]*=/      { pub=$NF }
        inpeer && /^[[:space:]]*AllowedIPs[[:space:]]*=/     { ip=$NF }
        END { flush() }
    ' "$conf" 2>/dev/null || true
}

_wg_peer_field() {
    local cred="${1:-}" field="${2:-}"
    _wg_peers | awk -F'\t' -v c="$cred" -v f="$field" '$1 == c { print $f; exit }'
}

_wg_peer_exists() {
    local cred="${1:-}" ids
    [[ -n "$cred" ]] || return 1
    ids="$(_wg_peers | cut -f1)"
    str_has_line "$ids" "$cred"
}

# Stream the server config with one named [Peer] block removed. Buffers each
# block until it knows whether to keep it, because the identifying comment is
# inside the block and not on its first line.
_wg_strip_peer_stream() {
    local cred="${1:-}"
    local in_peer=0 buf="" drop=0 line trimmed
    while IFS= read -r line || [[ -n "$line" ]]; do
        trimmed="${line//[$'\t\r ']/}"
        if [[ "$trimmed" == "[Peer]" ]]; then
            if (( in_peer )) && (( ! drop )); then printf '%s' "$buf"; fi
            in_peer=1; buf="$line"$'\n'; drop=0; continue
        fi
        if (( in_peer )); then
            buf+="$line"$'\n'
            if [[ "$trimmed" == "#vpn55-cred=${cred}" ]]; then drop=1; fi
        else
            printf '%s\n' "$line"
        fi
    done
    if (( in_peer )) && (( ! drop )); then printf '%s' "$buf"; fi
}

# ─── The key spool ────────────────────────────────────────────────────────────
# Server-generated private keys live here, mode 0600, root-only, and only until
# the TTL expires. This is the whole of the custody compromise: long enough that
# the panel can issue now and the user can scan this evening, short enough that
# the exit node is not a permanent store of every user's identity.
#
# Swept on every read path rather than by a timer. A timer is another unit to
# install, another thing to fail silently, and the sweep costs one `find`.
_wg_spool_sweep() {
    [[ -d "$VPN55_WG_SPOOL" ]] || return 0
    local ttl="$VPN55_WG_KEY_TTL_HOURS"
    [[ "$ttl" =~ ^[0-9]+$ ]] || ttl=24

    local f
    if [[ "$ttl" -eq 0 ]]; then
        for f in "$VPN55_WG_SPOOL"/*.conf; do
            [[ -f "$f" ]] || continue
            fs_shred "$f" || true
        done
        return 0
    fi

    while IFS= read -r f; do
        [[ -n "$f" ]] || continue
        debug "spool: shredding expired ${f##*/}"
        fs_shred "$f" || true
    done < <(find "$VPN55_WG_SPOOL" -maxdepth 1 -type f -name '*.conf' -mmin "+$(( ttl * 60 ))" 2>/dev/null || true)
    return 0
}

_wg_spool_path() { printf '%s/%s.conf' "$VPN55_WG_SPOOL" "${1:-}"; }

_wg_spool_held() {
    local cred="${1:-}"
    [[ -n "$cred" ]] || return 1
    [[ -s "$(_wg_spool_path "$cred")" ]]
}

# ─── Credentials ──────────────────────────────────────────────────────────────
# Ids are opaque and carry no user name: they end up in file names in the spool
# and in every log line the panel writes, and a name in either is a name that
# outlives the account.
_wg_new_cred_id() {
    local raw
    raw="$(fs_random_hex 6)" || return 1
    printf 'wg-%s' "$raw"
}

# vpn_wireguard_cred_add <user> [pubkey=<client public key>]
#
# The option is the one this adapter declares in _capabilities. It used to be a
# bare second positional argument, which meant the contract's cred_add had a
# WireGuard-shaped parameter in it and vpn55.sh was prompting every protocol
# for a public key. Named options let an adapter take something specific without
# the caller knowing what.
#
# With a public key, the server never generates or holds a private key for this
# credential — that is the client-generated path, available whatever the default
# custody setting is. Without one, the default applies.
#
# Prints the credential id on stdout and nothing else. The one-time config goes
# to the spool; the caller reads it back through _client_config, which is the
# same path the panel and the portal use.
vpn_wireguard_cred_add() {
    local user="${1:-}"
    shift || true

    _wg_installed || { error "$(_wg_label) is not installed on this host."; return 1; }
    [[ -n "$user" ]] || { error "vpn_wireguard_cred_add <user> [pubkey=…]"; return 1; }
    users_exists "$user" || { error "No such user '${user}' in the registry."; return 1; }

    # An unknown option is an error rather than something to skip. Silently
    # ignoring one means a panel drops a field an operator filled in and reports
    # success, which is the worst of the three possible behaviours.
    local given_pub="" opt
    for opt in "$@"; do
        [[ -n "$opt" ]] || continue
        case "$opt" in
            pubkey=*) given_pub="${opt#pubkey=}" ;;
            *)
                error "Unknown credential option '${opt%%=*}' for this protocol."
                error "Ask it what it accepts with the 'capabilities' verb."
                return 1 ;;
        esac
    done

    local enabled
    enabled="$(users_get "$user" enabled 2>/dev/null)" || enabled="1"
    if [[ "$enabled" != "1" ]]; then
        error "User '${user}' is disabled — enable them before issuing a credential."
        return 1
    fi

    _wg_state_dir || return 1

    local custody="server" cpriv="" cpub=""
    if [[ -n "$given_pub" ]]; then
        # WireGuard keys are 32 bytes of base64: 43 characters and a '='.
        if [[ ! "$given_pub" =~ ^[A-Za-z0-9+/]{43}=$ ]]; then
            error "'${given_pub}' is not a WireGuard public key (44 characters of base64)."
            return 1
        fi
        custody="client"
        cpub="$given_pub"
    else
        custody="$(_wg_custody)"
        if [[ "$custody" == "client" ]]; then
            error "This server issues client-generated credentials."
            error "Generate a keypair on the device ('$(_wg_tool) genkey | tee private | $(_wg_tool) pubkey')"
            error "and pass the PUBLIC key as the second argument."
            return 1
        fi
        cpriv="$("$(_wg_tool)" genkey)" || { error "cannot generate a client private key"; return 1; }
        cpub="$("$(_wg_tool)" pubkey <<< "$cpriv")" || { error "cannot derive the client public key"; return 1; }
    fi

    local known_keys
    known_keys="$(_wg_peers | cut -f3)"
    if str_has_line "$known_keys" "$cpub"; then
        error "That public key is already configured on this server."
        return 1
    fi

    # A pre-shared key is a symmetric layer over the normal handshake. It is
    # shared by construction, so it is server-generated even on the
    # client-custody path — that is not the user's private key and holding it
    # does not weaken the custody claim.
    local psk spub
    psk="$("$(_wg_tool)" genpsk)" || { error "cannot generate a pre-shared key"; return 1; }
    spub="$(_wg_server_pubkey)" || return 1

    local cred=""
    for _ in 1 2 3 4 5; do
        cred="$(_wg_new_cred_id)" || return 1
        users_cred_add "$user" "$cred" "$VPN55_WG_TAG" >/dev/null 2>&1 && break
        cred=""
    done
    [[ -n "$cred" ]] || { error "could not register a unique credential id after five tries."; return 1; }

    local ip
    if ! ip="$(net_pool_alloc "$VPN55_WG_TAG" "$cred")"; then
        users_cred_revoke "$user" "$cred" >/dev/null 2>&1 || true
        error "No address left in $(_wg_subnet)."
        return 1
    fi

    local conf
    conf="$(_wg_server_conf)"
    {
        printf '\n[Peer]\n'
        printf '# vpn55-cred = %s\n'    "$cred"
        printf '# vpn55-user = %s\n'    "$user"
        printf '# vpn55-added = %s\n'   "$(_wg_now)"
        printf '# vpn55-custody = %s\n' "$custody"
        printf 'PublicKey    = %s\n'    "$cpub"
        printf 'PresharedKey = %s\n'    "$psk"
        printf 'AllowedIPs   = %s/32\n' "$ip"
    } >> "$conf" || {
        error "cannot append the peer to $conf"
        net_pool_free "$VPN55_WG_TAG" "$cred" || true
        users_cred_revoke "$user" "$cred" >/dev/null 2>&1 || true
        return 1
    }
    chmod 0600 "$conf" || { error "cannot set mode on $conf"; return 1; }

    # The spool holds the emitted config BODY, complete with the private key on
    # the server-custody path. On the client path there is no private key to
    # hold and the same file is simply written without one.
    #
    # The comment header is NOT spooled. It is prose addressed to the person who
    # will read this file, so it is rendered in their language at the moment it
    # is handed over — which is the only moment anyone knows what that language
    # is. Spooling it would freeze one translation into a file that lives for
    # hours and is then fetched by somebody else.
    local spool
    spool="$(_wg_spool_path "$cred")"
    _wg_build_client_body "$ip" "$psk" "$spub" "$custody" "$cpriv" \
        | fs_write_atomic "$spool" 0600 || { error "cannot spool the client config"; return 1; }

    _wg_sync || warn "the peer is in the config but the live interface was not updated"
    _wg_spool_sweep || true

    printf '%s' "$cred"
    return 0
}

# vpn_wireguard_cred_remove <cred_id>
#
# Prints, on stdout, one record in the shape every adapter uses:
#
#   revoked  <tag>  <cred_id>  <latency>  <seconds>
#
# latency is a closed vocabulary — `immediate` here, `crl` for the certificate
# protocols — and seconds is the worst-case delay before the revocation actually
# bites. One contract verb hides three genuinely different operations; the panel
# reads this rather than assuming all three are instant.
vpn_wireguard_cred_remove() {
    local cred="${1:-}"
    [[ -n "$cred" ]] || { error "vpn_wireguard_cred_remove <cred_id>"; return 1; }
    _wg_installed || { error "$(_wg_label) is not installed on this host."; return 1; }
    _wg_peer_exists "$cred" || { error "No credential '${cred}' on this server."; return 1; }

    local iface conf pub
    iface="$(_wg_iface)"; conf="$(_wg_server_conf)"
    pub="$(_wg_peer_field "$cred" 3)"

    # The live interface first. A peer removed only from the file keeps working
    # until something restarts the tunnel, which can be weeks — and "revoked" in
    # the panel while the device still connects is the worst possible lie for a
    # product whose whole claim is that revocation is instant.
    if [[ -n "$pub" ]] && _wg_active; then
        "$(_wg_tool)" set "$iface" peer "$pub" remove 2>/dev/null \
            || warn "could not remove the peer from the running interface"
    fi

    _wg_strip_peer_stream "$cred" < "$conf" | fs_replace_in_place "$conf" 0600 || return 1

    fs_shred "$(_wg_spool_path "$cred")" || true
    net_pool_free "$VPN55_WG_TAG" "$cred" || warn "could not release the address lease"

    local row user
    if row="$(users_cred_find "$cred" 2>/dev/null)"; then
        user="${row%%$'\t'*}"
        users_cred_revoke "$user" "$cred" >/dev/null 2>&1 \
            || warn "the peer is gone but the registry still shows '${cred}' active"
    fi

    printf 'revoked\t%s\t%s\timmediate\t0\n' "$VPN55_WG_TAG" "$cred"
    success "Credential '${cred}' revoked — the device is off the tunnel now."
    return 0
}

# One record per line:
#
#   cred_id  user  state  address  created  custody  key_held
#
# state is the registry's vocabulary (active / revoked); key_held says whether a
# complete config with a private key can still be handed out, which is what the
# panel needs to decide between "Download" and "Rotate".
vpn_wireguard_cred_list() {
    _wg_spool_sweep || true

    local cred user pub ip created custody state row held
    while IFS=$'\t' read -r cred user pub ip created custody; do
        [[ -n "$cred" ]] || continue
        state="active"
        if row="$(users_cred_find "$cred" 2>/dev/null)"; then
            state="${row##*$'\t'}"
        else
            state="unregistered"
        fi
        if _wg_spool_held "$cred"; then held=1; else held=0; fi
        printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
            "$cred" "$user" "$state" "${ip%%/*}" "$created" "${custody:-server}" "$held"
    done < <(_wg_peers)
    return 0
}

# ─── Client config ────────────────────────────────────────────────────────────
#
# The file is built in two halves, and the split is an i18n decision rather than
# a tidiness one.
#
#   _wg_build_client_header  prose, addressed to the person who will read it.
#                            Translated. Rendered at the moment of handover,
#                            because that is the only moment anyone knows which
#                            language to render it in.
#   _wg_build_client_body    the tunnel itself. Not prose, not translated, and
#                            byte-for-byte what the client parser consumes.
#
# Only the body is spooled. Freezing one language into a file that lives for
# hours and is then fetched by somebody else would make the credential's
# language a property of who ISSUED it.

# _wg_build_client_header <cred> <user> <custody> [locale]
_wg_build_client_header() {
    local cred="${1:-}" user="${2:-}" custody="${3:-server}" locale="${4:-}"
    local tag="$VPN55_WG_TAG"

    i18n_render_comments '# ' "$tag" "$locale" header \
        "cred=${cred}" "user=${user}" || return 1
    printf '#\n'

    if [[ "$custody" == "client" ]]; then
        i18n_render_comments '# ' "$tag" "$locale" custody.client || return 1
    else
        i18n_render_comments '# ' "$tag" "$locale" custody.server \
            "ttl_hours=${VPN55_WG_KEY_TTL_HOURS}" || return 1
    fi

    i18n_render_comments '# ' "$tag" "$locale" routing || return 1

    if _wg_is_awg; then
        i18n_render_comments '# ' "$tag" "$locale" transport.awg || return 1
    fi
    return 0
}

# _wg_build_client_body <ip> <psk> <spub> <custody> <cpriv>
#
# Takes no credential id and no user name: nothing in the body names either
# of them. They belonged to the header, and the header is now elsewhere.
_wg_build_client_body() {
    local ip="${1:-}" psk="${2:-}" spub="${3:-}"
    local custody="${4:-server}" cpriv="${5:-}"
    local endpoint port dns keepalive mtu
    endpoint="$(_wg_endpoint)"; port="$(_wg_port)"; dns="$(_wg_dns)"
    keepalive="$(_wg_keepalive)"; mtu="$(_wg_mtu)"

    printf '[Interface]\n'

    if [[ "$custody" == "client" || -z "$cpriv" ]]; then
        printf '# vpn55: private-key-not-held\n'
        printf 'PrivateKey = REPLACE_WITH_YOUR_PRIVATE_KEY\n'
    else
        printf 'PrivateKey = %s\n' "$cpriv"
    fi

    printf 'Address    = %s/32\n' "${ip%%/*}"
    if [[ -n "$dns" ]]; then
        printf 'DNS        = %s\n' "${dns//,/, }"
    fi
    if [[ -n "$mtu" ]]; then
        printf 'MTU        = %s\n' "$mtu"
    fi

    # Same emitter as the server config, so the two halves cannot drift. This is
    # the requirement the whole mode turns on: identical on both ends or the
    # tunnel never handshakes.
    _awg_params || return 1

    printf '\n[Peer]\n'
    printf 'PublicKey    = %s\n' "$spub"
    printf 'PresharedKey = %s\n' "$psk"
    printf 'Endpoint     = %s:%s\n' "$endpoint" "$port"
    printf 'AllowedIPs   = 0.0.0.0/0, ::/0\n'
    # Mobile carriers and home routers drop an idle UDP mapping within a minute
    # or two. Without a keepalive the tunnel looks connected and the first
    # request after a pause hangs until the client happens to re-handshake.
    printf 'PersistentKeepalive = %s\n' "$keepalive"
    return 0
}

# vpn_wireguard_artifacts <cred_id> — one record per line:
#
#   artifact  <id>  <label>  <filename>  <encoding>  <qr>  <note>
#
# This adapter has exactly one artifact, which is why the contract got away with
# assuming a single unnamed config until a protocol with four turned up. It is
# text and it is small enough to scan, so it is the only artifact in the project
# that sets qr to 1.
#
# The qr flag is not "is this a string" — it is "will a camera actually resolve
# this". Getting that wrong is worse than omitting the code, because a QR that
# imports a broken tunnel looks like it worked.
vpn_wireguard_artifacts() {
    local cred="${1:-}"
    [[ -n "$cred" ]] || { error "vpn_wireguard_artifacts <cred_id>"; return 1; }
    _wg_peer_exists "$cred" || { error "No credential '${cred}' on this server."; return 1; }
    _wg_spool_sweep || true

    local note qr
    if _wg_spool_held "$cred"; then
        qr=1
        note="Complete and ready to import. Scan it with the WireGuard app or save it as a .conf file."
    else
        # Past the TTL the private key is gone, so the config still describes the
        # tunnel but cannot connect until the holder fills their key in. A QR of
        # that imports a tunnel that fails, so the flag goes to 0 — the artifact
        # is still worth handing over, just not worth photographing.
        qr=0
        note="The private key has been erased, so this needs the holder's own key filled in before it will connect."
    fi

    printf 'artifact\tconf\tWireGuard tunnel configuration\tvpn55-%s.conf\ttext\t%s\t%s\n' \
        "$cred" "$qr" "$note"
    return 0
}

# vpn_wireguard_client_config <cred_id> [artifact] [locale] — config on stdout.
#
# While the spool entry lives, this is the complete file. After the TTL it is the
# same file with the private key replaced by a placeholder and a
# `# vpn55: private-key-not-held` marker, so the panel can tell the two apart
# without parsing prose. It stays exit 0 in both cases: a config the user can
# complete themselves is a useful answer, not an error.
#
# The locale is the third positional argument on every adapter, and it reaches
# here from a caller that does not know which protocol it is talking to — a
# language tag is not protocol vocabulary. An unknown or absent tag renders in
# the default locale rather than failing; somebody still needs the file.
vpn_wireguard_client_config() {
    local cred="${1:-}" want="${2:-conf}" locale="${3:-}"
    [[ -n "$cred" ]] || { error "vpn_wireguard_client_config <cred_id> [artifact] [locale]"; return 1; }
    _wg_installed || { error "$(_wg_label) is not installed on this host."; return 1; }

    # There is only one, but naming a different one has to fail loudly rather
    # than quietly return this one — a caller that asked for something else has
    # a bug, and handing it a WireGuard config would hide that.
    if [[ -n "$want" && "$want" != "conf" ]]; then
        error "'${want}' is not an artifact this protocol produces."
        error "Ask it what it has with the 'artifacts' verb."
        return 1
    fi

    _wg_spool_sweep || true
    _wg_peer_exists "$cred" || { error "No credential '${cred}' on this server."; return 1; }

    local user ip custody psk spub
    user="$(_wg_peer_field "$cred" 2)"
    custody="$(_wg_peer_field "$cred" 6)"

    # The header goes out in front of BOTH paths below, and is built here rather
    # than inside either of them so that the spooled and the rebuilt config
    # cannot end up carrying different prose.
    _wg_build_client_header "$cred" "$user" "${custody:-server}" "$locale" || return 1

    local spool
    spool="$(_wg_spool_path "$cred")"
    if [[ -s "$spool" ]]; then
        printf '\n'
        cat "$spool" || { error "cannot read the spooled config for '${cred}'"; return 1; }
        return 0
    fi

    ip="$(_wg_peer_field "$cred" 4)"
    spub="$(_wg_server_pubkey)" || return 1

    # The pre-shared key is read back out of the server config: it is a shared
    # secret, not the user's private key, so re-emitting it is exactly right.
    psk="$(awk -v c="# vpn55-cred = ${cred}" '
        $0 == c { f = 1 } f && /^[[:space:]]*PresharedKey[[:space:]]*=/ { print $NF; exit }
    ' "$(_wg_server_conf)" 2>/dev/null || true)"

    if [[ "${custody:-server}" == "server" ]]; then
        warn "The private key for '${cred}' has been erased — this config needs it filled in."
        warn "If the user no longer has it, revoke this credential and issue a new one."
    fi

    printf '\n'
    _wg_build_client_body "$ip" "$psk" "$spub" "${custody:-server}" ""
    return 0
}

# ─── Status ───────────────────────────────────────────────────────────────────
# The uniform shape. Field 1 is the record type, so a reader never has to guess
# from the field count, and the second field is always the adapter tag so the
# panel can concatenate every adapter's output into one stream.
#
#   service  <tag>  <state>  <enabled>  <listen>  <since>  <cred_count>
#   cred     <tag>  <cred_id>  <user>  <state>  <address>  <rx>  <tx>  <handshake>  <endpoint>
#   note     <tag>  <severity>  <message>
#
#   state      absent | stopped | running   (closed vocabulary, all protocols)
#   enabled    1 | 0  — starts at boot
#   listen     a display string, not necessarily one port: a protocol that
#              serves two writes both, and the reader only ever prints it.
#   since      unix epoch the service came up, or -
#   rx / tx    bytes as the protocol reports them RIGHT NOW, or - when unknown.
#              Every protocol resets these; the collector accumulates. `-` means
#              "no reading", which is not the same as 0 and must not be treated
#              as a counter reset.
#   handshake  unix epoch of the last proof this credential was live.
#              0 = never, as a FACT.  - = no reading.
#              This adapter can tell those apart — the kernel answers 0 for a
#              peer that has never completed a handshake — so it never emits -.
#              An adapter whose daemon keeps no history must emit - rather than
#              claiming a 0 it cannot support.
#              Always an absolute time, never a formatted age: only the panel
#              knows the viewer's locale.
#   endpoint   the peer's current remote address, or -. LIVE state only. It is
#              not retained anywhere and the collector must not persist it —
#              docs/security-model.md §2 says VPN55 keeps no per-user connection
#              IP history.
#   note       severity is info | warn | crit. This record exists so an adapter
#              can surface something specific — a degraded mode, an expiring
#              credential store — without the panel learning what it means.
#              A reader that does not understand notes ignores the line, which
#              is why the record type is field 1 everywhere.
vpn_wireguard_status() {
    _wg_spool_sweep || true

    local tag="$VPN55_WG_TAG"
    local iface port state enabled since count
    iface="$(_wg_iface)"; port="$(_wg_port)"

    if ! _wg_installed; then
        printf 'service\t%s\tabsent\t0\tudp/%s\t-\t0\n' "$tag" "$port"
        return 0
    fi

    if _wg_active; then state="running"; else state="stopped"; fi
    if distro_service_is_enabled "$(_wg_unit)"; then enabled=1; else enabled=0; fi

    since="-"
    if [[ "$state" == "running" ]] && distro_has_systemd; then
        local stamp
        stamp="$(systemctl show -p ActiveEnterTimestamp --value "$(_wg_unit)" 2>/dev/null || true)"
        if [[ -n "$stamp" ]]; then
            since="$(date -d "$stamp" +%s 2>/dev/null || printf '-')"
        fi
    fi

    _wg_notes || true

    # `wg show <if> dump` prints the interface PRIVATE key in column 1 of the
    # first line and every peer's PRE-SHARED key in column 2 of the rest. Columns
    # are selected explicitly and the first line is skipped for exactly that
    # reason — never widen this to $0.
    declare -A rx tx hs ep
    if [[ "$state" == "running" ]]; then
        local d_pub d_ep d_hs d_rx d_tx
        while IFS=$'\t' read -r d_pub d_ep d_hs d_rx d_tx; do
            [[ -n "$d_pub" ]] || continue
            ep["$d_pub"]="$d_ep"
            hs["$d_pub"]="$d_hs"
            rx["$d_pub"]="$d_rx"
            tx["$d_pub"]="$d_tx"
        done < <("$(_wg_tool)" show "$iface" dump 2>/dev/null \
                 | awk 'NR > 1 { print $1 "\t" $3 "\t" $5 "\t" $6 "\t" $7 }' || true)
    fi

    local peers
    peers="$(_wg_peers)"
    count="$(printf '%s' "$peers" | grep -c . || true)"
    printf 'service\t%s\t%s\t%s\tudp/%s\t%s\t%s\n' "$tag" "$state" "$enabled" "$port" "$since" "${count:-0}"

    [[ -n "$peers" ]] || return 0

    local cred user pub ip created _custody cstate row
    while IFS=$'\t' read -r cred user pub ip created _custody; do
        [[ -n "$cred" ]] || continue
        cstate="unregistered"
        if row="$(users_cred_find "$cred" 2>/dev/null)"; then
            cstate="${row##*$'\t'}"
        fi
        printf 'cred\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
            "$tag" "$cred" "$user" "$cstate" "${ip%%/*}" \
            "${rx[$pub]:--}" "${tx[$pub]:--}" \
            "${hs[$pub]:-0}" \
            "$( [[ -n "${ep[$pub]:-}" && "${ep[$pub]}" != "(none)" ]] && printf '%s' "${ep[$pub]}" || printf -- '-' )"
    done <<< "$peers"
    return 0
}

# Facts worth surfacing that are neither per-credential nor "is the service up".
# The panel prints these without knowing what any of them mean.
_wg_notes() {
    local tag="$VPN55_WG_TAG" impl held

    # Which transport mode is running, and what it costs. The stock mode is the
    # one that needs saying: it works perfectly and it is the single easiest
    # thing on this server for a censor to block, which is not a fact an
    # operator will discover on their own until their users cannot connect.
    # docs/circumvention.md §5 is where the reasoning lives.
    if _wg_is_awg; then
        printf 'note\t%s\tinfo\t%s\n' "$tag" \
            "Obfuscated transport is active: junk packets and per-server message-type values, so there is no fixed handshake signature to match on. Clients need an app that speaks it, and the parameters in each config must be carried exactly as issued."
    else
        printf 'note\t%s\twarn\t%s\n' "$tag" \
            "This transport has a fixed-size handshake with a fixed type byte, so it can be blocked by signature alone, with no false positives to deter anyone. If your users are on a filtered network, reinstall in obfuscated mode — it changes nothing else."
    fi

    impl="$(_wg_userspace)"
    if [[ -n "$impl" ]]; then
        printf 'note\t%s\twarn\t%s\n' "$tag" \
            "This host has no kernel module, so the tunnel runs in userspace via ${impl}. It works, at noticeably more CPU per gigabit."
    fi

    # An operator is entitled to know the box is currently holding private keys,
    # because it is only true some of the time and it is the whole substance of
    # the key-custody promise.
    held="$(find "$VPN55_WG_SPOOL" -maxdepth 1 -type f -name '*.conf' 2>/dev/null | grep -c . || true)"
    if [[ "${held:-0}" -gt 0 ]]; then
        printf 'note\t%s\tinfo\t%s\n' "$tag" \
            "${held} client configuration(s) are still retrievable, which means this server is still holding those private keys. Each is erased ${VPN55_WG_KEY_TTL_HOURS}h after it was issued."
    fi
    return 0
}

# ─── Registration ─────────────────────────────────────────────────────────────
# vpn55.sh sources every lib/proto_*.sh by glob and each adapter announces
# itself. The guard is for the case where this file is sourced on its own — a
# test harness, or a panel-side check — where the registry does not exist.
if declare -F vpn_adapter_register >/dev/null 2>&1; then
    vpn_adapter_register "$VPN55_WG_TAG" "WireGuard" || true
fi
