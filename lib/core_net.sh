# shellcheck shell=bash
#
# lib/core_net.sh — IP forwarding, NAT, the firewall façade, and the IP pool
# allocator.
#
# ── The firewall rule ─────────────────────────────────────────────────────────
# Exactly ONE backend is used on a given host. It is chosen once, written to
# $VPN55_ETC/net.conf, and every rule from every caller goes through the net_fw_*
# verbs below — never through a raw iptables/nft call somewhere else. Mixing two
# backends is how a rule survives an uninstall: the rule is added through one and
# the teardown looks for it in the other.
#
# Backends carry different amounts of native bookkeeping (ufw has rule comments,
# firewalld has none, nftables has handles), so none of them is trusted to
# remember what VPN55 added. A ledger at $VPN55_ETC/fw.state records every applied
# rule against a caller-supplied tag, and net_fw_revoke_tag reverses exactly what
# is written there. That ledger — not the backend — is what makes an uninstall
# complete.
#
# Every rule verb is idempotent, because every adapter's _install is required to
# be re-runnable and each re-run replays the same calls. The ledger refuses a
# duplicate row and the nftables backend is asked before it is told; ufw and
# firewalld already skip a rule they hold.
#
# ── The pool rule ─────────────────────────────────────────────────────────────
# One parent /16, partitioned into /24 slots, so NAT and routing stay a single
# rule set. Three independent allocators over one range is a routing bug that
# looks like a firewall bug and gets found in week three.
#
# This file does not know which slot belongs to whom. A caller claims a slot by
# an opaque owner tag; the canonical slot assignment lives in CLAUDE.md
# § Networking, which is the only place it belongs.
#
# Sourced, not executed. errexit does not cover a ||-guarded function body, so
# every command here that creates, moves or deletes is guarded individually.

[[ -n "${VPN55_NET_LOADED:-}" ]] && return 0
VPN55_NET_LOADED=1

# Shared state root. Assigned with := so whichever lib loads first wins and the
# others agree, with no ordering dependency between them.
: "${VPN55_ETC:=/etc/vpn55}"

: "${VPN55_NET_PARENT:=10.8.0.0/16}"     # one parent, partitioned into /24 slots
: "${VPN55_NET_CONF:=$VPN55_ETC/net.conf}"
: "${VPN55_FW_STATE:=$VPN55_ETC/fw.state}"
: "${VPN55_POOL_CONF:=$VPN55_ETC/pools.conf}"
: "${VPN55_LEASE_DIR:=$VPN55_ETC/leases}"
: "${VPN55_SYSCTL_CONF:=/etc/sysctl.d/99-vpn55-forward.conf}"
: "${VPN55_NFT_CONF:=$VPN55_ETC/nftables.conf}"

VPN55_FW_BACKEND="${VPN55_FW_BACKEND:-}"   # ufw | firewalld | nftables

# ─── State plumbing ───────────────────────────────────────────────────────────
_net_ensure_state_dir() {
    if [[ ! -d "$VPN55_ETC" ]]; then
        mkdir -p "$VPN55_ETC" || { error "cannot create $VPN55_ETC"; return 1; }
        chmod 0700 "$VPN55_ETC" || { error "cannot set mode on $VPN55_ETC"; return 1; }
    fi
    if [[ ! -d "$VPN55_LEASE_DIR" ]]; then
        mkdir -p "$VPN55_LEASE_DIR" || { error "cannot create $VPN55_LEASE_DIR"; return 1; }
        chmod 0700 "$VPN55_LEASE_DIR" || { error "cannot set mode on $VPN55_LEASE_DIR"; return 1; }
    fi
    return 0
}

# Replace a file atomically. Content arrives on stdin. A half-written pool table
# is worse than no pool table: it hands out an address that is already leased.
_net_write_atomic() {
    local dest="${1:-}" tmp
    [[ -n "$dest" ]] || { error "_net_write_atomic: no destination"; return 1; }
    tmp="${dest}.tmp.$$"

    cat > "$tmp" || { error "cannot write $tmp"; rm -f "$tmp" 2>/dev/null || true; return 1; }
    chmod 0600 "$tmp" || { error "cannot set mode on $tmp"; rm -f "$tmp" 2>/dev/null || true; return 1; }
    mv -f "$tmp" "$dest" || { error "cannot replace $dest"; rm -f "$tmp" 2>/dev/null || true; return 1; }
    return 0
}

# Is this exact row already in the table? Exact means every field, not just the
# tag — two ports opened under one tag are two legitimate rows.
_net_record_exists() {
    local dest="${1:-}"; shift
    [[ -f "$dest" ]] || return 1
    local row
    row="$(IFS=$'\t'; printf '%s' "$*")"
    grep -qxF "$row" "$dest" 2>/dev/null
}

# Append one TAB-separated record. Fields must not contain a TAB or a newline —
# the panel parses these files, and a stray separator is a silently wrong row.
#
# An identical row is a no-op rather than a second line. Every adapter's _install
# is required to be re-runnable, and each re-run replays the same net_fw_* calls;
# without this the ledger grows a duplicate set on every run, and a revoke that
# reads the ledger then tries to remove the same rule N times. The rule verbs
# below stay honest about their backend regardless — this only governs the
# bookkeeping.
_net_append_record() {
    local dest="${1:-}"; shift
    local field
    for field in "$@"; do
        case "$field" in
            *$'\t'*|*$'\n'*)
                error "record field contains a tab or newline: ${field}"
                return 1 ;;
        esac
    done
    _net_ensure_state_dir || return 1

    if _net_record_exists "$dest" "$@"; then
        debug "record already present in ${dest##*/}: $*"
        return 0
    fi

    printf '%s\n' "$(IFS=$'\t'; printf '%s' "$*")" >> "$dest" \
        || { error "cannot append to $dest"; return 1; }
    chmod 0600 "$dest" 2>/dev/null || true
    return 0
}

# Rewrite a TAB-separated table without the rows whose <field_index> equals
# <value>. Used by every revoke/release path, so the awkward parts live once:
#
#   - `grep -v` exits 1 when it filters EVERYTHING out, which is a legitimate
#     "the table is now empty" result. Under the caller's `set -o pipefail` that
#     exit status would surface as a failure and abort a teardown that in fact
#     succeeded, so the filter is run into a variable with `|| true` rather than
#     straight down a pipe.
#   - The empty case still has to write, or a revoked rule stays in the ledger.
_net_drop_rows() {
    local file="${1:-}" idx="${2:-}" value="${3:-}" remaining
    [[ -n "$file" && -n "$idx" ]] || { error "_net_drop_rows <file> <field> <value>"; return 1; }
    [[ -f "$file" ]] || return 0

    remaining="$(awk -F'\t' -v i="$idx" -v v="$value" '$i != v' "$file" 2>/dev/null || true)"

    if [[ -n "$remaining" ]]; then
        printf '%s\n' "$remaining" | _net_write_atomic "$file" || return 1
    else
        printf '' | _net_write_atomic "$file" || return 1
    fi
    return 0
}

_net_conf_get() {
    local key="${1:-}"
    [[ -r "$VPN55_NET_CONF" ]] || return 1
    local line
    line="$(grep -m1 "^${key}=" "$VPN55_NET_CONF" 2>/dev/null)" || return 1
    printf '%s' "${line#*=}"
}

_net_conf_set() {
    local key="${1:-}" value="${2:-}"
    [[ -n "$key" ]] || { error "_net_conf_set: no key"; return 1; }
    _net_ensure_state_dir || return 1

    local remaining=""
    if [[ -f "$VPN55_NET_CONF" ]]; then
        remaining="$(grep -v "^${key}=" "$VPN55_NET_CONF" 2>/dev/null || true)"
    fi

    {
        if [[ -n "$remaining" ]]; then
            printf '%s\n' "$remaining"
        fi
        printf '%s=%s\n' "$key" "$value"
    } | _net_write_atomic "$VPN55_NET_CONF" || { error "cannot write $VPN55_NET_CONF"; return 1; }
    return 0
}

# ─── Interfaces and addresses ─────────────────────────────────────────────────
net_wan_iface() {
    local iface
    iface="$(ip -4 route show default 2>/dev/null | awk '/default/ {print $5; exit}')"
    if [[ -z "$iface" ]]; then
        iface="$(ip -4 route get 1.1.1.1 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="dev"){print $(i+1); exit}}')"
    fi
    if [[ -z "$iface" ]]; then
        error "Cannot determine the outbound interface — is there a default route?"
        return 1
    fi
    printf '%s' "$iface"
}

net_wan_address() {
    local addr
    addr="$(ip -4 route get 1.1.1.1 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="src"){print $(i+1); exit}}')"
    if [[ -z "$addr" ]]; then
        local iface
        iface="$(net_wan_iface)" || return 1
        addr="$(ip -4 -o addr show dev "$iface" scope global 2>/dev/null | awk '{print $4; exit}')"
        addr="${addr%%/*}"
    fi
    [[ -n "$addr" ]] || { error "Cannot determine this host's outbound address."; return 1; }
    printf '%s' "$addr"
}

net_is_private_ip() {
    case "${1:-}" in
        10.*|127.*|169.254.*|192.168.*) return 0 ;;
        172.1[6-9].*|172.2[0-9].*|172.3[0-1].*) return 0 ;;
        100.6[4-9].*|100.[7-9][0-9].*|100.1[0-1][0-9].*|100.12[0-7].*) return 0 ;;
        *) return 1 ;;
    esac
}

# The address clients will actually dial. VPN55 never asks a third party what its
# own IP is — there is no telemetry and no phone-home in this project, and an
# IP-echo service is exactly the kind of outbound call that turns into one. A
# host behind provider NAT gets an honest failure here and the operator types the
# real endpoint in.
net_public_endpoint() {
    local addr
    addr="$(net_wan_address)" || return 1
    if net_is_private_ip "$addr"; then
        warn "Outbound address ${addr} is in private space — this host is behind NAT."
        warn "Clients cannot reach it at that address; the public endpoint must be set by hand."
        printf '%s' "$addr"
        return 2
    fi
    printf '%s' "$addr"
    return 0
}

# ─── DNS resolvers handed to clients ──────────────────────────────────────────
# Every tunnel protocol pushes a resolver at its clients, and the choice is
# identical for all of them — so it lives here rather than once per adapter.
# Nothing below knows what a tunnel is; it answers "what should a client on the
# far side of one be told to query".
#
# Moved out of the WireGuard adapter at the Phase 3 checkpoint. It was the first
# thing the second adapter had to copy, which is the definition of a thing that
# belongs on the shared floor.

# The host's own upstream resolvers.
#
# /etc/resolv.conf is the WRONG file on any host running systemd-resolved: it
# points at the 127.0.0.53 stub, which means nothing to a client on the far side
# of a tunnel — a client told to query 127.0.0.53 is querying its own phone. The
# real upstreams are in the resolved-managed copy, which is why that is read
# first. Loopback and link-local addresses are dropped for the same reason.
net_resolvers_system() {
    local src out=""
    for src in /run/systemd/resolve/resolv.conf /etc/resolv.conf; do
        [[ -r "$src" ]] || continue
        out="$(awk '/^nameserver[[:space:]]/ { print $2 }' "$src" 2>/dev/null \
            | grep -vE '^(127\.|::1$|169\.254\.|fe80:)' \
            | head -2 | paste -sd, - 2>/dev/null || true)"
        [[ -n "$out" ]] && break
    done
    [[ -n "$out" ]] || return 1
    printf '%s' "$out"
}

# net_resolvers_resolve <system|cloudflare|quad9|custom> [custom_list]
#   Turns a choice into the literal string an adapter bakes into a client
#   config. An adapter is expected to do this ONCE, at install, and store the
#   result: re-resolving later would silently change what already-issued
#   credentials point at.
net_resolvers_resolve() {
    local choice="${1:-}" custom="${2:-}"
    case "$choice" in
        system)
            local sys
            if ! sys="$(net_resolvers_system)"; then
                error "This host has no usable upstream resolver — only a loopback stub."
                error "A client on the far side of a tunnel cannot reach that, so 'system'"
                error "is not an option here. Choose cloudflare, quad9 or custom."
                return 1
            fi
            printf '%s' "$sys" ;;
        cloudflare) printf '1.1.1.1,1.0.0.1' ;;
        quad9)      printf '9.9.9.9,149.112.112.112' ;;
        custom)
            if [[ ! "$custom" =~ ^[0-9a-fA-F.:,]+$ ]]; then
                error "Custom resolvers must be a comma-separated list of IP addresses."
                return 1
            fi
            printf '%s' "$custom" ;;
        *)
            error "Unknown DNS choice '${choice}' — use system, cloudflare, quad9 or custom."
            return 1 ;;
    esac
}

# The operator-facing explanation of that choice, so both adapters say the same
# thing. It is a privacy decision rather than a convenience one, and the text
# says so — the resolver sees every hostname every user visits.
net_resolvers_explain() {
    info "DNS resolver baked into every client config."
    info "  The resolver sees every hostname every user visits, so this is a"
    info "  privacy decision, not a convenience one."
    info "  system      this host's own upstreams. No observer the user has not"
    info "              already accepted by choosing this server."
    info "  cloudflare  1.1.1.1 — fast, and a second party watching the queries."
    info "  quad9       9.9.9.9 — non-profit, and it BLOCKS domains it considers"
    info "              malicious. Filtering is filtering; know before choosing it."
    info "  custom      your own resolver."
    return 0
}

# ─── IP forwarding ────────────────────────────────────────────────────────────
net_forwarding_active() {
    [[ "$(cat /proc/sys/net/ipv4/ip_forward 2>/dev/null || echo 0)" == "1" ]]
}

net_forwarding_enable() {
    local want_v6="${1:-0}"

    {
        printf '# Written by VPN55. Removing this file disables tunnel routing.\n'
        printf 'net.ipv4.ip_forward = 1\n'
        if [[ "$want_v6" == "1" ]]; then
            printf 'net.ipv6.conf.all.forwarding = 1\n'
        fi
    } | _net_write_atomic "$VPN55_SYSCTL_CONF" || return 1

    chmod 0644 "$VPN55_SYSCTL_CONF" || { error "cannot set mode on $VPN55_SYSCTL_CONF"; return 1; }

    sysctl -q --system >/dev/null 2>&1 || sysctl -q -p "$VPN55_SYSCTL_CONF" >/dev/null 2>&1 \
        || { error "cannot apply sysctl settings from $VPN55_SYSCTL_CONF"; return 1; }

    if ! net_forwarding_active; then
        error "IP forwarding is still off after applying $VPN55_SYSCTL_CONF."
        return 1
    fi
    success "IP forwarding enabled (persisted in $VPN55_SYSCTL_CONF)"
    return 0
}

# Only ever removes what VPN55 wrote. Forwarding may still be on afterwards
# because something else on the host wants it — that is correct, and saying so is
# better than turning off routing another service depends on.
net_forwarding_disable() {
    if [[ -f "$VPN55_SYSCTL_CONF" ]]; then
        rm -f "$VPN55_SYSCTL_CONF" || { error "cannot remove $VPN55_SYSCTL_CONF"; return 1; }
        sysctl -q --system >/dev/null 2>&1 || true
    fi
    if net_forwarding_active; then
        warn "IP forwarding is still enabled — another sysctl file on this host sets it."
    fi
    return 0
}

# ─── Firewall façade ──────────────────────────────────────────────────────────
# net_fw_backend resolves the backend once and remembers it. Order of preference
# is "whatever is already managing this host's firewall", because taking rules
# away from an active ufw or firewalld and putting them in a private nft table is
# how an operator ends up with two rule sets and no idea which one is live.

# Pure probe: prints what this host would use, and writes NOTHING.
_net_fw_detect() {
    # `ufw status` prints its verdict on the first line and a rule table after
    # it, so `| grep -q` would exit on the match, SIGPIPE ufw, and — under
    # pipefail — read as "ufw is not active". VPN55 would then put its rules in a
    # private nft table beside a live ufw, which is exactly the two-rule-sets
    # failure the one-backend rule exists to prevent. Capture, then test.
    local ufw_probe=""
    if command -v ufw >/dev/null 2>&1; then
        ufw_probe="$(ufw status 2>/dev/null || true)"
    fi

    if str_contains "$ufw_probe" "Status: active"; then
        printf 'ufw'
    elif command -v firewall-cmd >/dev/null 2>&1 && firewall-cmd --state >/dev/null 2>&1; then
        printf 'firewalld'
    elif command -v nft >/dev/null 2>&1; then
        printf 'nftables'
    else
        error "No usable firewall backend found."
        error "Install one of: ufw, firewalld, or nftables — then re-run."
        return 1
    fi
    return 0
}

# What is ALREADY settled, or — if nothing is — what would be chosen. Read-only,
# so a report can print the answer without committing to it. Which backend a host
# uses is a decision with consequences for every later teardown; making it as a
# side effect of running `--doctor` would settle it without anyone deciding.
net_fw_backend_peek() {
    if [[ -n "$VPN55_FW_BACKEND" ]]; then
        printf '%s' "$VPN55_FW_BACKEND"
        return 0
    fi
    local stored
    stored="$(_net_conf_get fw_backend 2>/dev/null)" || stored=""
    if [[ -n "$stored" ]]; then
        printf '%s' "$stored"
        return 0
    fi
    _net_fw_detect || return 1
}

# Resolve AND persist. Everything that applies or reverses a rule goes through
# this one, so the backend is pinned the first time a rule is written and every
# later teardown looks in the same place.
net_fw_backend() {
    if [[ -n "$VPN55_FW_BACKEND" ]]; then
        printf '%s' "$VPN55_FW_BACKEND"
        return 0
    fi

    local stored
    stored="$(_net_conf_get fw_backend 2>/dev/null)" || stored=""
    if [[ -n "$stored" ]]; then
        VPN55_FW_BACKEND="$stored"
        printf '%s' "$VPN55_FW_BACKEND"
        return 0
    fi

    VPN55_FW_BACKEND="$(_net_fw_detect)" || return 1

    _net_conf_set fw_backend "$VPN55_FW_BACKEND" || return 1
    info "Firewall backend: ${VPN55_FW_BACKEND} (recorded in $VPN55_NET_CONF)"
    printf '%s' "$VPN55_FW_BACKEND"
    return 0
}

# ── nftables helpers ──
_net_nft_tables() {
    nft add table inet vpn55 2>/dev/null \
        || { error "cannot create nft table inet vpn55"; return 1; }
    nft add chain inet vpn55 input '{ type filter hook input priority 0 ; policy accept ; }' 2>/dev/null \
        || { error "cannot create nft chain vpn55/input"; return 1; }
    nft add chain inet vpn55 forward '{ type filter hook forward priority 0 ; policy accept ; }' 2>/dev/null \
        || { error "cannot create nft chain vpn55/forward"; return 1; }
    nft add table ip vpn55nat 2>/dev/null \
        || { error "cannot create nft table ip vpn55nat"; return 1; }
    nft add chain ip vpn55nat postrouting '{ type nat hook postrouting priority 100 ; policy accept ; }' 2>/dev/null \
        || { error "cannot create nft chain vpn55nat/postrouting"; return 1; }
    return 0
}

# Rule comments are `vpn55:<tag>:<kind>:<a>:<b>` — fully identifying, and with the
# tag terminated by a colon. Without that terminator a revoke of tag `wg` would
# also match every rule belonging to `wg2`.
_net_nft_del_tagged() {
    local family="${1:-}" table="${2:-}" chain="${3:-}" tag="${4:-}"
    local handles handle
    handles="$(nft -a list chain "$family" "$table" "$chain" 2>/dev/null \
        | grep -F "vpn55:${tag}:" | grep -oE 'handle [0-9]+$' | awk '{print $2}')" || return 0
    for handle in $handles; do
        nft delete rule "$family" "$table" "$chain" handle "$handle" 2>/dev/null || true
    done
    return 0
}

# nft has no "add if absent": a second identical rule is not an error there, it is
# simply added again. ufw skips a duplicate and firewalld returns ALREADY_ENABLED,
# so this is the one backend where a re-run of an adapter's _install would stack a
# fresh copy of every rule. Matching is on the full comment, which is why the
# comment carries the whole identity rather than just the tag.
_net_nft_rule_present() {
    local family="${1:-}" table="${2:-}" chain="${3:-}" comment="${4:-}" listing
    listing="$(nft list chain "$family" "$table" "$chain" 2>/dev/null || true)"
    str_contains "$listing" "\"${comment}\""
}

# ── ufw helpers ──
# ufw owns no NAT verb, so masquerade goes into a marked block at the top of
# /etc/ufw/before.rules — still inside ufw, which is the point. The markers are
# what makes removal exact.
_net_ufw_nat_block_add() {
    local tag="${1:-}" cidr="${2:-}" wan="${3:-}"
    local rules="/etc/ufw/before.rules"

    [[ -f "$rules" ]] || { error "$rules not found — is ufw installed?"; return 1; }

    if grep -q "^# BEGIN VPN55 ${tag}$" "$rules" 2>/dev/null; then
        return 0
    fi

    {
        printf '# BEGIN VPN55 %s\n' "$tag"
        printf '*nat\n'
        printf ':POSTROUTING ACCEPT [0:0]\n'
        printf -- '-A POSTROUTING -s %s -o %s -j MASQUERADE\n' "$cidr" "$wan"
        printf 'COMMIT\n'
        printf '# END VPN55 %s\n' "$tag"
        cat "$rules"
    } | _net_write_atomic "${rules}.vpn55" || return 1

    chmod 0640 "${rules}.vpn55" || { error "cannot set mode on ${rules}.vpn55"; return 1; }
    mv -f "${rules}.vpn55" "$rules" || { error "cannot update $rules"; return 1; }
    return 0
}

_net_ufw_nat_block_remove() {
    local tag="${1:-}"
    local rules="/etc/ufw/before.rules"

    [[ -f "$rules" ]] || return 0
    grep -q "^# BEGIN VPN55 ${tag}$" "$rules" 2>/dev/null || return 0

    sed "/^# BEGIN VPN55 ${tag}$/,/^# END VPN55 ${tag}$/d" "$rules" \
        | _net_write_atomic "${rules}.vpn55" || return 1
    chmod 0640 "${rules}.vpn55" || { error "cannot set mode on ${rules}.vpn55"; return 1; }
    mv -f "${rules}.vpn55" "$rules" || { error "cannot update $rules"; return 1; }
    return 0
}

# ── Rule verbs ──
# Every one takes a tag first. The tag is the caller's handle on its own rules and
# the only thing revocation needs to know.
#
# ⚠ Each verb writes the LEDGER BEFORE it touches the firewall, and the order is
# deliberate. Applying first and recording second means a failed record — a full
# disk, a read-only /etc — leaves a live rule that no uninstall will ever find,
# which is precisely the orphan the ledger exists to prevent. Recording first
# inverts the failure: what is left behind is a row describing a rule that was
# never applied, and every revoke branch tolerates a missing rule, so removing it
# is a no-op. A phantom row is recoverable; an orphan rule is not.

net_fw_open_port() {
    local tag="${1:-}" transport="${2:-}" port="${3:-}"
    [[ -n "$tag" && -n "$transport" && -n "$port" ]] \
        || { error "net_fw_open_port <tag> <tcp|udp> <port>"; return 1; }
    case "$transport" in tcp|udp) ;; *) error "transport must be tcp or udp"; return 1 ;; esac

    local backend
    backend="$(net_fw_backend)" || return 1

    _net_append_record "$VPN55_FW_STATE" "$tag" "port" "$transport" "$port" || return 1

    case "$backend" in
        ufw)
            ufw allow "${port}/${transport}" comment "vpn55:${tag}" >/dev/null \
                || { error "ufw could not open ${port}/${transport}"; return 1; } ;;
        firewalld)
            firewall-cmd --permanent --add-port="${port}/${transport}" >/dev/null \
                || { error "firewalld could not open ${port}/${transport}"; return 1; } ;;
        nftables)
            _net_nft_tables || return 1
            local c_in="vpn55:${tag}:port:${transport}:${port}"
            if ! _net_nft_rule_present inet vpn55 input "$c_in"; then
                nft add rule inet vpn55 input "$transport" dport "$port" accept comment "\"${c_in}\"" \
                    || { error "nft could not open ${port}/${transport}"; return 1; }
            fi ;;
    esac

    debug "fw: opened ${port}/${transport} for tag ${tag} via ${backend}"
    return 0
}

# Allow the tunnel subnet to be routed. Not the same as opening a port: this is
# the forward path, and forgetting it is the classic "connects but no traffic".
net_fw_allow_subnet() {
    local tag="${1:-}" cidr="${2:-}"
    [[ -n "$tag" && -n "$cidr" ]] || { error "net_fw_allow_subnet <tag> <cidr>"; return 1; }

    local backend
    backend="$(net_fw_backend)" || return 1

    _net_append_record "$VPN55_FW_STATE" "$tag" "subnet" "$cidr" "-" || return 1

    case "$backend" in
        ufw)
            ufw route allow from "$cidr" comment "vpn55:${tag}" >/dev/null \
                || { error "ufw could not allow routing from ${cidr}"; return 1; }
            ufw route allow to "$cidr" comment "vpn55:${tag}" >/dev/null \
                || { error "ufw could not allow routing to ${cidr}"; return 1; } ;;
        firewalld)
            firewall-cmd --permanent --zone=trusted --add-source="$cidr" >/dev/null \
                || { error "firewalld could not trust ${cidr}"; return 1; } ;;
        nftables)
            _net_nft_tables || return 1
            # Two rules, two comments: one identity per rule, or the presence
            # check matches the outbound rule and never adds the return path.
            local c_out="vpn55:${tag}:subnet:${cidr}:out"
            local c_ret="vpn55:${tag}:subnet:${cidr}:ret"
            if ! _net_nft_rule_present inet vpn55 forward "$c_out"; then
                nft add rule inet vpn55 forward ip saddr "$cidr" accept comment "\"${c_out}\"" \
                    || { error "nft could not allow forwarding from ${cidr}"; return 1; }
            fi
            if ! _net_nft_rule_present inet vpn55 forward "$c_ret"; then
                nft add rule inet vpn55 forward ip daddr "$cidr" ct state established,related accept comment "\"${c_ret}\"" \
                    || { error "nft could not allow return traffic to ${cidr}"; return 1; }
            fi ;;
    esac

    debug "fw: allowed subnet ${cidr} for tag ${tag} via ${backend}"
    return 0
}

net_fw_masquerade() {
    local tag="${1:-}" cidr="${2:-}" wan="${3:-}"
    [[ -n "$tag" && -n "$cidr" ]] || { error "net_fw_masquerade <tag> <cidr> [wan_iface]"; return 1; }
    if [[ -z "$wan" ]]; then
        wan="$(net_wan_iface)" || return 1
    fi

    local backend
    backend="$(net_fw_backend)" || return 1

    _net_append_record "$VPN55_FW_STATE" "$tag" "masquerade" "$cidr" "$wan" || return 1

    case "$backend" in
        ufw)
            _net_ufw_nat_block_add "$tag" "$cidr" "$wan" || return 1 ;;
        firewalld)
            # Zone-level and not per-source, so it is reference-counted through the
            # ledger: the last tag to be revoked is the one that turns it off.
            firewall-cmd --permanent --add-masquerade >/dev/null \
                || { error "firewalld could not enable masquerade"; return 1; } ;;
        nftables)
            _net_nft_tables || return 1
            local c_nat="vpn55:${tag}:masquerade:${cidr}:${wan}"
            if ! _net_nft_rule_present ip vpn55nat postrouting "$c_nat"; then
                nft add rule ip vpn55nat postrouting ip saddr "$cidr" oifname "$wan" masquerade comment "\"${c_nat}\"" \
                    || { error "nft could not add masquerade for ${cidr}"; return 1; }
            fi ;;
    esac

    debug "fw: masquerade ${cidr} out ${wan} for tag ${tag} via ${backend}"
    return 0
}

# Reverse every rule recorded under this tag, then drop them from the ledger.
# Reads the ledger rather than the live ruleset, so a rule the backend renamed,
# renumbered or lost its comment on still gets removed.
net_fw_revoke_tag() {
    local tag="${1:-}"
    [[ -n "$tag" ]] || { error "net_fw_revoke_tag <tag>"; return 1; }
    [[ -f "$VPN55_FW_STATE" ]] || return 0

    local backend
    backend="$(net_fw_backend)" || return 1

    local rec_tag kind a b
    while IFS=$'\t' read -r rec_tag kind a b; do
        [[ "$rec_tag" == "$tag" ]] || continue
        case "$backend:$kind" in
            ufw:port)
                ufw delete allow "${b}/${a}" >/dev/null 2>&1 || true ;;
            ufw:subnet)
                ufw route delete allow from "$a" >/dev/null 2>&1 || true
                ufw route delete allow to "$a" >/dev/null 2>&1 || true ;;
            ufw:masquerade)
                _net_ufw_nat_block_remove "$tag" || true ;;
            firewalld:port)
                firewall-cmd --permanent --remove-port="${b}/${a}" >/dev/null 2>&1 || true ;;
            firewalld:subnet)
                firewall-cmd --permanent --zone=trusted --remove-source="$a" >/dev/null 2>&1 || true ;;
            firewalld:masquerade)
                # Zone-level, so it is only turned off once no OTHER tag still
                # holds a masquerade record. awk rather than grep -P: PCRE is a
                # build option, and a missing -P here would silently tear down
                # NAT another tag is still using.
                if ! awk -F'\t' -v t="$tag" \
                    '$1 != t && $2 == "masquerade" { found = 1 } END { exit !found }' \
                    "$VPN55_FW_STATE"; then
                    firewall-cmd --permanent --remove-masquerade >/dev/null 2>&1 || true
                fi ;;
            nftables:*)
                _net_nft_del_tagged inet vpn55 input "$tag"
                _net_nft_del_tagged inet vpn55 forward "$tag"
                _net_nft_del_tagged ip vpn55nat postrouting "$tag" ;;
        esac
    done < "$VPN55_FW_STATE"

    _net_drop_rows "$VPN55_FW_STATE" 1 "$tag" \
        || { error "cannot rewrite the firewall ledger"; return 1; }

    net_fw_reload || return 1
    success "Firewall rules for '${tag}' removed."
    return 0
}

net_fw_reload() {
    local backend
    backend="$(net_fw_backend)" || return 1
    case "$backend" in
        ufw)       ufw reload >/dev/null 2>&1 || { error "ufw reload failed"; return 1; } ;;
        firewalld) firewall-cmd --reload >/dev/null 2>&1 || { error "firewall-cmd --reload failed"; return 1; } ;;
        nftables)  net_fw_persist || return 1 ;;
    esac
    return 0
}

# ufw and firewalld persist their own rules. An nftables ruleset does not survive
# a reboot on its own, and a NAT rule that vanishes overnight looks like the VPN
# broke rather than like the firewall did — so the tables are written out and
# replayed by a unit at boot.
net_fw_persist() {
    local backend
    backend="$(net_fw_backend)" || return 1
    [[ "$backend" == "nftables" ]] || return 0

    _net_ensure_state_dir || return 1

    {
        printf '#!/usr/sbin/nft -f\n'
        printf '# Written by VPN55. Replayed at boot by vpn55-firewall.service.\n'
        printf 'table inet vpn55\n'
        printf 'delete table inet vpn55\n'
        printf 'table ip vpn55nat\n'
        printf 'delete table ip vpn55nat\n'
        nft list table inet vpn55 2>/dev/null || true
        nft list table ip vpn55nat 2>/dev/null || true
    } | _net_write_atomic "$VPN55_NFT_CONF" || return 1

    local nft_bin
    nft_bin="$(command -v nft)" || { error "nft disappeared from PATH"; return 1; }

    if [[ ! -f /etc/systemd/system/vpn55-firewall.service ]]; then
        {
            printf '[Unit]\n'
            printf 'Description=VPN55 firewall rules\n'
            printf 'DefaultDependencies=no\n'
            printf 'Before=network-pre.target\n'
            printf 'Wants=network-pre.target\n'
            printf '\n[Service]\n'
            printf 'Type=oneshot\n'
            printf 'RemainAfterExit=yes\n'
            printf 'ExecStart=%s -f %s\n' "$nft_bin" "$VPN55_NFT_CONF"
            printf '\n[Install]\n'
            printf 'WantedBy=multi-user.target\n'
        } | _net_write_atomic /etc/systemd/system/vpn55-firewall.service || return 1

        chmod 0644 /etc/systemd/system/vpn55-firewall.service \
            || { error "cannot set mode on vpn55-firewall.service"; return 1; }
        distro_daemon_reload || return 1
        distro_service_enable vpn55-firewall.service || return 1
    fi
    return 0
}

# Everything VPN55 has ever added, gone. The last step of an uninstall.
net_fw_revoke_all() {
    [[ -f "$VPN55_FW_STATE" ]] || return 0
    local tags tag
    tags="$(cut -f1 "$VPN55_FW_STATE" 2>/dev/null | sort -u)"
    for tag in $tags; do
        net_fw_revoke_tag "$tag" || warn "could not fully revoke tag '${tag}'"
    done

    local backend
    backend="$(net_fw_backend)" || backend=""
    if [[ "$backend" == "nftables" ]]; then
        nft delete table inet vpn55 2>/dev/null || true
        nft delete table ip vpn55nat 2>/dev/null || true
        distro_service_disable vpn55-firewall.service || true
        rm -f /etc/systemd/system/vpn55-firewall.service || { error "cannot remove the firewall unit"; return 1; }
        rm -f "$VPN55_NFT_CONF" || { error "cannot remove $VPN55_NFT_CONF"; return 1; }
        distro_daemon_reload || true
    fi

    rm -f "$VPN55_FW_STATE" || { error "cannot remove $VPN55_FW_STATE"; return 1; }
    return 0
}

net_fw_rules() {
    [[ -f "$VPN55_FW_STATE" ]] || return 0
    cat "$VPN55_FW_STATE"
}

# ─── IP pool allocator ────────────────────────────────────────────────────────
# The parent must be a /16 so that slot N is simply the Nth /24 inside it. A
# different prefix length would make the slot arithmetic a thing to get wrong at
# 2am, and nothing here needs the flexibility.
_net_parent_prefix() {
    local parent="$VPN55_NET_PARENT"
    case "$parent" in
        *.*.0.0/16) printf '%s' "${parent%.0.0/16}" ;;
        *)
            error "VPN55_NET_PARENT must be an x.y.0.0/16 network; got '${parent}'."
            return 1 ;;
    esac
}

net_pool_subnet() {
    local slot="${1:-}" prefix
    _net_valid_slot "$slot" || return 1
    prefix="$(_net_parent_prefix)" || return 1
    printf '%s.%s.0/24' "$prefix" "$slot"
}

net_pool_gateway() {
    local slot="${1:-}" prefix
    _net_valid_slot "$slot" || return 1
    prefix="$(_net_parent_prefix)" || return 1
    printf '%s.%s.1' "$prefix" "$slot"
}

_net_valid_slot() {
    local slot="${1:-}"
    if [[ ! "$slot" =~ ^[0-9]+$ ]] || [[ "$slot" -lt 0 ]] || [[ "$slot" -gt 255 ]]; then
        error "pool slot must be an integer 0–255; got '${slot}'."
        return 1
    fi
    return 0
}

_net_valid_owner() {
    local owner="${1:-}"
    if [[ ! "$owner" =~ ^[a-z][a-z0-9_]{0,31}$ ]]; then
        error "pool owner tag must match ^[a-z][a-z0-9_]{0,31}\$; got '${owner}'."
        return 1
    fi
    return 0
}

# Claim a slot for an owner tag. Idempotent for the same pair, and a hard error on
# any conflict — silently handing out an already-claimed /24 is the overlapping
# subnet bug this whole allocator exists to prevent.
net_pool_claim() {
    local owner="${1:-}" slot="${2:-}"
    _net_valid_owner "$owner" || return 1
    _net_valid_slot "$slot" || return 1
    _net_ensure_state_dir || return 1

    if [[ -f "$VPN55_POOL_CONF" ]]; then
        local cur_slot cur_owner
        while IFS=$'\t' read -r cur_slot cur_owner; do
            [[ -n "$cur_slot" ]] || continue
            if [[ "$cur_owner" == "$owner" && "$cur_slot" == "$slot" ]]; then
                return 0
            fi
            if [[ "$cur_owner" == "$owner" ]]; then
                error "'${owner}' already holds pool slot ${cur_slot}; it cannot also take ${slot}."
                return 1
            fi
            if [[ "$cur_slot" == "$slot" ]]; then
                error "Pool slot ${slot} ($(net_pool_subnet "$slot")) is already claimed by '${cur_owner}'."
                return 1
            fi
        done < "$VPN55_POOL_CONF"
    fi

    _net_append_record "$VPN55_POOL_CONF" "$slot" "$owner" || return 1
    debug "pool: slot ${slot} ($(net_pool_subnet "$slot")) claimed by ${owner}"
    return 0
}

net_pool_slot() {
    local owner="${1:-}" cur_slot cur_owner
    _net_valid_owner "$owner" || return 1
    [[ -f "$VPN55_POOL_CONF" ]] || return 1
    while IFS=$'\t' read -r cur_slot cur_owner; do
        if [[ "$cur_owner" == "$owner" ]]; then
            printf '%s' "$cur_slot"
            return 0
        fi
    done < "$VPN55_POOL_CONF"
    return 1
}

net_pool_release() {
    local owner="${1:-}"
    _net_valid_owner "$owner" || return 1

    _net_drop_rows "$VPN55_POOL_CONF" 2 "$owner" \
        || { error "cannot rewrite $VPN55_POOL_CONF"; return 1; }

    if [[ -f "${VPN55_LEASE_DIR}/${owner}" ]]; then
        rm -f "${VPN55_LEASE_DIR}/${owner}" || { error "cannot remove leases for ${owner}"; return 1; }
    fi
    return 0
}

# Allocate the next free address in the owner's /24. Idempotent per credential:
# asking twice for the same cred_id returns the same address rather than burning
# a second one.
net_pool_alloc() {
    local owner="${1:-}" cred_id="${2:-}"
    _net_valid_owner "$owner" || return 1
    [[ -n "$cred_id" ]] || { error "net_pool_alloc <owner> <cred_id>"; return 1; }
    case "$cred_id" in
        *$'\t'*|*$'\n'*) error "credential id may not contain a tab or newline"; return 1 ;;
    esac

    local slot prefix lease_file
    slot="$(net_pool_slot "$owner")" || { error "'${owner}' has not claimed a pool slot."; return 1; }
    prefix="$(_net_parent_prefix)" || return 1
    lease_file="${VPN55_LEASE_DIR}/${owner}"
    _net_ensure_state_dir || return 1

    if [[ -f "$lease_file" ]]; then
        local l_ip l_cred
        while IFS=$'\t' read -r l_ip l_cred; do
            if [[ "$l_cred" == "$cred_id" ]]; then
                printf '%s' "$l_ip"
                return 0
            fi
        done < "$lease_file"
    fi

    # Read the leased addresses ONCE. Re-reading per candidate would be 253
    # processes, and doing it as `cut | grep -q` would also be wrong: grep exits
    # on its first match and the SIGPIPE that kills cut becomes the pipeline's
    # status under pipefail, so an address already in use would read as free.
    # Handing out a duplicate address is the failure this allocator exists to
    # prevent — see the note in ui.sh.
    local leased=""
    if [[ -f "$lease_file" ]]; then
        leased="$(cut -f1 "$lease_file" 2>/dev/null || true)"
    fi

    # .1 is the tunnel gateway, .255 is broadcast; hosts run .2 through .254.
    local host candidate
    for (( host = 2; host <= 254; host++ )); do
        candidate="${prefix}.${slot}.${host}"
        if str_has_line "$leased" "$candidate"; then
            continue
        fi
        _net_append_record "$lease_file" "$candidate" "$cred_id" || return 1
        printf '%s' "$candidate"
        return 0
    done

    error "Pool slot ${slot} ($(net_pool_subnet "$slot")) is full — 253 addresses are in use."
    return 1
}

net_pool_free() {
    local owner="${1:-}" cred_id="${2:-}"
    _net_valid_owner "$owner" || return 1
    [[ -n "$cred_id" ]] || { error "net_pool_free <owner> <cred_id>"; return 1; }

    local lease_file="${VPN55_LEASE_DIR}/${owner}"
    [[ -f "$lease_file" ]] || return 0

    _net_drop_rows "$lease_file" 2 "$cred_id" \
        || { error "cannot rewrite leases for ${owner}"; return 1; }
    return 0
}

# Machine-readable: one `address<TAB>cred_id` per line.
net_pool_leases() {
    local owner="${1:-}"
    _net_valid_owner "$owner" || return 1
    local lease_file="${VPN55_LEASE_DIR}/${owner}"
    [[ -f "$lease_file" ]] || return 0
    cat "$lease_file"
}

net_pool_claims() {
    [[ -f "$VPN55_POOL_CONF" ]] || return 0
    cat "$VPN55_POOL_CONF"
}

# Does the parent range collide with something already routed on this host? A
# collision here is the difference between "the tunnel works" and "the tunnel
# steals the office LAN".
net_pool_check_conflicts() {
    local prefix
    prefix="$(_net_parent_prefix)" || return 1

    # index(), not a regex: passing "^10.8\\." through `awk -v` makes awk print
    # `warning: escape sequence '\.' treated as plain '.'` on every single call,
    # which reads to an operator as the check malfunctioning. An exact prefix
    # match needs no escaping and cannot mis-match a dot for any character.
    local hits
    hits="$(ip -4 route show 2>/dev/null | awk -v p="${prefix}." 'index($1, p) == 1 { print }')"
    if [[ -n "$hits" ]]; then
        warn "Routes already exist inside ${VPN55_NET_PARENT}:"
        printf '%s\n' "$hits" >&2
        warn "Set VPN55_NET_PARENT to an unused /16 before installing, or these will collide."
        return 1
    fi
    return 0
}

# ─── Report ───────────────────────────────────────────────────────────────────
net_report() {
    # _peek, not net_fw_backend: a report must not pin the backend choice.
    local wan addr backend
    wan="$(net_wan_iface 2>/dev/null)" || wan="unknown"
    addr="$(net_wan_address 2>/dev/null)" || addr="unknown"
    backend="$(net_fw_backend_peek 2>/dev/null)" || backend="none found"
    if [[ -z "$(_net_conf_get fw_backend 2>/dev/null)" && "$backend" != "none found" ]]; then
        backend="${backend} (would be chosen; not yet committed)"
    fi

    ui_kv "Outbound interface" "$wan"
    if [[ "$addr" != "unknown" ]] && net_is_private_ip "$addr"; then
        ui_kv "Outbound address" "${addr} (private — this host is behind NAT)"
    else
        ui_kv "Outbound address" "$addr"
    fi

    if net_forwarding_active; then
        ui_kv "IP forwarding" "enabled"
    else
        ui_kv "IP forwarding" "disabled"
    fi

    ui_kv "Firewall backend" "$backend"
    ui_kv "Tunnel parent range" "$VPN55_NET_PARENT"

    local claims
    claims="$(net_pool_claims)"
    if [[ -n "$claims" ]]; then
        local slot owner
        while IFS=$'\t' read -r slot owner; do
            [[ -n "$slot" ]] || continue
            ui_kv "  pool slot ${slot}" "$(net_pool_subnet "$slot") → ${owner}"
        done <<< "$claims"
    else
        ui_kv "Pool slots claimed" "none"
    fi
    return 0
}
