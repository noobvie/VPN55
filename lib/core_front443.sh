# shellcheck shell=bash
#
# lib/core_front443.sh — the shared-443 front: nginx's stream module in front of
# the operator's own vhosts and one loopback service, on the public address.
#
# docs/security-model.md §6C.8 is the design and wins on any conflict with this
# header. What this file adds is the nginx that the design did not spell out,
# and the one operational fact the design could not know without a socket.
#
# ── Protocol-neutral, on purpose ─────────────────────────────────────────────
#
# This file fronts "a loopback port". It does not know what listens there and
# must never learn: CI greps every file outside lib/proto_*.sh for protocol
# vocabulary, and a front that knew its backend's name would be the branch the
# adapter contract forbids. The adapter that wants the front calls
# front443_install with its port and reads front443_check back.
#
# ── The one piece of nginx the design left open: PROXY protocol ──────────────
#
# The web side must receive the PROXY protocol header, or every visitor becomes
# 127.0.0.1 and the rate limiters the vhosts run on $binary_remote_addr collapse
# into one bucket. The loopback service must NOT receive it — it cannot parse a
# PROXY header and would drop the connection.
#
# nginx sets `proxy_protocol` per SERVER, not per upstream, and it takes no
# variable (stream, server; on|off|v2 — nginx.org, ngx_stream_proxy_module).
# The front server therefore emits the header to BOTH upstreams, and the
# non-TLS path goes through a second stream server whose only job is to accept
# the header and forward plain bytes:
#
#     public:443 ─ssl_preread─┬─ TLS ────► 127.0.0.1:WEB   (http, listen … proxy_protocol)
#                             └─ else ───► 127.0.0.1:STRIP (stream, listen … proxy_protocol)
#                                                            └──► 127.0.0.1:BACKEND (plain)
#
# Two servers, one extra loopback hop on the tunnel side only. The alternative
# — adding the header on the web side in a second hop — needs the stream realip
# module to re-derive the client address at that hop and STILL needs a strip
# hop for the other path, so it is strictly more. The strip hop is a loopback
# TCP port rather than a UNIX socket because under SELinux nginx (httpd_t) may
# bind http_port_t ports without any relabelling and 8008 is one of them
# (80, 443, 488, 8008, 8009, 8443 — httpd_selinux(8)); a socket file's label
# under /run is one more thing to be wrong about on an enforcing host.
#
# ── Ports, and why these ─────────────────────────────────────────────────────
#
# WEB_PORT 8443 and STRIP_PORT 8008 both carry http_port_t already; 4443 (the
# design's first draft) carries nothing, and nginx on 4443 fails to bind under
# enforcing with a message in the audit log and nowhere else. Both are
# env-overridable. The backend port is the caller's; on an SELinux host the
# nginx→backend hop is an httpd_t connect to a port labelled for the backend,
# which `httpd_can_network_relay` does NOT cover (it reaches http-labelled ports
# only), so `httpd_can_network_connect` is set, recorded, and reversed — see
# _front443_selinux_ensure for the cost.
#
# ── Two reloads, never one ───────────────────────────────────────────────────
#
# On SIGHUP nginx opens the NEW cycle's listening sockets before it closes the
# old ones it no longer needs. Linux refuses a bind to <address>:443 while a
# wildcard *:443 is still in LISTEN state — SO_REUSEADDR does not help against
# a listening socket. So a single reload that moves the vhosts to loopback AND
# adds the public-address front fails with EADDRINUSE, and nginx keeps running
# the old configuration, silently. This file reloads twice: first the vhosts
# leave 443 (the wildcard socket closes), then the front takes it. Both reloads
# are graceful — connections in flight finish on the old workers — and the gap
# in which a NEW connection to 443 is refused is the time between them. Remove
# runs the same two phases in reverse. A restart would also work and would drop
# every connection nginx is carrying.
#
# ── `nginx -t` proves parse, not bind ────────────────────────────────────────
#
# `nginx -t` never binds anything, and `systemctl reload` returns before the
# master has processed the signal. After every reload this file polls `ss` and
# asserts the ADDRESS that holds each port — the front's public address on 443,
# 127.0.0.1 on the web and strip ports, and no wildcard anywhere on 443. A
# check that grepped `ss` for ":443" would go green whichever process won.
#
# ── Restore is by marker, line by line ───────────────────────────────────────
#
# Every rewritten `listen` line carries the ORIGINAL text after a marker, and a
# second 443 listener in the same server block (the usual `[::]:443` twin) is
# disabled the same way rather than rewritten, because two identical
# `listen 127.0.0.1:8443` lines in one block are a duplicate nginx refuses.
# Remove rewrites the tagged lines back and never copies a file. A vhost the
# operator deleted in between is skipped and logged; a marker whose original no
# longer parses is left in place with a warning. What is deliberately lost: an
# edit the operator made to the LIVE half of a tagged line — the marker holds
# the original, and the original is what comes back.
#
# ── Sourced, not executed ────────────────────────────────────────────────────
#
# Every consumer calls into here ||-guarded, so errexit is off throughout. Each
# filesystem command carries its own guard.

[[ -n "${VPN55_FRONT443_LOADED:-}" ]] && return 0
VPN55_FRONT443_LOADED=1

: "${VPN55_ETC:=/etc/vpn55}"
: "${VPN55_NGINX_CONF:=/etc/nginx/nginx.conf}"
: "${VPN55_FRONT443_STATE:=${VPN55_ETC}/front443.state}"
: "${VPN55_FRONT443_WEB_PORT:=8443}"
: "${VPN55_FRONT443_STRIP_PORT:=8008}"
: "${VPN55_FRONT443_STREAM_DIR:=/etc/nginx/vpn55-stream.d}"
: "${VPN55_FRONT443_STREAM_CONF:=${VPN55_FRONT443_STREAM_DIR}/front443.conf}"
: "${VPN55_FRONT443_REALIP_CONF:=/etc/nginx/conf.d/vpn55-front443-realip.conf}"
: "${VPN55_FRONT443_DROPIN:=/etc/systemd/system/nginx.service.d/vpn55-front443.conf}"
: "${VPN55_FRONT443_BIND_WAIT:=10}"       # seconds to wait for the master to (re)bind
: "${VPN55_FRONT443_REPAIR_CMD:=vpn55.sh --front443-repair}"
: "${VPN55_FRONT443_REMOVE_CMD:=vpn55.sh --front443-remove}"

# The marker every touched line carries. Grep for it; never for "443".
VPN55_FRONT443_MARK="vpn55-front443"
VPN55_FRONT443_MARK_WAS="# ${VPN55_FRONT443_MARK}: was "
VPN55_FRONT443_MARK_OFF="# ${VPN55_FRONT443_MARK}: off: "
VPN55_FRONT443_INCLUDE_LINE="stream { include ${VPN55_FRONT443_STREAM_DIR}/*.conf; } # ${VPN55_FRONT443_MARK}"
VPN55_FRONT443_PORT=443

# ─── Thin wrappers over the host ─────────────────────────────────────────────
# Everything that touches nginx, systemd, ss or SELinux goes through one of
# these, so tests/front443.sh can replace them and exercise every decision in
# this file without a server. Nothing else in the file calls the binaries.
_front443_nginx_dump()   { nginx -T 2>/dev/null; }
_front443_nginx_test()   { nginx -t >/dev/null 2>&1; }
_front443_nginx_test_out() { nginx -t 2>&1; }
_front443_nginx_flags()  { nginx -V 2>&1; }
_front443_nginx_active() { distro_service_is_active nginx; }
_front443_nginx_reload() { systemctl reload nginx; }
_front443_daemon_reload() { distro_daemon_reload; }
_front443_ss()           { ss -Hlnt "sport = :${1:-}" 2>/dev/null; }
_front443_ss_p()         { ss -Hlntp "sport = :${1:-}" 2>/dev/null; }
_front443_selinux_mode() { command -v getenforce >/dev/null 2>&1 || return 1; getenforce 2>/dev/null; }
_front443_getsebool()    { getsebool "${1:-}" 2>/dev/null | awk '{print $NF; exit}'; }
_front443_setsebool()    { setsebool -P "${1:-}" "${2:-}" >/dev/null 2>&1; }
_front443_public_v4()    { net_wan_address; }
_front443_public_v6() {
    local a
    a="$(ip -6 route get 2606:4700:4700::1111 2>/dev/null \
        | awk '{for(i=1;i<=NF;i++) if($i=="src"){print $(i+1); exit}}')"
    # Global unicast only. A link-local or ULA source is not an address the
    # internet can reach, and binding it would be a front nobody arrives at.
    case "$a" in 2*|3*) printf '%s' "$a"; return 0 ;; esac
    return 1
}
_front443_sleep()        { sleep 0.5; }
_front443_pid_comm()     { cat "/proc/${1:-0}/comm" 2>/dev/null; }
_front443_have()         { command -v "${1:-}" >/dev/null 2>&1; }

# ─── The ledger ──────────────────────────────────────────────────────────────
# TAB-separated, one record per line, first field is the record type — the
# same shape as fw.state, for the same reason: remove reads THIS, never the
# live host, because nothing on the host is trusted to remember what was ours.
#
#   web_port      <n>
#   strip_port    <n>
#   backend_port  <n>
#   bind          <public v4>
#   bind6         <public v6 | ->
#   file          <vhost path>            one per rewritten file
#   realip        <snippet path>
#   stream        <stream conf path>
#   include       <nginx.conf path>
#   dropin        <systemd drop-in path>
#   pkg           <package installed by us>
#   selinux       <boolean>  <value before us>
#   installed     <timestamp>             written last; its absence means a
#                                         partial install to be rolled back
_front443_ledger_add() {
    local field row
    [[ $# -ge 2 ]] || { error "_front443_ledger_add <type> <field>…"; return 1; }
    for field in "$@"; do
        case "$field" in
            *$'\t'*|*$'\n'*) error "ledger field contains a tab or newline: ${field}"; return 1 ;;
        esac
    done
    fs_ensure_dir "$VPN55_ETC" 0700 || return 1
    row="$(IFS=$'\t'; printf '%s' "$*")"
    if [[ -f "$VPN55_FRONT443_STATE" ]] && grep -qxF "$row" "$VPN55_FRONT443_STATE" 2>/dev/null; then
        return 0
    fi
    printf '%s\n' "$row" >> "$VPN55_FRONT443_STATE" \
        || { error "cannot append to $VPN55_FRONT443_STATE"; return 1; }
    chmod 0600 "$VPN55_FRONT443_STATE" 2>/dev/null || true
    return 0
}

# _front443_ledger_del <type> <field>… — drop the one exact row. Used by the
# scoped rollback for a `file` row whose rewrite was undone; nowhere else, and
# never for the rows remove reads — those go with the ledger itself.
_front443_ledger_del() {
    local row remaining
    [[ -f "$VPN55_FRONT443_STATE" ]] || return 0
    row="$(IFS=$'\t'; printf '%s' "$*")"
    remaining="$(grep -vxF "$row" "$VPN55_FRONT443_STATE" || true)"
    printf '%s\n' "$remaining" | fs_replace_in_place "$VPN55_FRONT443_STATE" 0600 \
        || { error "cannot rewrite ${VPN55_FRONT443_STATE}"; return 1; }
    return 0
}

# Every row of one type, fields after the type, TAB-joined, one per line.
_front443_ledger_rows() {
    local type="${1:-}"
    [[ -n "$type" && -r "$VPN55_FRONT443_STATE" ]] || return 1
    _fl_t="$type" awk -F'\t' '$1 == ENVIRON["_fl_t"] { s = ""; for (i = 2; i <= NF; i++) s = s (i > 2 ? "\t" : "") $i; print s }' \
        "$VPN55_FRONT443_STATE" 2>/dev/null
}

# The second field of the FIRST row of one type. Returns 1 when absent.
_front443_ledger_get() {
    local rows v
    rows="$(_front443_ledger_rows "${1:-}")" || return 1
    v="${rows%%$'\n'*}"; v="${v%%$'\t'*}"
    [[ -n "$v" ]] || return 1
    printf '%s' "$v"
}


front443_installed() { [[ -f "$VPN55_FRONT443_STATE" ]]; }

# ─── Ports ───────────────────────────────────────────────────────────────────
_front443_port_ok() {
    [[ "${1:-}" =~ ^[0-9]+$ ]] && [[ "$1" -ge 1 && "$1" -le 65535 ]]
}

_front443_ports_validate() {
    local backend="${1:-}" web="${2:-}" strip="${3:-}"
    _front443_port_ok "$backend" || { error "backend port must be 1-65535, got '${backend}'"; return 1; }
    _front443_port_ok "$web"     || { error "web port must be 1-65535, got '${web}'"; return 1; }
    _front443_port_ok "$strip"   || { error "strip port must be 1-65535, got '${strip}'"; return 1; }
    if [[ "$backend" == "$VPN55_FRONT443_PORT" || "$web" == "$VPN55_FRONT443_PORT" || "$strip" == "$VPN55_FRONT443_PORT" ]]; then
        error "none of the loopback ports may be ${VPN55_FRONT443_PORT} — that is the port the front takes"
        return 1
    fi
    if [[ "$backend" == "$web" || "$backend" == "$strip" || "$web" == "$strip" ]]; then
        error "backend, web and strip ports must be three different ports (got ${backend}/${web}/${strip})"
        return 1
    fi
    return 0
}

# ─── ss, read by ADDRESS ─────────────────────────────────────────────────────
# `ss -Hlnt "sport = :P"` — column 4 is Local Address:Port. iproute2 prints
# the v4 wildcard as 0.0.0.0:P (older releases: *:P) and the v6 one as [::]:P.
#
# Three forms the kernel emits that a bare `$4` comparison misses, normalised
# here so every reader sees one spelling (R1, hypothesis 5):
#   · a scope suffix — `[fe80::1%eth0]:P`, `*%eth0:P`, `0.0.0.0%eth0:P` (a
#     socket bound with SO_BINDTODEVICE; nginx never does this, another holder
#     of 443 might) → the `%ifname` is dropped;
#   · a v4-mapped v6 socket — `[::ffff:203.0.113.10]:P` is that v4 address in
#     the same port space, and `[::ffff:0.0.0.0]:P` is the v4 wildcard by
#     another spelling → unmapped to the dotted quad;
#   · `:::P` — the v6 wildcard as iproute2 printed it before brackets.
_front443_ss_locals() {
    _front443_ss "${1:-}" | awk '{
        a = $4
        if (match(a, /%[^]:%]*\]:/)) a = substr(a, 1, RSTART - 1) substr(a, RSTART + RLENGTH - 2)
        if (match(a, /%[^]:%]*:[0-9]+$/)) { p = substr(a, RSTART); sub(/^%[^:]*/, "", p); a = substr(a, 1, RSTART - 1) p }
        if (a ~ /^\[::ffff:[0-9.]+\]:[0-9]+$/) { sub(/^\[::ffff:/, "", a); sub(/\]:/, ":", a) }
        print a
    }'
}

_front443_wildcard_held() {
    local port="${1:-}" l
    while IFS= read -r l; do
        case "$l" in
            "0.0.0.0:${port}"|"*:${port}"|"[::]:${port}"|":::${port}") return 0 ;;
        esac
    done < <(_front443_ss_locals "$port")
    return 1
}

# _front443_addr_held <addr> <port> — that exact address holds the port.
_front443_addr_held() {
    local addr="${1:-}" port="${2:-}" want l
    [[ -n "$addr" ]] || return 1
    case "$addr" in *:*) want="[${addr}]:${port}" ;; *) want="${addr}:${port}" ;; esac
    while IFS= read -r l; do
        [[ "$l" == "$want" ]] && return 0
    done < <(_front443_ss_locals "$port")
    return 1
}

_front443_port_held() {
    [[ -n "$(_front443_ss_locals "${1:-}")" ]]
}

# _front443_wait_for <what> <fn> [args…] — poll until fn succeeds or the wait
# runs out. Prints nothing on success; the caller decides what a timeout means.
_front443_wait_for() {
    local what="${1:-}"; shift
    local deadline tries=0
    deadline=$(( ${VPN55_FRONT443_BIND_WAIT:-10} * 2 ))
    while ! "$@"; do
        tries=$(( tries + 1 ))
        if [[ "$tries" -ge "$deadline" ]]; then
            debug "front443: gave up waiting for ${what}"
            return 1
        fi
        _front443_sleep
    done
    return 0
}

# ─── The holder of a port, by pid → comm ─────────────────────────────────────
# front443_holder_is_nginx <tcp-port>
#   True when every process holding the port is nginx. Decided by reading
#   /proc/<pid>/comm for each pid `ss -p` names — not by matching the process
#   name inside ss's own output, which is a string a process chooses.
front443_holder_is_nginx() {
    [[ "${1:-}" == "tcp" ]] && shift
    local port="${1:-}" rows pids pid comm n=0
    _front443_port_ok "$port" || { error "front443_holder_is_nginx [tcp] <port>"; return 1; }
    rows="$(_front443_ss_p "$port")"
    [[ -n "$rows" ]] || return 1
    pids="$(printf '%s\n' "$rows" | grep -oE 'pid=[0-9]+' | cut -d= -f2 | sort -u || true)"
    [[ -n "$pids" ]] || return 1
    while IFS= read -r pid; do
        [[ -n "$pid" ]] || continue
        comm="$(_front443_pid_comm "$pid" || true)"
        [[ "$comm" == "nginx" ]] || return 1
        n=$(( n + 1 ))
    done <<< "$pids"
    [[ "$n" -gt 0 ]]
}

# ─── Scanning `nginx -T` ─────────────────────────────────────────────────────
# `nginx -T` prints every file the running configuration includes, each under a
# `# configuration file <path>:` header, verbatim — so the line numbers below
# are the file's own. Directories are never globbed: a file in sites-available
# that nothing includes is not a listener, and an RHEL host has no
# sites-enabled at all (lib/panel_deploy.sh, pnl_vhost_paths).
#
# Records, TAB-separated, first field is the type:
#
#   listen  <file>  <line>  <spelling>  <params|->  <server_has_real_ip_header 0|1>
#   realip  <file>  <line>  <http|server>
#   refuse  <file>  <line>  <reason>
#
# `refuse` (R1, hypothesis 4): a public-443 `listen` that is not the ONLY
# thing on its line, or whose `;` is on a later line. The rewrite works a line
# at a time and the marker holds the line's remainder, so `listen 443 ssl;
# listen 80;` would have gone live as one loopback listener with the port-80
# one buried in the marker comment — a listener silently gone until remove —
# and `listen 443` continued on the next line would have left a stray `ssl;`
# that fails -t AND a marker whose original never parses, so even the rollback
# could not put it back. Both are refused before anything is touched, by file
# and line, and the rewrite itself declines any line that is not one
# terminated listen. A line ending in CR (a vhost pasted from Windows) is one
# terminated listen: nginx reads CR as whitespace and so does this.
#
# ⚠ `params` is `-` when the directive has none, never empty. Every reader
# splits these records with `IFS=$'\t' read`, and a tab is IFS WHITESPACE: two
# adjacent tabs are one delimiter, so an empty field vanishes and every field
# after it shifts left. With `listen 443;` — the barest spelling there is — the
# real_ip_header flag landed in the params variable and the trap-6 warning was
# lost for exactly that vhost.
#
# A `listen` record is emitted for every http listener that would hold the
# PUBLIC 443 — spelled 443, *:443, 0.0.0.0:443, [::]:443, <pub4>:443 or
# [<pub6>]:443. Any other specific address (the panel on its tunnel address)
# is exactly the listener the front exists to leave alone. `quic`/`udp`
# listeners are UDP and the front cannot carry them, so they are skipped.
# Files under the stream directory are ours and are skipped.
#
# `realip` records name every real_ip_header directive outside our snippet.
# A SERVER-level one overrides the http-level snippet the front installs, so
# behind the front that vhost sees every visitor as 127.0.0.1 (trap 6 — warned,
# not solved in this version). An HTTP-level one is a DUPLICATE of the snippet
# and `nginx -t` refuses the pair, so the install must stop before writing it.
_front443_scan_text() {
    local pub4="${1:-}" pub6="${2:-}"
    _fs_p4="$pub4" _fs_p6="$pub6" _fs_sd="${VPN55_FRONT443_STREAM_DIR}/" _fs_rc="$VPN55_FRONT443_REALIP_CONF" \
    _fs_was="$VPN55_FRONT443_MARK_WAS" awk '
        function ispublic(spec,   p4, p6) {
            p4 = ENVIRON["_fs_p4"]; p6 = ENVIRON["_fs_p6"]
            if (spec == "443" || spec == "*:443" || spec == "0.0.0.0:443" || spec == "[::]:443") return 1
            if (p4 != "" && spec == p4 ":443") return 1
            if (p6 != "" && spec == "[" p6 "]:443") return 1
            return 0
        }
        # A server block starts at `server {`, `server{`, or a bare `server`
        # whose brace is on the next line. `sdepth` is the depth INSIDE it;
        # `entered` says the brace has actually been seen, so the bare form is
        # not read as closed on the line before it opens.
        function isstart(code) { return code ~ /^[ \t]*server[ \t]*(\{.*)?$/ }
        function sole(code) { return code ~ /^[ \t]*listen[ \t][^;]*;[ \t\r]*$/ }
        BEGIN { file = ""; lno = 0; depth = 0; sdepth = -1; entered = 0; nsid = 0; cur = ""; nrec = 0; nrip = 0; nref = 0 }
        /^# configuration file .*:$/ {
            file = $0; sub(/^# configuration file /, "", file); sub(/:$/, "", file)
            lno = 0; depth = 0; sdepth = -1; entered = 0; cur = file "#0"
            next
        }
        {
            lno++
            code = $0; sub(/#.*/, "", code)
            if (isstart(code)) { nsid++; cur = file "#" nsid; sdepth = depth + 1; entered = 0 }
            ours = (index(file, ENVIRON["_fs_sd"]) == 1 || file == ENVIRON["_fs_rc"])
            if (!ours && sole(code)) {
                body = code; sub(/^[ \t]*listen[ \t]+/, "", body); sub(/;.*/, "", body)
                n = split(body, t, /[ \t]+/)
                spec = t[1]; params = ""; skip = 0
                for (i = 2; i <= n; i++) {
                    if (t[i] == "") continue
                    if (t[i] == "quic" || t[i] == "udp") skip = 1
                    params = params (params == "" ? "" : " ") t[i]
                }
                if (!skip && ispublic(spec)) {
                    nrec++; rfile[nrec] = file; rline[nrec] = lno; rspec[nrec] = spec; rparams[nrec] = params
                    rsid[nrec] = (sdepth >= 0 ? cur : file "#0")
                }
            } else if (!ours && code ~ /(^|[ \t;{}])listen[ \t]/) {
                # A listen somewhere on a line that is not one terminated
                # listen: `server { listen 443 ssl; }`, `listen 80; listen 443
                # ssl;`, `listen 443 ssl; }`, or `listen 443` continued below.
                # Refused only when one of them would hold the public 443 —
                # any other listen on such a line is not ours to judge.
                nseg = split(code, seg, /;/)
                for (i = 1; i <= nseg; i++) {
                    piece = " " seg[i]
                    if (piece !~ /[ \t{}]listen[ \t]/) continue
                    sub(/^.*[ \t{}]listen[ \t]+/, "", piece); sub(/[ \t\r].*$/, "", piece)
                    if (ispublic(piece)) {
                        nref++; xfile[nref] = file; xline[nref] = lno
                        xwhy[nref] = (index(code, ";") == 0 ? "the listen directive does not end on this line" : "a public-443 listen shares its line with other text")
                        break
                    }
                }
            }
            if (!ours && code ~ /^[ \t]*real_ip_header[ \t]/) {
                sid = (sdepth >= 0 ? cur : file "#0")
                rip[sid] = 1
                nrip++; pfile[nrip] = file; pline[nrip] = lno; pscope[nrip] = (sdepth >= 0 ? "server" : "http")
            }
            nopen = gsub(/\{/, "{", code); nclose = gsub(/\}/, "}", code)
            depth += nopen - nclose
            if (sdepth >= 0 && depth >= sdepth) entered = 1
            if (sdepth >= 0 && entered && depth < sdepth) { sdepth = -1; entered = 0; cur = file "#0" }
        }
        END {
            for (i = 1; i <= nrec; i++)
                printf "listen\t%s\t%d\t%s\t%s\t%d\n", rfile[i], rline[i], rspec[i], (rparams[i] == "" ? "-" : rparams[i]), (rsid[i] in rip) ? 1 : 0
            for (i = 1; i <= nrip; i++)
                printf "realip\t%s\t%d\t%s\n", pfile[i], pline[i], pscope[i]
            for (i = 1; i <= nref; i++)
                printf "refuse\t%s\t%d\t%s\n", xfile[i], xline[i], xwhy[i]
        }'
}

# front443_scan — the records above, from the live configuration.
# The public addresses are resolved here so a specific-address spelling is
# recognised; a host with no public v4 is refused by front443_available, but
# scan on its own degrades to the wildcard spellings rather than failing.
front443_scan() {
    local pub4 pub6=""
    pub4="$(_front443_public_v4 2>/dev/null || true)"
    pub6="$(_front443_public_v6 2>/dev/null || true)"
    _front443_nginx_dump | _front443_scan_text "$pub4" "$pub6"
}

# Whether a foreign top-level `stream {` exists — ours is the one marked line.
_front443_foreign_stream() {
    local dump="${1:-}"
    _fs_m="$VPN55_FRONT443_MARK" awk '
        /^[ \t]*stream[ \t]*\{/ && index($0, ENVIRON["_fs_m"]) == 0 { hit = 1 }
        END { exit !hit }' <<< "$dump"
}

_front443_dump_has_include() {
    local dump="${1:-}"
    _fs_m="$VPN55_FRONT443_MARK" awk '
        /^[ \t]*stream[ \t]*\{/ && index($0, ENVIRON["_fs_m"]) > 0 { hit = 1 }
        END { exit !hit }' <<< "$dump"
}

_front443_dump_has_module() {
    local dump="${1:-}"
    awk '/^[ \t]*load_module[ \t].*ngx_stream_module\.so/ { hit = 1 } END { exit !hit }' <<< "$dump"
}

# Whether the configuration has any live listener on 127.0.0.1:<web> — i.e.
# whether nginx would bind the web port at all. It binds it only because a
# rewritten vhost listens there; on a host whose only 443 holder was an
# address-bound listener the front leaves alone (the VPN55 panel on its
# tunnel address — the self-collision §6C.8 opens with), NO vhost moves, the
# port is never bound, and a bind check that demanded it would fail the
# install on exactly that host (R1). So the web port is required when, and
# only when, the configuration says something listens there.
_front443_dump_expects_web() {
    local dump="${1:-}" web="${2:-}"
    [[ -n "$web" ]] || return 1
    _fs_w="$web" awk '
        { code = $0; sub(/#.*/, "", code)
          if (code ~ ("^[ \t]*listen[ \t]+127\\.0\\.0\\.1:" ENVIRON["_fs_w"] "([ \t;]|$)")) hit = 1 }
        END { exit !hit }' <<< "$dump"
}

# Any marker line — a tagged listen or an off-switched one — anywhere in the dump.
_front443_dump_has_markers() {
    local dump="${1:-}"
    _fs_was="$VPN55_FRONT443_MARK_WAS" _fs_off="$VPN55_FRONT443_MARK_OFF" awk '
        index($0, ENVIRON["_fs_was"]) > 0 || index($0, ENVIRON["_fs_off"]) > 0 { hit = 1 }
        END { exit !hit }' <<< "$dump"
}

# ─── The front's traces, read without a ledger ───────────────────────────────
# Everything the ledger's `file` rows would have named, found from the host
# itself: every file `nginx -T` prints that carries a marker line, and every
# file under nginx's directory that does — the second because `-T` fails on a
# broken configuration and prints nothing, and a half-removed host is exactly
# where it may be broken. Both, deduplicated, in first-seen order. The stream
# directory is ours and is deleted whole, so it is not a "file" here.
_front443_marked_files() {
    local dump dir
    dump="$(_front443_nginx_dump 2>/dev/null)" || dump=""
    dir="$(dirname "$VPN55_NGINX_CONF")"
    {
        _fs_was="$VPN55_FRONT443_MARK_WAS" _fs_off="$VPN55_FRONT443_MARK_OFF" awk '
            /^# configuration file .*:$/ { f = $0; sub(/^# configuration file /, "", f); sub(/:$/, "", f); next }
            f != "" && (index($0, ENVIRON["_fs_was"]) > 0 || index($0, ENVIRON["_fs_off"]) > 0) { print f }' <<< "$dump"
        if [[ -d "$dir" ]]; then
            grep -rlF -e "$VPN55_FRONT443_MARK_WAS" -e "$VPN55_FRONT443_MARK_OFF" "$dir" 2>/dev/null || true
        fi
    } | _fs_sd="$VPN55_FRONT443_STREAM_DIR" awk '
        $0 == "" { next }
        index($0, ENVIRON["_fs_sd"] "/") == 1 { next }
        !seen[$0]++'
    return 0
}

# front443_traces_present — the front's own files or markers exist on a host
# with no ledger to name them: a front whose ledger went missing (a hand `rm`,
# a restore that did not carry /etc/vpn55). With the ledger present this is
# not the question — front443_installed is.
front443_traces_present() {
    front443_installed && return 1
    [[ -n "$(_front443_marked_files)" ]] && return 0
    _front443_include_present && return 0
    [[ -f "$VPN55_FRONT443_STREAM_CONF" || -f "$VPN55_FRONT443_REALIP_CONF" || -f "$VPN55_FRONT443_DROPIN" ]] && return 0
    return 1
}

# The addresses the stream file binds, for the waits a ledger-less remove
# runs: `<v4>` on the first line, `<v6 or empty>` on the second.
_front443_stream_conf_binds() {
    [[ -r "$VPN55_FRONT443_STREAM_CONF" ]] || { printf '\n\n'; return 0; }
    awk '
        /^[ \t]*listen[ \t]+\[/ { a = $2; sub(/^\[/, "", a); sub(/\]:.*$/, "", a); if (v6 == "") v6 = a; next }
        /^[ \t]*listen[ \t]+[0-9]/ { a = $2; sub(/:[0-9]+.*$/, "", a); if (a != "127.0.0.1" && v4 == "") v4 = a }
        END { print v4; print v6 }' "$VPN55_FRONT443_STREAM_CONF"
}

# ─── The stream module ───────────────────────────────────────────────────────
# Prints one of: static | loaded | missing | absent
#   static   built in (`--with-stream` with no =dynamic)
#   loaded   built as a dynamic module and a load_module line is in effect
#   missing  dynamic, and nothing loads it
#   absent   nginx was built without the stream module at all
#
# Debian's build says `--with-stream=dynamic`, so a bare grep for "with-stream"
# reports a static module on every Debian host and the stream block then fails
# with "unknown directive". The token is compared whole.
_front443_module_state() {
    local flags toks tok dyn=0 stat=0
    flags="$(_front443_nginx_flags)" || true
    read -ra toks <<< "${flags//$'\n'/ }"
    for tok in ${toks[@]+"${toks[@]}"}; do
        case "$tok" in
            --with-stream)         stat=1 ;;
            --with-stream=dynamic) dyn=1 ;;
        esac
    done
    if [[ "$stat" -eq 1 ]]; then printf 'static'; return 0; fi
    if [[ "$dyn" -eq 0 ]]; then printf 'absent'; return 0; fi
    if _front443_dump_has_module "$(_front443_nginx_dump)"; then printf 'loaded'; else printf 'missing'; fi
    return 0
}

_front443_flag_present() {
    local flags toks tok
    flags="$(_front443_nginx_flags)" || true
    read -ra toks <<< "${flags//$'\n'/ }"
    for tok in ${toks[@]+"${toks[@]}"}; do
        [[ "$tok" == "${1:-}" || "$tok" == "${1:-}=dynamic" ]] && return 0
    done
    return 1
}

_front443_module_pkg() {
    _distro_need_detect || return 1
    case "$VPN55_OS_FAMILY" in
        debian) printf 'libnginx-mod-stream' ;;
        rhel)   printf 'nginx-mod-stream' ;;
        *)      return 1 ;;
    esac
}

_front443_module_ensure() {
    local state pkg
    state="$(_front443_module_state)"
    case "$state" in
        static|loaded) return 0 ;;
        absent)
            error "this nginx was built without the stream module (nginx -V has no --with-stream),"
            error "so it cannot front port 443. Install a build that has it."
            return 1 ;;
    esac

    pkg="$(_front443_module_pkg)" || {
        error "the stream module is dynamic and not loaded, and this distribution has no"
        error "known package for it. Add 'load_module modules/ngx_stream_module.so;' to"
        error "the top of ${VPN55_NGINX_CONF} and re-run."
        return 1
    }
    if ! distro_pkg_installed "$pkg"; then
        info "Installing the nginx stream module (${pkg})…"
        distro_pkg_install "$pkg" || return 1
        _front443_ledger_add pkg "$pkg" || return 1
    fi
    state="$(_front443_module_state)"
    if [[ "$state" != "loaded" ]]; then
        error "${pkg} is installed but ${VPN55_NGINX_CONF} does not include its load_module"
        error "line (Debian: include /etc/nginx/modules-enabled/*.conf; RHEL:"
        error "include /usr/share/nginx/modules/*.conf;). Add the include at the TOP of"
        error "nginx.conf — the module must load before the stream block — and re-run."
        return 1
    fi
    return 0
}

# ─── SELinux ─────────────────────────────────────────────────────────────────
# nginx runs as httpd_t. Its connect to 127.0.0.1:<backend> is a connect to
# whatever port type the backend's own policy gave that port, and
# httpd_can_network_relay reaches http-labelled ports only. So the boolean is
# httpd_can_network_connect, set persistently.
#
# The cost, stated: with it on, an nginx worker may open a TCP connection to
# ANY port on any host — a compromised worker can reach the panel's loopback
# port, a database, anything. Before the front, policy confined it to
# http-labelled ports. The narrower alternative — a local policy module
# allowing httpd_t exactly one port type, plus httpd_can_network_relay for the
# 8443/8008 hops — needs checkpolicy on the host and a module to carry through
# upgrades, and is deliberately not this version. Relabelling the backend port
# to http_port_t is the §6C.6 trap in reverse and is never done.
#
# The value BEFORE us is recorded, and remove puts it back only if we changed
# it. Permissive hosts get the same treatment so that switching to enforcing
# later does not break the front.
_front443_selinux_ensure() {
    local mode cur
    mode="$(_front443_selinux_mode)" || return 0
    case "$mode" in Enforcing|Permissive) ;; *) return 0 ;; esac

    if ! _front443_have getsebool || ! _front443_have setsebool; then
        if [[ "$mode" == "Enforcing" ]]; then
            error "SELinux is enforcing and getsebool/setsebool are missing, so nginx cannot be"
            error "allowed to connect to the loopback ports. Install policycoreutils and re-run."
            return 1
        fi
        warn "SELinux is permissive and setsebool is missing; the front works now and will"
        warn "stop working if the host is switched to enforcing."
        return 0
    fi

    cur="$(_front443_getsebool httpd_can_network_connect)"
    if [[ "$cur" == "on" ]]; then
        debug "selinux: httpd_can_network_connect already on"
        return 0
    fi
    # Ledger first, boolean second. The other order has a window in which the
    # boolean is on and nothing records it — a failed ledger write there would
    # leave a host more permissive than it was with no row to reverse it. A row
    # recorded for a boolean that then failed to flip costs nothing: remove
    # sets it back to the `off` it never left.
    _front443_ledger_add selinux httpd_can_network_connect "${cur:-off}" || return 1
    if _front443_setsebool httpd_can_network_connect 1; then
        info "SELinux: httpd_can_network_connect set on, so nginx may reach the loopback ports."
        info "  Cost: nginx workers may now open TCP connections to any port. Reversed on remove."
        return 0
    fi
    if [[ "$mode" == "Enforcing" ]]; then
        error "could not set httpd_can_network_connect; under enforcing the front cannot reach"
        error "its loopback ports. Nothing was changed."
        return 1
    fi
    warn "could not set httpd_can_network_connect (permissive host — continuing)"
    return 0
}

_front443_selinux_revert() {
    local rows row prior
    rows="$(_front443_ledger_rows selinux)" || return 0
    row="${rows%%$'\n'*}"
    [[ -n "$row" ]] || return 0
    prior="${row#*$'\t'}"
    [[ "$prior" == "off" ]] || return 0
    _front443_have setsebool || return 0
    if _front443_setsebool httpd_can_network_connect 0; then
        info "SELinux: httpd_can_network_connect set back to off."
    else
        warn "could not set httpd_can_network_connect back to off — do it by hand:"
        warn "  setsebool -P httpd_can_network_connect 0"
    fi
    return 0
}

# ─── Rewriting one vhost ─────────────────────────────────────────────────────
# _front443_rewrite_text <web_port> <pub4> <pub6>  — file content on stdin.
#
# The first public-443 listener in each server block becomes
#     listen 127.0.0.1:<web> <params> proxy_protocol; # vpn55-front443: was <original>
# every further one in the same block becomes
#     # vpn55-front443: off: <original>
# `ipv6only=…` is dropped from the params (it is meaningless on a v4 loopback
# address and nginx refuses it there); an existing `proxy_protocol` is not
# doubled. A line already carrying the marker counts as the block's kept
# listener, which is what makes a certbot-added twin go to `off` on repair.
#
# Two passes over the text, not one. The kept line of a block is whichever
# tagged line it ALREADY holds, wherever it sits — certbot inserts its
# `listen 443 ssl` where it likes, and a hand edit lands anywhere. A single
# pass that met a new bare 443 ABOVE the block's tagged line would rewrite it
# to a second `listen 127.0.0.1:<web>`, which nginx refuses as a duplicate, and
# the repair that was meant to fix drift would fail `nginx -t` instead.
_front443_rewrite_text() {
    _fr_web="${1:-}" _fr_p4="${2:-}" _fr_p6="${3:-}" \
    _fr_was="$VPN55_FRONT443_MARK_WAS" _fr_off="$VPN55_FRONT443_MARK_OFF" awk '
        function ispublic(spec,   p4, p6) {
            p4 = ENVIRON["_fr_p4"]; p6 = ENVIRON["_fr_p6"]
            if (spec == "443" || spec == "*:443" || spec == "0.0.0.0:443" || spec == "[::]:443") return 1
            if (p4 != "" && spec == p4 ":443") return 1
            if (p6 != "" && spec == "[" p6 "]:443") return 1
            return 0
        }
        function isstart(code) { return code ~ /^[ \t]*server[ \t]*(\{.*)?$/ }
        # Walks the block structure once per pass. Sets `cur` to the id of the
        # server block the line is in ("" outside any) and returns the code
        # half of the line; the caller updates depth after using it.
        function enter(line,   code) {
            code = line; sub(/#.*/, "", code)
            if (isstart(code)) { nsid++; cur = nsid; sdepth = depth + 1; entered = 0 }
            return code
        }
        function leave(code,   nopen, nclose) {
            nopen = gsub(/\{/, "{", code); nclose = gsub(/\}/, "}", code)
            depth += nopen - nclose
            if (sdepth >= 0 && depth >= sdepth) entered = 1
            if (sdepth >= 0 && entered && depth < sdepth) { sdepth = -1; entered = 0; cur = "" }
        }
        BEGIN { n = 0; was = ENVIRON["_fr_was"]; off = ENVIRON["_fr_off"]; web = ENVIRON["_fr_web"] }
        { lines[++n] = $0 }
        END {
            # Pass 1: which blocks already hold a tagged (kept) listener.
            depth = 0; sdepth = -1; entered = 0; nsid = 0; cur = ""
            for (i = 1; i <= n; i++) {
                code = enter(lines[i])
                if (code ~ /^[ \t]*listen[ \t]/ && index(lines[i], was) > 0 && cur != "") haskept[cur] = 1
                leave(code)
            }
            # Pass 2: the rewrite, seeded with what pass 1 found.
            depth = 0; sdepth = -1; entered = 0; nsid = 0; cur = ""; kept = 0
            for (i = 1; i <= n; i++) {
                line = lines[i]
                indent = line; sub(/[^ \t].*$/, "", indent)
                rest = substr(line, length(indent) + 1)
                code = enter(line)
                if (isstart(code)) kept = (cur in haskept) ? 1 : 0
                out = line
                # Only a line that IS one terminated listen is rewritten; the
                # scanner has refused every public-443 listen that is not, so
                # anything else met here is left exactly as it stands.
                if (code ~ /^[ \t]*listen[ \t][^;]*;[ \t\r]*$/ && index(line, was) == 0) {
                    body = code; sub(/^[ \t]*listen[ \t]+/, "", body); sub(/;.*/, "", body)
                    m = split(body, t, /[ \t]+/)
                    spec = t[1]; params = ""; skip = 0
                    for (j = 2; j <= m; j++) {
                        if (t[j] == "") continue
                        if (t[j] == "quic" || t[j] == "udp") skip = 1
                        if (t[j] ~ /^ipv6only=/ || t[j] == "proxy_protocol") continue
                        params = params (params == "" ? "" : " ") t[j]
                    }
                    if (!skip && ispublic(spec)) {
                        if (!kept) {
                            out = indent "listen 127.0.0.1:" web (params == "" ? "" : " " params) " proxy_protocol; " was rest
                            kept = 1
                        } else {
                            out = indent off rest
                        }
                    }
                }
                print out
                leave(code)
                if (cur == "") kept = 0
            }
        }'
}

# _front443_restore_text — file content on stdin. Tagged lines come back as
# their original text; a tag whose original no longer looks like a listen
# directive is left exactly as found and reported on stderr. Exit 3 when any
# line was left, so the caller can say so by file name.
_front443_restore_text() {
    _fr_was="$VPN55_FRONT443_MARK_WAS" _fr_off="$VPN55_FRONT443_MARK_OFF" awk '
        BEGIN { was = ENVIRON["_fr_was"]; off = ENVIRON["_fr_off"]; left = 0 }
        {
            line = $0
            indent = line; sub(/[^ \t].*$/, "", indent)
            rest = substr(line, length(indent) + 1)
            orig = ""; tagged = 0
            if (substr(rest, 1, 7) == "listen " && (i = index(line, was)) > 0) {
                orig = substr(line, i + length(was)); tagged = 1
            } else if (substr(rest, 1, length(off)) == off) {
                orig = substr(rest, length(off) + 1); tagged = 1
            }
            if (!tagged) { print line; next }
            if (orig ~ /^listen[ \t][^;]*;/) {
                print indent orig
            } else {
                left++
                printf "line %d: marker found but its original does not parse as a listen directive — left as is\n", NR > "/dev/stderr"
                print line
            }
        }
        END { exit (left > 0 ? 3 : 0) }'
}

# Rewrite through the file's own inode (owner and mode survive). Returns 0 and
# sets VPN55_FRONT443_CHANGED=1 when the bytes changed, 0 when they did not.
VPN55_FRONT443_CHANGED=0
_front443_apply_text() {
    local file="${1:-}" tmp="${2:-}"
    VPN55_FRONT443_CHANGED=0
    if cmp -s "$file" "$tmp"; then
        rm -f "$tmp" || { error "cannot remove $tmp"; return 1; }
        return 0
    fi
    fs_replace_in_place "$file" < "$tmp" || { rm -f "$tmp" 2>/dev/null || true; return 1; }
    rm -f "$tmp" || { error "cannot remove $tmp"; return 1; }
    VPN55_FRONT443_CHANGED=1
    return 0
}

_front443_rewrite_file() {
    local file="${1:-}" web="${2:-}" pub4="${3:-}" pub6="${4:-}" tmp
    [[ -f "$file" ]] || { error "cannot rewrite ${file}: not a file"; return 1; }
    tmp="${file}.${VPN55_FRONT443_MARK}.$$"
    ( umask 077; _front443_rewrite_text "$web" "$pub4" "$pub6" < "$file" > "$tmp"; ) \
        || { error "cannot rewrite ${file}"; rm -f "$tmp" 2>/dev/null || true; return 1; }
    _front443_apply_text "$file" "$tmp" || return 1
    return 0
}

_front443_restore_file() {
    local file="${1:-}" tmp rc=0
    [[ -f "$file" ]] || { info "${file} is gone since the install — skipped"; return 0; }
    tmp="${file}.${VPN55_FRONT443_MARK}.$$"
    ( umask 077; _front443_restore_text < "$file" > "$tmp"; ) || rc=$?
    if [[ "$rc" -ne 0 && "$rc" -ne 3 ]]; then
        error "cannot restore ${file}"; rm -f "$tmp" 2>/dev/null || true; return 1
    fi
    _front443_apply_text "$file" "$tmp" || return 1
    if [[ "$rc" -eq 3 ]]; then
        warn "${file}: one or more ${VPN55_FRONT443_MARK} markers were left in place because"
        warn "their recorded original no longer reads as a listen directive. Edit by hand."
    fi
    return 0
}

# ─── The files that are ours ─────────────────────────────────────────────────
_front443_stream_conf_text() {
    local backend="${1:-}" web="${2:-}" strip="${3:-}" pub4="${4:-}" pub6="${5:-}"
    cat <<CONF
# Written by VPN55 (lib/core_front443.sh). Regenerated on repair; do not edit.
#
# One question is asked of the first bytes of every connection to the public
# 443: is this a TLS ClientHello? If so it goes to the operator's vhosts on the
# loopback web port with the PROXY protocol header, so they still see the real
# client address. Anything else goes to the loopback service — through a second
# server that swallows the PROXY header, because that service cannot read one
# and nginx sets proxy_protocol per server, not per upstream.
#
# Routing is on protocol, never on name: a site added next month needs no edit.
# The public address is bound explicitly — never the wildcard — so that another
# address-bound :443 in this same nginx (the VPN55 panel on its tunnel address)
# can coexist with it.

map \$ssl_preread_protocol \$${VPN55_FRONT443_MARK//-/_}_upstream {
    ""       127.0.0.1:${strip};
    default  127.0.0.1:${web};
}

server {
    listen ${pub4}:${VPN55_FRONT443_PORT};
CONF
    if [[ -n "$pub6" ]]; then
        printf '    listen [%s]:%s;\n' "$pub6" "$VPN55_FRONT443_PORT"
    fi
    cat <<CONF
    ssl_preread on;
    proxy_protocol on;
    proxy_pass \$${VPN55_FRONT443_MARK//-/_}_upstream;
}

# The strip hop: accepts the PROXY header from the server above and forwards
# plain bytes. Loopback only.
server {
    listen 127.0.0.1:${strip} proxy_protocol;
    proxy_pass 127.0.0.1:${backend};
}
CONF
}

_front443_realip_text() {
    cat <<'CONF'
# Written by VPN55 (lib/core_front443.sh). Remove with the front, not by hand.
#
# Every vhost that used to listen on the public 443 now listens on the loopback
# web port with `proxy_protocol`, and the front hands it the PROXY protocol
# header carrying the real client address. These two lines make nginx believe
# that header — from 127.0.0.1 only, which is the only place the front connects
# from — so $remote_addr, access logs and per-address rate limits keep working.
#
# A vhost that sets its own real_ip_header overrides this and will see every
# visitor as 127.0.0.1. VPN55 warns about such a vhost by name at install.
#
# What this trusts, stated: ANY local process may connect to the loopback web
# port and send a PROXY header naming any address, and nginx will believe it
# — in the access log, in limit_req buckets, in allow/deny lists. Before the
# front a local process was 127.0.0.1 and could not claim to be anyone else.
# docs/security-model.md §6C.8 ("R1 review") records why this is stated as a
# cost rather than closed with a UNIX socket.
set_real_ip_from 127.0.0.1;
real_ip_header  proxy_protocol;
CONF
}

_front443_dropin_text() {
    cat <<'DROPIN'
# Written by VPN55 (lib/core_front443.sh).
#
# The shared-443 front binds this host's public address explicitly, which on
# some hosts is not yet assigned when nginx starts at boot. systemd cannot
# order a unit after "that interface has an address", so nginx is allowed to
# fail and come back instead. Without this, a reboot where nginx starts first
# leaves EVERY site on this host down until someone restarts it by hand.
#
# Removed with the front.
[Unit]
StartLimitIntervalSec=0

[Service]
Restart=on-failure
RestartSec=10s
DROPIN
}

_front443_conf_d_included() {
    [[ -r "$VPN55_NGINX_CONF" ]] \
        && grep -Eq '^[[:space:]]*include[[:space:]].*conf\.d' "$VPN55_NGINX_CONF"
}

# The one line in nginx.conf. Appended at the end, so every load_module include
# at the top has already run; removed by marker, so an operator's other edits
# to nginx.conf survive.
_front443_include_present() {
    [[ -r "$VPN55_NGINX_CONF" ]] && grep -qF "# ${VPN55_FRONT443_MARK}" "$VPN55_NGINX_CONF"
}

_front443_include_add() {
    _front443_include_present && return 0
    [[ -w "$VPN55_NGINX_CONF" ]] || { error "cannot write ${VPN55_NGINX_CONF}"; return 1; }
    # A file whose last byte is not a newline would glue our line to its last.
    if [[ -s "$VPN55_NGINX_CONF" ]] && [[ "$(tail -c1 "$VPN55_NGINX_CONF" | od -An -c | tr -d ' ')" != '\n' ]]; then
        printf '\n' >> "$VPN55_NGINX_CONF" || { error "cannot append to ${VPN55_NGINX_CONF}"; return 1; }
    fi
    printf '%s\n' "$VPN55_FRONT443_INCLUDE_LINE" >> "$VPN55_NGINX_CONF" \
        || { error "cannot append to ${VPN55_NGINX_CONF}"; return 1; }
    return 0
}

# Removed by SHAPE — a `stream {` line ending in our marker — never by the bare
# marker word: an operator's own comment in nginx.conf that happens to mention
# vpn55-front443 is theirs to keep.
_front443_include_remove() {
    local remaining
    _front443_include_present || return 0
    remaining="$(grep -vE "^[[:space:]]*stream[[:space:]]*\{.*#[[:space:]]*${VPN55_FRONT443_MARK}[[:space:]]*$" "$VPN55_NGINX_CONF" || true)"
    printf '%s\n' "$remaining" | fs_replace_in_place "$VPN55_NGINX_CONF" \
        || { error "cannot rewrite ${VPN55_NGINX_CONF}"; return 1; }
    return 0
}

# ─── Availability ────────────────────────────────────────────────────────────
# front443_available — can this host carry the front? Prints the reason on
# failure. A probe, not an installer: it installs nothing.
front443_available() {
    local dump state pkg

    _front443_have nginx || { error "nginx is not installed"; return 1; }
    _front443_have ss    || { error "ss (iproute2) is missing; the front cannot verify its binds"; return 1; }

    if ! _front443_nginx_test; then
        error "nginx's current configuration does not pass 'nginx -t'; fix that first:"
        _front443_nginx_test_out | sed 's/^/    /' >&2
        return 1
    fi

    state="$(_front443_module_state)"
    case "$state" in
        absent)
            error "this nginx was built without the stream module (no --with-stream in nginx -V)"
            return 1 ;;
        missing)
            pkg="$(_front443_module_pkg 2>/dev/null)" || {
                error "the stream module is dynamic, not loaded, and this distribution has no known package for it"
                return 1
            }
            debug "front443: stream module would come from ${pkg}" ;;
    esac
    # ssl_preread is what the routing decision is made with; realip is what
    # gives the vhosts their client address back. Neither is optional.
    _front443_flag_present --with-stream_ssl_preread_module \
        || { error "this nginx lacks --with-stream_ssl_preread_module; the front cannot tell TLS from anything else"; return 1; }
    _front443_flag_present --with-http_realip_module \
        || { error "this nginx lacks --with-http_realip_module; the vhosts could not recover the client address"; return 1; }

    dump="$(_front443_nginx_dump)"
    if _front443_foreign_stream "$dump"; then
        error "nginx.conf already has a top-level stream {} block that is not VPN55's."
        error "nginx allows exactly one, so the front cannot add its own. Not fronted in this"
        error "version — move the existing block's contents into ${VPN55_FRONT443_STREAM_DIR}/"
        error "and let VPN55 own the block, or choose another port."
        return 1
    fi

    _front443_conf_d_included \
        || { error "${VPN55_NGINX_CONF} does not include conf.d/, so the real-IP snippet would never be read"; return 1; }

    _front443_public_v4 >/dev/null 2>&1 \
        || { error "this host's public IPv4 address cannot be determined, and the front never binds the wildcard"; return 1; }

    return 0
}

# ─── Install ─────────────────────────────────────────────────────────────────
# front443_install <backend_port> [web_port] [strip_port]
#
# The optional ports default to the VPN55_FRONT443_*_PORT environment. On a
# re-run the ledger's ports are the only ones accepted; front443_repair passes
# all three from the ledger so that an environment changed since the install
# cannot turn a repair into a refusal (R1, hypothesis 10).
#
# Idempotent: with the ledger present and every invariant holding, it changes
# nothing and reloads nothing.
#
# Failure rolls back what THIS CALL did, and the scope of that differs:
#   · a FRESH install rolls back to nothing — front443_remove over the ledger
#     written so far, exactly as a refused install would leave the host;
#   · a RE-RUN (front443_repair; the adapter's second install) puts back only
#     the vhost files this call rewrote, from a byte copy taken just before,
#     and leaves the front that was already carrying traffic where it was.
#     Running front443_remove here would take a working tunnel down because a
#     certbot vhost nginx rejected — the repair for drift becoming an outage.
#     A byte copy is right within one call (nobody edits the file between our
#     read and our write seconds later); it is wrong across an install and an
#     uninstall, which is why remove restores by marker instead.
#
# The caller brings the loopback service up FIRST. The front never points at a
# dead port, so a backend nothing listens on is a refusal, not a warning.
VPN55_FRONT443_FRESH=1
VPN55_FRONT443_SNAP=""
front443_install() {
    local rc=0
    VPN55_FRONT443_FRESH=1
    VPN55_FRONT443_SNAP=""
    _front443_install_run "$@" || rc=$?
    if [[ -n "$VPN55_FRONT443_SNAP" ]]; then
        rm -rf "${VPN55_FRONT443_SNAP:?}" 2>/dev/null || true
    fi
    VPN55_FRONT443_SNAP=""
    return "$rc"
}

_front443_install_run() {
    local backend="${1:-}" web="${2:-$VPN55_FRONT443_WEB_PORT}" strip="${3:-$VPN55_FRONT443_STRIP_PORT}"
    local pub4 pub6="" records files=() f seen want6=0 realip_http="" realip_srv="" refused="" fresh=1
    local vhost_changed=0 stream_changed=0 rtype rfile rline rspec rflag nsnap=0 need_web=0

    _front443_ports_validate "$backend" "$web" "$strip" || return 1

    front443_available || return 1
    pub4="$(_front443_public_v4)" || return 1
    # net_wan_address is the caller's contract, but the file the address lands
    # in is a `listen` line, and `listen :443` or `listen 0.0.0.0:443` is the
    # wildcard by another spelling. Refused here, never discovered at bind.
    case "$pub4" in
        ""|"0.0.0.0"|"*"|"::"|"[::]") error "the public address resolved to '${pub4}', which is not an address the front may bind"; return 1 ;;
    esac

    if front443_installed; then
        fresh=0
        VPN55_FRONT443_FRESH=0
        local rb rw rs rbind
        rb="$(_front443_ledger_get backend_port || true)"
        rw="$(_front443_ledger_get web_port || true)"
        rs="$(_front443_ledger_get strip_port || true)"
        rbind="$(_front443_ledger_get bind || true)"
        if [[ -n "$rb" && "$rb" != "$backend" ]] || [[ -n "$rw" && "$rw" != "$web" ]] || [[ -n "$rs" && "$rs" != "$strip" ]]; then
            error "the front is recorded with ports backend=${rb} web=${rw} strip=${rs}, and this run"
            error "asks for backend=${backend} web=${web} strip=${strip}. The recorded ports win: the"
            error "vhosts already listen on them. Unset any VPN55_FRONT443_WEB_PORT /"
            error "VPN55_FRONT443_STRIP_PORT override and re-run; to move the ports, remove the"
            error "service that shares the port and install it again. Nothing was changed."
            return 1
        fi
        # The ledger holds one bind, and every later read takes the FIRST row
        # of a type — so a re-run that silently recorded a second address would
        # leave check verifying the old one for ever. A host whose public
        # address moved is a remove-and-install, said here.
        if [[ -n "$rbind" && "$rbind" != "$pub4" ]]; then
            error "the front is recorded on ${rbind}:${VPN55_FRONT443_PORT} but this host's public address is now"
            error "${pub4}. Run front443_remove and install the front again on the new address."
            return 1
        fi
        VPN55_FRONT443_SNAP="$(mktemp -d "${TMPDIR:-/tmp}/vpn55-front443.XXXXXX")" \
            || { error "cannot create a directory for the pre-rewrite copies"; return 1; }
    else
        # No ledger, but the host carries the front's own traces: tagged
        # vhost lines, the include, or the stream file. That is a front whose
        # ledger went missing (a hand `rm`, a restore that did not carry
        # /etc/vpn55) — NOT a host to install onto. A fresh install here found
        # no public-443 listener (they are all tagged), saw the web port held
        # by those very vhosts, and told the operator to pick ANOTHER web port
        # — which would have pointed a new front at a port nothing listens on
        # and, on the rollback, restored nothing, because the ledger it was
        # rolling back held no file rows (R1, hypothesis 9c). Refused; the
        # way back is the remove verb, which reads the marked files from the
        # host itself when there is no ledger (front443_remove).
        if front443_traces_present; then
            error "this host carries VPN55's shared-443 front but its ledger ${VPN55_FRONT443_STATE}"
            error "is missing, so nothing can be installed onto it. Take the traces down first —"
            error "the marked vhost lines are put back to their originals, the stream file, the"
            error "include, the snippet and the drop-in are removed, and nginx is reloaded:"
            error "    ${VPN55_FRONT443_REMOVE_CMD}"
            error "then re-run. Nothing was changed."
            return 1
        fi
    fi

    # The backend must already be there — by address, on loopback — for a
    # FRESH install: the front is never put on pointing at a dead port. A
    # re-run is a different question. The front is already on; what a re-run
    # does is put the vhosts, the stream file and the include back the way
    # they were, and none of that depends on the service being up — nginx
    # accepts a proxy_pass to a port nothing holds. Refusing here on a re-run
    # meant drift could not be repaired while the fronted service was stopped
    # (R1, hypothesis 9a): the website stayed broken until the tunnel came
    # back. So the re-run goes ahead, says so, and the check's backend row
    # says the rest.
    if ! _front443_addr_held 127.0.0.1 "$backend"; then
        if [[ "$fresh" -eq 1 ]]; then
            error "nothing is listening on 127.0.0.1:${backend}. Start the loopback service first;"
            error "the front never points at a dead port."
            return 1
        fi
        warn "nothing is listening on 127.0.0.1:${backend}. The front is re-applied anyway — its"
        warn "files do not depend on the service being up — and until that service is started"
        warn "the tunnel is refused while the website is served. The check reports it as 'backend'."
    fi
    # Fresh install: the two loopback ports must be nobody's. On a re-run they
    # are ours and the bind verification below checks them by address.
    if [[ "$fresh" -eq 1 ]]; then
        _front443_port_held "$web" \
            && { error "port ${web} is already in use; set VPN55_FRONT443_WEB_PORT to a free one"; return 1; }
        _front443_port_held "$strip" \
            && { error "port ${strip} is already in use; set VPN55_FRONT443_STRIP_PORT to a free one"; return 1; }
    fi

    # Scan before touching anything.
    records="$(front443_scan)" || { error "cannot scan the nginx configuration"; return 1; }
    while IFS=$'\t' read -r rtype rfile rline rspec _ rflag; do
        case "$rtype" in
            listen)
                seen=0
                for f in ${files[@]+"${files[@]}"}; do [[ "$f" == "$rfile" ]] && seen=1; done
                [[ "$seen" -eq 1 ]] || files+=("$rfile")
                case "$rspec" in \[*\]:443) want6=1 ;; esac
                if [[ "$rflag" == "1" ]]; then
                    str_has_line "$realip_srv" "$rfile" || realip_srv="${realip_srv}${realip_srv:+$'\n'}${rfile}"
                fi ;;
            realip)
                [[ "$rspec" == "http" ]] && realip_http="${realip_http}${realip_http:+$'\n'}${rfile}:${rline}" ;;
            refuse)
                refused="${refused}${refused:+$'\n'}${rfile}:${rline}: ${rspec}" ;;
        esac
    done <<< "$records"

    if [[ -n "$refused" ]]; then
        error "these listen lines cannot be rewritten as they stand — the front works one"
        error "directive per line, and a marker must hold a complete original:"
        printf '%s\n' "$refused" | sed 's/^/    /' >&2
        error "Put each public-443 listen on a line of its own, ending in ';', and re-run."
        error "Nothing was changed."
        return 1
    fi
    if [[ -n "$realip_http" ]]; then
        error "nginx already sets real_ip_header at the http level, and the front's snippet"
        error "would be a duplicate directive nginx refuses:"
        printf '%s\n' "$realip_http" | sed 's/^/    /' >&2
        error "Move that directive into the server blocks that need it and re-run."
        return 1
    fi
    if [[ -n "$realip_srv" ]]; then
        warn "These vhosts set their own real_ip_header, which overrides the front's. Behind"
        warn "the front their connection address is 127.0.0.1, so unless that directive"
        warn "trusts 127.0.0.1 they will log every visitor as 127.0.0.1 — and if it does,"
        warn "the header becomes spoofable. Not solved in this version:"
        printf '%s\n' "$realip_srv" | sed 's/^/    /' >&2
    fi

    if [[ "$fresh" -eq 0 ]]; then
        # A re-run keeps the v6 decision the install made: the stream file is
        # regenerated from the ledger, so it is byte-identical unless drift
        # removed it, and the ledger's single bind6 row stays the only one.
        pub6="$(_front443_ledger_get bind6 || true)"
        [[ "$pub6" == "-" ]] && pub6=""
    elif [[ "$want6" -eq 1 ]]; then
        if pub6="$(_front443_public_v6)"; then
            debug "front443: a vhost listened on [::]:443 and the host has ${pub6}; the front binds it too"
        else
            info "A vhost listened on [::]:443 but this host has no global IPv6 address; the"
            info "front binds IPv4 only."
            pub6=""
        fi
    fi

    # ── Phase 0: nothing here changes what nginx binds ──
    # Every failure from here on rolls back: the module step may already have
    # written a `pkg` row, and a ledger with rows and no `installed` stamp is
    # what front443_installed reads as "on" — the next status read would then
    # report a front that was never there as broken.
    _front443_module_ensure   || { _front443_rollback; return 1; }
    _front443_selinux_ensure  || { _front443_rollback; return 1; }
    _front443_ledger_add backend_port "$backend" || { _front443_rollback; return 1; }
    _front443_ledger_add web_port     "$web"     || { _front443_rollback; return 1; }
    _front443_ledger_add strip_port   "$strip"   || { _front443_rollback; return 1; }
    _front443_ledger_add bind         "$pub4"    || { _front443_rollback; return 1; }
    _front443_ledger_add bind6        "${pub6:--}" || { _front443_rollback; return 1; }

    fs_ensure_dir "$(dirname "$VPN55_FRONT443_REALIP_CONF")" 0755 || { _front443_rollback; return 1; }
    fs_write_if_changed "$VPN55_FRONT443_REALIP_CONF" 0644 "$(_front443_realip_text)" \
        || { error "cannot write ${VPN55_FRONT443_REALIP_CONF}"; _front443_rollback; return 1; }
    [[ "$VPN55_FS_CHANGED" -eq 1 ]] && vhost_changed=1
    _front443_ledger_add realip "$VPN55_FRONT443_REALIP_CONF" || { _front443_rollback; return 1; }

    # ── Phase 1: the vhosts leave 443 ──
    for f in ${files[@]+"${files[@]}"}; do
        _front443_ledger_add file "$f" || { _front443_rollback; return 1; }
        if [[ -n "$VPN55_FRONT443_SNAP" ]]; then
            # The byte copy the scoped rollback restores from (header above).
            nsnap=$(( nsnap + 1 ))
            printf '%s\n' "$f" > "${VPN55_FRONT443_SNAP}/${nsnap}.path" \
                || { error "cannot record ${f} for rollback"; _front443_rollback; return 1; }
            cp "$f" "${VPN55_FRONT443_SNAP}/${nsnap}.bytes" \
                || { error "cannot copy ${f} for rollback"; _front443_rollback; return 1; }
        fi
        _front443_rewrite_file "$f" "$web" "$pub4" "$pub6" || { _front443_rollback; return 1; }
        if [[ "$VPN55_FRONT443_CHANGED" -eq 1 ]]; then
            vhost_changed=1
            info "moved ${f} off the public 443 (tagged; restored on remove)"
        fi
    done

    if ! _front443_nginx_test; then
        error "nginx rejected the rewritten configuration; every change has been reverted:"
        _front443_nginx_test_out | sed 's/^/    /' >&2
        _front443_rollback
        return 1
    fi

    if [[ "$vhost_changed" -eq 1 ]] && _front443_nginx_active; then
        _front443_nginx_reload || { error "nginx would not reload"; _front443_rollback; return 1; }
        if ! _front443_wait_for "the wildcard :443 to close" _front443_not_wildcard_held "$VPN55_FRONT443_PORT"; then
            error "after the reload something still holds the wildcard :${VPN55_FRONT443_PORT}:"
            _front443_ss_p "$VPN55_FRONT443_PORT" | sed 's/^/    /' >&2
            error "The reload was rejected at runtime (journalctl -u nginx). Reverted."
            _front443_rollback
            return 1
        fi
    fi

    # ── Phase 2: the front takes 443 ──
    fs_ensure_dir "$VPN55_FRONT443_STREAM_DIR" 0755 || { _front443_rollback; return 1; }
    fs_write_if_changed "$VPN55_FRONT443_STREAM_CONF" 0644 \
        "$(_front443_stream_conf_text "$backend" "$web" "$strip" "$pub4" "$pub6")" \
        || { error "cannot write ${VPN55_FRONT443_STREAM_CONF}"; _front443_rollback; return 1; }
    [[ "$VPN55_FS_CHANGED" -eq 1 ]] && stream_changed=1
    _front443_ledger_add stream "$VPN55_FRONT443_STREAM_CONF" || { _front443_rollback; return 1; }

    if ! _front443_include_present; then
        _front443_include_add || { _front443_rollback; return 1; }
        stream_changed=1
    fi
    _front443_ledger_add include "$VPN55_NGINX_CONF" || { _front443_rollback; return 1; }

    if ! _front443_nginx_test; then
        error "nginx rejected the stream front; every change has been reverted:"
        _front443_nginx_test_out | sed 's/^/    /' >&2
        _front443_rollback
        return 1
    fi

    # The web port is bound only because a vhost listens there; with none
    # moved (the panel-only host) it is not expected, and a check that
    # demanded it would fail every install on that host.
    need_web=0
    _front443_dump_expects_web "$(_front443_nginx_dump)" "$web" && need_web=1
    if [[ "$need_web" -eq 0 ]]; then
        info "No vhost listens on 127.0.0.1:${web}: nothing on this host served the public"
        info "${VPN55_FRONT443_PORT} over TLS, so a TLS connection to the front is closed at once. A"
        info "site added later is routed there with no VPN55 edit."
    fi

    if _front443_nginx_active; then
        if [[ "$stream_changed" -eq 1 || "$vhost_changed" -eq 1 ]]; then
            _front443_nginx_reload || { error "nginx would not reload"; _front443_rollback; return 1; }
        fi
        if ! _front443_wait_for "the front to bind" _front443_binds_ok "$pub4" "$pub6" "$web" "$strip" "$need_web"; then
            error "after the reload the listeners are not what the front requires:"
            _front443_ss_p "$VPN55_FRONT443_PORT" | sed 's/^/    /' >&2
            _front443_ss_p "$web"   | sed 's/^/    /' >&2
            _front443_ss_p "$strip" | sed 's/^/    /' >&2
            if [[ "$need_web" -eq 1 ]]; then
                error "Expected ${pub4}:${VPN55_FRONT443_PORT}${pub6:+ and [${pub6}]:${VPN55_FRONT443_PORT}}, 127.0.0.1:${web} and"
                error "127.0.0.1:${strip}, and no wildcard on :${VPN55_FRONT443_PORT}. See journalctl -u nginx. Reverted."
            else
                error "Expected ${pub4}:${VPN55_FRONT443_PORT}${pub6:+ and [${pub6}]:${VPN55_FRONT443_PORT}} and 127.0.0.1:${strip}, and no"
                error "wildcard on :${VPN55_FRONT443_PORT}. See journalctl -u nginx. Reverted."
            fi
            _front443_rollback
            return 1
        fi
    else
        warn "nginx is not running; the front is configured and will bind when it starts."
    fi

    # The public address may not exist yet at boot — same drop-in the panel
    # uses, under our own name so the two can be removed independently.
    fs_ensure_dir "$(dirname "$VPN55_FRONT443_DROPIN")" 0755 || { _front443_rollback; return 1; }
    fs_write_if_changed "$VPN55_FRONT443_DROPIN" 0644 "$(_front443_dropin_text)" \
        || { error "cannot write ${VPN55_FRONT443_DROPIN}"; _front443_rollback; return 1; }
    if [[ "$VPN55_FS_CHANGED" -eq 1 ]]; then
        _front443_daemon_reload || true
    fi
    _front443_ledger_add dropin "$VPN55_FRONT443_DROPIN" || { _front443_rollback; return 1; }

    if ! _front443_ledger_get installed >/dev/null 2>&1; then
        _front443_ledger_add installed "$(fs_now)" || { _front443_rollback; return 1; }
    fi

    if [[ "$vhost_changed" -eq 1 || "$stream_changed" -eq 1 ]]; then
        success "Shared 443: nginx fronts ${pub4}:${VPN55_FRONT443_PORT}${pub6:+ and [${pub6}]:${VPN55_FRONT443_PORT}} — TLS to 127.0.0.1:${web}, everything else to 127.0.0.1:${backend}."
    else
        debug "front443: already installed and intact; nothing changed"
    fi
    return 0
}

_front443_not_wildcard_held() { ! _front443_wildcard_held "${1:-}"; }

# The bind invariant, whole: the public address holds 443, no wildcard does,
# the strip hop is held on 127.0.0.1, and so is the web port when a vhost is
# configured on it (need_web; _front443_dump_expects_web).
_front443_binds_ok() {
    local pub4="${1:-}" pub6="${2:-}" web="${3:-}" strip="${4:-}" need_web="${5:-1}"
    _front443_addr_held "$pub4" "$VPN55_FRONT443_PORT" || return 1
    if [[ -n "$pub6" ]]; then
        _front443_addr_held "$pub6" "$VPN55_FRONT443_PORT" || return 1
    fi
    _front443_wildcard_held "$VPN55_FRONT443_PORT" && return 1
    if [[ "$need_web" -eq 1 ]]; then
        _front443_addr_held 127.0.0.1 "$web" || return 1
    fi
    _front443_addr_held 127.0.0.1 "$strip" || return 1
    return 0
}

# What remove waits for after the vhosts are put back: one of the spellings a
# restored line can carry — the wildcard, or the public address itself. NOT
# "anything holds 443": the panel's tunnel-address bind holds 443 throughout,
# and a wait that any holder satisfied was met before the reload was even
# sent (R1, hypothesis 2).
_front443_public_443_held() {
    local pub4="${1:-}" pub6="${2:-}"
    _front443_wildcard_held "$VPN55_FRONT443_PORT" && return 0
    if [[ -n "$pub4" ]] && _front443_addr_held "$pub4" "$VPN55_FRONT443_PORT"; then return 0; fi
    if [[ -n "$pub6" ]] && _front443_addr_held "$pub6" "$VPN55_FRONT443_PORT"; then return 0; fi
    return 1
}

# Two scopes — see front443_install's header. A fresh install that failed goes
# back to nothing; a re-run that failed puts back only the files it rewrote.
_front443_rollback() {
    if [[ "${VPN55_FRONT443_FRESH:-1}" -eq 1 ]]; then
        warn "rolling the front back…"
        front443_remove || warn "the rollback did not complete cleanly — read the messages above"
        return 0
    fi
    _front443_rollback_scoped
    return 0
}

_front443_rollback_scoped() {
    local snap="${VPN55_FRONT443_SNAP:-}" p b f n=0 rc=0
    warn "the front stays as it was; undoing only what this run changed…"
    [[ -n "$snap" && -d "$snap" ]] || return 0
    for p in "$snap"/*.path; do
        [[ -f "$p" ]] || continue
        b="${p%.path}.bytes"
        f="$(cat "$p")" || { error "cannot read ${p}"; rc=1; continue; }
        [[ -n "$f" && -f "$f" && -f "$b" ]] || continue
        if ! cmp -s "$f" "$b"; then
            fs_replace_in_place "$f" < "$b" || { error "cannot put ${f} back as it was"; rc=1; continue; }
            info "put ${f} back as it was before this run"
            n=$(( n + 1 ))
        fi
        # A file that carries no marker once put back was never ours; the row
        # this run added for it would describe nothing.
        if ! grep -qF "$VPN55_FRONT443_MARK" "$f"; then
            _front443_ledger_del file "$f" || rc=1
        fi
    done
    if [[ "$n" -gt 0 ]] && _front443_have nginx && _front443_nginx_active; then
        if _front443_nginx_test; then
            _front443_nginx_reload || { error "nginx would not reload after the undo — see journalctl -u nginx"; rc=1; }
        else
            error "nginx -t still fails with this run's changes undone — the fault is in a file"
            error "this run did not write. Fix it and reload by hand:"
            _front443_nginx_test_out | sed 's/^/    /' >&2
            rc=1
        fi
    fi
    return "$rc"
}

# front443_repair — the same idempotent apply, with the ports the ledger holds.
front443_repair() {
    local backend web strip
    front443_installed || { error "the front is not installed; nothing to repair"; return 1; }
    backend="$(_front443_ledger_get backend_port)" || { error "the ledger has no backend port"; return 1; }
    web="$(_front443_ledger_get web_port)"     || web="$VPN55_FRONT443_WEB_PORT"
    strip="$(_front443_ledger_get strip_port)" || strip="$VPN55_FRONT443_STRIP_PORT"
    front443_install "$backend" "$web" "$strip"
}

# ─── A vhost VPN55 writes ITSELF, after the front is on ──────────────────────
# Everything above rewrites files that existed BEFORE the front. A file VPN55
# writes later — the self-serve portal's vhost, lib/panel_deploy.sh — must not
# land with a bare `listen 443`: `nginx -t` passes it, the reload fails at bind
# with EADDRINUSE and keeps the old workers, and front443_check then reports a
# broken vhost that VPN55 itself just wrote. So a writer renders through
# front443_render_vhost and the file lands ALREADY in the tagged loopback form
# the install would have produced — the same marker, so front443_remove puts
# its plain `listen 443` back like every other vhost's, and the same ledger
# row (front443_adopt_file), so remove knows to. With the front off both verbs
# are no-ops: the text passes through and nothing is recorded.
#
# The alternative — write `listen 443` and call front443_repair — is wrong in
# a way that matters: repair is front443_install, whose failure path ROLLS THE
# WHOLE FRONT BACK. A portal vhost nginx rejects would take the tunnel's front
# down with it.

# front443_info — the ledger, for a caller that must not read it directly.
#   backend <port> / web <port> / strip <port> / bind <v4> / bind6 <v6|->
#   installed <stamp>
# Prints nothing and returns 2 when the front is not installed.
front443_info() {
    local k v
    front443_installed || return 2
    for k in backend_port web_port strip_port bind bind6 installed; do
        v="$(_front443_ledger_get "$k" || true)"
        printf '%s\t%s\n' "${k%_port}" "${v:--}"
    done
    return 0
}

# front443_render_vhost — a vhost's text on stdin, out on stdout. With the
# front installed every public-443 listener becomes the tagged loopback form;
# with it off the text is unchanged.
front443_render_vhost() {
    local web pub4 pub6
    if ! front443_installed; then cat; return 0; fi
    web="$(_front443_ledger_get web_port || true)"
    [[ -n "$web" ]] || web="$VPN55_FRONT443_WEB_PORT"
    pub4="$(_front443_ledger_get bind || true)"
    pub6="$(_front443_ledger_get bind6 || true)"
    [[ "$pub6" == "-" ]] && pub6=""
    _front443_rewrite_text "$web" "$pub4" "$pub6"
}

# front443_adopt_file <path> — record a vhost VPN55 wrote while the front was
# on, so that remove restores it. The rewrite is run over it as well: on a file
# rendered through front443_render_vhost that is a no-op, and on one that was
# not it is the difference between a vhost the front carries and one that
# breaks the next reload. Ledger first, file second, like the install.
front443_adopt_file() {
    local file="${1:-}" web pub4 pub6
    [[ -n "$file" ]] || { error "front443_adopt_file <path>"; return 1; }
    front443_installed || return 0
    [[ -f "$file" ]] || { error "front443_adopt_file: ${file} is not a file"; return 1; }
    web="$(_front443_ledger_get web_port || true)"
    [[ -n "$web" ]] || web="$VPN55_FRONT443_WEB_PORT"
    pub4="$(_front443_ledger_get bind || true)"
    pub6="$(_front443_ledger_get bind6 || true)"
    [[ "$pub6" == "-" ]] && pub6=""
    _front443_ledger_add file "$file" || return 1
    _front443_rewrite_file "$file" "$web" "$pub4" "$pub6" || return 1
    return 0
}

# ─── Check ───────────────────────────────────────────────────────────────────
# front443_check — the invariants, on every read.
#   prints `ok` and returns 0, or one line per broken invariant and returns 1:
#       broken  <include|vhost|bind|backend>  <detail>  <repair>
#   prints `off` and returns 2 when the front is not installed.
#
# Four, not three: the design's three are what the CONFIGURATION says; `bind`
# is what the kernel says, and a status that could report ok while `ss` shows
# the wildcard holding 443 would be the check that goes green whichever won.
front443_check() {
    local backend web strip pub4 pub6 dump records rc=0 rtype rfile rline rspec need_web=1

    front443_installed || { printf 'off\n'; return 2; }
    backend="$(_front443_ledger_get backend_port || true)"
    web="$(_front443_ledger_get web_port || true)"
    strip="$(_front443_ledger_get strip_port || true)"
    pub4="$(_front443_ledger_get bind || true)"
    pub6="$(_front443_ledger_get bind6 || true)"
    [[ "$pub6" == "-" ]] && pub6=""

    if ! dump="$(_front443_nginx_dump)" || [[ -z "$dump" ]]; then
        printf 'broken\tinclude\tnginx -T fails, so the configuration cannot be read\t%s\n' "$VPN55_FRONT443_REPAIR_CMD"
        rc=1
    else
        if ! _front443_dump_has_include "$dump"; then
            printf 'broken\tinclude\tthe stream include is missing from %s\t%s\n' "$VPN55_NGINX_CONF" "$VPN55_FRONT443_REPAIR_CMD"
            rc=1
        elif ! str_has_line "$dump" "# configuration file ${VPN55_FRONT443_STREAM_CONF}:"; then
            printf 'broken\tinclude\t%s is not read by nginx\t%s\n' "$VPN55_FRONT443_STREAM_CONF" "$VPN55_FRONT443_REPAIR_CMD"
            rc=1
        fi
        records="$(printf '%s\n' "$dump" | _front443_scan_text "$pub4" "$pub6")"
        while IFS=$'\t' read -r rtype rfile rline rspec _; do
            case "$rtype" in
                listen)
                    printf 'broken\tvhost\t%s:%s listens on the public 443 (%s)\t%s\n' "$rfile" "$rline" "$rspec" "$VPN55_FRONT443_REPAIR_CMD"
                    rc=1 ;;
                refuse)
                    # Repair cannot rewrite this line; a person has to. Say
                    # so, rather than name a command that will refuse.
                    printf 'broken\tvhost\t%s:%s %s\tput that listen on a line of its own, ending in ";", then %s\n' "$rfile" "$rline" "$rspec" "$VPN55_FRONT443_REPAIR_CMD"
                    rc=1 ;;
            esac
        done <<< "$records"
        _front443_dump_expects_web "$dump" "$web" || need_web=0
    fi

    # With nginx stopped every bind below is missing at once, and four rows
    # saying "nothing holds …" would be the symptom four times over with the
    # cause in none of them. One row, naming it (R1, hypothesis 9b). The
    # backend row still follows: that one is not nginx's.
    if ! _front443_nginx_active && ! _front443_addr_held "$pub4" "$VPN55_FRONT443_PORT"; then
        printf 'broken\tbind\tnginx is not running, so %s:%s and the loopback ports are unbound\tsystemctl start nginx\n' "$pub4" "$VPN55_FRONT443_PORT"
        rc=1
    else
        if _front443_wildcard_held "$VPN55_FRONT443_PORT"; then
            printf 'broken\tbind\ta wildcard listener holds :%s\t%s\n' "$VPN55_FRONT443_PORT" "$VPN55_FRONT443_REPAIR_CMD"
            rc=1
        fi
        if ! _front443_addr_held "$pub4" "$VPN55_FRONT443_PORT"; then
            printf 'broken\tbind\tnothing holds %s:%s\t%s\n' "$pub4" "$VPN55_FRONT443_PORT" "$VPN55_FRONT443_REPAIR_CMD"
            rc=1
        fi
        if [[ -n "$pub6" ]] && ! _front443_addr_held "$pub6" "$VPN55_FRONT443_PORT"; then
            printf 'broken\tbind\tnothing holds [%s]:%s\t%s\n' "$pub6" "$VPN55_FRONT443_PORT" "$VPN55_FRONT443_REPAIR_CMD"
            rc=1
        fi
        if [[ "$need_web" -eq 1 ]] && ! _front443_addr_held 127.0.0.1 "$web"; then
            printf 'broken\tbind\tnothing holds 127.0.0.1:%s (the web port)\t%s\n' "$web" "$VPN55_FRONT443_REPAIR_CMD"
            rc=1
        fi
        if ! _front443_addr_held 127.0.0.1 "$strip"; then
            printf 'broken\tbind\tnothing holds 127.0.0.1:%s (the strip hop)\t%s\n' "$strip" "$VPN55_FRONT443_REPAIR_CMD"
            rc=1
        fi
    fi
    if ! _front443_addr_held 127.0.0.1 "$backend"; then
        printf 'broken\tbackend\tnothing holds 127.0.0.1:%s\tstart the service that listens there\n' "$backend"
        rc=1
    fi

    [[ "$rc" -eq 0 ]] && printf 'ok\n'
    return "$rc"
}

# ─── Remove ──────────────────────────────────────────────────────────────────
# Reverses the ledger. Phase A drops the front so the public :443 closes;
# phase B puts the vhosts back so the wildcard can bind again — the same two
# reloads as install, mirrored. Safe to run with nothing installed, with nginx
# stopped, or with nginx gone: files are restored regardless, reloads happen
# only where there is something to reload.
#
# Without a ledger (R1, hypothesis 9c: a hand `rm`, a restore that did not
# carry /etc/vpn55 — the ledger rides in the backup's reference area and is
# never placed) the same phases run from what the host itself says: the
# marked vhost lines name their own originals, and the front's other files
# are at paths only VPN55 writes. Two things the ledger alone knew are then
# not done and are said: the SELinux boolean's prior value (left as it is,
# with the command to put it back), and the ledger itself (there is none to
# delete). The waits use the addresses the stream file binds, when it is
# still there to read.
front443_remove() {
    local f pub4="" pub6="" rc=0 restored=0 vhost_restored=0 had_front=0 reloaded_a=0 salvage=0 files binds

    if front443_installed; then
        pub4="$(_front443_ledger_get bind || true)"
        pub6="$(_front443_ledger_get bind6 || true)"
        [[ "$pub6" == "-" ]] && pub6=""
        files="$(_front443_ledger_rows file || true)"
    else
        front443_traces_present || { debug "front443: nothing to remove"; return 0; }
        salvage=1
        files="$(_front443_marked_files)"
        binds="$(_front443_stream_conf_binds)"
        pub4="${binds%%$'\n'*}"; pub6="${binds#*$'\n'}"; pub6="${pub6%%$'\n'*}"
        warn "no ledger at ${VPN55_FRONT443_STATE}; the front is removed by what its own files say —"
        warn "the marked vhost lines, the stream file, the include, the snippet and the drop-in."
    fi

    # ── Phase A: the front goes ──
    if _front443_include_present; then had_front=1; fi
    _front443_include_remove || rc=1
    if [[ -f "$VPN55_FRONT443_STREAM_CONF" ]]; then
        had_front=1
        fs_remove "$VPN55_FRONT443_STREAM_CONF" || rc=1
    fi
    fs_rmdir_if_empty "$VPN55_FRONT443_STREAM_DIR"

    if [[ "$had_front" -eq 1 ]] && _front443_have nginx && _front443_nginx_active; then
        if _front443_nginx_test; then
            _front443_nginx_reload || { error "nginx would not reload after removing the front"; rc=1; }
            reloaded_a=1
            if [[ -n "$pub4" ]] && ! _front443_wait_for "the front to release :443" _front443_addr_not_held "$pub4" "$VPN55_FRONT443_PORT"; then
                warn "${pub4}:${VPN55_FRONT443_PORT} is still held after the reload — see journalctl -u nginx"
                rc=1
            fi
        else
            error "nginx -t fails with the front removed; the vhosts are restored next, then it is re-tested:"
            _front443_nginx_test_out | sed 's/^/    /' >&2
        fi
    fi

    # ── Phase B: the vhosts come back ──
    while IFS= read -r f; do
        [[ -n "$f" ]] || continue
        _front443_restore_file "$f" || { rc=1; continue; }
        if [[ "$VPN55_FRONT443_CHANGED" -eq 1 ]]; then restored=1; vhost_restored=1; fi
    done <<< "$files"

    if [[ -f "$VPN55_FRONT443_REALIP_CONF" ]]; then
        fs_remove "$VPN55_FRONT443_REALIP_CONF" || rc=1
        restored=1
    fi

    if _front443_have nginx && _front443_nginx_active; then
        if ! _front443_nginx_test; then
            error "nginx -t fails after the restore — nothing was reloaded. Fix and reload by hand:"
            _front443_nginx_test_out | sed 's/^/    /' >&2
            rc=1
        elif [[ "$restored" -eq 1 || ( "$had_front" -eq 1 && "$reloaded_a" -eq 0 ) ]]; then
            _front443_nginx_reload || { error "nginx would not reload after the restore"; rc=1; }
            # Waited for only when a vhost line actually came back: the
            # realip snippet going needs the reload but binds nothing, and a
            # host that never had a public-443 vhost (the panel-only host)
            # has nothing to wait for — before R1 that wait ran here too,
            # timed out, and kept the ledger for a "second run" that then
            # succeeded, every time.
            if [[ "$vhost_restored" -eq 1 ]] && ! _front443_wait_for "the vhosts to bind :443 again" _front443_public_443_held "$pub4" "$pub6"; then
                warn "neither the wildcard nor ${pub4:-the public address} holds :${VPN55_FRONT443_PORT} after the restore — see journalctl -u nginx"
                rc=1
            fi
        fi
    fi

    if [[ -f "$VPN55_FRONT443_DROPIN" ]]; then
        fs_remove "$VPN55_FRONT443_DROPIN" || rc=1
        fs_rmdir_if_empty "$(dirname "$VPN55_FRONT443_DROPIN")"
        _front443_daemon_reload || true
    fi

    if [[ "$salvage" -eq 1 ]]; then
        _front443_selinux_salvage_note
    else
        _front443_selinux_revert
    fi

    # The module package stays: it is harmless, and by now the operator may
    # rely on it for something of their own. The ledger names it.

    if [[ "$salvage" -eq 1 ]]; then
        [[ "$rc" -eq 0 ]] || warn "the removal did not complete; run it again once the messages above are dealt with."
    elif [[ "$rc" -eq 0 ]]; then
        fs_remove "$VPN55_FRONT443_STATE" || rc=1
    else
        warn "the ledger ${VPN55_FRONT443_STATE} is kept because the removal did not complete;"
        warn "run the removal again once the messages above are dealt with."
    fi
    [[ "$rc" -eq 0 ]] && success "Shared 443 removed; the vhosts are back on their original listen lines."
    return "$rc"
}

# What a ledger-less remove cannot know: whether the boolean was on before
# the front. It is left where it is, and the operator is told exactly when
# there is something to decide — the boolean is on.
_front443_selinux_salvage_note() {
    local mode cur
    mode="$(_front443_selinux_mode)" || return 0
    case "$mode" in Enforcing|Permissive) ;; *) return 0 ;; esac
    _front443_have getsebool || return 0
    cur="$(_front443_getsebool httpd_can_network_connect)"
    [[ "$cur" == "on" ]] || return 0
    warn "SELinux: httpd_can_network_connect is on, and without the ledger there is no record"
    warn "of whether the front set it. Left as it is; if it was off before the front:"
    warn "  setsebool -P httpd_can_network_connect 0"
    return 0
}

_front443_addr_not_held() { ! _front443_addr_held "${1:-}" "${2:-}"; }
