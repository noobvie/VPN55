#!/usr/bin/env bash
#
# tests/front443.sh — the shared-443 front's decisions that are wrong SILENTLY,
# checked without nginx.
#
# Every case here is one that produces no error on the host where it is wrong:
#
#   · a `listen` spelling the scanner does not recognise stays on the public
#     443, the front's reload fails with EADDRINUSE, and nginx keeps serving the
#     OLD configuration — every signal says success.
#   · a rewrite that is not byte-reversible leaves the operator's vhost changed
#     after "uninstall" in a way nobody notices until the next edit.
#   · a rewrite that touches the panel's tunnel-address `:443` — the one listener
#     the front exists to leave alone.
#   · a second install that is not a no-op reloads nginx on every status read.
#   · a status that reads `nginx -t` as proof of bind.
#
# Nothing here starts a process, binds a port, or writes outside one mktemp
# directory. Every host-touching call in lib/core_front443.sh goes through a
# wrapper, and the wrappers are replaced here with a fake host whose `ss`
# answers from what the on-disk configuration would bind AFTER a reload —
# and not before, which is the property the two-reload sequence depends on.

set -uo pipefail

ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)" || exit 1
cd "$ROOT" || exit 1

pass=0
fail=0
chk() {
    local what="$1" want="$2" got="$3"
    if [ "$want" = "$got" ]; then
        pass=$(( pass + 1 )); printf '  ok    %s\n' "$what"
    else
        fail=$(( fail + 1 ))
        printf '  FAIL  %s\n          want: %s\n          got:  %s\n' "$what" "$want" "$got"
    fi
}
group() { printf '\n%s\n' "$1"; }

WORK="$(mktemp -d)" || exit 1
trap 'rm -rf "$WORK"' EXIT

export VPN55_ETC="$WORK/etc" VPN55_NO_COLOR=1
export VPN55_NGINX_CONF="$WORK/nginx/nginx.conf"
export VPN55_FRONT443_STREAM_DIR="$WORK/nginx/vpn55-stream.d"
export VPN55_FRONT443_STREAM_CONF="$WORK/nginx/vpn55-stream.d/front443.conf"
export VPN55_FRONT443_REALIP_CONF="$WORK/nginx/conf.d/vpn55-front443-realip.conf"
export VPN55_FRONT443_DROPIN="$WORK/dropin/vpn55-front443.conf"
export VPN55_FRONT443_BIND_WAIT=1
mkdir -p "$VPN55_ETC" "$WORK/nginx/conf.d" "$WORK/nginx/sites-enabled" "$WORK/nginx/modules-enabled"

# shellcheck source=../lib/ui.sh
. lib/ui.sh
# shellcheck source=../lib/core_fs.sh
. lib/core_fs.sh
# shellcheck source=../lib/core_distro.sh
. lib/core_distro.sh
# shellcheck source=../lib/core_net.sh
. lib/core_net.sh
# shellcheck source=../lib/core_front443.sh
. lib/core_front443.sh

PUB4=203.0.113.10
PUB6=2001:db8::10
SITES="$WORK/nginx/sites-enabled"

# ─── The operator's host, as files ───────────────────────────────────────────
printf '%s\n' 'user www-data;
include /etc/nginx/modules-enabled/*.conf;
http {
    include /etc/nginx/conf.d/*.conf;
    include /etc/nginx/sites-enabled/*;
}' > "$VPN55_NGINX_CONF"

# site-a: the usual certbot pair, tab-indented on one line, a server-level
# real_ip_header (trap 6), ipv6only on the twin.
printf '%s\n' 'server {
    listen 80;
    server_name a.example;
    return 301 https://$host$request_uri;
}
server {
	listen 443 ssl http2 default_server;
    listen [::]:443 ssl http2 ipv6only=on;
    server_name a.example;
    real_ip_header X-Forwarded-For;
    ssl_certificate /etc/letsencrypt/live/a.example/fullchain.pem;
}' > "$SITES/site-a.conf"

# site-b: `*:443` with a trailing comment, a quic twin that must be left, an
# unrelated 8081 that is not the public 443, a second server on the public
# address spelled out, and a commented-out listen.
printf '%s\n' 'server {
    listen *:443 ssl; # b main
    listen 443 quic reuseport;
    listen 0.0.0.0:8081;
    server_name b.example;
}
server {
    listen 203.0.113.10:443 ssl;
    server_name c.example;
}
# listen 443 ssl;' > "$SITES/site-b.conf"

# The VPN55 panel: address-bound on the tunnel. Never touched.
printf '%s\n' 'server {
    listen 10.8.0.1:443 ssl http2;
    server_name panel;
}' > "$SITES/panel.conf"

cp "$SITES/site-a.conf" "$WORK/site-a.orig"
cp "$SITES/site-b.conf" "$WORK/site-b.orig"
cp "$SITES/panel.conf"  "$WORK/panel.orig"
cp "$VPN55_NGINX_CONF"  "$WORK/nginx.conf.orig"

# ─── The fake host ───────────────────────────────────────────────────────────
dump_file() { printf '# configuration file %s:\n' "$1"; cat "$1"; }
_front443_nginx_dump() {
    local f
    dump_file "$VPN55_NGINX_CONF"
    [ -f "$WORK/modload" ] && printf '# configuration file /etc/nginx/modules-enabled/50-mod-stream.conf:\nload_module modules/ngx_stream_module.so;\n'
    for f in "$WORK/nginx/conf.d"/*.conf "$SITES"/* "$VPN55_FRONT443_STREAM_DIR"/*.conf; do
        [ -f "$f" ] && dump_file "$f"
    done
    return 0
}
_front443_nginx_test()     { [ ! -f "$WORK/nginx_t_fails" ]; }
_front443_nginx_test_out() { echo "nginx: [emerg] fake failure"; return 1; }
_front443_nginx_flags()    { echo 'configure arguments: --with-stream=dynamic --with-stream_ssl_preread_module --with-http_realip_module'; }
_front443_nginx_active()   { return 0; }
_front443_daemon_reload()  { return 0; }
_front443_sleep()          { return 0; }
_front443_public_v4()      { printf '%s' "$PUB4"; }
_front443_public_v6()      { [ -f "$WORK/v6" ] || return 1; printf '%s' "$PUB6"; }
_front443_selinux_mode()   { [ -f "$WORK/semode" ] || return 1; cat "$WORK/semode"; }
_front443_getsebool()      { cat "$WORK/sebool" 2>/dev/null || echo off; }
_front443_setsebool()      { echo "setsebool $1 $2" >> "$WORK/se.log"; if [ "$2" = 1 ]; then echo on; else echo off; fi > "$WORK/sebool"; }
_front443_module_pkg()     { printf 'libnginx-mod-stream'; }
_front443_have()           { return 0; }
distro_pkg_installed()     { [ -f "$WORK/modload" ]; }
distro_pkg_install()       { echo "install $*" >> "$WORK/pkg.log"; touch "$WORK/modload"; }

# What the kernel would hold after a reload of the configuration on disk.
# Spellings map the way Linux reports them: 443 / *:443 → 0.0.0.0:443.
ss_recompute() {
    local f
    : > "$WORK/ss.txt"
    for f in "$SITES"/* "$VPN55_FRONT443_STREAM_DIR"/*.conf; do
        [ -f "$f" ] || continue
        awk '
            /^[ \t]*#/ { next }
            /^[ \t]*listen[ \t]/ {
                s = $2; sub(/;.*/, "", s)
                if ($0 ~ /[ \t](quic|udp)[ \t;]/) next
                if (s ~ /^[0-9]+$/) s = "0.0.0.0:" s
                sub(/^\*:/, "0.0.0.0:", s)
                printf "LISTEN 0 511 %s 0.0.0.0:*\n", s
            }' "$f" >> "$WORK/ss.txt"
    done
    [ -f "$WORK/backend_up" ] && printf 'LISTEN 0 511 127.0.0.1:1194 0.0.0.0:*\n' >> "$WORK/ss.txt"
    return 0
}
_front443_nginx_reload() {
    echo reload >> "$WORK/reloads"
    ss_recompute
}
_front443_ss()   { grep -E "^LISTEN [0-9]+ [0-9]+ [^ ]+:${1}( |$)" "$WORK/ss.txt" 2>/dev/null; }
_front443_ss_p() { _front443_ss "$1" | sed 's/$/ users:(("nginx",pid=4242,fd=6))/'; }
reloads() { wc -l < "$WORK/reloads" 2>/dev/null | tr -d ' ' || echo 0; }

touch "$WORK/backend_up"
ss_recompute

# ─────────────────────────────────────────────────────────────────────────────
group "The scanner reads nginx -T and recognises every spelling of the public 443"

records="$(_front443_nginx_dump | _front443_scan_text "$PUB4" "")"
count() { printf '%s\n' "$records" | grep -cE "$1"; }

chk "four listeners hold the public 443"          "4" "$(count '^listen')"
chk "bare 443, with file, line and params"        "1" "$(count $'^listen\t.*site-a\\.conf\t7\t443\tssl http2 default_server\t1$')"
chk "[::]:443 — the twin, ipv6only kept for now"  "1" "$(count $'^listen\t.*site-a\\.conf\t8\t\\[::\\]:443\tssl http2 ipv6only=on\t1$')"
chk "*:443 with a trailing comment, comment gone" "1" "$(count $'^listen\t.*site-b\\.conf\t2\t\\*:443\tssl\t0$')"
chk "the public address spelled out"              "1" "$(count $'^listen\t.*site-b\\.conf\t8\t203\\.0\\.113\\.10:443\tssl\t0$')"
chk "quic on 443 is skipped — UDP"                "0" "$(count 'quic')"
chk "0.0.0.0:8081 is not the public 443"          "0" "$(count ':8081')"
chk "the commented listen is not a listener"      "0" "$(count $'\t11\t')"
chk "the panel's tunnel address is NOT a hit"     "0" "$(count 'panel')"
chk "real_ip_header is flagged per SERVER block"  "1" "$(count $'^realip\t.*site-a\\.conf\t10\tserver$')"
chk "site-b carries no real_ip_header flag"       "0" "$(count $'site-b.*\t1$')"

records="$(_front443_nginx_dump | _front443_scan_text "$PUB4" "$PUB6")"
chk "with no [pub6] line present, v6 changes nothing" "4" "$(count '^listen')"

# A http-level real_ip_header is a duplicate of the snippet, not an override.
printf 'real_ip_header X-Real-IP;\n' > "$WORK/nginx/conf.d/00-realip.conf"
records="$(_front443_nginx_dump | _front443_scan_text "$PUB4" "")"
chk "an http-level real_ip_header is reported as http" "1" "$(count $'^realip\t.*00-realip\\.conf\t1\thttp$')"
rm -f "$WORK/nginx/conf.d/00-realip.conf"

# Our own stream file must never be scanned as a vhost.
mkdir -p "$VPN55_FRONT443_STREAM_DIR"
printf 'server {\n    listen %s:443;\n}\n' "$PUB4" > "$VPN55_FRONT443_STREAM_CONF"
records="$(_front443_nginx_dump | _front443_scan_text "$PUB4" "")"
chk "the front's own listen is not a vhost"        "4" "$(count '^listen')"
rm -rf "$VPN55_FRONT443_STREAM_DIR"

# The barest spelling — `listen 443;` with no parameters — beside a
# real_ip_header. The record's params field must be `-`, never empty: a tab is
# IFS whitespace, two adjacent tabs are one delimiter, and an empty field would
# shift the real_ip flag into the params variable of every reader — which is
# how the trap-6 warning went missing for exactly this vhost.
printf 'server {\n    listen 443;\n    real_ip_header X-Forwarded-For;\n}\n' > "$SITES/bare.conf"
records="$(_front443_nginx_dump | _front443_scan_text "$PUB4" "")"
chk "no params → the field is '-', and the flag is still 1" "1" "$(count $'^listen\t.*bare\\.conf\t2\t443\t-\t1$')"
flag="$(printf '%s\n' "$records" | grep 'bare\.conf' | { IFS=$'\t' read -r _ _ _ _ _ rflag; printf '%s' "$rflag"; })"
chk "…and a tab-split reader sees the flag in the flag variable" "1" "$flag"
rm -f "$SITES/bare.conf"

# A block written as `server` with its brace on the next line is one block.
printf 'server\n{\n    listen 443 ssl;\n    real_ip_header X-Real-IP;\n}\nserver\n{\n    listen 443 ssl;\n    server_name two;\n}\n' > "$SITES/brace.conf"
records="$(_front443_nginx_dump | _front443_scan_text "$PUB4" "")"
chk "brace-on-next-line: both listeners are found"         "2" "$(count $'^listen\t.*brace\\.conf\t')"
chk "brace-on-next-line: the flag stays in its own block"  "1" "$(count $'brace\\.conf\t3\t443\tssl\t1$')"
chk "brace-on-next-line: the second block is not flagged"  "1" "$(count $'brace\\.conf\t8\t443\tssl\t0$')"
rm -f "$SITES/brace.conf"

chk "a foreign stream block is detected"          "0" "$(_front443_foreign_stream "$(printf 'http {\n}\nstream {\n  server {}\n}\n')"; echo $?)"
chk "our marked stream line is not foreign"       "1" "$(_front443_foreign_stream "$(printf 'http {\n}\n%s\n' "$VPN55_FRONT443_INCLUDE_LINE")"; echo $?)"
chk "a commented stream block is not a block"     "1" "$(_front443_foreign_stream "$(printf '# stream {\n')"; echo $?)"

# ─────────────────────────────────────────────────────────────────────────────
group "Rewrite, then restore, is byte-exact — and a second rewrite is a no-op"

A="$WORK/a.conf"; B="$WORK/b.conf"
cp "$WORK/site-a.orig" "$A"; cp "$WORK/site-b.orig" "$B"
_front443_rewrite_file "$A" 8443 "$PUB4" "" >/dev/null 2>&1
_front443_rewrite_file "$B" 8443 "$PUB4" "" >/dev/null 2>&1
line() { sed -n "${2}p" "$1"; }

chk "first 443 in the block → loopback, params kept, proxy_protocol added, tab indent kept" \
    $'\tlisten 127.0.0.1:8443 ssl http2 default_server proxy_protocol; # vpn55-front443: was listen 443 ssl http2 default_server;' \
    "$(line "$A" 7)"
chk "the twin in the same block is switched off, not duplicated" \
    '    # vpn55-front443: off: listen [::]:443 ssl http2 ipv6only=on;' \
    "$(line "$A" 8)"
chk "the trailing comment rides along on the marker" \
    '    listen 127.0.0.1:8443 ssl proxy_protocol; # vpn55-front443: was listen *:443 ssl; # b main' \
    "$(line "$B" 2)"
chk "quic stays exactly as it was"                "    listen 443 quic reuseport;" "$(line "$B" 3)"
chk "0.0.0.0:8081 stays exactly as it was"        "    listen 0.0.0.0:8081;"       "$(line "$B" 4)"
chk "the second server block gets its own kept line" \
    '    listen 127.0.0.1:8443 ssl proxy_protocol; # vpn55-front443: was listen 203.0.113.10:443 ssl;' \
    "$(line "$B" 8)"
chk "the commented listen is untouched"           "# listen 443 ssl;"               "$(line "$B" 11)"
chk "the file has no untagged public 443 left"    "0" \
    "$(cat "$A" "$B" | _front443_scan_text "$PUB4" "" | grep -c '^listen' || true)"

cp "$A" "$WORK/a.once"
_front443_rewrite_file "$A" 8443 "$PUB4" "" >/dev/null 2>&1
chk "rewriting an already-rewritten file changes nothing" "0" "$(cmp -s "$A" "$WORK/a.once"; echo $?)"
chk "…and reports that nothing changed"           "0" "$VPN55_FRONT443_CHANGED"

_front443_restore_file "$A" >/dev/null 2>&1
_front443_restore_file "$B" >/dev/null 2>&1
chk "site-a restored byte for byte"               "0" "$(cmp -s "$A" "$WORK/site-a.orig"; echo $?)"
chk "site-b restored byte for byte"               "0" "$(cmp -s "$B" "$WORK/site-b.orig"; echo $?)"

# ipv6only= is dropped when the [::] line is the block's ONLY 443 listener,
# because 127.0.0.1 is not an IPv6 socket and nginx refuses the option there.
printf 'server {\n    listen [::]:443 ssl ipv6only=off http2;\n}\n' > "$WORK/v6only.conf"
_front443_rewrite_file "$WORK/v6only.conf" 8443 "$PUB4" "" >/dev/null 2>&1
chk "a lone [::]:443 is rewritten and ipv6only dropped" \
    '    listen 127.0.0.1:8443 ssl http2 proxy_protocol; # vpn55-front443: was listen [::]:443 ssl ipv6only=off http2;' \
    "$(line "$WORK/v6only.conf" 2)"

# The operator edits the file BETWEEN install and uninstall. Their edits must
# survive the restore; only the tagged lines change.
cp "$WORK/site-a.orig" "$A"
_front443_rewrite_file "$A" 8443 "$PUB4" "" >/dev/null 2>&1
sed -i 's/server_name a.example;/server_name a.example www.a.example;/' "$A"
printf '    # added by the operator\n' >> "$A"
_front443_restore_file "$A" >/dev/null 2>&1
sed 's/server_name a.example;/server_name a.example www.a.example;/' "$WORK/site-a.orig" > "$WORK/a.expect"
printf '    # added by the operator\n' >> "$WORK/a.expect"
chk "operator edits between install and remove survive the restore" "0" "$(cmp -s "$A" "$WORK/a.expect"; echo $?)"

# Drift lands ABOVE the block's tagged line. Two `listen 127.0.0.1:8443` lines
# in one block are a duplicate nginx refuses, so the new one must go to `off`
# wherever certbot or a hand put it — the tagged line is the block's kept
# listener no matter which comes first in the file.
printf 'server {\n    listen 443 ssl;\n    server_name a.example;\n    listen 127.0.0.1:8443 ssl proxy_protocol; # vpn55-front443: was listen 443 ssl;\n}\n' > "$WORK/above.conf"
_front443_rewrite_file "$WORK/above.conf" 8443 "$PUB4" "" >/dev/null 2>&1
chk "a bare 443 above the block's tagged line is switched off" \
    '    # vpn55-front443: off: listen 443 ssl;' "$(line "$WORK/above.conf" 2)"
chk "…and the block still has exactly one loopback listen" "1" "$(grep -c '^    listen 127\.0\.0\.1:8443' "$WORK/above.conf")"
chk "…while a bare 443 in a NEW block still becomes the kept line" "1" \
    "$(printf 'server {\n    listen 443 ssl;\n}\n' | _front443_rewrite_text 8443 "$PUB4" "" | grep -c '^    listen 127\.0\.0\.1:8443 ssl proxy_protocol; # vpn55-front443: was listen 443 ssl;$')"

# A marker whose original was mangled is LEFT, and said so.
printf 'server {\n    listen 127.0.0.1:8443 ssl proxy_protocol; # vpn55-front443: was garbage\n}\n' > "$WORK/mangled.conf"
cp "$WORK/mangled.conf" "$WORK/mangled.before"
out="$(_front443_restore_file "$WORK/mangled.conf" 2>&1)"
chk "a mangled marker is left untouched"          "0" "$(cmp -s "$WORK/mangled.conf" "$WORK/mangled.before"; echo $?)"
chk "…and the operator is told which file"        "1" "$(printf '%s\n' "$out" | grep -c 'mangled.conf.*left in place')"

# A vhost deleted since the install is skipped, not an error.
chk "a deleted vhost is skipped on restore"       "0" "$(_front443_restore_file "$WORK/no-such-file.conf" >/dev/null 2>&1; echo $?)"

# ─────────────────────────────────────────────────────────────────────────────
group "The stream front binds the public address and never the wildcard"

conf="$(_front443_stream_conf_text 1194 8443 8008 "$PUB4" "")"
cnt() { printf '%s\n' "$conf" | grep -cE "$1"; }
chk "listens on the public v4, port 443"          "1" "$(cnt "^ *listen ${PUB4}:443;")"
chk "no wildcard anywhere"                        "0" "$(cnt '0\.0\.0\.0|\*:443|\[::\]')"
chk "no v6 line when the host has none"           "0" "$(cnt '^ *listen \[')"
chk "routes on \$ssl_preread_protocol"            "1" "$(cnt '^map \$ssl_preread_protocol ')"
chk "non-TLS goes to the strip hop"               "1" "$(cnt '^ *"" +127\.0\.0\.1:8008;')"
chk "TLS goes to the web port"                    "1" "$(cnt '^ *default +127\.0\.0\.1:8443;')"
chk "the front emits PROXY protocol"              "1" "$(cnt '^ *proxy_protocol on;')"
chk "the strip hop ACCEPTS it on loopback"        "1" "$(cnt '^ *listen 127\.0\.0\.1:8008 proxy_protocol;')"
chk "and forwards plain to the backend"           "1" "$(cnt '^ *proxy_pass 127\.0\.0\.1:1194;')"
chk "exactly two servers"                         "2" "$(cnt '^server \{')"
conf="$(_front443_stream_conf_text 1194 8443 8008 "$PUB4" "$PUB6")"
chk "with a v6 address, a bracketed v6 listen"    "1" "$(cnt "^ *listen \[${PUB6}\]:443;")"

# The include line round-trips through nginx.conf, including one that lacks
# a trailing newline.
cp "$WORK/nginx.conf.orig" "$VPN55_NGINX_CONF"
_front443_include_add
chk "the include is appended as one marked line"  "1" "$(grep -cF "$VPN55_FRONT443_INCLUDE_LINE" "$VPN55_NGINX_CONF")"
_front443_include_add
chk "adding it twice adds it once"                "1" "$(grep -cF "$VPN55_FRONT443_INCLUDE_LINE" "$VPN55_NGINX_CONF")"
_front443_include_remove
chk "removing it restores nginx.conf byte for byte" "0" "$(cmp -s "$VPN55_NGINX_CONF" "$WORK/nginx.conf.orig"; echo $?)"
printf 'http {\n}' > "$VPN55_NGINX_CONF"     # no trailing newline
_front443_include_add
chk "no trailing newline: the line still lands on its own line" "1" "$(grep -c '^stream {' "$VPN55_NGINX_CONF")"
# The operator's own comment that happens to name the marker is theirs.
printf 'http {\n}\n# added by hand — see vpn55-front443 for why 443 is loopback\n' > "$VPN55_NGINX_CONF"
_front443_include_add
_front443_include_remove
chk "removal takes our line and leaves a comment that names the marker" "1" "$(grep -c 'added by hand' "$VPN55_NGINX_CONF")"
chk "…and our line is gone"                       "0" "$(grep -c '^stream {' "$VPN55_NGINX_CONF")"
cp "$WORK/nginx.conf.orig" "$VPN55_NGINX_CONF"

# ─────────────────────────────────────────────────────────────────────────────
group "ss is read by ADDRESS, in every form iproute2 prints"

printf 'LISTEN 0 511 0.0.0.0:443 0.0.0.0:*\nLISTEN 0 511 [::]:443 [::]:*\nLISTEN 0 511 10.8.0.1:443 0.0.0.0:*\nLISTEN 0 511 127.0.0.1:1194 0.0.0.0:*\n' > "$WORK/ss.txt"
chk "0.0.0.0:443 is the wildcard"                 "0" "$(_front443_wildcard_held 443; echo $?)"
chk "the tunnel address alone is not"             "1" "$(printf 'LISTEN 0 511 10.8.0.1:443 0.0.0.0:*\n' > "$WORK/ss.txt"; _front443_wildcard_held 443; echo $?)"
chk "*:443 (older ss) is the wildcard"            "0" "$(printf 'LISTEN 0 511 *:443 *:*\n' > "$WORK/ss.txt"; _front443_wildcard_held 443; echo $?)"
chk "[::]:443 is the wildcard"                    "0" "$(printf 'LISTEN 0 511 [::]:443 [::]:*\n' > "$WORK/ss.txt"; _front443_wildcard_held 443; echo $?)"
chk "a specific v4 is matched exactly"            "0" "$(printf 'LISTEN 0 511 203.0.113.10:443 0.0.0.0:*\n' > "$WORK/ss.txt"; _front443_addr_held "$PUB4" 443; echo $?)"
chk "a specific v6 is matched in brackets"        "0" "$(printf 'LISTEN 0 511 [2001:db8::10]:443 [::]:*\n' > "$WORK/ss.txt"; _front443_addr_held "$PUB6" 443; echo $?)"
chk "port 4430 does not match port 443"           "1" "$(printf 'LISTEN 0 511 203.0.113.10:4430 0.0.0.0:*\n' > "$WORK/ss.txt"; _front443_addr_held "$PUB4" 443; echo $?)"

# R1, hypothesis 5 — the forms a bare `$4` comparison missed. Each of these
# is a wildcard or the public address as the kernel may print it, and before
# R1 every one of them read as "nobody holds 443".
chk "[::ffff:0.0.0.0]:443 (v4-mapped) is the wildcard"  "0" "$(printf 'LISTEN 0 511 [::ffff:0.0.0.0]:443 [::]:*\n' > "$WORK/ss.txt"; _front443_wildcard_held 443; echo $?)"
chk ":::443 (pre-bracket iproute2) is the wildcard"     "0" "$(printf 'LISTEN 0 511 :::443 :::*\n' > "$WORK/ss.txt"; _front443_wildcard_held 443; echo $?)"
chk "*%eth0:443 (device-bound, old ss) is the wildcard" "0" "$(printf 'LISTEN 0 511 *%%eth0:443 *:*\n' > "$WORK/ss.txt"; _front443_wildcard_held 443; echo $?)"
chk "0.0.0.0%eth0:443 (device-bound) is the wildcard"   "0" "$(printf 'LISTEN 0 511 0.0.0.0%%eth0:443 0.0.0.0:*\n' > "$WORK/ss.txt"; _front443_wildcard_held 443; echo $?)"
chk "[::]%eth0:443 (device-bound v6) is the wildcard"   "0" "$(printf 'LISTEN 0 511 [::]%%eth0:443 [::]:*\n' > "$WORK/ss.txt"; _front443_wildcard_held 443; echo $?)"
chk "[::ffff:<pub4>]:443 is the public v4"              "0" "$(printf 'LISTEN 0 511 [::ffff:203.0.113.10]:443 [::]:*\n' > "$WORK/ss.txt"; _front443_addr_held "$PUB4" 443; echo $?)"
chk "[<pub6>%eth0]:443 is the public v6"                "0" "$(printf 'LISTEN 0 511 [2001:db8::10%%eth0]:443 [::]:*\n' > "$WORK/ss.txt"; _front443_addr_held "$PUB6" 443; echo $?)"
chk "a scoped link-local is not the public v6"          "1" "$(printf 'LISTEN 0 511 [fe80::1%%eth0]:443 [::]:*\n' > "$WORK/ss.txt"; _front443_addr_held "$PUB6" 443; echo $?)"
# What remove waits for: the panel's tunnel bind alone must NOT satisfy it.
chk "remove's wait: the panel's bind alone does not count" "1" "$(printf 'LISTEN 0 511 10.8.0.1:443 0.0.0.0:*\n' > "$WORK/ss.txt"; _front443_public_443_held "$PUB4" ""; echo $?)"
chk "remove's wait: the wildcard back does"                "0" "$(printf 'LISTEN 0 511 10.8.0.1:443 0.0.0.0:*\nLISTEN 0 511 0.0.0.0:443 0.0.0.0:*\n' > "$WORK/ss.txt"; _front443_public_443_held "$PUB4" ""; echo $?)"
chk "remove's wait: the public address back does"          "0" "$(printf 'LISTEN 0 511 203.0.113.10:443 0.0.0.0:*\n' > "$WORK/ss.txt"; _front443_public_443_held "$PUB4" ""; echo $?)"

_front443_pid_comm() { echo bash; }
printf 'LISTEN 0 511 0.0.0.0:443 0.0.0.0:*\n' > "$WORK/ss.txt"
chk "a holder whose comm is not nginx is refused" "1" "$(front443_holder_is_nginx 443; echo $?)"
_front443_pid_comm() { echo nginx; }
chk "…and one whose comm is nginx is accepted"    "0" "$(front443_holder_is_nginx tcp 443; echo $?)"
chk "an unheld port has no holder"                "1" "$(: > "$WORK/ss.txt"; front443_holder_is_nginx 443; echo $?)"
ss_recompute

# ─────────────────────────────────────────────────────────────────────────────
group "Install: two reloads, every bind verified by address, ledger complete"

echo Enforcing > "$WORK/semode"
echo off > "$WORK/sebool"
rm -f "$WORK/reloads" "$WORK/se.log" "$WORK/pkg.log" "$WORK/modload"
out="$(front443_install 1194 2>&1)"; rc=$?
chk "install succeeds"                            "0" "$rc"
chk "the module package was installed once"      "1" "$(grep -c 'install libnginx-mod-stream' "$WORK/pkg.log")"
chk "exactly two reloads"                         "2" "$(reloads)"
chk "the front holds the public address"          "0" "$(_front443_addr_held "$PUB4" 443; echo $?)"
chk "no wildcard holds 443 any more"              "1" "$(_front443_wildcard_held 443; echo $?)"
chk "the panel's tunnel bind survived"            "0" "$(_front443_addr_held 10.8.0.1 443; echo $?)"
chk "the web port is on loopback"                 "0" "$(_front443_addr_held 127.0.0.1 8443; echo $?)"
chk "the strip hop is on loopback"                "0" "$(_front443_addr_held 127.0.0.1 8008; echo $?)"
chk "site-a carries the marker"                   "2" "$(grep -c 'vpn55-front443' "$SITES/site-a.conf")"
chk "site-b carries the marker"                   "2" "$(grep -c 'vpn55-front443' "$SITES/site-b.conf")"
chk "the panel vhost is byte-identical"           "0" "$(cmp -s "$SITES/panel.conf" "$WORK/panel.orig"; echo $?)"
chk "the realip snippet exists"                   "1" "$(grep -c '^real_ip_header  proxy_protocol;' "$VPN55_FRONT443_REALIP_CONF")"
chk "the stream conf exists"                      "1" "$(grep -c "^    listen ${PUB4}:443;" "$VPN55_FRONT443_STREAM_CONF")"
chk "nginx.conf has the include"                  "1" "$(grep -cF "$VPN55_FRONT443_INCLUDE_LINE" "$VPN55_NGINX_CONF")"
chk "the drop-in exists"                          "1" "$(grep -c '^Restart=on-failure' "$VPN55_FRONT443_DROPIN")"
chk "the operator was warned about site-a's real_ip_header by name" "1" "$(printf '%s\n' "$out" | grep -c '^    .*site-a.conf$')"
chk "SELinux boolean set on"                      "1" "$(grep -c 'setsebool httpd_can_network_connect 1' "$WORK/se.log")"
chk "…and its prior value recorded"               $'httpd_can_network_connect\toff' "$(_front443_ledger_rows selinux)"
chk "ledger: ports"                               "1194 8443 8008" "$(printf '%s %s %s' "$(_front443_ledger_get backend_port)" "$(_front443_ledger_get web_port)" "$(_front443_ledger_get strip_port)")"
chk "ledger: bind, no v6"                         "$PUB4 -" "$(printf '%s %s' "$(_front443_ledger_get bind)" "$(_front443_ledger_get bind6)")"
chk "ledger: both vhost files, not the panel"     "2" "$(_front443_ledger_rows file | grep -c 'site-')"
chk "ledger: installed stamp"                     "1" "$(_front443_ledger_rows installed | grep -c 'T')"
chk "check says ok"                               "ok" "$(front443_check)"

snapshot() { find "$WORK/nginx" "$VPN55_ETC" "$WORK/dropin" -type f -exec sha256sum {} + | sort; }
before="$(snapshot)"
front443_install 1194 >/dev/null 2>&1; rc=$?
chk "a second install succeeds"                   "0" "$rc"
chk "…changes no file"                            "1" "$([ "$before" = "$(snapshot)" ] && echo 1 || echo 0)"
chk "…and reloads nothing"                        "2" "$(reloads)"
chk "different ports are refused, not applied"    "1" "$(front443_install 1195 >/dev/null 2>&1; echo $?)"

# ─────────────────────────────────────────────────────────────────────────────
group "Drift: certbot adds a new site with a bare listen 443; the guard catches it"

printf 'server {\n    listen 80;\n    server_name new.example;\n}\nserver {\n    listen 443 ssl;\n    server_name new.example;\n}\n' > "$SITES/new.conf"
cp "$SITES/new.conf" "$WORK/new.orig"
out="$(front443_check)"; rc=$?
chk "check exits 1"                               "1" "$rc"
chk "check names the file and line"               "1" "$(printf '%s\n' "$out" | grep -c $'^broken\tvhost\t.*new\\.conf:6 ')"
chk "check names the repair"                      "1" "$(printf '%s\n' "$out" | grep -c $'\tvpn55.sh --front443-repair$')"
chk "the live binds are still reported fine — the new site never bound" "0" "$(printf '%s\n' "$out" | grep -c $'^broken\tbind')"
front443_repair >/dev/null 2>&1; rc=$?
chk "repair succeeds"                             "0" "$rc"
chk "the new site is tagged"                      "1" "$(grep -c 'vpn55-front443: was listen 443 ssl;' "$SITES/new.conf")"
chk "check says ok again"                         "ok" "$(front443_check)"
chk "the new file is in the ledger"               "1" "$(_front443_ledger_rows file | grep -c 'new.conf')"

# A repair that FAILS must not take the working front down with it. The
# drifted vhost is one nginx rejects; repair rewrites it, `nginx -t` fails,
# and the only thing put back is that file — not the include, not the stream
# conf, not the sites that were carrying traffic a second ago.
before="$(snapshot)"
printf 'server {\n    listen 443 ssl;\n    server_name bad.example;\n    this_is_not_a_directive;\n}\n' > "$SITES/bad.conf"
cp "$SITES/bad.conf" "$WORK/bad.orig"
cp "$SITES/site-a.conf" "$WORK/site-a.fronted"
n_before="$(reloads)"
touch "$WORK/nginx_t_fails"
front443_repair >/dev/null 2>&1; rc=$?
rm -f "$WORK/nginx_t_fails"
chk "a repair nginx rejects fails"                "1" "$rc"
chk "…the rejected vhost is back to the bytes it had" "0" "$(cmp -s "$SITES/bad.conf" "$WORK/bad.orig"; echo $?)"
chk "…the ledger is still there"                  "1" "$([ -e "$VPN55_FRONT443_STATE" ] && echo 1 || echo 0)"
chk "…the stream conf is still there"             "1" "$([ -e "$VPN55_FRONT443_STREAM_CONF" ] && echo 1 || echo 0)"
chk "…nginx.conf still has the include"           "1" "$(grep -cF "$VPN55_FRONT443_INCLUDE_LINE" "$VPN55_NGINX_CONF")"
chk "…site-a is still on the loopback web port"   "0" "$(cmp -s "$SITES/site-a.conf" "$WORK/site-a.fronted"; echo $?)"
chk "…the front still holds the public address"   "0" "$(_front443_addr_held "$PUB4" 443; echo $?)"
chk "…nothing was reloaded on a config that failed -t" "$n_before" "$(reloads)"
chk "…no pre-rewrite copies are left behind"      "" "$VPN55_FRONT443_SNAP"
rm -f "$SITES/bad.conf"
chk "with the bad vhost gone, check says ok"      "ok" "$(front443_check)"
chk "…and the host is exactly as before the failed repair" "1" "$([ "$before" = "$(snapshot)" ] && echo 1 || echo 0)"

# A re-run on a host whose public address moved is a refusal, not a second
# `bind` row the check would never read.
PUB4_SAVED="$PUB4"; PUB4=198.51.100.7
chk "a re-run with a changed public address is refused" "1" "$(front443_install 1194 >/dev/null 2>&1; echo $?)"
PUB4="$PUB4_SAVED"
chk "…and the ledger still holds one bind"       "1" "$(_front443_ledger_rows bind | wc -l | tr -d ' ')"

# Drift the other way: a package upgrade replaced nginx.conf.
cp "$WORK/nginx.conf.orig" "$VPN55_NGINX_CONF"
out="$(front443_check)"
chk "a missing include is reported"               "1" "$(printf '%s\n' "$out" | grep -c $'^broken\tinclude\tthe stream include is missing')"
front443_repair >/dev/null 2>&1
chk "repair puts the include back"                "ok" "$(front443_check)"

# The kernel disagreeing with the config is reported even when -T looks right.
cp "$WORK/ss.txt" "$WORK/ss.keep"
printf 'LISTEN 0 511 0.0.0.0:443 0.0.0.0:*\n' >> "$WORK/ss.txt"
out="$(front443_check)"
chk "a wildcard on 443 fails the check whatever -T says" "1" "$(printf '%s\n' "$out" | grep -c $'^broken\tbind\ta wildcard listener holds :443')"
cp "$WORK/ss.keep" "$WORK/ss.txt"
rm -f "$WORK/backend_up"; ss_recompute
out="$(front443_check)"
chk "a dead backend is reported as backend, with its own repair" "1" "$(printf '%s\n' "$out" | grep -c $'^broken\tbackend\tnothing holds 127.0.0.1:1194\tstart the service')"
touch "$WORK/backend_up"; ss_recompute

# ─────────────────────────────────────────────────────────────────────────────
group "vpn55.sh --front443-check / --front443-repair: the console half of the guard"

# shellcheck source=../lib/cli.sh
. lib/cli.sh

r="$(cli_front443 check 2>"$WORK/cli.err")"; rc=$?
chk "check on an intact front: stdout ok, exit 0"      "ok 0" "$r $rc"
chk "…and one row per invariant, all ok"               "4" "$(grep -c '\[ ok \]' "$WORK/cli.err")"
chk "…naming include, vhost, backend and bind"         "include vhost backend bind" \
    "$(grep '\[ ok \]' "$WORK/cli.err" | awk '{print $4}' | paste -sd' ')"

# certbot's drift again, seen from the console this time.
printf 'server {\n    listen 443 ssl;\n    server_name drift.example;\n}\n' > "$SITES/drift.conf"
r="$(cli_front443 check 2>"$WORK/cli.err")"; rc=$?
chk "check on a drifted front exits 1"                 "1" "$rc"
chk "…stdout carries the engine's broken record"       "1" "$(printf '%s\n' "$r" | grep -c $'^broken\tvhost\t.*drift\\.conf:2 ')"
chk "…the vhost row is FAIL and names the file"        "1" "$(grep -c '\[FAIL\]  vhost .*drift\.conf' "$WORK/cli.err")"
chk "…the other three rows are still ok"               "3" "$(grep -c '\[ ok \]' "$WORK/cli.err")"
chk "…and the repair named is the flag this test drives" "1" "$(grep -c 'Repair: vpn55.sh --front443-repair' "$WORK/cli.err")"

r="$(cli_front443 repair 2>"$WORK/cli.err")"; rc=$?
chk "repair exits as the check after it does: 0"       "0" "$rc"
chk "…stdout ends with ok"                             "ok" "$(printf '%s\n' "$r" | tail -n1)"
chk "…the drifted vhost is now tagged"                 "1" "$(grep -c 'vpn55-front443: was listen 443 ssl;' "$SITES/drift.conf")"
chk "…and the engine agrees"                           "ok" "$(front443_check)"

# --front443-remove: the consequence is said, then asked; no terminal declines.
r="$(cli_front443 remove </dev/null 2>"$WORK/cli.err")"; rc=$?
chk "remove with no terminal and no VPN55_ASSUME_YES declines, exit 1" "1" "$rc"
chk "…having named the port the fronted service is on"  "1" "$(grep -c '127\.0\.0\.1:1194' "$WORK/cli.err")"
chk "…and the front is intact"                          "ok" "$(front443_check)"
r="$(VPN55_ASSUME_YES=1 cli_front443 remove </dev/null 2>/dev/null)"; rc=$?
chk "remove with VPN55_ASSUME_YES=1: stdout removed, exit 0" "removed 0" "$r $rc"
chk "…no ledger"                                        "0" "$([ -e "$VPN55_FRONT443_STATE" ] && echo 1 || echo 0)"
chk "…the drifted vhost is back on its bare listen"     "1" "$(grep -c '^    listen 443 ssl;$' "$SITES/drift.conf")"
r="$(cli_front443 remove </dev/null 2>/dev/null)"; rc=$?
chk "remove with nothing to remove: stdout off, exit 0" "off 0" "$r $rc"
rm -f "$SITES/drift.conf"
ss_recompute

r="$(cli_front443 check 2>/dev/null)"; rc=$?
chk "check with no front: stdout off, exit 2"          "off 2" "$r $rc"
chk "repair with no front is refused, exit 1"          "1" "$(cli_front443 repair >/dev/null 2>&1; echo $?)"
chk "an unknown action is refused, exit 2"             "2" "$(cli_front443 bogus >/dev/null 2>&1; echo $?)"

# Back to the state the groups below expect: installed and intact.
front443_install 1194 >/dev/null 2>&1
chk "the front is back for the groups that follow"     "ok" "$(front443_check)"

# ─────────────────────────────────────────────────────────────────────────────
group "The portal template that ships: fronted later, and written while fronted"

# Deployed FIRST, fronted LATER: the template's two listen lines must be
# spellings the scanner recognises, or a portal installed by hand before the
# front stays on the public 443 and the front's reload fails at bind — silently.
PORTAL_TPL=deploy/nginx/vpn55-portal.conf
records="$( { printf '# configuration file /etc/nginx/sites-enabled/vpn55-portal.conf:\n'; cat "$PORTAL_TPL"; } \
    | _front443_scan_text "$PUB4" "")"
chk "the template's 443 listeners are both recognised"   "2" "$(count '^listen')"
chk "…the bare 443 with its params"                       "1" "$(count $'^listen\t.*vpn55-portal\.conf\t[0-9]+\t443\tssl http2\t0$')"
chk "…and the [::]:443 twin"                              "1" "$(count $'^listen\t.*vpn55-portal\.conf\t[0-9]+\t\[::\]:443\tssl http2\t0$')"
chk "the port-80 block is not a hit"                      "0" "$(count $':80\t')"
chk "the template sets no real_ip_header of its own"      "0" "$(count '^realip')"

# Written WHILE fronted: the front is installed at this point (the drift
# group above left it repaired), so the render verb must move the https block
# to the loopback web port in the tagged form and leave port 80 alone.
rendered="$(sed -e 's|__PORTAL_HOST__|vpn.example|g' -e 's|__PORTAL_PORT__|8056|g' "$PORTAL_TPL" | front443_render_vhost)"
rcount() { printf '%s\n' "$rendered" | grep -cE "$1"; }
chk "render: the https listen is the loopback web port, tagged" "1" \
    "$(rcount '^    listen 127\.0\.0\.1:8443 ssl http2 proxy_protocol; # vpn55-front443: was listen 443 ssl http2;$')"
chk "render: the [::]:443 twin is switched off, not duplicated" "1" \
    "$(rcount '^    # vpn55-front443: off: listen \[::\]:443 ssl http2;$')"
chk "render: no live listen on the public 443 remains"     "0" "$(printf '%s\n' "$rendered" | _front443_scan_text "$PUB4" "" | grep -c '^listen' || true)"
chk "render: listen 80 is exactly as the template has it"  "1" "$(rcount '^    listen 80;$')"
chk "render: listen [::]:80 is exactly as the template has it" "1" "$(rcount '^    listen \[::\]:80;$')"
chk "render: the placeholders were the caller's job, not ours" "0" "$(rcount '__PORTAL_')"

# Then adopted: the ledger learns the file, so remove restores it, and the
# rewrite over an already-rendered file changes nothing.
printf '%s\n' "$rendered" > "$SITES/vpn55-portal.conf"
cp "$SITES/vpn55-portal.conf" "$WORK/portal.rendered"
front443_adopt_file "$SITES/vpn55-portal.conf" >/dev/null 2>&1; rc=$?
chk "adopt succeeds"                                       "0" "$rc"
chk "adopt records the file in the ledger"                 "1" "$(_front443_ledger_rows file | grep -c 'vpn55-portal.conf')"
chk "adopt changes nothing in a file already rendered"     "0" "$(cmp -s "$SITES/vpn55-portal.conf" "$WORK/portal.rendered"; echo $?)"
ss_recompute
chk "check still says ok with the portal vhost in place"   "ok" "$(front443_check)"

# A writer that ignored the render verb and wrote the template as-is: adopt
# rewrites it, so the file the ledger holds is one the front carries.
sed -e 's|__PORTAL_HOST__|vpn.example|g' -e 's|__PORTAL_PORT__|8056|g' "$PORTAL_TPL" > "$WORK/portal-plain.conf"
front443_adopt_file "$WORK/portal-plain.conf" >/dev/null 2>&1
chk "adopt rewrites an un-rendered file into the tagged form" "1" \
    "$(grep -c '^    listen 127\.0\.0\.1:8443 ssl http2 proxy_protocol; # vpn55-front443: was listen 443 ssl http2;$' "$WORK/portal-plain.conf")"
_front443_restore_file "$WORK/portal-plain.conf" >/dev/null 2>&1
chk "…and restore brings the template's lines back"        "1" "$(grep -c '^    listen 443 ssl http2;$' "$WORK/portal-plain.conf")"

# With the front OFF both verbs are no-ops — asserted after the remove below.

# ─────────────────────────────────────────────────────────────────────────────
group "Remove: the host is as it was"

rm -f "$WORK/reloads" "$WORK/se.log"
front443_remove >/dev/null 2>&1; rc=$?
chk "remove succeeds"                             "0" "$rc"
chk "two reloads, mirrored"                       "2" "$(reloads)"
chk "site-a byte-identical to before"             "0" "$(cmp -s "$SITES/site-a.conf" "$WORK/site-a.orig"; echo $?)"
chk "site-b byte-identical to before"             "0" "$(cmp -s "$SITES/site-b.conf" "$WORK/site-b.orig"; echo $?)"
chk "the certbot site byte-identical to before"   "0" "$(cmp -s "$SITES/new.conf" "$WORK/new.orig"; echo $?)"
chk "the portal vhost written while fronted is back on listen 443" "1" "$(grep -c '^    listen 443 ssl http2;$' "$SITES/vpn55-portal.conf")"
chk "…and its [::]:443 twin is live again"        "1" "$(grep -c '^    listen \[::\]:443 ssl http2;$' "$SITES/vpn55-portal.conf")"
# The template's own header MENTIONS the marker, so count marker LINES —
# a tagged listen or an off'd one — not the word.
chk "…with no marker line left"                   "0" "$(grep -cE '^[[:space:]]*(listen .*# vpn55-front443: was|# vpn55-front443: off:)' "$SITES/vpn55-portal.conf")"
chk "nginx.conf byte-identical to before"         "0" "$(cmp -s "$VPN55_NGINX_CONF" "$WORK/nginx.conf.orig"; echo $?)"
chk "no realip snippet"                           "0" "$([ -e "$VPN55_FRONT443_REALIP_CONF" ] && echo 1 || echo 0)"
chk "no stream conf, no stream dir"               "0" "$([ -e "$VPN55_FRONT443_STREAM_DIR" ] && echo 1 || echo 0)"
chk "no drop-in"                                  "0" "$([ -e "$VPN55_FRONT443_DROPIN" ] && echo 1 || echo 0)"
chk "the wildcard holds 443 again"                "0" "$(_front443_wildcard_held 443; echo $?)"
chk "SELinux boolean set back to off"             "1" "$(grep -c 'setsebool httpd_can_network_connect 0' "$WORK/se.log")"
chk "no ledger"                                   "0" "$([ -e "$VPN55_FRONT443_STATE" ] && echo 1 || echo 0)"
r="$(front443_check)"; rc=$?
chk "check now says off, exit 2"                  "off 2" "$r $rc"
chk "a second remove is a quiet no-op"            "0" "$(front443_remove >/dev/null 2>&1; echo $?)"
chk "front off: render_vhost passes text through unchanged" "0"     "$(cmp -s <(front443_render_vhost < "$PORTAL_TPL") "$PORTAL_TPL"; echo $?)"
chk "front off: adopt_file records nothing and succeeds" "0 0"     "$(front443_adopt_file "$SITES/vpn55-portal.conf" >/dev/null 2>&1; printf '%s ' $?; [ -e "$VPN55_FRONT443_STATE" ] && echo 1 || echo 0)"
r="$(front443_info)"; rc=$?
chk "front off: info prints nothing, exit 2"      " 2" "$r $rc"
rm -f "$SITES/new.conf" "$SITES/vpn55-portal.conf"

# When the boolean was already on, remove leaves it alone.
echo on > "$WORK/sebool"; rm -f "$WORK/se.log"
front443_install 1194 >/dev/null 2>&1
front443_remove  >/dev/null 2>&1
chk "a boolean that was already on is never touched" "0" "$(grep -c setsebool "$WORK/se.log" 2>/dev/null || echo 0)"
rm -f "$WORK/semode"

# ─────────────────────────────────────────────────────────────────────────────
group "A failure mid-install leaves nothing behind"

rm -f "$WORK/reloads"
touch "$WORK/nginx_t_fails"
front443_install 1194 >/dev/null 2>&1; rc=$?
rm -f "$WORK/nginx_t_fails"
chk "install fails when nginx -t rejects the rewrite" "1" "$rc"
chk "site-a rolled back byte for byte"           "0" "$(cmp -s "$SITES/site-a.conf" "$WORK/site-a.orig"; echo $?)"
chk "site-b rolled back byte for byte"           "0" "$(cmp -s "$SITES/site-b.conf" "$WORK/site-b.orig"; echo $?)"
chk "nginx.conf untouched"                        "0" "$(cmp -s "$VPN55_NGINX_CONF" "$WORK/nginx.conf.orig"; echo $?)"
chk "no realip snippet left"                      "0" "$([ -e "$VPN55_FRONT443_REALIP_CONF" ] && echo 1 || echo 0)"
chk "no ledger left"                              "0" "$([ -e "$VPN55_FRONT443_STATE" ] && echo 1 || echo 0)"
chk "nothing was reloaded on a config that failed -t" "0" "$(reloads)"

rm -f "$WORK/backend_up"; ss_recompute
chk "a backend nobody listens on is refused before anything is written" "1" "$(front443_install 1194 >/dev/null 2>&1; echo $?)"
chk "…and left no ledger"                         "0" "$([ -e "$VPN55_FRONT443_STATE" ] && echo 1 || echo 0)"
touch "$WORK/backend_up"; ss_recompute

chk "a loopback port equal to 443 is refused"     "1" "$(front443_install 443 >/dev/null 2>&1; echo $?)"
chk "a web port equal to the backend is refused"  "1" "$(front443_install 1194 1194 >/dev/null 2>&1; echo $?)"

# ─────────────────────────────────────────────────────────────────────────────
group "R1 review: a listen that shares its line, or does not end on it, is refused — never rewritten"

# `listen 443 ssl; listen 80;` used to go live as ONE loopback listener with
# the port-80 one buried in the marker comment; `listen 443` continued on the
# next line left a stray `ssl;` AND a marker whose original never parsed, so
# even the rollback left the file changed. Both are now `refuse` records.
printf 'server {\n    listen 443 ssl; listen 80;\n}\nserver {\n    listen 80; listen [::]:443 ssl;\n}\nserver { listen 443 ssl; }\nserver {\n    listen 443 ssl; }\nserver {\n    listen 443\n        ssl;\n}\nserver {\n    listen 80; listen [::]:80;\n}\n' > "$SITES/odd.conf"
records="$(_front443_nginx_dump | _front443_scan_text "$PUB4" "")"
chk "five public-443 listens on odd lines are refused"     "5" "$(count '^refuse')"
chk "…listen 443 ssl; listen 80; — shares its line"        "1" "$(count $'^refuse\t.*odd\\.conf\t2\ta public-443 listen shares')"
chk "…listen 80; listen [::]:443 — the 443 is the SECOND directive" "1" "$(count $'^refuse\t.*odd\\.conf\t5\ta public-443')"
chk "…server { listen 443 ssl; } on one line"              "1" "$(count $'^refuse\t.*odd\\.conf\t7\ta public-443')"
chk "…listen 443 ssl; } with the brace"                    "1" "$(count $'^refuse\t.*odd\\.conf\t9\ta public-443')"
chk "…listen 443 continued on the next line"               "1" "$(count $'^refuse\t.*odd\\.conf\t11\tthe listen directive does not end')"
chk "…and a line of port-80 listens is nobody's business" "0" "$(count $'\t14\t')"
chk "none of them is also a listen record"                 "0" "$(count $'^listen\t.*odd\\.conf')"
cp "$SITES/odd.conf" "$WORK/odd.orig"
_front443_rewrite_file "$SITES/odd.conf" 8443 "$PUB4" "" >/dev/null 2>&1
chk "the rewrite leaves every one of them byte for byte"   "0" "$(cmp -s "$SITES/odd.conf" "$WORK/odd.orig"; echo $?)"
# A fresh install stops before touching anything, naming file and line.
out="$(front443_install 1194 2>&1)"; rc=$?
chk "a fresh install onto such a host is refused"          "1" "$rc"
chk "…naming the file and line"                            "1" "$(printf '%s\n' "$out" | grep -c 'odd\.conf:2: a public-443 listen shares')"
chk "…with nothing written"                                "0" "$([ -e "$VPN55_FRONT443_STATE" ] && echo 1 || echo 0)"
chk "…and site-a untouched"                                "0" "$(cmp -s "$SITES/site-a.conf" "$WORK/site-a.orig"; echo $?)"
rm -f "$SITES/odd.conf"
# CR line endings are one terminated listen: nginx reads CR as whitespace.
printf 'server {\r\n    listen 443 ssl;\r\n    server_name crlf.example;\r\n}\r\n' > "$WORK/crlf.conf"
records="$( { printf '# configuration file /x/crlf.conf:\n'; cat "$WORK/crlf.conf"; } | _front443_scan_text "$PUB4" "")"
chk "a CRLF vhost is a listen record, not a refusal"       "1 0" "$(count '^listen') $(count '^refuse')"
cp "$WORK/crlf.conf" "$WORK/crlf.orig"
_front443_rewrite_file "$WORK/crlf.conf" 8443 "$PUB4" "" >/dev/null 2>&1
# The byte-level half needs an awk that keeps CR on read; MSYS gawk (a
# Windows dev box) strips it in text mode, Linux never does. CI is Linux.
if [ "$(printf 'a\r\n' | awk '{ print length($0) }')" = "2" ]; then
    chk "…it is rewritten, the CR riding in the marker"        "1" "$(grep -c $'^    listen 127\\.0\\.0\\.1:8443 ssl proxy_protocol; # vpn55-front443: was listen 443 ssl;\r$' "$WORK/crlf.conf")"
    _front443_restore_file "$WORK/crlf.conf" >/dev/null 2>&1
    chk "…and restored byte for byte, CRs included"            "0" "$(cmp -s "$WORK/crlf.conf" "$WORK/crlf.orig"; echo $?)"
else
    chk "…it is rewritten (awk here strips CR; the byte check runs on Linux)" "1" "$(grep -c '^    listen 127\.0\.0\.1:8443 ssl proxy_protocol; # vpn55-front443: was listen 443 ssl;' "$WORK/crlf.conf")"
    _front443_restore_file "$WORK/crlf.conf" >/dev/null 2>&1
    chk "…and restored, CRs aside"                              "0" "$(cmp -s <(tr -d '\r' < "$WORK/crlf.conf") <(tr -d '\r' < "$WORK/crlf.orig"); echo $?)"
fi

# Drift in that shape, seen by the guard: repair cannot rewrite it, and the
# repair string must say so rather than name a command that will refuse.
front443_install 1194 >/dev/null 2>&1
printf 'server { listen 443 ssl; server_name one.example; }\n' > "$SITES/oneline.conf"
out="$(front443_check)"; rc=$?
chk "check on a one-line vhost exits 1"                    "1" "$rc"
chk "…as a vhost row naming file, line and reason"         "1" "$(printf '%s\n' "$out" | grep -c $'^broken\tvhost\t.*oneline\\.conf:1 a public-443 listen shares')"
chk "…whose repair is by hand first"                       "1" "$(printf '%s\n' "$out" | grep -c $'\tput that listen on a line of its own, ending in ";", then vpn55.sh --front443-repair$')"
before="$(snapshot)"
front443_repair >/dev/null 2>&1; rc=$?
chk "repair refuses it"                                    "1" "$rc"
chk "…and changes nothing on the host"                     "1" "$([ "$before" = "$(snapshot)" ] && echo 1 || echo 0)"
rm -f "$SITES/oneline.conf"
chk "with the line gone, check says ok"                    "ok" "$(front443_check)"

# ─────────────────────────────────────────────────────────────────────────────
group "R1 review: repair reads its ports from the ledger; an install with other ports says what to do"

# --front443-repair in a shell where VPN55_FRONT443_STRIP_PORT was changed
# since the install used to refuse with "run front443_remove" — a bash
# function name, not a command anyone has.
VPN55_FRONT443_STRIP_PORT=9009 front443_repair >/dev/null 2>&1; rc=$?
chk "repair with a changed strip-port environment succeeds" "0" "$rc"
chk "…on the ledger's strip port"                          "8008" "$(_front443_ledger_get strip_port)"
out="$(VPN55_FRONT443_WEB_PORT=9443 front443_install 1194 2>&1)"; rc=$?
chk "an install asking for another web port is refused"    "1" "$rc"
chk "…and the message names the override to unset"         "1" "$(printf '%s\n' "$out" | grep -c 'Unset any VPN55_FRONT443_WEB_PORT')"
chk "…not a function name"                                 "0" "$(printf '%s\n' "$out" | grep -c 'run front443_remove')"
chk "…and the front is intact"                             "ok" "$(front443_check)"

# ─────────────────────────────────────────────────────────────────────────────
group "R1 review: nginx stopped is one row, not four"

_front443_nginx_active() { return 1; }
cp "$WORK/ss.txt" "$WORK/ss.keep"; : > "$WORK/ss.txt"
printf 'LISTEN 0 511 127.0.0.1:1194 0.0.0.0:*\n' > "$WORK/ss.txt"
out="$(front443_check)"; rc=$?
chk "check with nginx down exits 1"                        "1" "$rc"
chk "…one bind row, naming nginx"                          "1" "$(printf '%s\n' "$out" | grep -c $'^broken\tbind\tnginx is not running')"
chk "…whose repair is to start it"                         "1" "$(printf '%s\n' "$out" | grep -c $'\tsystemctl start nginx$')"
chk "…and no 'nothing holds' rows beside it"               "0" "$(printf '%s\n' "$out" | grep -c 'nothing holds')"
chk "…the backend row is still its own"                    "0" "$(printf '%s\n' "$out" | grep -c $'^broken\tbackend')"
_front443_nginx_active() { return 0; }
cp "$WORK/ss.keep" "$WORK/ss.txt"
chk "nginx back: ok"                                       "ok" "$(front443_check)"
front443_remove >/dev/null 2>&1

# ─────────────────────────────────────────────────────────────────────────────
group "R1 review: a host whose only 443 holder is the panel — the self-collision §6C.8 opens with"

# nginx holds 443 (on the tunnel address), so the offer is made; no vhost
# holds the PUBLIC 443, so none moves and nginx never binds the web port.
# Before R1 the install demanded that bind, failed, and rolled back — on
# exactly the host the section's first paragraph is about — and a remove on
# such a host waited for "anything on 443" (the panel, at once) or, without
# the panel, timed out and kept the ledger for a second run.
mkdir -p "$WORK/away"; mv "$SITES/site-a.conf" "$SITES/site-b.conf" "$WORK/away/"; ss_recompute
rm -f "$WORK/reloads"
out="$(front443_install 1194 2>&1)"; rc=$?
chk "install succeeds with no public-443 vhost"            "0" "$rc"
chk "…says why the web port is not bound"                  "1" "$(printf '%s\n' "$out" | grep -c 'No vhost listens on 127.0.0.1:8443')"
chk "…the front holds the public address"                  "0" "$(_front443_addr_held "$PUB4" 443; echo $?)"
chk "…the panel's bind survived"                           "0" "$(_front443_addr_held 10.8.0.1 443; echo $?)"
chk "…and the web port is not bound"                       "1" "$(_front443_addr_held 127.0.0.1 8443; echo $?)"
chk "…ledger: no file rows"                                "0" "$(_front443_ledger_rows file | grep -c . || true)"
chk "check says ok on that host"                           "ok" "$(front443_check)"
rm -f "$WORK/reloads"
front443_remove >/dev/null 2>&1; rc=$?
chk "remove completes in ONE run"                          "0" "$rc"
chk "…with no ledger left"                                 "0" "$([ -e "$VPN55_FRONT443_STATE" ] && echo 1 || echo 0)"
chk "…and two reloads"                                     "2" "$(reloads)"
mv "$WORK/away"/* "$SITES/"; ss_recompute

# ─────────────────────────────────────────────────────────────────────────────
group "R1 review: markers with no ledger is a half-removed front, not a host to install onto"

front443_install 1194 >/dev/null 2>&1
chk "the front is on"                                      "ok" "$(front443_check)"
rm -f "$VPN55_FRONT443_STATE"          # the hand `rm`
before="$(snapshot)"
out="$(front443_install 1194 2>&1)"; rc=$?
chk "a fresh install onto the traces is refused"           "1" "$rc"
chk "…naming the missing ledger"                           "1" "$(printf '%s\n' "$out" | grep -c 'ledger .*front443.state')"
chk "…not sent off to pick another web port"               "0" "$(printf '%s\n' "$out" | grep -c 'set VPN55_FRONT443_WEB_PORT')"
chk "…but to the remove verb"                              "1" "$(printf '%s\n' "$out" | grep -c 'vpn55.sh --front443-remove')"
chk "…and nothing changed"                                 "1" "$([ "$before" = "$(snapshot)" ] && echo 1 || echo 0)"
chk "traces_present says so"                               "0" "$(front443_traces_present; echo $?)"
chk "…and names every marked file, each once"              "site-a.conf site-b.conf" \
    "$(_front443_marked_files | xargs -n1 basename | paste -sd' ')"

# The way back: remove reads the marked files from the host itself.
rm -f "$WORK/reloads"
out="$(front443_remove 2>&1)"; rc=$?
chk "a ledger-less remove succeeds"                        "0" "$rc"
chk "…saying it works from the files"                      "1" "$(printf '%s\n' "$out" | grep -c 'no ledger at')"
chk "…two reloads, as with a ledger"                       "2" "$(reloads)"
chk "…site-a as it was"                                    "0" "$(cmp -s "$SITES/site-a.conf" "$WORK/site-a.orig"; echo $?)"
chk "…site-b as it was"                                    "0" "$(cmp -s "$SITES/site-b.conf" "$WORK/site-b.orig"; echo $?)"
chk "…nginx.conf as it was"                                "0" "$(cmp -s "$VPN55_NGINX_CONF" "$WORK/nginx.conf.orig"; echo $?)"
chk "…no stream conf, snippet or drop-in"                  "0" "$( { [ -e "$VPN55_FRONT443_STREAM_CONF" ] || [ -e "$VPN55_FRONT443_REALIP_CONF" ] || [ -e "$VPN55_FRONT443_DROPIN" ]; } && echo 1 || echo 0)"
chk "…the wildcard holds 443 again"                        "0" "$(_front443_wildcard_held 443; echo $?)"
chk "…no traces left"                                      "1" "$(front443_traces_present; echo $?)"
chk "…and a fresh install is accepted again"               "0" "$(front443_install 1194 >/dev/null 2>&1; echo $?)"

# The same with `nginx -T` broken (a half-removed host is where it may be):
# the files are found on disk instead. And SELinux on an enforcing host: the
# boolean's prior value is unknown without the ledger, so it is left and said.
rm -f "$VPN55_FRONT443_STATE"
echo Enforcing > "$WORK/semode"; echo on > "$WORK/sebool"; rm -f "$WORK/se.log"
_front443_nginx_dump() { return 1; }
out="$(front443_remove 2>&1)"; rc=$?
_front443_nginx_dump() { local f; dump_file "$VPN55_NGINX_CONF"; [ -f "$WORK/modload" ] && printf '# configuration file /etc/nginx/modules-enabled/50-mod-stream.conf:\nload_module modules/ngx_stream_module.so;\n'; for f in "$WORK/nginx/conf.d"/*.conf "$SITES"/* "$VPN55_FRONT443_STREAM_DIR"/*.conf; do [ -f "$f" ] && dump_file "$f"; done; return 0; }
chk "ledger-less remove with -T broken still succeeds"     "0" "$rc"
chk "…site-a as it was, found on disk"                     "0" "$(cmp -s "$SITES/site-a.conf" "$WORK/site-a.orig"; echo $?)"
chk "…site-b as it was"                                    "0" "$(cmp -s "$SITES/site-b.conf" "$WORK/site-b.orig"; echo $?)"
chk "…the boolean is not touched"                          "0" "$(grep -c setsebool "$WORK/se.log" 2>/dev/null || echo 0)"
chk "…and the command to put it back is printed"           "1" "$(printf '%s\n' "$out" | grep -c 'setsebool -P httpd_can_network_connect 0')"
rm -f "$WORK/semode" "$WORK/sebool" "$WORK/se.log"; ss_recompute

# ─────────────────────────────────────────────────────────────────────────────
group "R1 follow-up: drift is repaired while the fronted service is stopped"

# Before: the engine refused a dead backend on every run, so a certbot edit
# made while the tunnel was down for maintenance kept the WEBSITE broken until
# the tunnel came back. A fresh install still refuses (above); a re-run warns.
front443_install 1194 >/dev/null 2>&1
chk "the front is on"                                      "ok" "$(front443_check)"
printf 'server {\n    listen 443 ssl;\n    server_name drift.example;\n}\n' > "$SITES/drift.conf"
rm -f "$WORK/backend_up"; ss_recompute
out="$(front443_repair 2>&1)"; rc=$?
chk "repair with the backend stopped succeeds"             "0" "$rc"
chk "…saying the front is re-applied anyway"               "1" "$(printf '%s\n' "$out" | grep -c 'The front is re-applied anyway')"
chk "…the drifted vhost is tagged"                         "1" "$(grep -c 'vpn55-front443: was listen 443 ssl;' "$SITES/drift.conf")"
out="$(front443_check)"; rc=$?
chk "the check then fails on the backend row alone"        "1 backend" "$rc $(printf '%s\n' "$out" | awk -F'\t' '$1 == "broken" { print $2 }' | paste -sd' ')"
touch "$WORK/backend_up"; ss_recompute
chk "service back: ok"                                     "ok" "$(front443_check)"
front443_remove >/dev/null 2>&1
rm -f "$SITES/drift.conf"; ss_recompute
chk "site-a as it was"                                     "0" "$(cmp -s "$SITES/site-a.conf" "$WORK/site-a.orig"; echo $?)"

# ─────────────────────────────────────────────────────────────────────────────
group "IPv6: bound only when a vhost had [::]:443 AND the host has a global v6"

touch "$WORK/v6"
front443_install 1194 >/dev/null 2>&1
chk "the front binds the v6 too"                  "1" "$(grep -c "listen \[${PUB6}\]:443;" "$VPN55_FRONT443_STREAM_CONF")"
chk "ledger records it"                           "$PUB6" "$(_front443_ledger_get bind6)"
chk "check verifies the v6 bind by address"       "ok" "$(front443_check)"
front443_remove >/dev/null 2>&1
rm -f "$WORK/v6"

printf '\n  %d passed, %d failed\n\n' "$pass" "$fail"
[ "$fail" -eq 0 ]
