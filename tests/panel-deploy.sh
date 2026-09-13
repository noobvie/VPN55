#!/usr/bin/env bash
#
# tests/panel-deploy.sh — the panel deployment decisions that are wrong
# SILENTLY, checked without a server.
#
# Every case here is one that produces no error on the host where it is wrong:
#
#   · a vhost written to sites-enabled on a distribution that does not include
#     that directory. `nginx -t` parses a config the file is not in, the reload
#     returns 0, and the panel is simply unreachable.
#   · a firewall rule that allows the tunnel subnet to be ROUTED and never opens
#     the port on the host itself, so the tunnel carries traffic to the internet
#     perfectly and drops every packet aimed at the panel — while the firewall's
#     own status output shows the subnet allowed.
#   · a sed that repoints ssl_certificate and eats ssl_certificate_key with it,
#     leaving two certificates and no key.
#   · a panel deployed from a git checkout, which installs a sudoers rule
#     pinning a path the panel user can write to.
#
# Nothing here starts a process, binds a port, or writes outside one mktemp
# directory. The firewall binaries are stubs that record their argv.

# Every VPN55_* assigned below is read by a sourced lib, not by this file.
# shellcheck disable=SC2034
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
mkdir -p "$VPN55_ETC" "$WORK/bin"
export PATH="$WORK/bin:$PATH"
export FWLOG="$WORK/fw.log"

# Stubs that record their arguments and nothing else. `status` answers so the
# backend probe finds an active firewall; every --query- answers "absent" so a
# rule is recorded as ours.
for b in ufw firewall-cmd nft; do
    {
        printf '#!/bin/sh\n'
        printf 'case "$1" in status) echo "Status: active"; exit 0 ;; esac\n'
        printf 'case "$*" in *--query-*) exit 1 ;; esac\n'
        printf 'case "$1" in list) exit 1 ;; esac\n'
        printf 'echo "%s: $*" >> "$FWLOG"\n' "$b"
    } > "$WORK/bin/$b"
    chmod +x "$WORK/bin/$b"
done

# shellcheck source=../lib/ui.sh
. lib/ui.sh
# shellcheck source=../lib/core_fs.sh
. lib/core_fs.sh
# shellcheck source=../lib/core_distro.sh
. lib/core_distro.sh
# shellcheck source=../lib/core_i18n.sh
. lib/core_i18n.sh
# shellcheck source=../lib/core_net.sh
. lib/core_net.sh
# shellcheck source=../lib/core_adapters.sh
. lib/core_adapters.sh
# shellcheck source=../lib/panel_deploy.sh
. lib/panel_deploy.sh

# ─────────────────────────────────────────────────────────────────────────────
group "Where a vhost goes is READ from nginx.conf, never assumed"

export VPN55_NGINX_CONF="$WORK/nginx.conf"
layout() {
    printf '%s\n' "$1" > "$VPN55_NGINX_CONF"
    VPN55_PANEL_VHOST_DEST=""
    VPN55_PANEL_VHOST_LINK=""
    pnl_vhost_paths >/dev/null 2>&1 || { printf 'refused'; return 0; }
    printf '%s|%s' "${VPN55_PANEL_VHOST_DEST##*/etc/nginx/}" "${VPN55_PANEL_VHOST_LINK##*/etc/nginx/}"
}

chk "a Debian layout uses sites-available + a symlink" \
    "sites-available/vpn55-panel.conf|sites-enabled/vpn55-panel.conf" \
    "$(layout 'http {
    include /etc/nginx/conf.d/*.conf;
    include /etc/nginx/sites-enabled/*;
}')"

chk "an RHEL layout writes straight into conf.d" \
    "conf.d/vpn55-panel.conf|" \
    "$(layout 'http {
    include /etc/nginx/conf.d/*.conf;
}')"

chk "neither included is refused, not guessed at" \
    "refused" \
    "$(layout 'http {
}')"

# ─────────────────────────────────────────────────────────────────────────────
group "The panel's port is opened on INPUT, scoped to the tunnel"

fw_case() {
    local backend="$1" want="$2" label="$3"
    : > "$FWLOG"
    rm -f "$VPN55_ETC/fw.state"
    eval "net_fw_backend() { printf '%s' '${backend}'; }"
    net_fw_commit() { return 0; }
    _net_nft_tables() { return 0; }
    _net_nft_rule_present() { return 1; }
    net_fw_open_port_from panel 10.8.0.0/24 tcp 443 >/dev/null 2>&1
    if grep -qF "$want" "$FWLOG" 2>/dev/null; then
        chk "$label" "found" "found"
    else
        chk "$label" "$want" "$(tr '\n' ';' < "$FWLOG" 2>/dev/null)"
    fi
}

fw_case ufw \
    'ufw: allow from 10.8.0.0/24 to any port 443 proto tcp comment vpn55:panel' \
    "ufw allows the port FROM the tunnel, not to the world"
fw_case firewalld \
    'source address="10.8.0.0/24" port port="443" protocol="tcp" accept' \
    "firewalld's rich rule keeps its quoting"
fw_case nftables \
    'nft: add rule inet vpn55 input ip saddr 10.8.0.0/24 tcp dport 443 accept' \
    "nft matches on the source address"

: > "$FWLOG"
rm -f "$VPN55_ETC/fw.state"
net_fw_backend() { printf 'ufw'; }
net_fw_reload() { return 0; }
net_fw_open_port_from panel 10.8.0.0/24 tcp 443 >/dev/null 2>&1
: > "$FWLOG"
net_fw_revoke_tag panel >/dev/null 2>&1
chk "the uninstall removes exactly what the install added" "1" \
    "$(grep -cF 'ufw: delete allow from 10.8.0.0/24 to any port 443 proto tcp' "$FWLOG")"

# ─────────────────────────────────────────────────────────────────────────────
group "The rendered vhost, against the template that actually ships"

VPN55_PANEL_VHOST_SRC=deploy/nginx/vpn55-panel.conf
VPN55_PANEL_TLS_DIR=/etc/vpn55/panel-tls
pnl_tunnel_addresses() { printf '10.8.0.1\n10.8.1.1\n'; }
rendered="$(pnl_render_vhost)"
count() { printf '%s\n' "$rendered" | grep -cE "$1"; }

chk "one listen line per tunnel gateway"      "2" "$(count '^ *listen ')"
chk "the first gateway is listened on"        "1" "$(count '^ *listen 10\.8\.0\.1:443 ssl http2;$')"
chk "the second gateway is listened on"       "1" "$(count '^ *listen 10\.8\.1\.1:443 ssl http2;$')"
# ⚠ The one that regresses silently: `ssl_certificate  *[^;]*;` with a single
# space would also match the ssl_certificate_key line, rewriting it into a
# second certificate — leaving a vhost with no key at all.
chk "exactly one ssl_certificate survives"    "1" "$(count '^ *ssl_certificate +[^;]')"
chk "exactly one ssl_certificate_key survives" "1" "$(count '^ *ssl_certificate_key +[^;]')"
chk "the certificate is the self-signed one"  "1" "$(count 'panel-tls/panel\.crt;')"
chk "the key is the self-signed one"          "1" "$(count 'panel-tls/panel\.key;')"
chk "no placeholder is left behind"           "0" "$(count '__[A-Z_]+__')"
chk "every proxy_pass names the panel's port" "2" "$(count 'proxy_pass http://127\.0\.0\.1:8055;')"

unset -f count
VPN55_PANEL_DEPLOY_LOADED=""
# shellcheck source=../lib/panel_deploy.sh
. lib/panel_deploy.sh          # restores the real pnl_tunnel_addresses

# ─────────────────────────────────────────────────────────────────────────────
group "Only an adapter holding a pool claim contributes an address"

VPN55_ADAPTER_TAGS=(alpha beta gamma)
net_pool_claim alpha 0 >/dev/null 2>&1
net_pool_claim beta  1 >/dev/null 2>&1

chk "gamma claimed nothing, so it listens on nothing" \
    "10.8.0.1 10.8.1.1" "$(pnl_tunnel_addresses | tr '\n' ' ' | sed 's/ $//')"
chk "the firewall follows the same claims" \
    "10.8.0.0/24 10.8.1.0/24" "$(pnl_tunnel_subnets | tr '\n' ' ' | sed 's/ $//')"

# ─────────────────────────────────────────────────────────────────────────────
group "The panel is deployed from the install path, or not at all"

mkdir -p "$WORK/home/panel" "$WORK/checkout"
VPN55_HOME="$WORK/home"
VPN55_PANEL_SRC="$WORK/home/panel"
chown() { return 0; }    # the branch under test is the path comparison
chmod() { return 0; }

VPN55_ROOT="$WORK/checkout"
if pnl_check_tree >/dev/null 2>&1; then verdict=accepted; else verdict=refused; fi
chk "a git checkout is refused" "refused" "$verdict"

VPN55_ROOT="$WORK/home"
if pnl_check_tree >/dev/null 2>&1; then verdict=accepted; else verdict=refused; fi
chk "the install path is accepted" "accepted" "$verdict"

unset -f chown chmod

# ─────────────────────────────────────────────────────────────────────────────
group "The portal vhost: the template's bootstrap, and front-aware when 443 is shared"

# The engine is loaded here as vpn55.sh loads it, with a fake ledger that says
# the front is on. Nothing in this group binds anything: nginx, certbot, the
# firewall and the service manager are stubs that record what they were asked.
# shellcheck source=../lib/core_front443.sh
. lib/core_front443.sh

PORTAL_LOG="$WORK/portal.log"
VPN55_PORTAL_VHOST_SRC=deploy/nginx/vpn55-portal.conf
VPN55_PANEL_CONF="$WORK/etc/panel.conf"
VPN55_PORTAL_CONF="$WORK/etc/portal.conf"
VPN55_PORTAL_LE_LIVE="$WORK/letsencrypt/live"
VPN55_PORTAL_ACME_ROOT="$WORK/www/html"
VPN55_PANEL_UNIT_DEST="$WORK/vpn55-panel.service"
VPN55_PANEL_OFFLINE_SRC="$WORK/offline.src.html"
VPN55_PANEL_OFFLINE_DEST="$WORK/www/vpn55/offline.html"
VPN55_FRONT443_STATE="$WORK/etc/front443.state"
printf 'portal_port=8056\n' > "$VPN55_PANEL_CONF"
printf '<html>offline</html>\n' > "$VPN55_PANEL_OFFLINE_SRC"
: > "$VPN55_PANEL_UNIT_DEST"
printf 'http {\n    include /etc/nginx/conf.d/*.conf;\n    include /etc/nginx/sites-enabled/*;\n}\n' > "$VPN55_NGINX_CONF"

distro_require_root()      { return 0; }
distro_have()              { case "$1" in nginx|certbot) [ ! -f "$WORK/no-$1" ] ;; *) command -v "$1" >/dev/null 2>&1 ;; esac; }
distro_service_is_active() { return 0; }
_pnl_nginx_test()          { echo "nginx -t" >> "$PORTAL_LOG"; [ ! -f "$WORK/nginx_t_fails" ]; }
_pnl_nginx_test_out()      { echo "nginx: [emerg] fake failure"; return 1; }
_pnl_nginx_reload()        { echo "reload" >> "$PORTAL_LOG"; }
_pnl_certbot()             { echo "certbot $*" >> "$PORTAL_LOG"; mkdir -p "$VPN55_PORTAL_LE_LIVE/$host_under_test"; : > "$VPN55_PORTAL_LE_LIVE/$host_under_test/fullchain.pem"; : > "$VPN55_PORTAL_LE_LIVE/$host_under_test/privkey.pem"; }
net_fw_open_port()         { echo "fw $*" >> "$PORTAL_LOG"; }
front443_check()           { [ ! -f "$WORK/front_broken" ]; }
# ln -s is not available to an unprivileged Windows user, where these tests are
# also run; the link is recorded and its presence answered from the record.
fs_link()                  { echo "link $2" >> "$PORTAL_LOG"; : > "$2"; }
_pnl_link_present()        { [ -e "${1:-}" ]; }
# `-e`, so a pattern that starts with a dash is a pattern. `pcount -- '--nginx'`
# once made this `grep -c -- $PORTAL_LOG`: the LOG PATH became the pattern and grep
# read stdin — 0 at EOF, which was the expected answer, so the assertion passed
# for the wrong reason, and hung outright whenever stdin was open.
pcount() { grep -c -e "$1" "$PORTAL_LOG" 2>/dev/null || true; }

# The vhost paths follow the same probe as the panel's, relocated into WORK.
pnl_portal_vhost_paths() {
    VPN55_PORTAL_VHOST_DEST="$WORK/nginx/sites-available/vpn55-portal.conf"
    VPN55_PORTAL_VHOST_LINK="$WORK/nginx/sites-enabled/vpn55-portal.conf"
}
mkdir -p "$WORK/nginx/sites-available" "$WORK/nginx/sites-enabled"

chk "a hostname is accepted"                      "0" "$(pnl_portal_host_valid vpn.example.com; echo $?)"
chk "an address is not a hostname"                "1" "$(pnl_portal_host_valid 203.0.113.10; echo $?)"
chk "a bare label is not a hostname"              "1" "$(pnl_portal_host_valid localhost; echo $?)"
chk "a label with a leading dash is refused"      "1" "$(pnl_portal_host_valid -bad.example; echo $?)"

# ── No front: the template as it ships, two placeholders substituted ──
rm -f "$VPN55_FRONT443_STATE"
rendered="$(pnl_portal_render_vhost vpn.example full)"
count() { printf '%s\n' "$rendered" | grep -cE "$1"; }
chk "no front: listen 443 is the template's"      "1" "$(count '^    listen 443 ssl http2;$')"
chk "no front: the [::]:443 twin is live"         "1" "$(count '^    listen \[::\]:443 ssl http2;$')"
chk "no front: no marker line"                    "0" "$(count '^[[:space:]]*(listen .*# vpn55-front443: was|# vpn55-front443: off:)')"
chk "no front: the host is substituted"           "0" "$(count '__PORTAL_HOST__')"
chk "no front: the port is read from panel.conf"  "2" "$(count 'proxy_pass http://127\.0\.0\.1:8056;')"
chk "no front: nothing else is edited"            "0" "$(diff <(sed -e 's|__PORTAL_HOST__|vpn.example|g' -e 's|__PORTAL_PORT__|8056|g' deploy/nginx/vpn55-portal.conf) <(printf '%s\n' "$rendered") | grep -c '^[<>]')"

# ── The bootstrap stage: the header and the port-80 block, nothing else ──
rendered="$(pnl_portal_render_vhost vpn.example bootstrap)"
chk "bootstrap: exactly one server block"         "1" "$(count '^server \{')"
chk "bootstrap: it listens on 80"                 "1" "$(count '^    listen 80;$')"
chk "bootstrap: the acme path is served"          "1" "$(count 'acme-challenge')"
# Directives, not the header's prose — the template's own comments mention
# both `listen 443` and the certificate path.
chk "bootstrap: no 443 listener at all"           "0" "$(count '^[[:space:]]*listen .*443')"
chk "bootstrap: no certificate path — nginx -t would hard-fail on it" "0" "$(count '^[[:space:]]*ssl_certificate')"

# ── With the front on: the https block lands behind it, tagged ──
printf 'backend_port\t1194\nweb_port\t8443\nstrip_port\t8008\nbind\t203.0.113.10\nbind6\t-\ninstalled\t2026-09-11T00:00:00Z\n' > "$VPN55_FRONT443_STATE"
rendered="$(pnl_portal_render_vhost vpn.example full)"
chk "front on: the https listen is 127.0.0.1:<web> ssl http2 proxy_protocol, tagged" "1" \
    "$(count '^    listen 127\.0\.0\.1:8443 ssl http2 proxy_protocol; # vpn55-front443: was listen 443 ssl http2;$')"
chk "front on: no [::] listen line — the front carries v6" "1" "$(count '^    # vpn55-front443: off: listen \[::\]:443 ssl http2;$')"
chk "front on: no live listener on 443 at all"    "0" "$(count '^    listen (\[::\]:)?443 ')"
chk "front on: listen 80 is untouched"            "1" "$(count '^    listen 80;$')"
chk "front on: listen [::]:80 is untouched"       "1" "$(count '^    listen \[::\]:80;$')"
chk "front on: the bootstrap stage is the same as without" "0" \
    "$(diff <(pnl_portal_render_vhost vpn.example bootstrap) <(rm -f "$VPN55_FRONT443_STATE"; pnl_portal_render_vhost vpn.example bootstrap) | grep -c '^[<>]')"
printf 'backend_port\t1194\nweb_port\t8443\nstrip_port\t8008\nbind\t203.0.113.10\nbind6\t-\ninstalled\t2026-09-11T00:00:00Z\n' > "$VPN55_FRONT443_STATE"

# ── The whole run, front on, no certificate yet: port 80 first, then certbot, then https ──
host_under_test=vpn.example
: > "$PORTAL_LOG"
rm -rf "$VPN55_PORTAL_LE_LIVE"
VPN55_ASSUME_YES=1 portal_install VPN.Example >/dev/null 2>&1 < /dev/null; rc=$?
chk "install succeeds"                            "0" "$rc"
chk "the host is recorded, lowercased"            "vpn.example" "$(pnl_portal_host)"
chk "nginx -t ran twice: once per stage"          "2" "$(pcount '^nginx -t$')"
chk "reloaded twice: the port-80 half, then the https half" "2" "$(pcount '^reload$')"
chk "certbot ran ONCE, webroot, the template's acme root, the host" "1" \
    "$(pcount "^certbot certonly --webroot -w ${VPN55_PORTAL_ACME_ROOT} -d vpn.example --non-interactive --agree-tos --keep-until-expiring --register-unsafely-without-email$")"
chk "certbot never ran with --nginx"              "0" "$(pcount '--nginx')"
chk "port 80 was opened before the certificate, 443 after" \
    "fw portal tcp 80|certbot|fw portal tcp 443" \
    "$(grep -E '^(fw|certbot)' "$PORTAL_LOG" | sed 's/^certbot .*/certbot/; s/^fw portal tcp \([0-9]*\).*/fw portal tcp \1/' | paste -sd'|')"
chk "the vhost on disk carries the https block behind the front" "1" \
    "$(grep -c '^    listen 127\.0\.0\.1:8443 ssl http2 proxy_protocol; # vpn55-front443: was listen 443 ssl http2;$' "$VPN55_PORTAL_VHOST_DEST")"
chk "…and is linked into sites-enabled"           "1" "$([ -e "$VPN55_PORTAL_VHOST_LINK" ] && echo 1 || echo 0)"
chk "…and is in the front's ledger, so remove restores it" "1" "$(_front443_ledger_rows file | grep -c 'vpn55-portal.conf')"
chk "the offline page was installed"              "1" "$([ -f "$VPN55_PANEL_OFFLINE_DEST" ] && echo 1 || echo 0)"
chk "the acme root exists"                        "1" "$([ -d "$VPN55_PORTAL_ACME_ROOT" ] && echo 1 || echo 0)"
chk "deployed, as the screen will report it"      "0" "$(pnl_portal_installed; echo $?)"

# A second run with everything in place changes nothing and reloads nothing.
before="$(sha256sum "$VPN55_PORTAL_VHOST_DEST")"
: > "$PORTAL_LOG"
VPN55_ASSUME_YES=1 portal_install vpn.example >/dev/null 2>&1 < /dev/null; rc=$?
chk "a second run succeeds"                       "0" "$rc"
chk "…rewrites nothing"                           "1" "$([ "$before" = "$(sha256sum "$VPN55_PORTAL_VHOST_DEST")" ] && echo 1 || echo 0)"
chk "…reloads nothing"                            "0" "$(pcount '^reload$')"
chk "…and asks certbot for nothing"               "0" "$(pcount '^certbot')"

# A broken front is warned about, and the vhost is still written for it —
# writing `listen 443` onto a fronted host would be a second broken invariant.
touch "$WORK/front_broken"
out="$(VPN55_ASSUME_YES=1 portal_install vpn.example 2>&1 < /dev/null)"
chk "a broken front is named, with its repair"    "1" "$(printf '%s\n' "$out" | grep -c 'front443-repair')"
chk "…and the vhost still targets the front"      "1" "$(grep -c '^    listen 127\.0\.0\.1:8443' "$VPN55_PORTAL_VHOST_DEST")"
rm -f "$WORK/front_broken"

# nginx rejecting the https half puts the previous file back — the port-80
# half — rather than leaving a vhost the next reload of anything would refuse.
text="$(pnl_portal_render_vhost vpn.example bootstrap)"
fs_write_if_changed "$VPN55_PORTAL_VHOST_DEST" 0644 "$text" >/dev/null 2>&1
touch "$WORK/nginx_t_fails"
: > "$PORTAL_LOG"
VPN55_ASSUME_YES=1 portal_install vpn.example >/dev/null 2>&1 < /dev/null; rc=$?
rm -f "$WORK/nginx_t_fails"
chk "a rejected vhost fails the run"              "1" "$rc"
chk "…the previous file is back"                  "0" "$(cmp -s "$VPN55_PORTAL_VHOST_DEST" <(printf '%s\n' "$text"); echo $?)"
chk "…and nothing was reloaded"                   "0" "$(pcount '^reload$')"

# No certbot on the host: the port-80 half is in place and the run stops with
# the command to run — step 3 of the header, by hand.
rm -rf "$VPN55_PORTAL_LE_LIVE" "$VPN55_PORTAL_VHOST_DEST" "$VPN55_PORTAL_VHOST_LINK"
touch "$WORK/no-certbot"
out="$(VPN55_ASSUME_YES=1 portal_install vpn.example 2>&1 < /dev/null)"; rc=$?
rm -f "$WORK/no-certbot"
chk "without certbot the run stops after the port-80 half" "1" "$rc"
chk "…the port-80 vhost stays"                    "1" "$(grep -c '^    listen 80;$' "$VPN55_PORTAL_VHOST_DEST")"
chk "…with no https block"                        "0" "$(grep -c '^    ssl_certificate' "$VPN55_PORTAL_VHOST_DEST")"
chk "…and the operator is told the webroot command" "1" "$(printf '%s\n' "$out" | grep -c "certonly --webroot -w ${VPN55_PORTAL_ACME_ROOT} -d vpn.example")"

# Not a hostname: refused before anything is written.
rm -f "$VPN55_PORTAL_CONF"
VPN55_ASSUME_YES=1 portal_install 203.0.113.10 >/dev/null 2>&1 < /dev/null; rc=$?
chk "an address is refused"                       "1" "$rc"
chk "…and nothing was recorded"                   "" "$(pnl_portal_host)"

unset -f count pcount

printf '
  %d passed, %d failed

' "$pass" "$fail"
[ "$fail" -eq 0 ]
