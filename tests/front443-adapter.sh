#!/usr/bin/env bash
#
# tests/front443-adapter.sh — the certificate adapter's side of the shared-443
# front (docs/security-model.md §6C.8, S2), checked without a daemon.
#
# The one property that matters most is the one nothing on a host would
# report: with the front on, the CLIENT FILE must not change. The client dials
# <endpoint> 443 either way; only the server's own bind moves to loopback. A
# profile that came out different would still connect on a fresh install and
# would silently strand every profile issued before the front went on — the
# private keys in those are erased after hand-off, so they cannot be rebuilt.
# The first group here builds the same credential's profile with the front off
# and on and requires the bytes to be identical.
#
# The rest is what the adapter decides on its own, lifted out of the shipped
# file and evaluated against stubs rather than re-typed:
#
#   · the server render moves to `local 127.0.0.1` / `port <local_port>` and
#     nowhere else, and refuses a front on the wrong transport;
#   · the filtering LEVEL does not move — the front is port sharing, not probe
#     resistance, and must not be presented as such;
#   · the offer accepts exactly `nginx`, unattended through VPN55_OVPN_FRONT,
#     and records the choice so a re-run does not ask again;
#   · the loopback port may move until the front is installed against it and
#     not after, and may never be 443;
#   · _status's note records carry the loopback fact always, and one record
#     per broken invariant with its repair, at the severity the design states.
#
# Nothing here starts a process or writes outside one mktemp directory.

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
export VPN55_OVPN_PUB="$WORK/pub" VPN55_OVPN_LOG_DIR="$WORK/log" VPN55_OVPN_RUN_DIR="$WORK/run"
unset VPN55_OVPN_FRONT VPN55_OVPN_LOCAL_PORT
mkdir -p "$VPN55_ETC" "$WORK/pki"

# shellcheck source=../lib/ui.sh
. lib/ui.sh
# shellcheck source=../lib/core_fs.sh
. lib/core_fs.sh
# The adapter under test. Sourced by path so its registration guard sees no
# registry and stays quiet.
# shellcheck source=../lib/proto_openvpn.sh
. lib/proto_openvpn.sh

# ─── Collaborators the adapter reads, as stubs ───────────────────────────────
printf -- '-----BEGIN CERTIFICATE-----\nCA\n-----END CERTIFICATE-----\n'   > "$WORK/pki/ca.crt"
printf -- '-----BEGIN CERTIFICATE-----\nCRED\n-----END CERTIFICATE-----\n' > "$WORK/pki/cred.crt"
printf -- '-----BEGIN PRIVATE KEY-----\nKEY\n-----END PRIVATE KEY-----\n'  > "$WORK/pki/cred.key"
pki_ca_path()   { printf '%s/ca.crt' "$WORK/pki"; }
pki_cert_path() { printf '%s/%s.crt' "$WORK/pki" "${1:-}"; }
pki_key_path()  { printf '%s/%s.key' "$WORK/pki" "${1:-}"; }
net_endpoints_all()   { printf '%s\n' "${1:-}"; }
net_endpoints_count() { printf '0'; }
net_pool_subnet()     { printf '10.8.1.0/24'; }

# The front engine's public verbs, replaced per group below. Defining all three
# is what makes _ovpn_front_lib_loaded answer yes.
front443_install()   { return 0; }
front443_remove()    { return 0; }
front443_check()     { printf 'ok\n'; return 0; }
front443_installed() { [ -f "$WORK/front.ledger" ]; }
front443_available() { return 0; }
front443_holder_is_nginx() { [ -f "$WORK/holder_nginx" ]; }
front443_scan()      { cat "$WORK/scan" 2>/dev/null; return 0; }
_ovpn_active()       { [ -f "$WORK/active" ]; }

# A settled server: tcp on 443, the shared control-channel key form so no
# daemon is needed to mint a per-client one.
_ovpn_state_dir || exit 1
_ovpn_set transport tcp
_ovpn_set port 443
_ovpn_set endpoint vpn.example
_ovpn_set reneg_seconds 3600
_ovpn_set tls_mode crypt
_ovpn_set unit 'unit@vpn55.service'
_ovpn_set confdir "$WORK/confdir"
# The control-channel key is only ever read back with cat, so its content is
# free — and it is kept out of the leak sweep's vocabulary on purpose.
printf -- '-----BEGIN Static key V1-----\nabc\n-----END Static key V1-----\n' > "$(_ovpn_tls_key)"

# ─── 1. The client file is byte-identical with and without the front ─────────
group "client profile — byte-identical with and without the front"
before="$(_ovpn_build_profile cred)"; rc_b=$?
chk "profile builds without the front" 0 "$rc_b"
printf '%s\n' "$before" > "$WORK/profile.before"

_ovpn_set front nginx
_ovpn_set local_port 1194
after="$(_ovpn_build_profile cred)"; rc_a=$?
chk "profile builds with the front" 0 "$rc_a"
printf '%s\n' "$after" > "$WORK/profile.after"

if cmp -s "$WORK/profile.before" "$WORK/profile.after"; then same=1; else same=0; fi
chk "the two profiles are the same bytes" 1 "$same"
chk "the profile dials the public port" "remote vpn.example 443" "$(grep '^remote ' "$WORK/profile.after")"
chk "the profile is the client end of tcp" "proto tcp-client" "$(grep '^proto ' "$WORK/profile.after")"
chk "the loopback port appears nowhere in the profile" 0 "$(grep -c '1194' "$WORK/profile.after")"
chk "the profile never says 'local'" 0 "$(grep -c '^local ' "$WORK/profile.after")"

# ─── 2. The server render moves to loopback, and only there ──────────────────
group "server render"
_ovpn_set front ''
_ovpn_set local_port ''
conf_off="$(_ovpn_render_conf)"; rc=$?
chk "renders without the front" 0 "$rc"
chk "  binds the public port" 1 "$(printf '%s\n' "$conf_off" | grep -c '^port 443$')"
chk "  no 'local' line" 0 "$(printf '%s\n' "$conf_off" | grep -c '^local ')"
chk "  proto tcp" 1 "$(printf '%s\n' "$conf_off" | grep -c '^proto tcp$')"

_ovpn_set front nginx
_ovpn_set local_port 1194
conf_on="$(_ovpn_render_conf)"; rc=$?
chk "renders with the front" 0 "$rc"
chk "  local 127.0.0.1" 1 "$(printf '%s\n' "$conf_on" | grep -c '^local 127\.0\.0\.1$')"
chk "  port is the loopback port" 1 "$(printf '%s\n' "$conf_on" | grep -c '^port 1194$')"
chk "  the public port is not bound" 0 "$(printf '%s\n' "$conf_on" | grep -c '^port 443$')"
chk "  proto tcp" 1 "$(printf '%s\n' "$conf_on" | grep -c '^proto tcp$')"
chk "  exactly one port line" 1 "$(printf '%s\n' "$conf_on" | grep -c '^port ')"

# Everything after the bind lines is untouched: strip the lines that are
# allowed to differ and the two renders must agree.
norm() { grep -vE '^(local |port |proto |#)' | grep -v '^$'; }
if [ "$(printf '%s\n' "$conf_off" | norm)" = "$(printf '%s\n' "$conf_on" | norm)" ]; then same=1; else same=0; fi
chk "  every other directive is identical" 1 "$same"

_ovpn_set local_port 'x'
_ovpn_render_conf >/dev/null 2>&1; rc=$?
chk "a front with no numeric loopback port refuses to render" 1 "$rc"
_ovpn_set local_port 1194
_ovpn_set transport udp
_ovpn_render_conf >/dev/null 2>&1; rc=$?
chk "a front on udp refuses to render" 1 "$rc"
_ovpn_set transport tcp

# ─── 3. Accessors ────────────────────────────────────────────────────────────
group "accessors"
chk "_ovpn_front_on with the front" 0 "$(_ovpn_front_on; printf '%s' $?)"
chk "_ovpn_bind_port is the loopback port with the front" 1194 "$(_ovpn_bind_port)"
chk "_ovpn_port is still what clients dial" 443 "$(_ovpn_port)"
_ovpn_set front ''
chk "_ovpn_front_on without the front" 1 "$(_ovpn_front_on; printf '%s' $?)"
chk "_ovpn_bind_port is the public port without the front" 443 "$(_ovpn_bind_port)"
_ovpn_set front nginx

# ─── 4. The filtering level does not move ────────────────────────────────────
group "filtering level"
level_on="$(vpn_openvpn_capabilities | awk -F'\t' '$1 == "filtering" { print $2 }')"
_ovpn_set front ''
level_off="$(vpn_openvpn_capabilities | awk -F'\t' '$1 == "filtering" { print $2 }')"
chk "resistant without the front (tcp/443)" resistant "$level_off"
chk "resistant with the front — not a rung higher, not lower" resistant "$level_on"
chk "no option record claims the front" 0 "$(vpn_openvpn_capabilities | awk -F'\t' '$1 == "option"' | grep -c .)"

# ─── 5. The loopback port ────────────────────────────────────────────────────
group "loopback port"
_ovpn_set front nginx
_ovpn_set local_port ''
rm -f "$WORK/front.ledger"
_ovpn_local_port_settle >/dev/null 2>&1; rc=$?
chk "settles to the default when nothing is set" "0 1194" "$rc $(_ovpn_local_port)"
VPN55_OVPN_LOCAL_PORT=2194 _ovpn_local_port_settle >/dev/null 2>&1; rc=$?
chk "the environment moves it while the front is not installed" "0 2194" "$rc $(_ovpn_local_port)"
: > "$WORK/front.ledger"
VPN55_OVPN_LOCAL_PORT=3194 _ovpn_local_port_settle >/dev/null 2>&1; rc=$?
chk "and cannot move it once the front is installed" "1 2194" "$rc $(_ovpn_local_port)"
VPN55_OVPN_LOCAL_PORT=2194 _ovpn_local_port_settle >/dev/null 2>&1; rc=$?
chk "the same value re-settles fine with the front installed" "0 2194" "$rc $(_ovpn_local_port)"
rm -f "$WORK/front.ledger"
VPN55_OVPN_LOCAL_PORT=443 _ovpn_local_port_settle >/dev/null 2>&1; rc=$?
chk "443 is refused — that is the front's port" 1 "$rc"
VPN55_OVPN_LOCAL_PORT=abc _ovpn_local_port_settle >/dev/null 2>&1; rc=$?
chk "a non-number is refused" 1 "$rc"
VPN55_OVPN_LOCAL_PORT=70000 _ovpn_local_port_settle >/dev/null 2>&1; rc=$?
chk "out of range is refused" 1 "$rc"
chk "  and none of those touched the record" 2194 "$(_ovpn_local_port)"
_ovpn_set local_port 1194

# ─── 6. The offer ────────────────────────────────────────────────────────────
# stdin is never a terminal here, so ask_value answers with its default — which
# is VPN55_OVPN_FRONT. That is the unattended contract under test.
group "the offer, unattended"
printf 'listen\t/etc/nginx/sites-enabled/site-a\t7\t443\tssl http2\t1\nlisten\t/etc/nginx/sites-enabled/site-b\t3\t*:443\tssl\t0\n' > "$WORK/scan"
_ovpn_set front ''
_ovpn_set local_port ''
rm -f "$WORK/holder_nginx"

_ovpn_front_offer nginx tcp 443 </dev/null >/dev/null 2>&1; rc=$?
chk "holder not nginx → not offered" 1 "$rc"
chk "  nothing recorded" "" "$(_ovpn_front)"

: > "$WORK/holder_nginx"
_ovpn_front_offer nginx udp 1194 </dev/null >/dev/null 2>&1; rc=$?
chk "udp/1194 → not offered even with nginx on 443" 1 "$rc"
_ovpn_front_offer nginx tcp 8443 </dev/null >/dev/null 2>&1; rc=$?
chk "tcp/8443 → not offered; the front takes 443 only" 1 "$rc"

out="$(_ovpn_front_offer nginx tcp 443 </dev/null 2>&1)"; rc=$?
chk "VPN55_OVPN_FRONT unset → declined" 1 "$rc"
chk "  nothing recorded" "" "$(_ovpn_front)"
chk "  the vhosts were listed by name" 1 "$(printf '%s\n' "$out" | grep -c 'sites-enabled/site-b')"
chk "  the real_ip_header vhost is flagged" 1 "$(printf '%s\n' "$out" | grep -c 'site-a.*real_ip_header')"
chk "  the peers-as-loopback cost is stated" 1 "$(printf '%s\n' "$out" | grep -c '127\.0\.0\.1\. Status output')"
chk "  the availability cost is stated" 1 "$(printf '%s\n' "$out" | grep -c "nginx is now part of the tunnel's availability")"

VPN55_OVPN_FRONT=yes _ovpn_front_offer nginx tcp 443 </dev/null >/dev/null 2>&1; rc=$?
chk "VPN55_OVPN_FRONT=yes → declined (only 'nginx' accepts)" 1 "$rc"
chk "  nothing recorded" "" "$(_ovpn_front)"

front443_available() { error "fake: no stream module"; return 1; }
VPN55_OVPN_FRONT=nginx _ovpn_front_offer nginx tcp 443 </dev/null >/dev/null 2>&1; rc=$?
chk "host cannot carry the front → declined even when accepted" 1 "$rc"
chk "  nothing recorded" "" "$(_ovpn_front)"
front443_available() { return 0; }

VPN55_OVPN_FRONT=nginx _ovpn_front_offer nginx tcp 443 </dev/null >/dev/null 2>&1; rc=$?
chk "VPN55_OVPN_FRONT=nginx → accepted" 0 "$rc"
chk "  front recorded" nginx "$(_ovpn_front)"
chk "  loopback port recorded at its default" 1194 "$(_ovpn_local_port)"

_ovpn_set front ''
_ovpn_set local_port ''
VPN55_OVPN_FRONT=nginx VPN55_OVPN_LOCAL_PORT=2194 _ovpn_front_offer nginx tcp 443 </dev/null >/dev/null 2>&1; rc=$?
chk "accepted with a chosen loopback port" "0 2194" "$rc $(_ovpn_local_port)"

printf 'realip\t/etc/nginx/nginx.conf\t12\thttp\n' >> "$WORK/scan"
out="$(VPN55_OVPN_FRONT=nginx _ovpn_front_offer nginx tcp 443 </dev/null 2>&1)"
chk "an http-level real_ip_header is named before the question" 1 "$(printf '%s\n' "$out" | grep -c 'nginx.conf:12')"

# ─── 6b. Off the record: VPN55_OVPN_FRONT=no on a re-run ─────────────────────
# A restore carries `front=nginx` onto a host that may have no nginx; the
# same answer that declines the offer takes the service off the record — but
# only where the front is not on this host, and never by a refusal.
group "off the record"
_ovpn_set front nginx
_ovpn_set local_port 1194
rm -f "$WORK/front.ledger"
chk "wanted: the record and VPN55_OVPN_FRONT=no" 0 "$(VPN55_OVPN_FRONT=no _ovpn_front_drop_wanted; printf '%s' $?)"
chk "not wanted without the variable" 1 "$(_ovpn_front_drop_wanted; printf '%s' $?)"
chk "not wanted with VPN55_OVPN_FRONT=nginx" 1 "$(VPN55_OVPN_FRONT=nginx _ovpn_front_drop_wanted; printf '%s' $?)"
chk "not wanted with VPN55_OVPN_FRONT=yes (only 'no' is the word)" 1 "$(VPN55_OVPN_FRONT=yes _ovpn_front_drop_wanted; printf '%s' $?)"
_ovpn_set front ''
chk "not wanted with no record to drop" 1 "$(VPN55_OVPN_FRONT=no _ovpn_front_drop_wanted; printf '%s' $?)"
_ovpn_set front nginx

: > "$WORK/front.ledger"
out="$(_ovpn_front_drop_allowed 2>&1)"; rc=$?
chk "refused while the front is installed" 1 "$rc"
chk "  naming the remove verb" 1 "$(printf '%s\n' "$out" | grep -c 'vpn55.sh --front443-remove')"
chk "  the record is untouched" nginx "$(_ovpn_front)"
rm -f "$WORK/front.ledger"
front443_traces_present() { return 0; }
out="$(_ovpn_front_drop_allowed 2>&1)"; rc=$?
chk "refused while the front's traces remain without a ledger" 1 "$rc"
chk "  naming the remove verb" 1 "$(printf '%s\n' "$out" | grep -c 'vpn55.sh --front443-remove')"
front443_traces_present() { return 1; }
chk "allowed with neither" 0 "$(_ovpn_front_drop_allowed >/dev/null 2>&1; printf '%s' $?)"
unset -f front443_install
chk "refused when the engine is not loaded" 1 "$(_ovpn_front_drop_allowed >/dev/null 2>&1; printf '%s' $?)"
front443_install() { return 0; }

_ovpn_front_drop >/dev/null 2>&1; rc=$?
chk "the drop succeeds" 0 "$rc"
chk "  the record is gone" "" "$(_ovpn_front)"
chk "  the service binds the public port again" 443 "$(_ovpn_bind_port)"
chk "  the loopback port record is left (harmless, and re-usable)" 1194 "$(_ovpn_local_port)"
chk "  the failure text names the way off" 1 "$(_ovpn_set front nginx; _ovpn_cred_ids() { printf 'c1\n'; }; _ovpn_front_failed 2>&1 | grep -c 'VPN55_OVPN_FRONT=no'; unset -f _ovpn_cred_ids)"
_ovpn_set front nginx

# ─── 6c. The offer through the guided setup: setup_ask ───────────────────────
# Setup runs every install with stdin closed, so the offer above would be
# answered "no" by /dev/null without ever being shown. The verb asks the same
# question WITH the terminal, before the installs, and hands the answer on
# through VPN55_OVPN_FRONT — after which the offer must not replay the text at
# a closed stdin, and must still record the accepted choice.
group "the offer through setup (setup_ask)"
distro_require_root() { return 0; }
_ovpn_port_conflict() { [ -f "$WORK/conflict" ] || return 1; printf 'nginx'; }
printf 'listen	/etc/nginx/sites-enabled/site-b	3	*:443	ssl	0
' > "$WORK/scan"
_ovpn_set front ''
_ovpn_set local_port ''
: > "$WORK/holder_nginx"
: > "$WORK/conflict"
unset VPN55_OVPN_FRONT VPN55_OVPN_FRONT_ASKED

chk "expected transport reads the stored tcp/443" "$(printf 'tcp	443')" "$(_ovpn_transport_expected)"
chk "  VPN55_OVPN_PORT moves the expected port" "$(printf 'tcp	8443')" "$(VPN55_OVPN_PORT=8443 _ovpn_transport_expected)"
_ovpn_set transport ''; _ovpn_set port ''
chk "  unstored → the bootstrap's tcp443 default" "$(printf 'tcp	443')" "$(_ovpn_transport_expected)"
chk "  unstored + VPN55_OVPN_TRANSPORT=udp → udp/1194" "$(printf 'udp	1194')" "$(VPN55_OVPN_TRANSPORT=udp _ovpn_transport_expected)"
chk "  a transport the bootstrap refuses → 1" 1 "$(VPN55_OVPN_TRANSPORT=sctp _ovpn_transport_expected >/dev/null; printf '%s' $?)"
_ovpn_set transport tcp; _ovpn_set port 443

# The terminal, simulated: ask_value reads stdin only when ui_interactive says
# there is one, so say so and feed the answer on stdin.
ui_interactive() { return 0; }

out="$(VPN55_OVPN_FRONT=nginx vpn_openvpn_setup_ask <<< "no" 2>&1)"; rc=$?
chk "an answer already in the environment is not re-asked" "0 0" "$rc $(printf '%s
' "$out" | grep -c 'Share port')"
_ovpn_set front nginx
out="$(vpn_openvpn_setup_ask <<< "no" 2>&1)"; rc=$?
chk "a recorded front is not re-asked" "0 0" "$rc $(printf '%s
' "$out" | grep -c 'Share port')"
_ovpn_set front ''
rm -f "$WORK/conflict"
out="$(vpn_openvpn_setup_ask <<< "no" 2>&1)"; rc=$?
chk "a free port asks nothing" "0 0" "$rc $(printf '%s
' "$out" | grep -c 'Share port')"
: > "$WORK/conflict"
out="$(VPN55_OVPN_PORT=8443 vpn_openvpn_setup_ask <<< "no" 2>&1)"; rc=$?
chk "a run moved off 443 asks nothing" "0 0" "$rc $(printf '%s
' "$out" | grep -c 'Share port')"
rm -f "$WORK/holder_nginx"
out="$(vpn_openvpn_setup_ask <<< "no" 2>&1)"; rc=$?
chk "a holder that is not nginx asks nothing (install refuses, as before)" "0 0" "$rc $(printf '%s
' "$out" | grep -c 'Share port')"
: > "$WORK/holder_nginx"

# Asked, and typed 'nginx'. The verb runs in THIS shell so its exports land here.
out="$(vpn_openvpn_setup_ask <<< "nginx" 2>&1; printf 'rc=%s front=%s asked=%s' "$?" "${VPN55_OVPN_FRONT:-}" "${VPN55_OVPN_FRONT_ASKED:-}")"
chk "asked with a terminal, 'nginx' typed → handed on" 1 "$(printf '%s
' "$out" | grep -c 'rc=0 front=nginx asked=1')"
chk "  the costs were shown first" 1 "$(printf '%s
' "$out" | grep -c 'sites-enabled/site-b')"
chk "  the question itself was shown" 1 "$(printf '%s
' "$out" | grep -c 'Share port 443 through nginx')"
chk "  nothing recorded yet — that is the install's job" "" "$(_ovpn_front)"

out="$(vpn_openvpn_setup_ask <<< "" 2>&1; printf 'rc=%s front=%s asked=%s' "$?" "${VPN55_OVPN_FRONT:-}" "${VPN55_OVPN_FRONT_ASKED:-}")"
chk "a bare Enter declines — sharing takes a typed answer" 1 "$(printf '%s
' "$out" | grep -c 'rc=0 front=no asked=1')"
chk "  and says what the install will now do" 1 "$(printf '%s
' "$out" | grep -c 'will refuse tcp/443')"

ui_interactive() { [[ -t 0 ]]; }

# Then the install's offer, at the closed stdin setup gives it.
export VPN55_OVPN_FRONT=nginx VPN55_OVPN_FRONT_ASKED=1
out="$(_ovpn_front_offer nginx tcp 443 </dev/null 2>&1)"; rc=$?
chk "the offer accepts the setup answer unattended" 0 "$rc"
chk "  and records it" nginx "$(_ovpn_front)"
chk "  without replaying the cost list" 0 "$(printf '%s
' "$out" | grep -c 'sites-enabled/site-b')"
chk "  saying where the answer came from" 1 "$(printf '%s
' "$out" | grep -c 'answered at setup')"
_ovpn_set front ''
rm -f "$WORK/holder_nginx"
_ovpn_front_offer nginx tcp 443 </dev/null >/dev/null 2>&1; rc=$?
chk "  the host checks still run under an asked answer" 1 "$rc"
chk "  nothing recorded" "" "$(_ovpn_front)"
: > "$WORK/holder_nginx"
export VPN55_OVPN_FRONT=no
_ovpn_front_offer nginx tcp 443 </dev/null >/dev/null 2>&1; rc=$?
chk "a declined setup answer is declined by the offer" 1 "$rc"
unset VPN55_OVPN_FRONT VPN55_OVPN_FRONT_ASKED
rm -f "$WORK/conflict"
_ovpn_set front nginx
_ovpn_set local_port 1194

# ─── 7. Status notes ─────────────────────────────────────────────────────────
group "status notes"
_ovpn_set front ''
chk "no front → no front note" "" "$(_ovpn_front_notes)"

_ovpn_set front nginx
_ovpn_set local_port 1194
front443_check() { printf 'ok\n'; return 0; }
notes="$(_ovpn_front_notes)"
chk "front ok → exactly one record" 1 "$(printf '%s\n' "$notes" | grep -c .)"
chk "  it is a note" note "$(printf '%s\n' "$notes" | cut -f1)"
chk "  tagged with the adapter" "$VPN55_OVPN_TAG" "$(printf '%s\n' "$notes" | cut -f2)"
chk "  severity info" info "$(printf '%s\n' "$notes" | cut -f3)"
chk "  says peers are 127.0.0.1" 1 "$(printf '%s\n' "$notes" | cut -f4 | grep -c '127\.0\.0\.1')"
chk "  four fields, no stray tab in the sentence" 4 "$(printf '%s\n' "$notes" | awk -F'\t' '{ print NF }')"

front443_check() { printf 'off\n'; return 2; }
notes="$(_ovpn_front_notes)"
chk "front recorded but off → info + crit" "info crit" "$(printf '%s\n' "$notes" | cut -f3 | paste -sd' ' -)"
chk "  the repair is a re-install" 1 "$(printf '%s\n' "$notes" | grep -c 'Re-run the install')"
chk "  or the way off the record" 1 "$(printf '%s\n' "$notes" | grep -c 'VPN55_OVPN_FRONT=no')"

front443_check() {
    printf 'broken\tvhost\t/etc/nginx/sites-enabled/new:9 listens on the public 443 (443)\tvpn55.sh --front443-repair\n'
    printf 'broken\tbackend\tnothing holds 127.0.0.1:1194\tstart the service that listens there\n'
    return 1
}
rm -f "$WORK/active"
notes="$(_ovpn_front_notes)"
chk "broken, service stopped → info, crit (vhost), warn (backend)" "info crit warn" \
    "$(printf '%s\n' "$notes" | cut -f3 | paste -sd' ' -)"
chk "  the vhost record names the repair command" 1 "$(printf '%s\n' "$notes" | grep -c 'Repair: vpn55.sh --front443-repair')"
chk "  the backend record names its own repair" 1 "$(printf '%s\n' "$notes" | grep -c 'Repair: start the service that listens there')"
chk "  every record has four fields" "4 4 4" "$(printf '%s\n' "$notes" | awk -F'\t' '{ print NF }' | paste -sd' ' -)"
: > "$WORK/active"
notes="$(_ovpn_front_notes)"
chk "broken, service running → the backend record is crit too" "info crit crit" \
    "$(printf '%s\n' "$notes" | cut -f3 | paste -sd' ' -)"

unset -f front443_install
notes="$(_ovpn_front_notes)"
chk "engine not loaded → info + warn, never silence" "info warn" "$(printf '%s\n' "$notes" | cut -f3 | paste -sd' ' -)"
front443_install() { return 0; }

# ─── 8. The whole status stream stays well-formed with the front on ──────────
group "status stream shape"
_ovpn_installed() { return 0; }
distro_service_is_enabled() { return 0; }
distro_has_systemd() { return 1; }
pki_crl_expires_in() { printf '2592000'; }
_ovpn_spool_sweep() { return 0; }
front443_check() { printf 'ok\n'; return 0; }
stream="$(vpn_openvpn_status)"
chk "every record's first field is a known type" "" \
    "$(printf '%s\n' "$stream" | cut -f1 | grep -vE '^(service|cred|note)$')"
chk "the service record advertises what clients dial" "tcp/443" \
    "$(printf '%s\n' "$stream" | awk -F'\t' '$1 == "service" { print $5 }')"
chk "the loopback note is in the stream" 1 \
    "$(printf '%s\n' "$stream" | awk -F'\t' '$1 == "note"' | grep -c 'arrives from 127\.0\.0\.1')"

printf '\n%d passed, %d failed\n' "$pass" "$fail"
[ "$fail" -eq 0 ]
