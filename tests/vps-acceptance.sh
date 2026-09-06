#!/usr/bin/env bash
#
# tests/vps-acceptance.sh — the launch gate.
#
# Runs on a THROWAWAY VPS, as root, and answers the three questions a release
# has to answer before anyone is told a distribution is supported:
#
#   1. Does installing twice more change anything?  (idempotency)
#   2. Does uninstalling put the host back?         (reversal)
#   3. Is the box still on the network afterwards?  (the one that ends a job)
#   4. Would the rules survive a reboot?            (see `persistence` below)
#   5. Can the host be rebuilt after it is lost?    (see `backup_restore`)
#
# Question 5 is the newest and the least like the others: it is not about
# leaving the host alone, it is about whether the certificate authority and the
# register can come back onto a DIFFERENT machine. A backup nobody restored is
# not a backup, so the stage takes one, moves the real state aside, restores,
# and then SIGNS a certificate with the restored authority — because an archive
# that restores files but not a usable signing key passes every file comparison
# and fails the only thing it exists for.
#
# ── Why this is a script and not a checklist ─────────────────────────────────
# A VPN teardown touches NAT, routing and the firewall. The failure mode is not
# a stack trace, it is a machine that stops answering — and it is invisible to
# the person running the test, because their own session is already established
# and keeps working while every new connection is dropped. So the host is
# snapshotted before anything happens and compared byte for byte afterwards,
# and connectivity is re-probed after every single step rather than at the end.
#
# ── What it does NOT do ──────────────────────────────────────────────────────
# It does not connect a client and pass traffic. A tunnel that installs
# reversibly is not a tunnel that works, and nothing here claims otherwise:
# a green run means the host is left as it was found, not that anyone can
# connect. Client-side verification is a manual step and stays one.
#
# It does not reboot, because the run would end. `persistence` decides the
# question a reboot would answer — whether what is live has been written down —
# without needing one. A real reboot remains a manual step, and it is the only
# way to settle unit ORDERING as opposed to unit existence.
#
# It cannot prove a new inbound connection would be accepted. `connectivity`
# says exactly what it can and cannot see, in place, rather than implying more.
#
# ── Usage ────────────────────────────────────────────────────────────────────
#   ./tests/vps-acceptance.sh --yes-destroy-this-host
#   ./tests/vps-acceptance.sh --yes-destroy-this-host --only <tag>
#   ./tests/vps-acceptance.sh --yes-destroy-this-host --out /root/acc
#
# Exit codes:  0 every check passed · 1 a check failed · 2 it could not run
#
set -uo pipefail

TESTS_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(cd -- "$TESTS_DIR/.." && pwd)"
INSTALLER="$REPO_DIR/vpn55.sh"

OUT_DIR="${VPN55_ACC_OUT:-/var/tmp/vpn55-acceptance}"
ONLY_TAG=""
DESTRUCTIVE=0

PASS=0
FAIL=0
WARN=0

# ─── Output ───────────────────────────────────────────────────────────────────
# Deliberately not lib/ui.sh: this file has to be runnable against a tree that
# is mid-uninstall, and a test harness that depends on the thing under test
# reports a green run when the thing under test has been deleted.
say()  { printf '\n\033[1m== %s\033[0m\n' "$*"; }
note() { printf '   %s\n' "$*"; }
ok()   { PASS=$(( PASS + 1 )); printf '   \033[32mPASS\033[0m  %s\n' "$*"; }
bad()  { FAIL=$(( FAIL + 1 )); printf '   \033[31mFAIL\033[0m  %s\n' "$*"; }
soft() { WARN=$(( WARN + 1 )); printf '   \033[33mWARN\033[0m  %s\n' "$*"; }
fatal() { printf '\n\033[31mCANNOT RUN:\033[0m %s\n' "$*" >&2; exit 2; }

# ─── Arguments ────────────────────────────────────────────────────────────────
while [ $# -gt 0 ]; do
    case "$1" in
        --yes-destroy-this-host) DESTRUCTIVE=1 ;;
        --only) ONLY_TAG="${2:-}"; shift ;;
        --out)  OUT_DIR="${2:-}";  shift ;;
        -h|--help)
            sed -n '2,32p' "$0" | sed 's/^# \{0,1\}//'
            exit 0 ;;
        *) fatal "unknown argument '$1'" ;;
    esac
    shift
done

# ─── Preflight ────────────────────────────────────────────────────────────────
[ "$(id -u)" = "0" ] || fatal "run as root."
[ -x "$INSTALLER" ] || [ -f "$INSTALLER" ] || fatal "no installer at $INSTALLER"

if [ "$DESTRUCTIVE" != "1" ]; then
    cat >&2 <<'REFUSE'
This installs and removes VPN services, rewrites NAT and firewall rules, and
restarts daemons. On a host anyone depends on, that is an outage.

Run it on a VPS you are willing to lose, and say so:

    ./tests/vps-acceptance.sh --yes-destroy-this-host
REFUSE
    exit 2
fi

for tool in ip ss awk sed sort diff; do
    command -v "$tool" >/dev/null 2>&1 || fatal "missing '$tool' — cannot snapshot this host."
done

mkdir -p "$OUT_DIR" || fatal "cannot create $OUT_DIR"
RUN_LOG="$OUT_DIR/run.log"
: > "$RUN_LOG" || fatal "cannot write $RUN_LOG"

# Unattended: every confirmation in the installer would otherwise decline,
# which would make the whole run pass by doing nothing at all.
export VPN55_ASSUME_YES=1

# ─── Host snapshot ────────────────────────────────────────────────────────────
# One directory per snapshot, one file per fact, so a diff points at WHICH fact
# changed instead of producing one unreadable blob.
#
# Volatile fields are stripped, not tolerated. Counters, PIDs, uptimes and
# handshake ages change on their own between two snapshots taken a minute apart,
# and a diff that is never empty is a diff nobody reads — which is the same as
# not having taken it.
_scrub() {
    sed -E \
        -e 's/packets [0-9]+ bytes [0-9]+/packets N bytes N/g' \
        -e 's/\[[0-9]+:[0-9]+\]/[N:N]/g' \
        -e 's/pid=[0-9]+/pid=N/g' \
        -e 's/users:\(\(.*\)\)/users:(SCRUBBED)/g' \
        -e 's/# Generated by .*/# Generated by SCRUBBED/' \
        -e 's/^# (Completed|Warning|Table).*/# SCRUBBED/' \
        -e 's/[0-9]{4}-[0-9]{2}-[0-9]{2}[T ][0-9]{2}:[0-9]{2}:[0-9]{2}/TIMESTAMP/g' \
        -e 's/handle [0-9]+/handle N/g'
}

# _capture <snapshot dir> <name> <command…>
#
# Sorted, so a set-shaped fact (a package list, a unit list) does not diff
# merely because its order changed.
_capture() {
    local dir="$1" name="$2"
    shift 2
    { "$@" 2>/dev/null || true; } | _scrub | LC_ALL=C sort > "$dir/$name" 2>/dev/null || true
}

# _capture_ordered — same, and NOT sorted.
#
# ⚠ For a firewall, ORDER IS THE FACT. A rule that lands before the accept rule
# it was supposed to follow is the single worst outcome this project has, and
# sorting the ruleset makes it produce a byte-identical file — so the check that
# exists to catch it was structurally incapable of catching it. Counters and
# handles are still scrubbed, which is what made sorting look necessary; they
# were the only genuinely volatile part.
_capture_ordered() {
    local dir="$1" name="$2"
    shift 2
    { "$@" 2>/dev/null || true; } | _scrub > "$dir/$name" 2>/dev/null || true
}

# The firewall's DEFAULT VERDICT — the one fact a lockout is actually made of,
# read the same way from a snapshot and from a live connectivity check so the
# two can never disagree about what they are looking at.
_fw_policy_now() {
    {
        if command -v ufw >/dev/null 2>&1; then
            ufw status verbose 2>/dev/null | sed -n 's/^Default: /ufw-default: /p'
        fi
        if command -v firewall-cmd >/dev/null 2>&1; then
            printf 'firewalld-default-zone=%s\n' "$(firewall-cmd --get-default-zone 2>/dev/null || printf '?')"
            printf 'firewalld-target=%s\n' "$(firewall-cmd --permanent --get-target 2>/dev/null || printf '?')"
        fi
        if command -v nft >/dev/null 2>&1; then
            nft list ruleset 2>/dev/null | awk '/type filter hook (input|forward)/ { $1=$1; print }'
        fi
        if command -v iptables >/dev/null 2>&1; then
            iptables -S 2>/dev/null | awk '/^-P /'
        fi
    } 2>/dev/null | LC_ALL=C sort
}

snapshot() {
    local label="$1" dir="$OUT_DIR/snap-$1"
    rm -rf "$dir" || true
    mkdir -p "$dir" || { bad "cannot create snapshot dir $dir"; return 1; }

    _capture "$dir" links        ip -o link show
    _capture "$dir" addrs        ip -o addr show
    _capture "$dir" routes4      ip -4 route show
    _capture "$dir" routes6      ip -6 route show
    _capture "$dir" rules        ip rule show
    _capture "$dir" sysctl       sysctl net.ipv4.ip_forward net.ipv6.conf.all.forwarding
    _capture "$dir" listeners    ss -lntup
    _capture "$dir" units_enabled systemctl list-unit-files --state=enabled --no-legend --no-pager
    _capture "$dir" units_running systemctl list-units --type=service --state=running --no-legend --no-pager

    # Firewall state, from whichever backends exist. Each is captured
    # separately: a rule that moved from one backend to another is a real
    # finding and a single merged file would hide it.
    if command -v nft >/dev/null 2>&1;            then _capture_ordered "$dir" fw_nft  nft list ruleset; fi
    if command -v iptables-save >/dev/null 2>&1;  then _capture_ordered "$dir" fw_ipt  iptables-save; fi
    if command -v ip6tables-save >/dev/null 2>&1; then _capture_ordered "$dir" fw_ipt6 ip6tables-save; fi
    if command -v ufw >/dev/null 2>&1;            then _capture_ordered "$dir" fw_ufw  ufw status verbose; fi
    if command -v firewall-cmd >/dev/null 2>&1;   then _capture_ordered "$dir" fw_fwd  firewall-cmd --list-all-zones; fi

    # The default verdict, captured on its own so it can be asserted rather than
    # merely diffed. Buried in a hundred-line ruleset diff nobody reads it; on
    # its own line, a change is unmissable.
    _fw_policy_now > "$dir/fw_policy" 2>/dev/null || true

    # Files VPN55 is allowed to own. Names and modes only — contents change on
    # every run by design (keys, leases), and diffing them would drown the
    # signal that matters here, which is what was LEFT BEHIND.
    { find /etc/vpn55 /var/lib/vpn55 /var/log/vpn55 -printf '%M %p\n' 2>/dev/null || true; } \
        | LC_ALL=C sort > "$dir/vpn55_files" 2>/dev/null || true
    { find /etc/systemd/system -name '*vpn55*' -o -name '*.d' -type d 2>/dev/null || true; } \
        | LC_ALL=C sort > "$dir/units_files" 2>/dev/null || true

    if command -v dpkg-query >/dev/null 2>&1; then
        { dpkg-query -W -f='${binary:Package}\n' 2>/dev/null || true; } | LC_ALL=C sort > "$dir/packages"
    elif command -v rpm >/dev/null 2>&1; then
        { rpm -qa --qf '%{NAME}\n' 2>/dev/null || true; } | LC_ALL=C sort > "$dir/packages"
    elif command -v pacman >/dev/null 2>&1; then
        { pacman -Qq 2>/dev/null || true; } | LC_ALL=C sort > "$dir/packages"
    fi

    note "snapshot: $label"
    return 0
}

# diff_snapshots <a> <b> <report file> — prints nothing, returns 1 on difference
#
# ⚠ The file list is the UNION of both snapshots, not just the first one's.
# Iterating only over `a` meant a fact that appeared during the run was
# invisible: install ufw on a host that had none and `fw_ufw` exists in the
# final snapshot and in no baseline, so a whole new firewall backend could
# arrive and the reversal check would report the host unchanged.
diff_snapshots() {
    local a="$OUT_DIR/snap-$1" b="$OUT_DIR/snap-$2" report="$3" rc=0 f name
    : > "$report" || return 1

    local names
    names="$( { ls -1 "$a" 2>/dev/null; ls -1 "$b" 2>/dev/null; } | LC_ALL=C sort -u )"

    for name in $names; do
        f="$a/$name"
        if [ ! -f "$f" ]; then
            printf '=== %s: absent in %s, present in %s\n' "$name" "$1" "$2" >> "$report"
            rc=1
            continue
        fi
        if [ ! -f "$b/$name" ]; then
            printf '=== %s: present in %s, absent in %s\n' "$name" "$1" "$2" >> "$report"
            rc=1
            continue
        fi
        if ! diff -u "$f" "$b/$name" > /dev/null 2>&1; then
            {
                printf '=== %s\n' "$name"
                diff -u "$f" "$b/$name" | sed '1,2d'
                printf '\n'
            } >> "$report"
            rc=1
        fi
    done
    return "$rc"
}

# ─── Connectivity ─────────────────────────────────────────────────────────────
# The check that matters most, and the one a person cannot do for themselves:
# their own SSH session survives a broken firewall because it is already
# established. New connections are what stop working.
SSH_PORTS=""
FW_POLICY_BASELINE=""
connectivity() {
    local stage="$1" problems=0

    if ! ip route show default | grep -q .; then
        bad "[$stage] no default route — this host has lost its way off the network"
        problems=1
    fi

    # ⚠ What this check can and cannot see, stated because the comment that used
    # to be here claimed more than the code did.
    #
    # `ss` proves SSHD IS LISTENING. It does not prove a new connection would be
    # accepted: a DROP rule on the port leaves the daemon listening exactly like
    # this and the check passes, which is the failure it was written to catch.
    # Probing the port from here would not settle it either — a connection this
    # host makes to its own address is routed over loopback and does not
    # traverse the same path an outside client would.
    #
    # So the listener check is kept for what it does prove (the daemon did not
    # die), and the thing that CAN be asserted from here is asserted separately
    # below: the firewall's default verdict is unchanged from baseline. VPN55
    # adds only accept rules and never touches a policy, so a policy that moved
    # is either a bug or something else on this host — and either way it is the
    # fact a lockout is made of.
    local port
    for port in $SSH_PORTS; do
        if ! ss -lnt "sport = :$port" 2>/dev/null | grep -q ":$port"; then
            bad "[$stage] nothing is listening on tcp/$port any more — the way back in is gone"
            problems=1
        fi
    done

    local policy_now
    policy_now="$(_fw_policy_now)"
    if [ -z "$FW_POLICY_BASELINE" ]; then
        FW_POLICY_BASELINE="$policy_now"
    elif [ "$policy_now" != "$FW_POLICY_BASELINE" ]; then
        bad "[$stage] the firewall's DEFAULT VERDICT changed since baseline — this is how a lockout starts"
        printf '        was: %s\n' "$(printf '%s' "$FW_POLICY_BASELINE" | tr '\n' ';')"
        printf '        now: %s\n' "$(printf '%s' "$policy_now"      | tr '\n' ';')"
        problems=1
    fi

    # Outbound reachability is a WARN, not a FAIL: a test VPS with no egress is
    # unusual but legitimate, and failing the whole run for it would train
    # people to ignore the result.
    if ! timeout 5 bash -c ': > /dev/tcp/1.1.1.1/443' 2>/dev/null; then
        soft "[$stage] no outbound TCP to 1.1.1.1:443 — check whether that is expected here"
    fi
    if command -v getent >/dev/null 2>&1 && ! getent hosts one.one.one.one >/dev/null 2>&1; then
        soft "[$stage] DNS did not resolve"
    fi

    [ "$problems" = "0" ] && ok "[$stage] host is still reachable"
    return 0
}

# ─── Will these rules survive a reboot? ───────────────────────────────────────
# This harness cannot reboot: the run would end. But the failure it needs to
# catch does not require one to detect, only to SUFFER — and it is a bad one.
# nftables keeps no rules across a boot on its own, so a backend that adds live
# rules and never writes them out loses NAT overnight while every check here
# passes. firewalld has the mirror-image problem in the present tense: a
# --permanent write touches nothing running, so the port an install reports as
# open is closed until something reloads.
#
# Both are decidable right now, by asking whether what is LIVE and what is
# PERSISTED agree. That is the check.
persistence() {
    local stage="$1" backend=""
    [ -r /etc/vpn55/net.conf ] && backend="$(sed -n 's/^fw_backend=//p' /etc/vpn55/net.conf | head -1)"

    case "$backend" in
        nftables)
            if [ ! -s /etc/vpn55/nftables.conf ]; then
                bad "[$stage] nftables rules are live but nothing was written to /etc/vpn55/nftables.conf — they are gone at the next boot"
                return 0
            fi
            if ! systemctl is-enabled --quiet vpn55-firewall.service 2>/dev/null; then
                bad "[$stage] /etc/vpn55/nftables.conf exists but vpn55-firewall.service is not enabled — nothing replays it at boot"
                return 0
            fi
            # Every vpn55 rule comment that is live must appear in the file that
            # will be replayed. Comparing comments rather than whole rules keeps
            # this readable and is exact enough: the comment carries the rule's
            # full identity by design.
            local live saved missing=0 c
            live="$(nft list ruleset 2>/dev/null | grep -o 'vpn55:[^"]*' | LC_ALL=C sort -u)"
            saved="$(grep -o 'vpn55:[^"]*' /etc/vpn55/nftables.conf 2>/dev/null | LC_ALL=C sort -u)"
            for c in $live; do
                printf '%s\n' "$saved" | grep -qxF "$c" || { missing=1; note "        not persisted: $c"; }
            done
            if [ "$missing" = "1" ]; then
                bad "[$stage] live nftables rules are missing from the file replayed at boot"
            else
                ok "[$stage] nftables rules are persisted and the boot unit is enabled"
            fi ;;
        firewalld)
            # The permanent config is what survives; the runtime config is what
            # is actually enforcing. A port in one and not the other means the
            # install either did nothing yet or will lose it at reload.
            local perm run
            perm="$(firewall-cmd --permanent --list-ports 2>/dev/null | tr ' ' '\n' | LC_ALL=C sort -u)"
            run="$(firewall-cmd --list-ports 2>/dev/null | tr ' ' '\n' | LC_ALL=C sort -u)"
            if [ "$perm" != "$run" ]; then
                bad "[$stage] firewalld's permanent and runtime port sets disagree — the install did not reload"
                note "        permanent: $(printf '%s' "$perm" | tr '\n' ' ')"
                note "        runtime:   $(printf '%s' "$run"  | tr '\n' ' ')"
            else
                ok "[$stage] firewalld's permanent and runtime configuration agree"
            fi ;;
        ufw)
            if ! ufw status 2>/dev/null | grep -q 'Status: active'; then
                bad "[$stage] ufw is not active — its rules are not enforcing"
            elif grep -q '^# BEGIN VPN55 ' /etc/ufw/before.rules 2>/dev/null \
                 && ! iptables -t nat -S POSTROUTING 2>/dev/null | grep -q MASQUERADE; then
                bad "[$stage] the VPN55 NAT block is in before.rules but no MASQUERADE rule is live — ufw was not reloaded"
            else
                ok "[$stage] ufw is active and its NAT block is loaded"
            fi ;;
        "")
            note "[$stage] no firewall backend recorded yet — nothing to check" ;;
        *)
            soft "[$stage] unknown firewall backend '$backend' — persistence not checked" ;;
    esac
    return 0
}

# ─── Adapters ─────────────────────────────────────────────────────────────────
# Enumerated from the installer, never named here. A harness with a hard-coded
# list of services is a harness that silently skips the adapter added last —
# which is the one most likely to be broken.
adapters_available() {
    "$INSTALLER" --adapters 2>/dev/null \
        | awk -F'\t' '$1 == "adapter" && $4 == "1" { print $2 }'
}
adapters_all() {
    "$INSTALLER" --adapters 2>/dev/null \
        | awk -F'\t' '$1 == "adapter" { printf "%s\t%s\n", $2, $3 }'
}

run_installer() {
    # run_installer <log name> <args…>
    local name="$1"
    shift
    local log="$OUT_DIR/$name.log"
    {
        printf '### %s : vpn55.sh %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$*"
    } >> "$RUN_LOG"
    if "$INSTALLER" "$@" >"$log" 2>&1; then
        cat "$log" >> "$RUN_LOG"
        return 0
    fi
    cat "$log" >> "$RUN_LOG"
    return 1
}

# ─── Did the install actually DO anything? ────────────────────────────────────
#
# ⚠ Read this before trusting a green run, because it is the hole it closes.
#
# The two headline comparisons in this file are pass 2 against pass 3
# (idempotency) and baseline against final (reversal). BOTH ARE SATISFIED BY
# NOTHING HAVING HAPPENED. An install that returns 0 without starting a daemon
# leaves passes 2 and 3 identical to each other and the final host identical to
# its baseline, so every check goes green and the run authorises a README row
# for a distribution where the tunnel never came up.
#
# Until now the only thing standing between that and a false ✅ was the
# installer's own exit code — which is the code under test. A harness whose
# central guarantee is inherited from the thing it is testing is not evidence.
#
# So two assertions, and they are deliberately different in kind:
#
#   installed_something  the host CHANGED. Cheap, protocol-blind, and it cannot
#                        be satisfied by an install that no-oped.
#   service_is_up        the adapter itself reports `running`, and the port it
#                        says it listens on is open. This reads the same
#                        `--status` stream the panel reads, so it also exercises
#                        that contract on every acceptance run.
#
# Neither one proves traffic flows. Nothing in this file does — see the header.

# installed_something <baseline snapshot> <after snapshot> <tag>
installed_something() {
    local a="$1" b="$2" tag="$3"
    if diff_snapshots "$a" "$b" "$OUT_DIR/changed-$tag.diff"; then
        bad "[$tag] installing changed NOTHING on this host — the snapshot after the"
        printf '        install is identical to the baseline. Either the install silently\n'
        printf '        did nothing, or it failed in a way that still exited 0. Every other\n'
        printf '        check in this run would pass on such a host, which is why this one\n'
        printf '        exists. See %s.\n' "$OUT_DIR/install-$tag-1.log"
        return 1
    fi
    ok "[$tag] installing changed the host — there is something to test"
    return 0
}

# service_is_up <tag> — the adapter's own verdict, plus the listener behind it.
#
# The `service` record is <tag> <state> <enabled> <listen> <since> <creds>, and
# state is one of absent / stopped / running. `listen` is the adapter's own
# description of its port — "udp/51820", "udp/500,4500" — so the ports are
# parsed out of it rather than named here: this file still learns no protocol.
service_is_up() {
    local tag="$1" rec state listen port proto ss_flag missing=0
    rec="$("$INSTALLER" --status 2>/dev/null | awk -F'\t' -v t="$tag" '$1 == "service" && $2 == t { print; exit }')"

    if [ -z "$rec" ]; then
        bad "[$tag] --status reports no service record at all after a successful install"
        return 1
    fi
    state="$(printf '%s' "$rec"  | cut -f3)"
    listen="$(printf '%s' "$rec" | cut -f5)"

    if [ "$state" != "running" ]; then
        bad "[$tag] installed and exited 0, but the service reports '$state' — the tunnel is not up"
        return 1
    fi
    ok "[$tag] the service reports running"

    # "udp/500,4500" → proto=udp, ports 500 and 4500. A listen field this cannot
    # parse is reported and not failed: the adapter is allowed to describe
    # itself in a shape this harness has not seen, and guessing would be worse.
    proto="${listen%%/*}"
    case "$proto" in
        tcp) ss_flag="-lnt" ;;
        udp) ss_flag="-lnu" ;;
        *)   soft "[$tag] cannot read a port out of the listen field '$listen' — listener not checked"
             return 0 ;;
    esac

    local checked=0
    for port in $(printf '%s' "${listen#*/}" | tr ',' ' '); do
        case "$port" in
            ''|*[!0-9]*) continue ;;
        esac
        checked=$(( checked + 1 ))
        # Captured, then tested. `ss | grep -q` exits on the first match, which
        # SIGPIPEs ss — and this file runs under pipefail, so the pipeline would
        # read as "not listening" on exactly the hosts where it IS.
        local probe
        probe="$(ss "$ss_flag" 2>/dev/null || true)"
        if ! printf '%s\n' "$probe" | grep -qE "[:.]${port}([^0-9]|$)"; then
            bad "[$tag] reports running, but nothing is listening on ${proto}/${port}"
            missing=1
        fi
    done

    if [ "$checked" = "0" ]; then
        soft "[$tag] no numeric port in the listen field '$listen' — listener not checked"
    elif [ "$missing" = "0" ]; then
        ok "[$tag] the port it advertises is open ($listen)"
    fi
    return 0
}

# ─── The run ──────────────────────────────────────────────────────────────────
say "VPN55 acceptance — $(date -u +%Y-%m-%dT%H:%M:%SZ)"
note "tree:    $REPO_DIR"
note "output:  $OUT_DIR"

# Distribution identity, for the README matrix row this run authorises.
DISTRO_ID="unknown"; DISTRO_VER=""
if [ -r /etc/os-release ]; then
    # shellcheck disable=SC1091
    . /etc/os-release
    DISTRO_ID="${ID:-unknown}"
    DISTRO_VER="${VERSION_ID:-}"
fi
note "host:    ${DISTRO_ID} ${DISTRO_VER} · kernel $(uname -r)"
note "version: $("$INSTALLER" --version 2>/dev/null | head -1)"

# Only the port the current session actually arrived on is load-bearing.
# Watching every listener on the box would fail the run whenever the service
# under test legitimately stops one of its own — and a check that cries wolf is
# a check that gets ignored on the run where it was right.
if [ -n "${SSH_CONNECTION:-}" ]; then
    SSH_PORTS="$(printf '%s' "$SSH_CONNECTION" | awk '{ print $4 }')"
    note "session: this run is connected on tcp/${SSH_PORTS}"
else
    SSH_PORTS=""
    soft "not in an SSH session — the lockout check has nothing to watch. Run this over SSH."
fi

say "1 · Baseline"
snapshot baseline || fatal "cannot snapshot this host"
connectivity baseline

say "2 · Static distribution checks"
# These need no VPS at all, but they belong in the same report: a release is not
# ready because the tunnels worked, it is ready when the tunnels worked AND a
# user whose network blocks the website can still install it.
if grep -rniE 'vpn55\.org' "$REPO_DIR/vpn55.sh" "$REPO_DIR/lib" "$REPO_DIR/helper" 2>/dev/null \
     | grep -vE ':[0-9]+:[[:space:]]*#' | grep -q .; then
    bad "the installer or its libraries reference the project website"
else
    ok "no dependency on the project website in vpn55.sh, lib/ or helper/"
fi
if "$INSTALLER" --version 2>/dev/null | grep -q 'source base:'; then
    ok "the source base URL is reported by --version"
else
    soft "--version does not report the source base URL"
fi

say "3 · Adapters present"
ADAPTERS="$(adapters_available)"
if [ -n "$ONLY_TAG" ]; then
    ADAPTERS="$(printf '%s\n' "$ADAPTERS" | grep -Fx "$ONLY_TAG" || true)"
    [ -n "$ADAPTERS" ] || fatal "'$ONLY_TAG' is not available on this host."
fi
adapters_all | while IFS=$'\t' read -r tag label; do
    if printf '%s\n' "$ADAPTERS" | grep -qFx "$tag"; then
        note "will test: $label ($tag)"
    else
        note "skipping:  $label ($tag) — cannot run on this host"
    fi
done
[ -n "$ADAPTERS" ] || fatal "no tunnel service can run on this host — nothing to test."

# ─── Per-adapter: install ×3, then uninstall ──────────────────────────────────
for tag in $ADAPTERS; do
    say "4 · $tag — install, three times"

    if run_installer "install-$tag-1" --install "$tag"; then
        ok "$tag installed"
    else
        bad "$tag failed to install — see $OUT_DIR/install-$tag-1.log"
        connectivity "$tag/after-failed-install"
        continue
    fi
    snapshot "install-$tag-1" || true
    connectivity "$tag/installed"
    persistence  "$tag/installed"

    # The two checks that stop a green run on a host where nothing came up.
    # They go here, after pass 1, because this is the only point where "before"
    # and "after" are both available and the service has not yet been re-applied
    # twice on top of itself.
    installed_something baseline "install-$tag-1" "$tag" || true
    service_is_up "$tag" || true

    # The second run is what a re-run of the menu does. The third is what
    # catches state that alternates rather than settles — a rule appended each
    # time, a unit re-enabled, a lease re-allocated. Two runs would show that as
    # a stable difference and call it converged.
    for pass in 2 3; do
        if run_installer "install-$tag-$pass" --install "$tag"; then
            ok "$tag re-installed (pass $pass)"
        else
            bad "$tag failed on pass $pass — an installer must be safe to re-run"
        fi
        snapshot "install-$tag-$pass" || true
        connectivity "$tag/pass-$pass"
    done

    if diff_snapshots "install-$tag-2" "install-$tag-3" "$OUT_DIR/drift-$tag.diff"; then
        ok "$tag is idempotent — passes 2 and 3 left the host identical"
    else
        bad "$tag DRIFTS between identical runs — $OUT_DIR/drift-$tag.diff"
        sed -n '1,40p' "$OUT_DIR/drift-$tag.diff" | sed 's/^/        /'
    fi
done

# ─── Backup and restore ───────────────────────────────────────────────────────
# A backup nobody restored is not a backup, so this harness restores one.
#
# The stage runs between the install passes and the uninstall, because it needs
# a host with services on it: a certificate authority, a register with somebody
# in it, and at least one issued credential. Every move is a MOVE, never a
# delete, so a failure in the middle leaves the originals sitting beside the
# run's output where a person can put them back by hand — and the message says
# where they are.
#
# ── What this stage can and cannot prove ────────────────────────────────────
# It moves /etc/vpn55 and /var/lib/vpn55 aside. It does NOT move /etc/wireguard,
# /etc/openvpn or /etc/swanctl: those hold the running tunnels, and this harness
# is not allowed to drop the session it is running over. So the LIVE round-trip
# covers the certificate authority, the register and the leases; what the
# adapters own outside /etc/vpn55 is proved a weaker way, by reading the
# archive's own manifest and asserting that paths from outside /etc/vpn55 are in
# it at all. That is a real check — it is the one that fails the day an adapter
# stops answering backup_paths — and it is not the same as having restored them.
#
# ── The check that actually matters ─────────────────────────────────────────
# Step 6 signs a fresh certificate with the RESTORED authority. An archive that
# restores files but not a usable signing key passes every file comparison in
# this stage and fails the one thing it exists for. Only a signature catches it.

# _bak_facts <dir> — one file per fact, so a diff names WHICH fact moved.
_bak_facts() {
    local dir="$1"
    mkdir -p "$dir" || return 1

    openssl x509 -in /etc/vpn55/pki/ca.crt -noout -fingerprint -sha256 \
        > "$dir/ca_fp" 2>/dev/null || : > "$dir/ca_fp"
    "$INSTALLER" --list-users 2>/dev/null | sort > "$dir/users" || : > "$dir/users"
    ls -1 /etc/vpn55/pki/issued 2>/dev/null | sort > "$dir/issued" || : > "$dir/issued"
    sort /etc/vpn55/pki/index.txt 2>/dev/null > "$dir/index" || : > "$dir/index"
    cat /etc/vpn55/pki/serial 2>/dev/null > "$dir/serial" || : > "$dir/serial"
    cat /etc/vpn55/leases/* 2>/dev/null | sort > "$dir/leases" || : > "$dir/leases"
    return 0
}

# _bak_facts_diff <before> <after> <report> — 0 identical, 1 different.
_bak_facts_diff() {
    local a="$1" b="$2" out="$3" f name rc=0
    : > "$out"
    for f in "$a"/*; do
        [ -f "$f" ] || continue
        name="$(basename "$f")"
        if ! diff -u "$f" "$b/$name" >> "$out" 2>&1; then
            printf '=== %s\n' "$name" >> "$out"
            rc=1
        fi
    done
    return "$rc"
}

backup_restore() {
    command -v openssl >/dev/null 2>&1 || { soft "no openssl — skipping the backup stage"; return 0; }
    if [ ! -f /etc/vpn55/pki/ca.crt ]; then
        soft "no certificate authority on this host — nothing this stage can round-trip"
        return 0
    fi

    local work="$OUT_DIR/backup"
    local aside="$work/aside"
    local user="acc-bak-$$"
    local tag f d base archive="" mani probe restored=0 moved=""
    mkdir -p "$work" "$aside" || { bad "cannot create $work"; return 1; }

    # The passphrase is generated per run unless the operator pinned one, and it
    # is exported rather than written to a file — this is the automation channel
    # the library documents, and a file would leave a passphrase in $OUT_DIR
    # after the run finished.
    if [ -z "${VPN55_ACC_BACKUP_PASS:-}" ]; then
        VPN55_ACC_BACKUP_PASS="acc-$(head -c 18 /dev/urandom | od -An -tx1 | tr -d ' \n')"
    fi
    export VPN55_BACKUP_PASS="$VPN55_ACC_BACKUP_PASS"

    # ── 1. Something worth losing ────────────────────────────────────────────
    if "$REPO_DIR/helper/vpnctl" user-add "$user" >> "$RUN_LOG" 2>&1; then
        ok "created a test user for the backup stage"
    else
        soft "could not create a test user — this stage runs against whatever is already here"
        user=""
    fi
    if [ -n "$user" ]; then
        for tag in $ADAPTERS; do
            "$REPO_DIR/helper/vpnctl" cred-add "$user" "$tag" >> "$RUN_LOG" 2>&1 \
                || soft "could not issue a $tag credential for the backup stage"
        done
    fi

    _bak_facts "$work/before" || { bad "cannot record the pre-backup state"; return 1; }

    # ── 2. Take the backup ───────────────────────────────────────────────────
    if run_installer "backup" --backup --out "$work"; then
        ok "backup written"
    else
        bad "--backup failed — see $OUT_DIR/backup.log"
        return 1
    fi

    for f in "$work"/*.tar.gz.enc; do
        [ -f "$f" ] && archive="$f"
    done
    if [ -z "$archive" ]; then
        bad "--backup reported success but produced no archive in $work"
        return 1
    fi

    # ── 3. Does the archive carry what it claims? ────────────────────────────
    # The manifest is read out of the archive rather than taken from the log.
    # The passphrase goes in on stdin here for the same reason the library sends
    # it that way: /proc/<pid>/cmdline is world-readable for the life of the
    # process, and a harness that leaks it in argv is teaching the wrong thing.
    mani="$work/MANIFEST"
    if printf '%s\n' "$VPN55_BACKUP_PASS" \
         | openssl enc -d -aes-256-cbc -md sha512 -pbkdf2 -iter 600000 \
                -in "$archive" -pass stdin 2>/dev/null \
         | tar -xzO MANIFEST > "$mani" 2>/dev/null && [ -s "$mani" ]; then
        ok "the archive decrypts and its manifest is readable"

        if grep -q 'etc/vpn55/pki/private/ca.key' "$mani"; then
            ok "the certificate authority's private key is in the archive"
        else
            bad "the archive does NOT contain the CA private key — it protects nothing"
        fi

        if awk -F'\t' '$1 == "file" && $5 !~ /^etc\/vpn55\// { found = 1 } END { exit !found }' "$mani"; then
            ok "adapter-owned paths outside /etc/vpn55 are in the archive"
        else
            bad "NOTHING outside /etc/vpn55 is in the archive — an adapter is not answering backup_paths"
        fi

        # The spool, not a list of file suffixes: naming an artifact format here
        # would teach this harness which protocols exist, which is the rule the
        # whole adapter contract rests on. Every adapter spools its hand-off
        # artifacts, so this catches them all without knowing any of their names.
        if awk -F'\t' '$5 ~ /\/spool\// { found = 1 } END { exit !found }' "$mani"; then
            bad "the archive contains a CLIENT ARTIFACT — those are shredded after hand-off on purpose"
        else
            ok "no client artifact is in the archive"
        fi
    else
        soft "could not read the archive's manifest — the round-trip below still runs"
    fi

    # ── 4. Take the host's state away ────────────────────────────────────────
    for d in /etc/vpn55 /var/lib/vpn55; do
        [ -d "$d" ] || continue
        base="$aside/$(printf '%s' "${d#/}" | tr '/' '-')"
        if mv "$d" "$base" 2>>"$RUN_LOG"; then
            moved="$moved $d"
        else
            bad "cannot move $d aside — this stage cannot run safely, stopping here"
            return 1
        fi
    done
    note "moved aside:${moved:- nothing}  ->  $aside"

    # ── 5. Put it back from the archive ──────────────────────────────────────
    if run_installer "restore" --restore "$archive"; then
        ok "--restore completed"
        restored=1
    else
        bad "--restore FAILED — the originals are in $aside; see $OUT_DIR/restore.log"
    fi

    if [ "$restored" = "1" ]; then
        _bak_facts "$work/after" || true
        if _bak_facts_diff "$work/before" "$work/after" "$work/facts.diff"; then
            ok "the restored host is identical to the one that was backed up"
        else
            bad "the restore did NOT reproduce the host — $work/facts.diff"
            grep '^=== ' "$work/facts.diff" | sed 's/^/        /'
        fi

        # ── 6. Is the restored authority a WORKING authority? ────────────────
        # Everything above compares files. This signs with the restored key,
        # which is the only thing separating a backup from a pile of bytes. It
        # mutates index.txt and serial in the restored tree, deliberately —
        # that tree is discarded in step 7.
        probe="$work/probe"
        mkdir -p "$probe" || true
        if openssl req -new -newkey rsa:2048 -nodes \
                -keyout "$probe/p.key" -out "$probe/p.csr" \
                -subj "/CN=acc-restore-probe" >>"$RUN_LOG" 2>&1 \
           && openssl ca -batch -config /etc/vpn55/pki/openssl.cnf \
                -in "$probe/p.csr" -out "$probe/p.crt" -days 1 >>"$RUN_LOG" 2>&1 \
           && openssl verify -CAfile /etc/vpn55/pki/ca.crt "$probe/p.crt" >>"$RUN_LOG" 2>&1; then
            ok "the RESTORED authority signed a new certificate and it verifies — the CA survived"
        else
            bad "the restored authority CANNOT SIGN. The archive restored files but not a usable CA."
        fi
    fi

    # ── 7. Give the host back ────────────────────────────────────────────────
    # The harness promised to leave this machine as it was found, and that
    # promise has no exception for the stage that moved the most.
    for d in /etc/vpn55 /var/lib/vpn55; do
        base="$aside/$(printf '%s' "${d#/}" | tr '/' '-')"
        [ -d "$base" ] || continue
        if [ -d "$d" ]; then
            rm -rf "${d:?}" 2>>"$RUN_LOG" \
                || { bad "cannot clear the restored $d — the original is still in $base"; continue; }
        fi
        if mv "$base" "$d" 2>>"$RUN_LOG"; then
            note "put back: $d"
        else
            bad "COULD NOT PUT $d BACK. It is in $base — move it back by hand before anything else."
        fi
    done

    if [ -n "$user" ]; then
        "$REPO_DIR/helper/vpnctl" user-remove "$user" >> "$RUN_LOG" 2>&1 \
            || soft "could not remove the test user '$user' — remove it by hand"
    fi

    _bak_facts "$work/final" || true
    if _bak_facts_diff "$work/before" "$work/final" "$work/putback.diff"; then
        ok "the host is back to its pre-backup state"
    else
        # The test user was created before `before` was recorded and removed
        # after `final`, so a difference in `users` and `issued` is this stage's
        # own cleanup rather than residue. A moved CA fingerprint, serial or
        # lease table is not, and fails.
        if grep -qE '^=== (ca_fp|serial|leases)' "$work/putback.diff"; then
            bad "the backup stage changed the host — $work/putback.diff"
        else
            note "the only differences are this stage's own test user, removed above"
        fi
    fi

    unset VPN55_BACKUP_PASS
    return 0
}

say "5 · Backup and restore"
backup_restore

# ─── Uninstall ────────────────────────────────────────────────────────────────
# Reversal is checked against the ORIGINAL baseline, not against the state
# before this adapter's install. Anything else lets each adapter leave a little
# behind and calls the sum of it clean.
for tag in $ADAPTERS; do
    say "6 · $tag — uninstall"
    if run_installer "uninstall-$tag" --uninstall "$tag"; then
        ok "$tag uninstalled"
    else
        bad "$tag failed to uninstall — see $OUT_DIR/uninstall-$tag.log"
    fi
    connectivity "$tag/uninstalled"
done

say "7 · Reversal — is the host as we found it?"
snapshot final || true
connectivity final

if diff_snapshots baseline final "$OUT_DIR/residue.diff"; then
    ok "the host is byte-identical to its baseline"
else
    # Not automatically a failure. Installing packages is deliberate and
    # documented — an uninstall removes what it CONFIGURED, not what the
    # operator now has installed — so a package difference is reported and left
    # to a human, while a firewall or routing difference is not excusable and
    # fails the run on its own.
    if grep -q '^=== ' "$OUT_DIR/residue.diff"; then
        note "differences from baseline, by fact:"
        grep '^=== ' "$OUT_DIR/residue.diff" | sed 's/^/        /'
    fi
    # `listeners` is in this list deliberately. A daemon still bound to a port
    # after its uninstall is network state by any reading, and it was previously
    # only a warning — so a leftover process that is NOT a systemd unit (the
    # units_ facts below would have caught one that is) could survive an
    # uninstall while the run still printed PASSED. That is the same class of
    # miss as the one installed_something closes at the other end of the run.
    if grep -qE '^=== (fw_|routes|rules|sysctl|links|addrs|listeners)' "$OUT_DIR/residue.diff"; then
        bad "uninstall left NETWORK state behind — $OUT_DIR/residue.diff"
    else
        soft "uninstall left non-network residue — read $OUT_DIR/residue.diff and judge each line"
    fi
    if grep -qE '^=== units_' "$OUT_DIR/residue.diff"; then
        bad "uninstall left systemd units behind — $OUT_DIR/residue.diff"
    fi
fi

# What is left under VPN55's own directories, stated plainly rather than judged.
# The user registry and the certificate authority OUTLIVE an adapter uninstall
# on purpose; a harness that called that a leak would be arguing with a
# documented decision.
if [ -s "$OUT_DIR/snap-final/vpn55_files" ]; then
    note "still present under /etc/vpn55, /var/lib/vpn55, /var/log/vpn55:"
    sed 's/^/        /' "$OUT_DIR/snap-final/vpn55_files" | head -40
    note "(the user registry and the certificate authority are meant to survive"
    note " an adapter uninstall — see vpn55.sh's 'Remove VPN55 network state')"
fi

# ─── Verdict ──────────────────────────────────────────────────────────────────
say "Result"
printf '   passed %s · failed %s · warnings %s\n' "$PASS" "$FAIL" "$WARN"
printf '   logs and snapshots: %s\n' "$OUT_DIR"

# One machine-readable line, because the point of this run is to authorise a row
# in the README's distribution matrix — and a row nobody can trace back to a run
# is a claim, not a test.
{
    printf 'vpn55-acceptance\t%s\t%s\t%s\t%s\tpass=%s\tfail=%s\twarn=%s\tadapters=%s\n' \
        "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
        "$DISTRO_ID" "${DISTRO_VER:-none}" "$(uname -r)" \
        "$PASS" "$FAIL" "$WARN" "$(printf '%s' "$ADAPTERS" | tr '\n' ',' | sed 's/,$//')"
} | tee "$OUT_DIR/result.tsv"

if [ "$FAIL" -gt 0 ]; then
    printf '\n\033[31mNOT READY\033[0m — do not claim %s %s in the README.\n' "$DISTRO_ID" "$DISTRO_VER"
    exit 1
fi
printf '\n\033[32mPASSED\033[0m — %s %s may be claimed, with this run recorded.\n' "$DISTRO_ID" "$DISTRO_VER"
exit 0
