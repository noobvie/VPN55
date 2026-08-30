#!/usr/bin/env bash
#
# VPN55 — self-hosted multi-protocol VPN manager
# https://github.com/noobvie/VPN55
#
# Single entry point: interactive menu plus non-interactive flags.
#
# ⚠ This file is not called install.sh, and that is deliberate. It installs, but
# it is also the menu an operator comes back to for the life of the server, and
# it is the program the panel's sudo rule runs as root — `vpn55.sh --status`,
# with the argument pinned. A permanent management program named "install"
# invites the wrong assumption about what running it costs. Renamed 2026-08-30,
# before first deploy: once one sudoers file on one box names the old path, the
# rename stops being free.
#
# STATUS: Phase 9. Core libraries, the user registry, the shared PKI, all three
# protocol adapters, the panel, and now the two things a release needs: a way to
# get here at all, and a way to be tested. Nothing outside lib/proto_*.sh names a
# protocol: adapters register themselves through vpn_adapter_register and every
# screen dispatches by tag.
#
# ── What this file keeps, and what it does not ───────────────────────────────
# Four things: the bootstrap, the library sourcing, the main menu and the
# argument dispatch. Everything else moved out in Phase 9:
#
#   lib/ui_adapter.sh   the per-service screens — status, issue, deliver, revoke
#   lib/ui_screens.sh   host report, network, users, panel, teardown, update
#   lib/cli.sh          --status for the panel, and the verbs acceptance drives
#
# That split is not tidiness. Those screens are what moves whenever the adapter
# contract moves — the Phase 3 checkpoint rewrote three of them — and an entry
# point that changes every time a screen does is an entry point whose diffs stop
# being readable. What is left here is the part that has to be right before any
# library exists to help.
#
# ⚠ The bootstrap CANNOT be split out. It runs in the one situation where lib/ is
# not there to source from, so it has to be self-contained in this file. That is
# the reason this file has any bulk at all, and the reason it never grows a
# dependency on anything below the sourcing block.
#
# ── What Phase 9 added here ──────────────────────────────────────────────────
#   1. A bootstrap. The README's `bash <(curl …)` runs this file with no
#      directory to source lib/ from, so it now fetches a verified tree to
#      VPN55_HOME and hands over. Until this existed the advertised install
#      command could not work at all — which is exactly the kind of thing a
#      launch phase is for.
#   2. A self-update guard, --update. Bash executes the copy it parsed at
#      launch; new code on disk is not new code in this process. It stops.
#   3. Non-interactive --adapters / --install / --uninstall, because "run the
#      installer three times and prove nothing drifted" has to be something a
#      script can do. tests/vps-acceptance.sh drives them.
#
# Phase 4 changed NOTHING in this file, which is the result the Phase 3
# checkpoint was for. The third adapter registered itself, its status records
# parsed, its artifacts delivered and its revocation latency was reported — all
# through code written before it existed. A file that had to be edited to accept
# a new adapter would mean the contract was still carrying an assumption; this
# one did not. The Phase 3 checkpoint's own account of what it changed moved to
# lib/ui_adapter.sh with the screens it is about.
#
set -euo pipefail

VPN55_VERSION="0.9.0-phase9"

# ─── Distribution: the project website is never in the critical path ──────────
# The only thing this installer ever fetches is ITSELF, and only when it was
# started without a copy of the tree beside it. There is no version ping, no
# mirror list, no asset download and no telemetry — and nothing at any point
# touches the project's own site: that site can be blocked in the target market
# and the code host effectively cannot. A user who already has the install
# command must never need the website for anything.
#
# VPN55_MIRROR is the operator's escape hatch: a base URL under which the
# repository's files appear at their repository paths. Any static host will do —
# another code host, a plain web directory, an onion service — so a block is
# answered by changing one variable rather than by waiting for a new script.
# Note the repository path is case-sensitive on the raw host: the capitals are
# load-bearing.
#
# Full reasoning: docs/distribution.md §1. The fetching itself lives in
# lib/core_source.sh, sourced below with the rest.
: "${VPN55_MIRROR:=https://raw.githubusercontent.com/noobvie/VPN55/main}"
: "${VPN55_HOME:=/usr/local/lib/vpn55}"

# ─── Bootstrap: the one-line install has no directory ─────────────────────────
# `bash <(curl …)` — the command in the README — runs this file from a process
# substitution. BASH_SOURCE[0] is then /dev/fd/63 and its dirname is /dev/fd, so
# every `. "$VPN55_ROOT/lib/…"` below resolves to a path that does not exist.
# One file cannot source a project it did not bring with it.
#
# So when the libraries are not beside this script, this is a bootstrap run: it
# fetches a verified copy of the tree to VPN55_HOME and hands over to it. The
# path is pinned rather than chosen because the panel's sudo rules name it —
# deploy/sudoers.d/vpn55-panel.
#
# ⚠ Be honest about what this does and does not prove. The manifest arrives over
# the same connection as the files, so it catches a truncated download or a
# mirror serving an error page — not a mirror that is lying to you. `curl | bash`
# cannot verify itself: by the time this code could check a signature it is
# already running as root. The verified path is the one in the README, and
# docs/distribution.md §5 says so in the same words.
_vpn55_bootstrap() {
    local tmp="" lib="lib/core_source.sh" want got

    if [[ "$(id -u)" != "0" ]]; then
        printf '[ERROR] VPN55 installs as root. Re-run with sudo.\n' >&2
        exit 1
    fi
    if ! command -v curl >/dev/null 2>&1 && ! command -v wget >/dev/null 2>&1; then
        printf '[ERROR] Need curl or wget to fetch VPN55. Install one and try again.\n' >&2
        exit 1
    fi

    printf '[INFO]  Fetching VPN55 from %s\n' "$VPN55_MIRROR" >&2
    tmp="$(mktemp -d "${TMPDIR:-/tmp}/vpn55-boot.XXXXXX")" || {
        printf '[ERROR] cannot create a temporary directory\n' >&2
        exit 1
    }

    _vpn55_boot_get() {
        local url="$1" dest="$2"
        if command -v curl >/dev/null 2>&1; then
            curl -fsSL --max-time 30 -o "$dest" -- "$url"
        else
            wget -q --timeout=30 -O "$dest" -- "$url"
        fi
    }

    if ! _vpn55_boot_get "${VPN55_MIRROR%/}/MANIFEST.sha256" "$tmp/MANIFEST.sha256" \
       || ! _vpn55_boot_get "${VPN55_MIRROR%/}/$lib" "$tmp/core_source.sh"; then
        printf '[ERROR] could not reach %s\n' "$VPN55_MIRROR" >&2
        printf '[ERROR] If this host is blocked, set VPN55_MIRROR to another base URL.\n' >&2
        rm -rf "$tmp" || true
        exit 1
    fi

    # Check the one file about to be sourced as root against the list. Same
    # channel, so this is a corruption check and not a provenance one — but
    # sourcing a half-downloaded file as root is worth ruling out on its own.
    if command -v sha256sum >/dev/null 2>&1; then
        want="$(awk -v p="$lib" '$2 == p { print $1; exit }' "$tmp/MANIFEST.sha256")"
        got="$(sha256sum "$tmp/core_source.sh" | cut -d' ' -f1)"
        if [[ -z "$want" || "$want" != "$got" ]]; then
            printf '[ERROR] %s does not match the file list this mirror served.\n' "$lib" >&2
            rm -rf "$tmp" || true
            exit 1
        fi
    fi

    # shellcheck source=lib/core_source.sh
    . "$tmp/core_source.sh" || { rm -rf "$tmp" || true; exit 1; }
    rm -rf "$tmp" || true

    src_fetch "$VPN55_HOME" || exit 1
    printf '[INFO]  Starting %s/vpn55.sh\n' "$VPN55_HOME" >&2
    exec "$VPN55_HOME/vpn55.sh" "$@"
}

VPN55_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" 2>/dev/null && pwd)" || VPN55_ROOT=""
if [[ -z "$VPN55_ROOT" || ! -r "$VPN55_ROOT/lib/ui.sh" ]]; then
    _vpn55_bootstrap "$@"
fi
readonly VPN55_VERSION VPN55_ROOT

# ─── Libraries ────────────────────────────────────────────────────────────────
# Sourced up-front, all of them, before any dispatch. A lib sourced lazily inside
# a menu arm is a lib whose absence is discovered halfway through an install.
# shellcheck source=lib/ui.sh
. "$VPN55_ROOT/lib/ui.sh"
# shellcheck source=lib/core_source.sh
. "$VPN55_ROOT/lib/core_source.sh"
# shellcheck source=lib/core_fs.sh
. "$VPN55_ROOT/lib/core_fs.sh"
# shellcheck source=lib/core_i18n.sh
. "$VPN55_ROOT/lib/core_i18n.sh"
# shellcheck source=lib/core_distro.sh
. "$VPN55_ROOT/lib/core_distro.sh"
# shellcheck source=lib/core_net.sh
. "$VPN55_ROOT/lib/core_net.sh"
# shellcheck source=lib/core_users.sh
. "$VPN55_ROOT/lib/core_users.sh"
# shellcheck source=lib/core_pki.sh
. "$VPN55_ROOT/lib/core_pki.sh"
# shellcheck source=lib/core_adapters.sh
. "$VPN55_ROOT/lib/core_adapters.sh"
# shellcheck source=lib/ui_adapter.sh
. "$VPN55_ROOT/lib/ui_adapter.sh"
# shellcheck source=lib/ui_screens.sh
. "$VPN55_ROOT/lib/ui_screens.sh"
# shellcheck source=lib/cli.sh
. "$VPN55_ROOT/lib/cli.sh"

# ─── Adapter registry ─────────────────────────────────────────────────────────
# This file must never learn which protocols exist. Each lib/proto_*.sh announces
# itself with a tag and a display label; everything below iterates the registry
# and dispatches by tag. Adding a fourth adapter is dropping in a file — there is
# no list here to extend, which is the property that makes the contract real
# rather than aspirational.
#
# The registry itself moved to lib/core_adapters.sh in Phase 6, when helper/vpnctl
# became its second consumer. Two copies of "which tags are legitimate" is one
# copy too many once one of them is deciding what root may restart.

# ─── Menu ─────────────────────────────────────────────────────────────────────
# Every arm is ||-guarded. Under `set -e` an unguarded non-zero return from a
# screen kills the whole script instead of returning here, which reads to the
# operator as a crash rather than as a failed action.
main_menu() {
    while true; do
        section "VPN55 ${VPN55_VERSION}"
        cat >&2 <<'MENU'
  1) Host report          — OS, container, firewall, pools
  2) Network setup        — IP forwarding, NAT, firewall backend
  3) Users                — the identity registry
  4) Tunnel services      — install and manage protocols
  5) Admin panel

  S) Update VPN55 itself
  U) Remove VPN55 network state
  0) Quit
MENU
        local key=""
        ask_key key "Select [0-5 / S / U]" || return 0
        case "$key" in
            1)     screen_doctor    || true; press_enter || true ;;
            2)     screen_network   || true; press_enter || true ;;
            3)     screen_users     || true ;;
            4)     screen_protocols || true; press_enter || true ;;
            5)     screen_panel     || true; press_enter || true ;;
            s|S)   screen_update    || true; press_enter || true ;;
            u|U)   screen_uninstall || true; press_enter || true ;;
            0|q|Q) return 0 ;;
            *)     warn "Unknown option '${key}'." ;;
        esac
    done
}

usage() {
    cat <<USAGE
VPN55 ${VPN55_VERSION} — self-hosted multi-protocol VPN manager

  vpn55.sh [option]

  -h, --help        This text
  -V, --version     Version, revision and source base URL
      --doctor      Print a host report and exit; changes nothing
      --list-users  The user registry, one TAB-separated record per line
      --status      Every adapter's state, machine-readable; changes nothing
      --adapters    Tunnel services present here, machine-readable
      --install   <tag>   Install one tunnel service
      --uninstall <tag>   Remove one tunnel service, reversing its install
      --update      Replace this installation with the current code, then stop
      --verify      Check this installation against its own file list
      --revision    Print what identifies the code in this tree

With no option, the interactive menu is shown. Every action runs as root on the
local host. The only thing fetched over the network is VPN55 itself, and only by
--update or by a first run that had no copy of the tree beside it.

--install and --uninstall are what tests/vps-acceptance.sh drives. Without a
terminal, every confirmation DECLINES; set VPN55_ASSUME_YES=1 to run unattended.

Environment:
  VPN55_MIRROR      Base URL for source assets. Defaults to the code host.
  VPN55_HOME        Where an installed copy lives. Defaults to
                    /usr/local/lib/vpn55 — the path the panel's sudo rules name.
  VPN55_ASSUME_YES  Set to 1 to answer every confirmation with yes.
  VPN55_ETC         State directory. Defaults to /etc/vpn55.
  VPN55_NET_PARENT  Tunnel parent range, an x.y.0.0/16. Defaults to 10.8.0.0/16.
  VPN55_ARTIFACT_LOCALE
                    Language of the files handed to a user: vi (default), en
                    or fr. Set it to skip the per-delivery prompt. This
                    installer's own output stays English either way.
  VPN55_NO_COLOR    Set to disable colour. NO_COLOR is honoured too.
  VPN55_DEBUG       Set for verbose diagnostics.
USAGE
}

main() {
    case "${1:-}" in
        -h|--help)    usage; return 0 ;;
        -V|--version)
            printf 'VPN55 %s\n' "$VPN55_VERSION"
            printf 'revision:    %s\n' "$(src_revision "$VPN55_ROOT")"
            printf 'installed:   %s\n' "$VPN55_ROOT"
            printf 'source base: %s\n' "$VPN55_MIRROR"
            return 0 ;;
        --revision)
            src_revision "$VPN55_ROOT"
            printf '\n'
            return 0 ;;
    esac

    distro_require_root || return 1
    distro_detect || return 1
    vpn_adapter_load "$VPN55_ROOT/lib" || true

    # users_init is deliberately NOT called here. Every write path takes the
    # registry lock, which creates the directory itself, and every read path
    # globs safely over a missing one — so --doctor and --list-users touch
    # nothing. An entry point that creates state just by starting is an entry
    # point whose read-only modes are not read-only.

    case "${1:-}" in
        --doctor)     screen_doctor || return 1 ;;
        --list-users) users_list || return 1 ;;
        --status)     cli_status || return 1 ;;
        --adapters)   cli_adapters || return 1 ;;
        --install)    cli_install   "${2:-}" || return $? ;;
        --uninstall)  cli_uninstall "${2:-}" || return $? ;;
        --verify)     cli_verify || return 1 ;;
        --update)
            local rc=0
            src_update "$VPN55_ROOT" || rc=$?
            case "$rc" in
                0)  return 0 ;;
                10) info "Run vpn55.sh again to use it."; return 0 ;;
                *)  return 1 ;;
            esac ;;
        "")           main_menu || return 1 ;;
        *)
            error "Unknown option '${1}'."
            usage >&2
            return 2 ;;
    esac
    return 0
}

main "$@"
