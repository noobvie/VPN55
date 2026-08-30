# shellcheck shell=bash
#
# lib/core_distro.sh — OS family, package manager, kernel-module probe,
# container detection, service control.
#
# This file REPORTS. It does not decide policy: whether a host that cannot load a
# kernel module should fall back to a userspace implementation or be refused is an
# adapter's decision, made against the facts collected here. Keeping the judgement
# out of this file is what stops it acquiring protocol knowledge.
#
# Service control lives here rather than in its own lib because it is the same
# `systemctl` on every host and every adapter needs it; there is no second home
# for it that is not an empty file.
#
# Sourced, not executed. errexit does not cover a ||-guarded function body, so
# every fallible command below is checked explicitly — see CLAUDE.md.

[[ -n "${VPN55_DISTRO_LOADED:-}" ]] && return 0
VPN55_DISTRO_LOADED=1

# Populated by distro_detect. Empty until then, and safe to read under `set -u`.
VPN55_OS_ID=""          # debian, ubuntu, rocky, fedora, arch, ol …
VPN55_OS_ID_LIKE=""     # raw ID_LIKE from /etc/os-release
VPN55_OS_NAME=""        # PRETTY_NAME
VPN55_OS_VERSION=""     # VERSION_ID
VPN55_OS_FAMILY=""      # debian | rhel | arch
VPN55_PKG_MGR=""        # apt-get | dnf | yum | pacman
VPN55_VIRT=""           # none, or the container/hypervisor type

# ─── Root ─────────────────────────────────────────────────────────────────────
distro_is_root() { [[ "${EUID:-$(id -u)}" -eq 0 ]]; }

distro_require_root() {
    if ! distro_is_root; then
        error "VPN55 must run as root — it writes system configuration."
        return 1
    fi
    return 0
}

distro_have() { command -v "${1:-}" >/dev/null 2>&1; }

# ─── OS detection ─────────────────────────────────────────────────────────────
# /etc/os-release is shell syntax, but sourcing it into this shell would clobber
# NAME, VERSION and friends in the caller. Read it in a subshell and hand back
# only the four fields we use.
_distro_read_os_release() {
    [[ -r /etc/os-release ]] || return 1
    (
        set +u
        # shellcheck source=/dev/null
        . /etc/os-release >/dev/null 2>&1 || exit 1
        printf '%s\n%s\n%s\n%s\n' \
            "${ID:-}" "${ID_LIKE:-}" "${VERSION_ID:-}" "${PRETTY_NAME:-${NAME:-}}"
    )
}

# The supported matrix. Extended past the Office Tools set (Debian/Ubuntu/Rocky/
# Alma/CentOS) with Fedora, Arch and Oracle Linux.
#
#   debian  →  debian ubuntu linuxmint pop devuan raspbian
#   rhel    →  rhel centos rocky almalinux fedora ol (Oracle) amzn
#   arch    →  arch manjaro endeavouros cachyos
#
# A distro not named here still resolves through ID_LIKE, which is how a
# derivative nobody has heard of works on the first try instead of being refused.
_distro_family_for() {
    case "${1:-}" in
        debian|ubuntu|linuxmint|pop|devuan|raspbian)  printf 'debian' ;;
        rhel|centos|rocky|almalinux|fedora|ol|amzn)   printf 'rhel'   ;;
        arch|manjaro|endeavouros|cachyos)             printf 'arch'   ;;
        *)                                            return 1        ;;
    esac
}

distro_detect() {
    local fields=()
    if ! mapfile -t fields < <(_distro_read_os_release); then
        error "Cannot read /etc/os-release — this does not look like a supported Linux host."
        return 1
    fi
    if [[ ${#fields[@]} -lt 4 ]]; then
        error "/etc/os-release is present but unreadable or empty."
        return 1
    fi

    VPN55_OS_ID="${fields[0]}"
    VPN55_OS_ID_LIKE="${fields[1]}"
    VPN55_OS_VERSION="${fields[2]}"
    VPN55_OS_NAME="${fields[3]:-$VPN55_OS_ID}"

    VPN55_OS_FAMILY="$(_distro_family_for "$VPN55_OS_ID")" || VPN55_OS_FAMILY=""

    if [[ -z "$VPN55_OS_FAMILY" ]]; then
        local like
        for like in $VPN55_OS_ID_LIKE; do
            VPN55_OS_FAMILY="$(_distro_family_for "$like")" && break
            VPN55_OS_FAMILY=""
        done
    fi

    if [[ -z "$VPN55_OS_FAMILY" ]]; then
        error "Unsupported OS: ${VPN55_OS_NAME:-unknown} (ID=${VPN55_OS_ID:-?})."
        error "Supported: Debian, Ubuntu, RHEL, CentOS, Rocky, AlmaLinux, Fedora, Oracle, Arch."
        return 1
    fi

    # Resolve the package manager from what is actually on the box, not from the
    # family alone — CentOS 7 has yum and no dnf.
    case "$VPN55_OS_FAMILY" in
        debian) VPN55_PKG_MGR="apt-get" ;;
        rhel)   if distro_have dnf; then VPN55_PKG_MGR="dnf"; else VPN55_PKG_MGR="yum"; fi ;;
        arch)   VPN55_PKG_MGR="pacman" ;;
    esac

    if ! distro_have "$VPN55_PKG_MGR"; then
        error "Expected package manager '$VPN55_PKG_MGR' for ${VPN55_OS_NAME}, but it is not installed."
        return 1
    fi

    debug "detected ${VPN55_OS_NAME} family=${VPN55_OS_FAMILY} pkg=${VPN55_PKG_MGR}"
    return 0
}

# Cheap guard for every function below that needs the detection results.
_distro_need_detect() {
    if [[ -z "$VPN55_OS_FAMILY" ]]; then
        distro_detect || return 1
    fi
    return 0
}

# ─── Packages ─────────────────────────────────────────────────────────────────
distro_pkg_refresh() {
    _distro_need_detect || return 1
    case "$VPN55_PKG_MGR" in
        apt-get) apt-get update -qq || { error "apt-get update failed"; return 1; } ;;
        dnf|yum) "$VPN55_PKG_MGR" makecache -q || { error "$VPN55_PKG_MGR makecache failed"; return 1; } ;;
        pacman)  pacman -Sy --noconfirm >/dev/null || { error "pacman -Sy failed"; return 1; } ;;
    esac
    return 0
}

distro_pkg_install() {
    [[ $# -gt 0 ]] || { error "distro_pkg_install: no packages given"; return 1; }
    _distro_need_detect || return 1
    case "$VPN55_PKG_MGR" in
        apt-get)
            DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends "$@" \
                || { error "apt-get install failed: $*"; return 1; } ;;
        dnf|yum)
            "$VPN55_PKG_MGR" install -y "$@" \
                || { error "$VPN55_PKG_MGR install failed: $*"; return 1; } ;;
        pacman)
            pacman -S --needed --noconfirm "$@" \
                || { error "pacman install failed: $*"; return 1; } ;;
    esac
    return 0
}

distro_pkg_remove() {
    [[ $# -gt 0 ]] || { error "distro_pkg_remove: no packages given"; return 1; }
    _distro_need_detect || return 1
    case "$VPN55_PKG_MGR" in
        apt-get) DEBIAN_FRONTEND=noninteractive apt-get purge -y "$@" || return 1 ;;
        dnf|yum) "$VPN55_PKG_MGR" remove -y "$@" || return 1 ;;
        pacman)  pacman -Rns --noconfirm "$@" || return 1 ;;
    esac
    return 0
}

# True when the package is installed. Used to keep an _install idempotent.
distro_pkg_installed() {
    local pkg="${1:-}"
    [[ -n "$pkg" ]] || return 1
    _distro_need_detect || return 1
    case "$VPN55_PKG_MGR" in
        apt-get)
            # Captured, not piped into `grep -q` — see the SIGPIPE note in ui.sh.
            [[ "$(dpkg-query -W -f='${Status}' "$pkg" 2>/dev/null || true)" == "install ok installed" ]] ;;
        dnf|yum) rpm -q "$pkg" >/dev/null 2>&1 ;;
        pacman)  pacman -Qi "$pkg" >/dev/null 2>&1 ;;
        *)       return 1 ;;
    esac
}

# ─── Virtualisation / containers ──────────────────────────────────────────────
# Reported, never judged. "This host is a container" and "this host cannot load a
# kernel module" are different statements, and only the second one matters.
distro_virt() {
    if [[ -n "$VPN55_VIRT" ]]; then
        printf '%s' "$VPN55_VIRT"
        return 0
    fi

    local virt=""

    # OpenVZ / Virtuozzo first: it is the one that genuinely cannot load modules,
    # and its own markers are more reliable than systemd's on the old kernels it
    # tends to run.
    if [[ -e /proc/user_beancounters ]] || { [[ -d /proc/vz ]] && [[ ! -d /proc/bc ]]; }; then
        virt="openvz"
    elif distro_have systemd-detect-virt; then
        virt="$(systemd-detect-virt --container 2>/dev/null || true)"
        if [[ -z "$virt" || "$virt" == "none" ]]; then
            virt="$(systemd-detect-virt 2>/dev/null || true)"
        fi
    fi

    if [[ -z "$virt" || "$virt" == "none" ]]; then
        if [[ -e /.dockerenv ]]; then
            virt="docker"
        elif grep -qa 'container=lxc' /proc/1/environ 2>/dev/null; then
            virt="lxc"
        elif grep -qaE '/(docker|lxc|kubepods)' /proc/1/cgroup 2>/dev/null; then
            virt="container"
        fi
    fi

    [[ -z "$virt" ]] && virt="none"
    VPN55_VIRT="$virt"
    printf '%s' "$VPN55_VIRT"
}

distro_is_container() {
    case "$(distro_virt)" in
        none|kvm|qemu|vmware|xen|microsoft|oracle|bochs|bhyve|parallels|amazon|zvm)
            return 1 ;;
        *)  return 0 ;;
    esac
}

# ─── Kernel modules ───────────────────────────────────────────────────────────
# Four distinct answers, because collapsing them is what produces "install failed"
# on a host where the module was compiled in and never needed loading at all.
#
#   builtin      compiled into the kernel — nothing to load, always present
#   loaded       already in the running kernel
#   loadable     modinfo finds it; modprobe has not been tried
#   unavailable  no such module for this kernel, or loading is not permitted
distro_module_state() {
    local mod="${1:-}"
    [[ -n "$mod" ]] || { error "distro_module_state: no module name"; return 1; }

    local norm="${mod//-/_}"

    if [[ -d "/sys/module/$norm" ]] || grep -q "^${norm} " /proc/modules 2>/dev/null; then
        printf 'loaded'
        return 0
    fi

    local builtin_list
    builtin_list="/lib/modules/$(uname -r)/modules.builtin"
    if [[ -r "$builtin_list" ]] && grep -qE "/${norm}\.ko" "$builtin_list" 2>/dev/null; then
        printf 'builtin'
        return 0
    fi

    if distro_have modinfo && modinfo "$mod" >/dev/null 2>&1; then
        printf 'loadable'
        return 0
    fi

    printf 'unavailable'
    return 1
}

# True when the module is usable right now, with nothing left to load.
distro_module_ready() {
    local state
    state="$(distro_module_state "${1:-}")" || return 1
    [[ "$state" == "loaded" || "$state" == "builtin" ]]
}

# Load it, then VERIFY. modprobe can exit 0 in a container while the module never
# appears — a container's /lib/modules is the host's, so modinfo answers for a
# kernel this host is not allowed to modify.
distro_module_load() {
    local mod="${1:-}"
    [[ -n "$mod" ]] || { error "distro_module_load: no module name"; return 1; }

    if distro_module_ready "$mod"; then
        return 0
    fi

    if ! distro_have modprobe; then
        error "modprobe is not available — cannot load kernel module '$mod'."
        return 1
    fi

    modprobe "$mod" >/dev/null 2>&1 || true

    if distro_module_ready "$mod"; then
        return 0
    fi

    if distro_is_container; then
        error "Kernel module '$mod' could not be loaded inside a $(distro_virt) container."
        error "A container shares the host kernel: the module has to be loaded on the HOST,"
        error "or this host needs a userspace implementation instead. That is a hosting"
        error "limitation rather than a VPN55 failure — a KVM instance does not have it."
    else
        error "Kernel module '$mod' could not be loaded on this kernel ($(uname -r))."
        error "The matching kernel headers or an extra module package may be missing."
    fi
    return 1
}

# ─── Services ─────────────────────────────────────────────────────────────────
distro_has_systemd() { distro_have systemctl && [[ -d /run/systemd/system ]]; }

_distro_need_systemd() {
    if ! distro_has_systemd; then
        error "systemd is required for service control and was not found."
        return 1
    fi
    return 0
}

distro_service_is_active()  { distro_has_systemd && systemctl is-active  --quiet "${1:-}"; }
distro_service_is_enabled() { distro_has_systemd && systemctl is-enabled --quiet "${1:-}" 2>/dev/null; }

distro_service_start() {
    _distro_need_systemd || return 1
    systemctl start "${1:-}" || { error "cannot start service ${1:-}"; return 1; }
}

distro_service_stop() {
    _distro_need_systemd || return 1
    systemctl stop "${1:-}" || { error "cannot stop service ${1:-}"; return 1; }
}

distro_service_restart() {
    _distro_need_systemd || return 1
    systemctl restart "${1:-}" || { error "cannot restart service ${1:-}"; return 1; }
}

distro_service_enable() {
    _distro_need_systemd || return 1
    systemctl enable --now "${1:-}" || { error "cannot enable service ${1:-}"; return 1; }
}

# Disabling is part of an uninstall, and an uninstall must not abort because a
# unit was already gone.
distro_service_disable() {
    _distro_need_systemd || return 1
    systemctl disable --now "${1:-}" 2>/dev/null || true
    return 0
}

distro_daemon_reload() {
    _distro_need_systemd || return 1
    systemctl daemon-reload || { error "systemctl daemon-reload failed"; return 1; }
}

# ─── Report ───────────────────────────────────────────────────────────────────
# What `vpn55.sh --doctor` prints. Facts only.
distro_report() {
    _distro_need_detect || return 1
    ui_kv "Operating system" "${VPN55_OS_NAME:-unknown}"
    ui_kv "Release"          "${VPN55_OS_ID}${VPN55_OS_VERSION:+ ${VPN55_OS_VERSION}}"
    ui_kv "Family"           "${VPN55_OS_FAMILY} (${VPN55_PKG_MGR})"
    ui_kv "Kernel"           "$(uname -r)"
    ui_kv "Architecture"     "$(uname -m)"

    local virt
    virt="$(distro_virt)"
    if distro_is_container; then
        ui_kv "Virtualisation" "${virt} — container"
    else
        ui_kv "Virtualisation" "${virt}"
    fi

    if distro_has_systemd; then
        ui_kv "Service manager" "systemd"
    else
        ui_kv "Service manager" "none detected — service control unavailable"
    fi
    return 0
}
