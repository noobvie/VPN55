# shellcheck shell=bash
#
# lib/ui.sh — colors, logging, prompts, QR rendering.
#
# Vendored from Office Tools lib/ui.sh (same author; pinned copy, deliberately not
# a submodule — see ATTRIBUTIONS.md). Kept verbatim: the colour set, info/success/
# warn/die, section, press_enter, ask_proceed and its [Y/n/0] contract.
#
# Four deliberate changes from the vendored original, each load-bearing here:
#
#   1. error() is new. CLAUDE.md's lib rule is
#      `cmd || { error "..."; return 1; }` — that helper has to exist.
#   2. ALL log output goes to stderr, not stdout. The adapter contract puts
#      machine-readable data on stdout (_cred_list, _client_config, _status); a
#      log line on stdout would poison a caller that is parsing it.
#   3. Colour is suppressed when stdout is not a TTY, or when NO_COLOR /
#      VPN55_NO_COLOR is set. Escape codes in a piped or logged stream are noise.
#   4. ask_proceed DECLINES with no terminal or at EOF, where the original
#      proceeded. Office Tools prompts before installing a web tool; this one
#      prompts before tearing down a firewall, and "nobody answered" must not
#      read as consent. VPN55_ASSUME_YES=1 is the explicit opt-in.
#
# Sourced, not executed. errexit is disabled inside any ||-guarded function body,
# so nothing in this file relies on the caller's `set -e` — see CLAUDE.md.

[[ -n "${VPN55_UI_LOADED:-}" ]] && return 0
VPN55_UI_LOADED=1

# ─── Colors ───────────────────────────────────────────────────────────────────
# Logging goes to stderr, so the TTY test is on fd 2.
if [[ -t 2 && -z "${NO_COLOR:-}" && -z "${VPN55_NO_COLOR:-}" ]]; then
    RED=$'\033[0;31m'; GREEN=$'\033[0;32m'; YELLOW=$'\033[1;33m'
    CYAN=$'\033[0;36m'; BOLD=$'\033[1m';    DIM=$'\033[2m'
    RESET=$'\033[0m'
else
    RED=''; GREEN=''; YELLOW=''; CYAN=''; BOLD=''; DIM=''; RESET=''
fi

# ─── Logging ──────────────────────────────────────────────────────────────────
info()    { printf '%s[INFO]%s  %s\n'  "$CYAN"   "$RESET" "$*" >&2; }
success() { printf '%s[OK]%s    %s\n'  "$GREEN"  "$RESET" "$*" >&2; }
warn()    { printf '%s[WARN]%s  %s\n'  "$YELLOW" "$RESET" "$*" >&2; }
error()   { printf '%s[ERROR]%s %s\n'  "$RED"    "$RESET" "$*" >&2; }
die()     { printf '%s%s[FATAL]%s %s\n' "$RED" "$BOLD" "$RESET" "$*" >&2; exit 1; }

# Only shown when VPN55_DEBUG is set. Never on by default — a VPN tool that logs
# chattily is a VPN tool that logs something it should not have.
debug() {
    if [[ -n "${VPN55_DEBUG:-}" ]]; then
        printf '%s[DEBUG]%s %s\n' "$DIM" "$RESET" "$*" >&2
    fi
}

section() {
    printf '\n%s%s%s%s\n' "$BOLD" "$CYAN" "───────────────────────────────────────────────────────" "$RESET" >&2
    printf '%s%s  %s%s\n'  "$BOLD" "$CYAN" "$*" "$RESET" >&2
    printf '%s%s%s%s\n\n'  "$BOLD" "$CYAN" "───────────────────────────────────────────────────────" "$RESET" >&2
}

# Aligned key/value line, for status and doctor output.
ui_kv() {
    local key="${1:-}" value="${2:-}"
    printf '  %s%-26s%s %s\n' "$DIM" "$key" "$RESET" "$value" >&2
}

ui_rule() {
    printf '  %s%s%s\n' "$DIM" "─────────────────────────────────────────────────" "$RESET" >&2
}

# ─── Text tests ───────────────────────────────────────────────────────────────
# Use these instead of `producer | grep -q needle`.
#
# `grep -q` exits the instant it matches. Whatever is upstream then gets SIGPIPE
# on its next write and dies with status 141 — and because every entry point here
# runs with `set -o pipefail`, that 141 becomes the status of the whole pipeline.
# So the test reports "not found" precisely when the match came EARLY and the
# producer still had more to write.
#
# That makes it worst on the cases that matter: a chain with one rule answers
# correctly and a chain with two does not, so it passes every small test and
# fails once there is real data. It is also timing-dependent — a producer whose
# entire output fits in the pipe buffer exits before grep reads, and the same
# code then works. Found in Phase 2, where an idempotent firewall rule check
# stacked a duplicate rule on every re-run.
#
# `set -e` being suppressed inside a ||-guarded lib body does NOT cover this:
# pipefail is a separate option and stays on.

# True when <needle> appears in <haystack> as a complete line.
str_has_line() {
    local haystack="${1:-}" needle="${2:-}"
    [[ $'\n'"$haystack"$'\n' == *$'\n'"$needle"$'\n'* ]]
}

# True when <needle> appears anywhere in <haystack>. The needle is quoted inside
# the pattern, so it is matched literally — no glob, no regex.
str_contains() {
    local haystack="${1:-}" needle="${2:-}"
    [[ "$haystack" == *"$needle"* ]]
}

# ─── Prompts ──────────────────────────────────────────────────────────────────
# Every prompt degrades safely when stdin is not a terminal: a non-interactive
# run must never block on a read that will never be answered.
ui_interactive() { [[ -t 0 ]]; }

# `printf -v "$name"` EVALUATES an array subscript in the target, so a name of
# the form `x[$(command)]` runs that command. Every caller here passes a literal
# today, but this is a lib: validate the name rather than relying on that.
_ui_valid_varname() {
    local name="${1:-}" caller="${2:-prompt}"
    if [[ ! "$name" =~ ^[A-Za-z_][A-Za-z0-9_]*$ ]]; then
        error "${caller}: '${name}' is not a valid variable name"
        return 1
    fi
    return 0
}

press_enter() {
    if ! ui_interactive; then
        return 0
    fi
    printf '\n  %sPress Enter to return to the menu…%s' "$DIM" "$RESET" >&2
    read -r _
    printf '\n' >&2
}

# Returns 0 (proceed) or 1 (abort — n or 0 pressed).
#
# A present operator pressing Enter means yes: that is the vendored [Y/n/0]
# contract and it stays. An ABSENT one does not. With no terminal, or at EOF
# because the operator pressed Ctrl-D, this aborts — the alternative is that
# Ctrl-D at "Remove VPN55 network state?" reads as consent and tears down the
# firewall. VPN55_ASSUME_YES=1 is the deliberate opt-in for automation.
ask_proceed() {
    local prompt="${1:-Proceed}" reply=""

    if [[ "${VPN55_ASSUME_YES:-}" == "1" ]]; then
        return 0
    fi
    if ! ui_interactive; then
        warn "No terminal to confirm '${prompt}' — declining. Set VPN55_ASSUME_YES=1 to proceed unattended."
        return 1
    fi

    printf '  %s%s? [Y/n/0]: %s' "$BOLD" "$prompt" "$RESET" >&2
    if ! read -r reply; then
        printf '\n' >&2
        warn "Input ended before '${prompt}' was answered — declining."
        return 1
    fi
    if [[ "${reply,,}" == "n" || "$reply" == "0" ]]; then
        return 1
    fi
    return 0
}

# ask_value <varname> <prompt> [default]
#
# The internal names are prefixed __ui_av_ because `printf -v` writes into the
# CALLEE's local when the names collide — the caller passes "reply" and gets the
# callee's own scratch variable back instead of the answer.
ask_value() {
    local __ui_av_name="${1:-}" __ui_av_prompt="${2:-}" __ui_av_default="${3:-}"
    local __ui_av_reply=""

    _ui_valid_varname "$__ui_av_name" ask_value || return 1
    case "$__ui_av_name" in
        __ui_av_*)
            error "ask_value: '$__ui_av_name' collides with an internal name"
            return 1 ;;
    esac

    if ui_interactive; then
        if [[ -n "$__ui_av_default" ]]; then
            printf '  %s%s%s [%s]: ' "$BOLD" "$__ui_av_prompt" "$RESET" "$__ui_av_default" >&2
        else
            printf '  %s%s%s: ' "$BOLD" "$__ui_av_prompt" "$RESET" >&2
        fi
        read -r __ui_av_reply
    fi

    [[ -z "$__ui_av_reply" ]] && __ui_av_reply="$__ui_av_default"
    printf -v "$__ui_av_name" '%s' "$__ui_av_reply"
}

# ask_key <varname> <prompt>  — single-line menu selection, no default.
#
# EOF yields "0", the quit key, and that is not cosmetic: a menu loop reads a
# key, falls through to its "unknown option" arm on an empty answer, and asks
# again — so returning "" on Ctrl-D spins the loop forever printing a warning.
# The quit key is the only answer that terminates it.
ask_key() {
    local __ui_ak_name="${1:-}" __ui_ak_prompt="${2:-Select}"
    local __ui_ak_reply=""

    _ui_valid_varname "$__ui_ak_name" ask_key || return 1
    case "$__ui_ak_name" in
        __ui_ak_*)
            error "ask_key: '$__ui_ak_name' collides with an internal name"
            return 1 ;;
    esac

    if ui_interactive; then
        printf '\n  %s%s: %s' "$BOLD" "$__ui_ak_prompt" "$RESET" >&2
        read -r __ui_ak_reply || __ui_ak_reply="0"
    else
        __ui_ak_reply="0"
    fi
    printf -v "$__ui_ak_name" '%s' "$__ui_ak_reply"
}

# ─── QR ───────────────────────────────────────────────────────────────────────
# Client configs get scanned off the terminal from Phase 2 onward. Renders to
# stderr with the rest of the presentation layer, so a caller redirecting stdout
# to a file still sees the code.
ui_qr() {
    local payload="${1:-}"
    if [[ -z "$payload" ]]; then
        error "ui_qr: nothing to encode"
        return 1
    fi
    if ! command -v qrencode >/dev/null 2>&1; then
        warn "qrencode is not installed — skipping the QR code."
        warn "Install it with the package named 'qrencode' and re-run."
        return 1
    fi
    printf '%s' "$payload" | qrencode -t ANSIUTF8 >&2
}
