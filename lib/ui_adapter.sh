# shellcheck shell=bash
#
# lib/ui_adapter.sh — the interactive screens for a tunnel service.
#
# Split out of vpn55.sh in Phase 9. Everything here is PRESENTATION over the
# adapter contract: it dispatches through vpn_adapter_call, reads the contract's
# uniform record shapes, and decides how each artifact reaches a human. None of
# it decides anything a protocol should decide.
#
# It lives beside ui.sh rather than in vpn55.sh because this is the block that
# moves whenever the contract moves — the Phase 3 checkpoint rewrote three of
# these screens — and an entry point that changes every time a screen does is an
# entry point whose diffs stop being readable.
#
# ⚠ Being in lib/ does not exempt it from the contract. The CI hygiene sweep
# greps every *.sh outside lib/proto_*.sh for protocol vocabulary, so a protocol
# name here fails the build exactly as it would have in vpn55.sh. That is the
# point: the split moved the code, not the rule.
#
# ⚠ errexit does NOT protect these bodies. Every screen is called as `fn || true`
# from a menu arm, which disables errexit for the whole call — see CLAUDE.md.
# Guard anything that writes.
#
# ── What the Phase 3 checkpoint changed in here ──────────────────────────────
# Written while these screens were still in the entry point, and kept because it
# is the record of why they ask what they ask. Three of them were putting
# questions only one protocol could answer. Each was fixed in the CONTRACT rather
# than branched around, which is why none of them left a protocol name behind:
#
#   1. The issue screen prompted for a "client public key". That is a keypair
#      protocol's concept and a certificate protocol has no use for it. Adapters
#      now DECLARE their options through the capabilities verb, and this file
#      prompts for whatever comes back without knowing what any of it is.
#
#   2. The revocation screen explained the delay AFTER the operator had
#      confirmed. For a protocol where revocation is not instant that is the
#      wrong order — the delay is the thing they were deciding about. The same
#      capabilities verb reports it up front.
#
#   3. The config screen assumed one text artifact, small enough for a QR code.
#      A certificate protocol produces four, one of them binary, none of them
#      scannable. Adapters now list their artifacts and this file delivers each
#      according to what it was told, so a fourth adapter with a fifth shape
#      needs no change here.
#
# Phase 4 then changed NOTHING in any of them, which is what the checkpoint was
# for: the third adapter registered itself, its options were prompted, its four
# artifacts delivered and its revocation latency reported, all through code
# written before it existed.
# ─── Adapter screens ──────────────────────────────────────────────────────────
# Everything below dispatches through vpn_adapter_call and reads the contract's
# uniform _status shape. There is no protocol name anywhere in it, and there is
# no list to extend when a fourth adapter is dropped into lib/ — which is the
# property that makes the contract real rather than aspirational.
#
# The _status records this parses:
#   service  <tag>  <state>  <enabled>  <listen>  <since>  <cred_count>
#   cred     <tag>  <cred_id>  <user>  <state>  <address>  <rx>  <tx>  <handshake>  <endpoint>

# Presentation only. `-` means the adapter had no reading — which is NOT zero,
# and rendering it as "0 B" would report a running tunnel as idle.
_fmt_bytes() {
    local n="${1:-}"
    if [[ ! "$n" =~ ^[0-9]+$ ]]; then
        printf '—'
        return 0
    fi
    if   (( n < 1024 ));       then printf '%s B'  "$n"
    elif (( n < 1048576 ));    then printf '%s KB' "$(( n / 1024 ))"
    elif (( n < 1073741824 )); then printf '%s MB' "$(( n / 1048576 ))"
    else printf '%s.%01d GB' "$(( n / 1073741824 ))" "$(( (n % 1073741824) * 10 / 1073741824 ))"
    fi
}

# The adapters emit an absolute epoch, never a formatted age, so that the panel
# can format it for the viewer's locale. This is the installer's own rendering
# of the same number.
#
# "never" and "unknown" are DIFFERENT answers and this is the only place that
# knows it. 0 means the adapter is asserting the credential has never been used;
# "-" means it has no reading, because its daemon keeps no history. Collapsing
# the second into the first tells an operator that a user who connected
# yesterday has never connected at all, which is the kind of wrong that gets
# someone's access removed.
_fmt_age() {
    local when="${1:-}" now diff
    if [[ "$when" == "-" || -z "$when" ]]; then
        printf 'unknown'
        return 0
    fi
    if [[ ! "$when" =~ ^[0-9]+$ ]] || [[ "$when" -eq 0 ]]; then
        printf 'never'
        return 0
    fi
    now="$(date +%s)"
    diff=$(( now - when ))
    if   (( diff < 0 ));      then printf 'in the future'
    elif (( diff < 120 ));    then printf '%ss ago' "$diff"
    elif (( diff < 7200 ));   then printf '%sm ago' "$(( diff / 60 ))"
    elif (( diff < 172800 )); then printf '%sh ago' "$(( diff / 3600 ))"
    else                           printf '%sd ago' "$(( diff / 86400 ))"
    fi
}

_fmt_yesno() {
    if [[ "${1:-}" == "1" ]]; then printf 'yes'; else printf 'no'; fi
}

# The service record's state field, or "unknown" when the adapter cannot answer.
_adapter_state() {
    local tag="${1:-}" line
    line="$(vpn_adapter_call "$tag" status 2>/dev/null \
        | awk -F'\t' '$1 == "service" { print $3; exit }')" || line=""
    printf '%s' "${line:-unknown}"
}

_adapter_show_status() {
    local tag="${1:-}" label="${2:-}"
    local rows
    rows="$(vpn_adapter_call "$tag" status)" \
        || { error "could not read the status of ${label}."; return 1; }

    local kind f3 f4 f5 f6 f7 f8 f9 f10
    local shown_creds=0 up_since
    local -a notes=()

    while IFS=$'\t' read -r kind _ f3 f4 f5 f6 f7 f8 f9 f10; do
        case "$kind" in
            service)
                if [[ "$f6" == "-" ]]; then up_since="not running"; else up_since="$(_fmt_age "$f6")"; fi
                ui_kv "Service"        "$f3"
                ui_kv "Starts at boot" "$(_fmt_yesno "$f4")"
                ui_kv "Listening on"   "$f5"
                ui_kv "Up since"       "$up_since"
                ui_kv "Credentials"    "$f7" ;;
            cred)
                if [[ "$shown_creds" -eq 0 ]]; then
                    ui_rule
                    shown_creds=1
                fi
                ui_kv "$f3" "${f4} · ${f5} · ${f6} · in $(_fmt_bytes "$f7") / out $(_fmt_bytes "$f8") · last seen $(_fmt_age "$f9")${f10:+ · from ${f10}}" ;;
            note)
                # An adapter saying something specific about itself. This file
                # renders the severity and prints the text; it does not know and
                # must not learn what any particular note is about.
                notes+=("${f3}"$'\t'"${f4}") ;;
        esac
    done <<< "$rows"

    # Printed after the table rather than interleaved with it: a warning in the
    # middle of a list scrolls past, and the point of a note is to be seen.
    if [[ ${#notes[@]} -gt 0 ]]; then
        local n severity text
        ui_rule
        for n in "${notes[@]}"; do
            severity="${n%%$'\t'*}"
            text="${n#*$'\t'}"
            case "$severity" in
                crit) error "$text" ;;
                warn) warn  "$text" ;;
                *)    info  "$text" ;;
            esac
        done
    fi
    return 0
}

# ─── The filtering disclosure, in the terminal ───────────────────────────────
#
# The panel has shown this since Phase 5. The terminal did not, and the terminal
# is where services are actually installed — so the one interface that acts on
# the answer was the one interface that never printed it.
#
# docs/circumvention.md §5 asks for it "wherever a user picks a protocol", which
# is this file twice: once in the list, so the three can be compared before one
# is chosen, and once before an install, where the choice is made.
#
# The LEVEL is our word and gets a short label; the SENTENCE is the adapter's
# own and is printed verbatim, the same rule the panel follows and the same one
# `custody` already follows below. Nothing here learns which protocol it holds.

# A short label for the list. An unknown level prints itself rather than
# collapsing to "unknown" — a new answer should look like a new answer.
_filtering_label() {
    case "${1:-}" in
        resistant) printf 'hard to block' ;;
        partial)   printf 'partly exposed' ;;
        exposed)   printf 'EASY TO BLOCK' ;;
        "")        printf '' ;;
        *)         printf '%s' "$1" ;;
    esac
}

# Field 2 of the adapter's own filtering record, or empty if it declares none.
_adapter_filtering_level() {
    vpn_adapter_call "${1:-}" capabilities 2>/dev/null \
        | awk -F'\t' '$1 == "filtering" { print $2; exit }'
}

# Level + sentence, printed. Used before an install, where there is room for the
# whole thing and the operator is one keypress from committing to it.
_adapter_filtering_notice() {
    local tag="${1:-}" caps level sentence
    caps="$(vpn_adapter_call "$tag" capabilities 2>/dev/null || true)"
    level="$(printf '%s\n' "$caps"    | awk -F'\t' '$1 == "filtering" { print $2; exit }')"
    sentence="$(printf '%s\n' "$caps" | awk -F'\t' '$1 == "filtering" { print $3; exit }')"
    [[ -n "$level" ]] || return 0

    # `exposed` is the one an operator can act on by choosing differently, so it
    # is the one that gets a colour. The others are stated, not flagged.
    if [[ "$level" == "exposed" ]]; then
        warn "On a filtered network: $(_filtering_label "$level")"
    else
        info "On a filtered network: $(_filtering_label "$level")"
    fi
    if [[ -n "$sentence" ]]; then
        info "  ${sentence}"
    fi
    return 0
}

_adapter_install() {
    local tag="${1:-}" label="${2:-}"
    if ! vpn_adapter_call "$tag" available; then
        error "${label} cannot run on this host — nothing was changed."
        return 1
    fi

    # Before the install, not after. An operator who learns here that this is the
    # protocol a censor blocks first can still pick another one; the same
    # sentence printed at the end is an obituary.
    #
    # It is deliberately not a confirmation prompt. Two of the three adapters
    # settle their own transport choice inside `install` — which is where that
    # question belongs — and a gate here would ask about a level that the very
    # next prompt can change.
    _adapter_filtering_notice "$tag" || true

    vpn_adapter_call "$tag" install
}

_adapter_uninstall() {
    local tag="${1:-}" label="${2:-}"
    warn "This removes ${label}: its service, its keys, its NAT and every firewall"
    warn "rule it added. Credentials are marked revoked and cannot be restored."
    if ! ask_proceed "Remove ${label} now"; then
        info "Nothing was changed."
        return 0
    fi
    vpn_adapter_call "$tag" uninstall
}

# ─── Delivering a credential's artifacts ──────────────────────────────────────
# An adapter lists what it has; this decides how each one reaches a human. The
# rendering stays out of the adapter so a config can be piped to a file without
# terminal escape codes landing in it.
#
#   artifact  <id>  <label>  <filename>  <encoding>  <qr>  <note>
#
# Three properties, three decisions, none of them guessed:
#
#   encoding  base64 means the artifact is binary and CANNOT survive being read
#             through command substitution — NULs are dropped and trailing
#             newlines eaten. It is decoded to a file, which is the only way
#             binary reaches anyone from here.
#   qr        drawn only when the adapter says a camera will actually resolve
#             it. A QR of eight kilobytes of XML is a picture of nothing, and
#             offering one is worse than offering none because it looks like it
#             should work.
#   size      a terminal is a bad place for a large file. Everything is written
#             to disk; only something small enough to read is also printed.
VPN55_ARTIFACT_PRINT_MAX=4096

# The ceiling on what is worth drawing as a QR code, in bytes of payload.
#
# The adapter declares `qr 1`, and that declaration is a promise about a payload
# it does not always control — an artifact carrying translated prose is as long
# as the locale makes it, and the locale is chosen here, at handover, not there.
# So the promise is checked rather than trusted.
#
# 600 bytes is where a terminal stops being able to show one. qrencode defaults
# to error-correction level L, so 600 bytes is a version-19 symbol: 93 modules
# plus the 4-module quiet zone each side is 101 columns, and -t ANSIUTF8 halves
# the ROWS but not the columns. Past that the code wraps, and a wrapped QR is not
# a smaller QR, it is a picture of nothing — which is worse than no code at all,
# because it looks as though it should have worked.
#
# Refusing loudly is the point. A silent skip would leave an operator waiting for
# a code the adapter said was coming.
VPN55_ARTIFACT_QR_MAX=600

# ─── Which language the ARTIFACTS are written in ──────────────────────────────
#
# This installer is English and stays English: its audience is an operator with
# root on a Linux box. The files it hands over are a different audience entirely
# — they are read by the person who will use the VPN, and the market is Vietnam.
# So the language of the artifacts is asked once, per delivery, and it is not
# inferred from anything.
#
# Not from the shell's LANG: that is a fact about the operator's terminal, and
# the operator is usually not the person who will read the file. Not from
# geography either — where a server is standing is not what language anyone
# reads. Asked, or taken from --locale, or the default.
#
# The default is Vietnamese, which is the same default the panel uses.
: "${VPN55_ARTIFACT_LOCALE:=}"

_artifact_locale() {
    if [[ -n "$VPN55_ARTIFACT_LOCALE" ]]; then
        i18n_resolve "$VPN55_ARTIFACT_LOCALE"
        return 0
    fi
    if ! ui_interactive; then
        i18n_resolve "$VPN55_DEFAULT_LOCALE"
        return 0
    fi

    local reply=""
    info "Language for the files handed to the user (the installer stays English):"
    ui_kv "1" "Tiếng Việt  (vi — default)"
    ui_kv "2" "English     (en)"
    ui_kv "3" "Français    (fr)"
    ask_key reply "Select [1-3]" || true
    case "$reply" in
        2) printf '%s' "en" ;;
        3) printf '%s' "fr" ;;
        *) printf '%s' "$VPN55_DEFAULT_LOCALE" ;;
    esac
    return 0
}

_adapter_deliver() {
    local tag="${1:-}" cred="${2:-}" locale="${3:-}"
    [[ -n "$locale" ]] || locale="$(_artifact_locale)"
    local rows
    rows="$(vpn_adapter_call "$tag" artifacts "$cred")" || return 1
    if [[ -z "$rows" ]]; then
        warn "This credential has no artifacts left to hand out."
        return 0
    fi

    local kind id label filename encoding qr note body dest
    local -a written=()

    while IFS=$'\t' read -r kind id label filename encoding qr note; do
        [[ "$kind" == "artifact" ]] || continue
        [[ -n "$id" ]] || continue

        body="$(vpn_adapter_call "$tag" client_config "$cred" "$id" "$locale")" || {
            warn "could not read the '${label}' artifact — skipping it."
            continue
        }

        # A file name comes from the adapter, but it lands in the operator's
        # working directory, so it is checked here rather than trusted. A
        # filename containing a slash would write outside the directory the
        # operator is standing in, which is not what "save the config" means.
        case "$filename" in
            ""|*/*|.*) warn "'${label}' has an unusable file name — skipping it."; continue ;;
        esac
        dest="./${filename}"

        ui_rule
        info "${label} — ${note}"

        # umask inside the subshell, not chmod afterwards: several of these
        # contain a private key, and the gap between creating a file and
        # restricting it is a gap in which it was world-readable.
        if [[ "$encoding" == "base64" ]]; then
            ( umask 077; printf '%s' "$body" | base64 -d > "$dest"; ) 2>/dev/null \
                || { error "cannot decode '${label}' into ${dest}"; rm -f "$dest" 2>/dev/null || true; continue; }
        else
            ( umask 077; printf '%s\n' "$body" > "$dest"; ) \
                || { error "cannot write ${dest}"; rm -f "$dest" 2>/dev/null || true; continue; }
        fi
        chmod 0600 "$dest" || warn "could not restrict the permissions on ${dest}"
        written+=("$dest")
        success "Saved ${dest}"

        if [[ "$encoding" == "text" ]] && [[ "${#body}" -le "$VPN55_ARTIFACT_PRINT_MAX" ]]; then
            printf '%s\n' "$body" >&2
        elif [[ "$encoding" == "text" ]]; then
            info "(${#body} bytes — too long to print here; read the file.)"
        fi

        if [[ "$qr" == "1" ]]; then
            if [[ "${#body}" -le "$VPN55_ARTIFACT_QR_MAX" ]]; then
                ui_qr "$body" || true
            else
                warn "Not drawing a QR code for '${label}': ${#body} bytes is past the"
                warn "${VPN55_ARTIFACT_QR_MAX}-byte ceiling a terminal can render legibly, and a code no"
                warn "camera reads is worse than none. Hand over ${dest} instead."
            fi
        fi
    done <<< "$rows"

    ui_rule
    if [[ ${#written[@]} -gt 0 ]]; then
        warn "Those files are in the current directory and some of them contain a"
        warn "private key. Move them to the person they belong to, then delete them"
        warn "from this server — it does not keep a second copy to fall back on."
    fi
    return 0
}

# Issuing. Every prompt below comes from the adapter's own capabilities record,
# so this screen asks for a certificate protocol's nothing and a keypair
# protocol's public key without containing the words for either.
_adapter_cred_add() {
    local tag="${1:-}" label="${2:-}"
    local user="" cred="" caps="" custody=""

    ask_value user "User name" || return 1
    [[ -n "$user" ]] || { error "A user name is required."; return 1; }

    caps="$(vpn_adapter_call "$tag" capabilities 2>/dev/null || true)"

    # Key custody is a disclosure, not a detail. Whether the server has ever
    # held this person's private key is something they are entitled to know, and
    # the moment of issue is when the operator can still choose otherwise.
    custody="$(printf '%s\n' "$caps" | awk -F'\t' '$1 == "custody" { print $3; exit }')"
    if [[ -n "$custody" ]]; then
        info "$custody"
    fi

    # The option rows are collected FIRST and prompted for afterwards, and the
    # order is load-bearing rather than stylistic.
    #
    # Prompting inside `while read … <<< "$caps"` redirects the loop body's
    # stdin to the here-string, so ask_value's `read` would consume the next
    # capability row instead of the operator's answer — except that it never
    # even gets that far: ask_value tests `[[ -t 0 ]]` first, finds stdin is not
    # a terminal, and silently returns the default. The prompt is never printed
    # and the option is always empty. A menu that quietly cannot accept the one
    # input it exists to accept, with no error anywhere.
    #
    # Reading each row with `<<< "$row"` instead scopes the redirect to the
    # `read` alone, so ask_value still has the terminal.
    local -a optrows=() opts=()
    mapfile -t optrows < <(printf '%s\n' "$caps" | awk -F'\t' '$1 == "option"')

    local row _kind key prompt required help value
    for row in ${optrows[@]+"${optrows[@]}"}; do
        IFS=$'\t' read -r _kind key prompt required help <<< "$row"
        [[ -n "$key" ]] || continue

        if [[ -n "$help" ]]; then
            info "$help"
        fi
        value=""
        ask_value value "$prompt" || return 1
        if [[ -z "$value" && "$required" == "1" ]]; then
            error "${label} requires a value for '${prompt}'."
            return 1
        fi
        if [[ -n "$value" ]]; then
            opts+=("${key}=${value}")
        fi
    done

    # ${arr[@]+"${arr[@]}"} rather than "${arr[@]}": under `set -u` an empty
    # array expansion is an unbound-variable error on bash before 4.4, and a
    # protocol that declares no options produces exactly that empty array.
    cred="$(vpn_adapter_call "$tag" cred_add "$user" ${opts[@]+"${opts[@]}"})" || return 1
    [[ -n "$cred" ]] || { error "${label} returned no credential id."; return 1; }
    success "Credential '${cred}' issued to '${user}'."

    _adapter_deliver "$tag" "$cred" || true
    return 0
}

_adapter_cred_list() {
    local tag="${1:-}"
    local rows
    rows="$(vpn_adapter_call "$tag" cred_list)" || return 1
    if [[ -z "$rows" ]]; then
        info "No credentials issued yet."
        return 0
    fi

    local cred user state address created custody held config_state addr_part
    ui_rule
    while IFS=$'\t' read -r cred user state address created custody held; do
        [[ -n "$cred" ]] || continue
        if [[ "$held" == "1" ]]; then
            config_state="downloadable"
        else
            config_state="no longer downloadable"
        fi
        # `-` in the address column means this protocol has no per-credential
        # address to pin — its daemon hands one out at connect time. Printing the
        # dash would read as a missing value in a row of real ones, so the field
        # is left out instead. It is an absence, not a blank.
        addr_part=""
        if [[ -n "$address" && "$address" != "-" ]]; then
            addr_part="${address} · "
        fi
        ui_kv "$cred" "${user} · ${state} · ${addr_part}${custody}-generated · config ${config_state} · issued ${created}"
    done <<< "$rows"
    ui_rule
    return 0
}

_adapter_cred_config() {
    local tag="${1:-}" cred=""
    ask_value cred "Credential id" || return 1
    [[ -n "$cred" ]] || { error "A credential id is required."; return 1; }
    _adapter_deliver "$tag" "$cred"
}

# One verb, three genuinely different operations. Both halves of this matter:
#
#   BEFORE  the adapter's declared worst case, so the operator decides knowing
#           whether "revoke" means "gone" or "gone eventually". This used to be
#           printed only afterwards, which is the wrong order for the one thing
#           they were actually deciding about.
#   AFTER   what the adapter actually achieved, which can be better than the
#           declared worst case — an adapter that managed to end the live
#           session says so, and is believed, because over-warning on the days
#           it is instant is how an operator learns to ignore the warning on the
#           day it is not.
_revoke_latency_note() {
    local latency="${1:-}" seconds="${2:-}" when="${3:-before}"
    case "$latency" in
        immediate)
            if [[ "$when" == "before" ]]; then
                info "Revocation on this service is immediate: the device loses access at once."
            else
                info "Effective now — that device is already off the tunnel."
            fi ;;
        "")
            warn "This service did not say when a revocation takes effect. Treat it as delayed." ;;
        *)
            if [[ "$seconds" == "-1" ]]; then
                warn "Revocation here is '${latency}', and there is NO guaranteed limit on how"
                warn "long an already-connected device can keep its session. It stops being"
                warn "able to reconnect at once; the session it already has may continue."
            elif [[ "$seconds" =~ ^[0-9]+$ ]] && [[ "$seconds" -gt 0 ]]; then
                # Rendered in whichever unit does not round to zero. Integer
                # division alone turns any bound under an hour into "up to 0h",
                # which reads as "instant" — the exact opposite of what this
                # sentence exists to say.
                local human
                if   (( seconds >= 7200 )); then human="$(( seconds / 3600 )) hours"
                elif (( seconds >= 3600 )); then human="an hour"
                elif (( seconds >= 120 ));  then human="$(( seconds / 60 )) minutes"
                else                             human="${seconds} seconds"
                fi
                warn "Revocation here is '${latency}': a device that is already connected can"
                warn "keep that session for up to ${human}. It cannot reconnect after this."
            else
                warn "Revocation here is '${latency}' — it is not necessarily instant."
            fi ;;
    esac
    return 0
}

_adapter_cred_remove() {
    local tag="${1:-}" cred="" caps="" result="" latency="" seconds=""
    ask_value cred "Credential id to revoke" || return 1
    [[ -n "$cred" ]] || { error "A credential id is required."; return 1; }

    caps="$(vpn_adapter_call "$tag" capabilities 2>/dev/null || true)"
    latency="$(printf '%s\n' "$caps" | awk -F'\t' '$1 == "revoke" { print $2; exit }')"
    seconds="$(printf '%s\n' "$caps" | awk -F'\t' '$1 == "revoke" { print $3; exit }')"
    _revoke_latency_note "$latency" "$seconds" before

    ask_proceed "Revoke '${cred}'" || { info "Nothing was changed."; return 0; }

    result="$(vpn_adapter_call "$tag" cred_remove "$cred")" || return 1
    latency="$(printf '%s' "$result" | awk -F'\t' '$1 == "revoked" { print $4; exit }')"
    seconds="$(printf '%s' "$result" | awk -F'\t' '$1 == "revoked" { print $5; exit }')"
    _revoke_latency_note "$latency" "$seconds" after
    return 0
}

_screen_adapter() {
    local tag="${1:-}" label="${2:-}"
    while true; do
        section "$label"
        ui_kv "State" "$(_adapter_state "$tag")"
        _adapter_filtering_notice "$tag" || true
        cat >&2 <<'MENU'

  1) Status and live connections
  2) Install / re-apply   (safe to re-run)
  3) Issue a credential
  4) List credentials
  5) Show a client config + QR
  6) Revoke a credential

  U) Remove this service
  0) Back
MENU
        local key=""
        ask_key key "Select [0-6 / U]" || return 0
        case "$key" in
            1)     _adapter_show_status "$tag" "$label" || true ;;
            2)     _adapter_install     "$tag" "$label" || true ;;
            3)     _adapter_cred_add    "$tag" "$label" || true ;;
            4)     _adapter_cred_list   "$tag"          || true ;;
            5)     _adapter_cred_config "$tag"          || true ;;
            6)     _adapter_cred_remove "$tag"          || true ;;
            u|U)   _adapter_uninstall   "$tag" "$label" || true ;;
            0|q|Q) return 0 ;;
            *)     warn "Unknown option '${key}'." ;;
        esac
        press_enter || true
    done
}

screen_protocols() {
    while true; do
        section "Tunnel services"

        if [[ ${#VPN55_ADAPTER_TAGS[@]} -eq 0 ]]; then
            info "No protocol adapters are present in this checkout."
            info "An adapter is a file in lib/ — this screen has no list to update."
            info ""
            info "Nothing was installed or changed."
            return 0
        fi

        # Each row carries its filtering level beside its state, because this is
        # the screen where the three are compared. Listing a protocol that a
        # censor blocks first alongside two that survive, with nothing to tell
        # them apart, is the interface failure docs/circumvention.md §5 names.
        #
        # The level is the adapter's own and is read live, so a WireGuard
        # service reads differently here depending on how it was installed.
        # Adapters that declare none show their state alone.
        local i tag level
        for i in "${!VPN55_ADAPTER_TAGS[@]}"; do
            tag="${VPN55_ADAPTER_TAGS[$i]}"
            if vpn_adapter_call "$tag" available >/dev/null 2>&1; then
                level="$(_filtering_label "$(_adapter_filtering_level "$tag")")"
                if [[ -n "$level" ]]; then
                    ui_kv "$(( i + 1 ))) ${VPN55_ADAPTER_LABELS[$i]}" \
                          "$(_adapter_state "$tag")  ·  ${level}"
                else
                    ui_kv "$(( i + 1 ))) ${VPN55_ADAPTER_LABELS[$i]}" "$(_adapter_state "$tag")"
                fi
            else
                ui_kv "$(( i + 1 ))) ${VPN55_ADAPTER_LABELS[$i]}" "cannot run on this host"
            fi
        done
        info ""
        info "The second column after the state is how each protocol fares on a"
        info "network that filters. Open one to read the service's own explanation."

        local key=""
        ask_key key "Select a service [1-${#VPN55_ADAPTER_TAGS[@]} / 0 to go back]" || return 0
        case "$key" in
            0|q|Q) return 0 ;;
            *)
                if [[ "$key" =~ ^[0-9]+$ ]] && (( key >= 1 )) && (( key <= ${#VPN55_ADAPTER_TAGS[@]} )); then
                    _screen_adapter "${VPN55_ADAPTER_TAGS[$(( key - 1 ))]}" \
                                    "${VPN55_ADAPTER_LABELS[$(( key - 1 ))]}" || true
                else
                    warn "Unknown option '${key}'."
                    press_enter || true
                fi ;;
        esac
    done
}

