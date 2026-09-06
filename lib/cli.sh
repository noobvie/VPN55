# shellcheck shell=bash
#
# lib/cli.sh — the non-interactive verbs, and the status stream the panel reads.
#
# Split out of vpn55.sh in Phase 9. Two audiences, neither of them a person at
# a terminal:
#
#   cli_status              the panel's ONE privileged read, behind an
#                           argument-pinned sudo rule. Its output shape is a
#                           contract with panel/lib/records.js.
#   cli_adapters / _install / _uninstall / _verify
#                           what tests/vps-acceptance.sh drives, because "run the
#                           installer three times and prove nothing drifted" has
#                           to be something a script can do.
#
# Everything human goes to stderr through ui.sh, so stdout stays clean whatever
# happens — a log line on stdout would poison the reader parsing it.
# ─── Machine-readable status, for the panel ───────────────────────────────────
# One TAB-separated record per line on STDOUT, first field the record type, so a
# reader can skip a type it does not understand. Everything human goes to stderr
# through ui.sh, so stdout is clean whatever happens.
#
#   stamp       <epoch>
#   adapter     <tag>  <label>  <available 0|1>
#   capability  <tag>  <the adapter's own capability record, verbatim>
#   service     <tag>  <state> <enabled> <listen> <since> <cred_count>
#   cred        <tag>  <cred_id> <user> <state> <address> <rx> <tx> <handshake> <endpoint> <connected>
#   credmeta    <tag>  <cred_id> <user> <state> <address> <created> <custody> <held 0|1>
#   note        <tag>  <info|warn|crit>  <message>
#   user        <name> <created> <enabled> <quota> <expires> <conn_limit> <reset> <creds>
#
# The service/cred/credmeta/note records are the adapters' own output, passed
# through untouched — this is a transport, not a second opinion. Nothing here
# reformats a value, because the panel formats for its viewer's locale and a
# number that arrived pre-formatted cannot be.
#
# ── `cred` and `credmeta` are not two views of the same thing ────────────────
#
# `cred` is LIVE state, from the running daemon: who is connected, how many
# bytes, when the last handshake was. It says nothing about a credential the
# service is not currently carrying.
#
# `credmeta` is the INVENTORY, from the adapter's `_cred_list`: when it was
# issued, who holds the key, and whether a configuration file for it still
# exists on this host. That last field is the one the self-serve portal turns
# into a decision — the adapters shred a spooled key some hours after issue, so
# `held 0` means "there is nothing left to download, this has to be rotated",
# and a portal without it would offer a download that can only fail.
#
# It costs one extra `_cred_list` per adapter per poll — three subprocess trees
# on a three-protocol host, not one per credential, which is why it is here
# rather than the artifact list the portal also wants. At a few hundred
# credentials this becomes the most expensive thing in the poll; the fix then is
# inside the adapters' `_cred_list`, not a second status mode here.
#
# ⚠ This mode changes no configuration and issues, revokes and installs nothing,
# but it is not inert: an adapter's _status sweeps its own expired key spool as
# it runs, which is how the hand-off window in docs/security-model.md §6.1 is
# actually enforced. Polling it makes that guarantee tighter, not looser. Said
# plainly here because "read-only" would otherwise be a claim this does not meet.
cli_status() {
    printf 'stamp\t%s\n' "$(date +%s)"

    local i tag label avail caps meta row
    if [[ ${#VPN55_ADAPTER_TAGS[@]} -gt 0 ]]; then
        for i in "${!VPN55_ADAPTER_TAGS[@]}"; do
            tag="${VPN55_ADAPTER_TAGS[$i]}"
            label="${VPN55_ADAPTER_LABELS[$i]}"

            if vpn_adapter_call "$tag" available >/dev/null 2>&1; then avail=1; else avail=0; fi
            printf 'adapter\t%s\t%s\t%s\n' "$tag" "$label" "$avail"

            # The capability records carry no tag of their own — they are read
            # one adapter at a time by a caller that already knows which. A
            # stream does not, so the tag is added on the way past.
            caps="$(vpn_adapter_call "$tag" capabilities 2>/dev/null || true)"
            if [[ -n "$caps" ]]; then
                while IFS= read -r row; do
                    [[ -n "$row" ]] || continue
                    printf 'capability\t%s\t%s\n' "$tag" "$row"
                done <<< "$caps"
            fi

            # An adapter that cannot answer says so as a note, in the same
            # stream. Dropping the record instead would render as a service with
            # no credentials, which is a different and much more reassuring lie.
            vpn_adapter_call "$tag" status 2>/dev/null \
                || printf 'note\t%s\tcrit\t%s\n' "$tag" \
                   "This service could not be read. What is shown for it is stale or missing, not empty."

            # The credential inventory. Captured first and printed afterwards so
            # that an adapter which fails halfway cannot leave half a record set
            # in the stream — and it is deliberately silent on failure: the
            # `note` above already covers "this service could not be read", and
            # a second crit note for the same outage would read as two problems.
            meta="$(vpn_adapter_call "$tag" cred_list 2>/dev/null || true)"
            if [[ -n "$meta" ]]; then
                while IFS= read -r row; do
                    [[ -n "$row" ]] || continue
                    printf 'credmeta\t%s\t%s\n' "$tag" "$row"
                done <<< "$meta"
            fi
        done
    fi

    while IFS= read -r row; do
        [[ -n "$row" ]] || continue
        printf 'user\t%s\n' "$row"
    done < <(users_list 2>/dev/null || true)

    return 0
}


# ─── Non-interactive verbs ────────────────────────────────────────────────────
# Everything below exists because a release has to be TESTABLE. "Run the
# installer three times and confirm nothing drifts" is not a thing a person can
# do reliably by hand across eight distributions, and a check nobody runs is not
# a check. tests/vps-acceptance.sh drives exactly these verbs.
#
# They take a TAG, which is data the registry produced — this file still learns
# no protocol name from them.
#
# ⚠ Count-guarded, like cli_status above and for the reason spelled out at
# vpn_adapter_label: ${!arr[@]+"${!arr[@]}"} does not iterate the keys of a
# POPULATED array, it attempts an indirect expansion through the array's joined
# value and errors out. This function emitting nothing is not a cosmetic bug —
# tests/vps-acceptance.sh reads it to decide what to test, and an empty answer
# ends the whole run with "no tunnel service can run on this host".
cli_adapters() {
    local i tag avail
    [[ ${#VPN55_ADAPTER_TAGS[@]} -gt 0 ]] || return 0
    for i in "${!VPN55_ADAPTER_TAGS[@]}"; do
        tag="${VPN55_ADAPTER_TAGS[$i]}"
        if vpn_adapter_call "$tag" available >/dev/null 2>&1; then avail=1; else avail=0; fi
        printf 'adapter\t%s\t%s\t%s\t%s\n' \
            "$tag" "${VPN55_ADAPTER_LABELS[$i]}" "$avail" "$(_adapter_state "$tag")"
    done
    return 0
}

# ─── The rendezvous file ──────────────────────────────────────────────────────
#
# Someone who cannot reach the website is handed a rendezvous.txt and its
# signature — over chat, on a USB stick, out of a .onion. This is what tells
# them whether to believe it, and it is the one verb that must never guess:
# a rendezvous that cannot be verified is treated as hostile, because a mirror
# list from an unknown source is the attack, not the fallback.
cli_rendezvous() {
    local file="${1:-}" sigfile="${2:-}"
    [[ -n "$file" ]] || { error "--rendezvous <file> [signature]"; return 2; }
    [[ -f "$file" ]] || { error "no such file: ${file}"; return 1; }
    [[ -n "$sigfile" ]] || sigfile="${file}.minisig"

    if [[ ! -f "$sigfile" ]]; then
        error "no signature at ${sigfile}."
        error "An unsigned mirror list is exactly what an attacker would hand you."
        error "Ask whoever gave you this file for the .minisig beside it."
        return 1
    fi

    src_rendezvous_check "$file" "$sigfile" || return 1

    success "Signed by the VPN55 release key, and in date (checked with $(src_sig_backend))."
    info ""

    # `[[ … ]] && cmd` as a bare statement returns 1 on a false test, which is
    # the shape CLAUDE.md rules out. The rule is not conditional on the current
    # caller guarding with `||`; the next one may not.
    local v
    v="$(src_rendezvous_values "$file" version | head -n1)"
    if [[ -n "$v" ]]; then ui_kv "Release" "$v"; fi
    v="$(src_rendezvous_values "$file" serial | head -n1)"
    if [[ -n "$v" ]]; then ui_kv "Serial" "$v"; fi
    v="$(src_rendezvous_values "$file" expires | head -n1)"
    if [[ -n "$v" ]]; then ui_kv "Good until" "$v"; fi

    info ""
    info "Mirrors, in order. Set one as VPN55_MIRROR:"
    while IFS= read -r v; do
        [[ -n "$v" ]] || continue
        info "    ${v}"
    done < <(src_rendezvous_values "$file" mirror)

    local onion
    onion="$(src_rendezvous_values "$file" onion | head -n1)"
    if [[ -n "$onion" ]]; then
        info ""
        info "Documentation over Tor: ${onion}"
    fi

    # The digests are the half that survives being handed a copy from anywhere
    # at all — including a mirror this file does not name.
    local any=0
    while IFS= read -r v; do
        [[ -n "$v" ]] || continue
        if [[ "$any" -eq 0 ]]; then
            info ""
            info "Check what you downloaded against these:"
            any=1
        fi
        info "    ${v}"
    done < <(src_rendezvous_values "$file" sha256)

    # A signature proves the file was not forged. It does not prove it is the
    # NEWEST one, and a replayed genuine file pinning somebody to a burned
    # mirror is the attack this cannot see on its own.
    info ""
    info "This proves the file is genuine and unexpired. It cannot prove it is the"
    info "latest — a real older copy is still real. If you have seen a higher serial"
    info "than the one above, this is an old file and something replayed it at you."
    return 0
}

# ─── Endpoints ────────────────────────────────────────────────────────────────
# docs/circumvention.md §4. The list is shared by every service that can carry
# one, so it is managed here rather than per adapter.
#
# There is no --endpoint-set. A list is added to and removed from; a "set" verb
# would make the ORDER a thing an operator retypes, and order is what decides
# which address a client tries first.
cli_endpoints() {
    local action="${1:-list}" host="${2:-}"
    case "$action" in
        list|"")
            local primary_note=0 entry
            printf 'Additional endpoints:\n'
            while IFS= read -r entry; do
                [[ -n "$entry" ]] || continue
                printf '  %s\n' "$entry"
                primary_note=1
            done < <(net_endpoints_extra)
            if [[ "$primary_note" -eq 0 ]]; then
                printf '  (none — every client config lists this host alone)\n'
            fi
            printf '\n'
            info "Each service pairs these with its own port, and lists its own"
            info "address first. Run --status to see what each one is doing with them."
            net_endpoints_explain
            return 0 ;;
        add)
            [[ -n "$host" ]] || { error "--endpoint-add <host>"; return 2; }
            net_endpoints_add "$host" || return 1
            return 0 ;;
        remove)
            [[ -n "$host" ]] || { error "--endpoint-remove <host>"; return 2; }
            net_endpoints_remove "$host" || return 1
            return 0 ;;
        *)
            error "unknown endpoint action '${action}'."
            return 2 ;;
    esac
}

_cli_require_tag() {
    local tag="${1:-}"
    if [[ -z "$tag" ]]; then
        error "this option needs a service tag. Run --adapters to list them."
        return 2
    fi
    if ! vpn_adapter_known "$tag"; then
        error "no adapter registered under '${tag}'. Run --adapters to list them."
        return 2
    fi
    return 0
}

cli_install() {
    local tag="${1:-}" rc=0
    _cli_require_tag "$tag" || return $?
    _adapter_install "$tag" "$(vpn_adapter_label "$tag" || true)" || rc=1
    return "$rc"
}

# Uninstall keeps its confirmation. ask_proceed declines when there is no
# terminal, so an unattended caller has to say VPN55_ASSUME_YES=1 out loud —
# which is the difference between automating a teardown and tearing down because
# a cron job ran the wrong line.
cli_uninstall() {
    local tag="${1:-}" rc=0
    _cli_require_tag "$tag" || return $?
    _adapter_uninstall "$tag" "$(vpn_adapter_label "$tag" || true)" || rc=1
    return "$rc"
}

# Has anything in this installation been altered since it was fetched?
#
# Two questions, answered in the right order and reported separately, because
# they fail differently and an operator needs to know which one did.
#
#   1. Is the file list itself genuine?  The signature answers that, and
#      src_fetch downloads MANIFEST.sha256.minisig into the tree alongside the
#      manifest — so on any copy that came from a mirror it is sitting right
#      there. Not checking it was leaving the harder half of the answer unread
#      on disk.
#   2. Do the files match the list?  That is the corruption-and-accident check,
#      and on its own it proves nothing about provenance: whoever could rewrite
#      a file could rewrite the line about it. docs/distribution.md §5.
#
# Question 1 is a WARNING and not a failure when there is no key compiled in or
# no signature beside the manifest, for the same reason src_fetch treats it that
# way: the project has no release key yet, and a --verify that always failed
# would be a --verify nobody runs. It is a hard failure the moment the signature
# is present and wrong, which is the case that matters.
cli_verify() {
    if src_is_git_checkout "$VPN55_ROOT"; then
        info "This is a git checkout — ask git instead:"
        info "    git -C ${VPN55_ROOT} status --short"
        return 0
    fi
    if [[ ! -f "$VPN55_ROOT/$VPN55_MANIFEST" ]]; then
        error "no ${VPN55_MANIFEST} in ${VPN55_ROOT} — this copy did not come from a mirror."
        return 1
    fi

    local manifest="$VPN55_ROOT/$VPN55_MANIFEST" sig="$VPN55_ROOT/${VPN55_MANIFEST}.minisig"
    if [[ -s "$sig" && -n "${VPN55_PUBKEY:-}" ]]; then
        if src_minisign_verify "$manifest" "$sig"; then
            success "The file list is signed by the VPN55 release key (via $(src_sig_backend))."
        else
            error "${VPN55_MANIFEST} is NOT signed by the VPN55 release key."
            error "Do not trust this installation. Re-install from a mirror you can reach:"
            error "    vpn55.sh --update"
            return 1
        fi
    elif [[ -z "${VPN55_PUBKEY:-}" ]]; then
        warn "No release key is built into this copy, so the file list's signature"
        warn "cannot be checked. What follows is a corruption check only."
    else
        warn "No ${VPN55_MANIFEST}.minisig beside the file list, so its provenance"
        warn "cannot be checked. What follows is a corruption check only."
    fi

    if src_manifest_verify "$VPN55_ROOT"; then
        success "Every file matches ${VPN55_MANIFEST} — revision $(src_revision "$VPN55_ROOT")."
        return 0
    fi
    error "This installation does not match its own file list."
    return 1
}



# ─── Backup and restore ───────────────────────────────────────────────────────
# Two verbs with their own small argument loops, because both take options and
# the dispatcher in vpn55.sh takes one positional after the verb and no more.
#
# ⚠ Neither of these is reachable from the panel. There is no route, no vpnctl
# verb and no sudoers rule that leads here, and deploy/vpn55-panel.service puts
# /var/backups/vpn55 in InaccessiblePaths=. A panel compromise costs the seven
# write verbs it already costs; it must not also cost the CA key in one file.
# If a future release wants a "download the backup" button, the answer is no —
# read the passphrase note in lib/core_backup.sh first.
cli_backup() {
    local outdir="$VPN55_BACKUP_DIR"
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --passfile)
                if [[ -z "${2:-}" ]]; then error "--passfile needs a path."; return 2; fi
                VPN55_BACKUP_PASSFILE="$2"; shift 2 ;;
            --out)
                if [[ -z "${2:-}" ]]; then error "--out needs a directory."; return 2; fi
                outdir="$2"; shift 2 ;;
            *)
                error "unknown argument '${1}' after --backup."
                info  "Usage: vpn55.sh --backup [--passfile <path>] [--out <dir>]"
                return 2 ;;
        esac
    done
    bak_create "$outdir" || return 1
    return 0
}

# The archive is a positional; everything else is a flag. --force is spelled out
# rather than assumed, because the thing it overrides is "this host already has
# a different certificate authority" — which is the one refusal here that is
# protecting a live fleet rather than protecting the operator from a typo.
cli_restore() {
    local archive="" force=0
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --passfile)
                if [[ -z "${2:-}" ]]; then error "--passfile needs a path."; return 2; fi
                VPN55_BACKUP_PASSFILE="$2"; shift 2 ;;
            --force) force=1; shift ;;
            -*)
                error "unknown argument '${1}' after --restore."
                info  "Usage: vpn55.sh --restore <archive> [--passfile <path>] [--force]"
                return 2 ;;
            *)
                if [[ -n "$archive" ]]; then
                    error "one archive at a time."
                    return 2
                fi
                archive="$1"; shift ;;
        esac
    done

    if [[ -z "$archive" ]]; then
        error "which archive? Run --backup-list to see what is on this host."
        info  "Usage: vpn55.sh --restore <archive> [--passfile <path>] [--force]"
        return 2
    fi

    bak_restore "$archive" "$force" || return 1
    return 0
}
