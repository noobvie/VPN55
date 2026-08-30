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
#   cred        <tag>  <cred_id> <user> <state> <address> <rx> <tx> <handshake> <endpoint>
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
cli_adapters() {
    local i tag avail
    for i in ${!VPN55_ADAPTER_TAGS[@]+"${!VPN55_ADAPTER_TAGS[@]}"}; do
        tag="${VPN55_ADAPTER_TAGS[$i]}"
        if vpn_adapter_call "$tag" available >/dev/null 2>&1; then avail=1; else avail=0; fi
        printf 'adapter\t%s\t%s\t%s\t%s\n' \
            "$tag" "${VPN55_ADAPTER_LABELS[$i]}" "$avail" "$(_adapter_state "$tag")"
    done
    return 0
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

# Has anything in this installation been altered since it was fetched? Same
# caveat as everywhere else: it proves the tree matches its own manifest, which
# is an integrity check against corruption and accident, not against someone who
# could rewrite both. docs/distribution.md §5.
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
    if src_manifest_verify "$VPN55_ROOT"; then
        success "Every file matches ${VPN55_MANIFEST} — revision $(src_revision "$VPN55_ROOT")."
        return 0
    fi
    error "This installation does not match its own file list."
    return 1
}

