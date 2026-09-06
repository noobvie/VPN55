# shellcheck shell=bash
#
# lib/core_backup.sh — the one archive that has to outlive the host.
#
# ── Why this exists ──────────────────────────────────────────────────────────
# Four things on a VPN55 host cannot be regenerated and are stored nowhere else
# on earth: the CA private key, the WireGuard server key and its peer table, the
# OpenVPN tls-crypt key, and the user register. Losing the box loses all four at
# once, and every credential on the fleet dies with them. Until this file
# existed there was no backup of any of it — the uninstall screen said so out
# loud, which was honest and was not a plan.
#
# docs/backup.md is the design. This is the smallest thing that is actually
# honest, and it is deliberately not a disaster-recovery product.
#
# ── Three rules that shape every line below ─────────────────────────────────
#
# 1. MEMBERS ARE NAMED, NEVER SWEPT. A directory sweep of the PKI would
#    preserve a client private key that an interrupted issue left behind — the
#    one thing this project shreds on purpose — into an archive that outlives
#    the revocation. So the member list is explicit, and `_bak_guard` refuses
#    the whole backup if a named member turns out to be a credential in the
#    user register rather than a server.
#
# 2. THIS FILE LEARNS NO PROTOCOL NAMES. /etc/wireguard, /etc/openvpn and
#    /etc/swanctl do not appear here. Each adapter answers `backup_paths` with
#    the paths it owns, the same way it answers every other question, so a
#    fourth protocol is still a file you drop in. An adapter that does not
#    implement the verb is WARNED about loudly rather than skipped quietly:
#    "your protocol's state is not in the backup" is not a footnote.
#
# 3. THE PANEL MUST NOT BE ABLE TO READ THE RESULT. There is no panel route, no
#    vpnctl verb and no sudoers rule that reaches anything in this file, and
#    deploy/vpn55-panel.service names /var/backups/vpn55 in InaccessiblePaths=
#    so the exclusion survives a mistake about file modes. A panel compromise
#    costs the seven verbs it already costs; it must not also hand over the CA
#    key in one file.
#
# ── Not coupled to Grin Node Toolkit ────────────────────────────────────────
# The passphrase-off-argv trick and the one-archive-per-host-per-day naming were
# read from that project's gbe_*/gbp_* engine and are good ideas. Nothing is
# sourced, shared or imported: the threat models differ (see the passphrase note
# at _bak_passphrase) and a shared lib would have to serve both.
#
# ── errexit ──────────────────────────────────────────────────────────────────
# Reached from ||-guarded callers, so errexit is off for the whole body. Every
# create/copy/move/delete is guarded on its own line. See CLAUDE.md.
#
# Sourced, not executed.

[[ -n "${VPN55_BACKUP_LOADED:-}" ]] && return 0
VPN55_BACKUP_LOADED=1

: "${VPN55_ETC:=/etc/vpn55}"
: "${VPN55_BACKUP_DIR:=/var/backups/vpn55}"
: "${VPN55_BACKUP_CONF:=$VPN55_ETC/backup.conf}"

# The panel's state directory. Named here rather than asked of the panel,
# because a restore has to work on a host where the panel is not installed.
: "${VPN55_PANEL_STATE:=/var/lib/vpn55/panel}"

# PBKDF2 rounds. Raising this does not break an existing archive — openssl
# records the parameters it used in the file header — but LOWERING it does not
# help either: the count that matters is the one the archive was written with.
: "${VPN55_BACKUP_ITER:=600000}"

# The format tag in the manifest header. Bump it only for a change an older
# restore path could not read; the restore refuses an unknown tag rather than
# guessing at a layout.
VPN55_BACKUP_FORMAT="vpn55-backup-1"

# Passphrase floor. Twelve is not a policy claim, it is the length below which
# 600k PBKDF2 rounds stop being the thing standing between a stolen archive and
# the CA key.
: "${VPN55_BACKUP_PASS_MIN:=12}"

# Set by --passfile. Read as a whole first line, so a passphrase may contain
# spaces; the trailing newline is stripped and nothing else is.
VPN55_BACKUP_PASSFILE="${VPN55_BACKUP_PASSFILE:-}"


# ─── Small helpers ────────────────────────────────────────────────────────────

bak_available() {
    local missing="" tool
    for tool in openssl tar; do
        command -v "$tool" >/dev/null 2>&1 || missing="${missing} ${tool}"
    done
    if ! command -v sha256sum >/dev/null 2>&1 && ! command -v shasum >/dev/null 2>&1; then
        missing="${missing} sha256sum"
    fi
    if [[ -n "$missing" ]]; then
        error "backup needs these and they are not installed:${missing}"
        return 1
    fi
    return 0
}

_bak_sha256() {
    local f="${1:-}" out
    [[ -f "$f" ]] || return 1
    if command -v sha256sum >/dev/null 2>&1; then
        out="$(sha256sum "$f" 2>/dev/null)" || return 1
    else
        out="$(shasum -a 256 "$f" 2>/dev/null)" || return 1
    fi
    printf '%s' "${out%% *}"
}

# Mode and ownership travel WITH each member rather than being applied from a
# table at restore time. A table is a second place to describe the same fact,
# and the copy that goes stale is the one that puts ca.key back at 0644.
_bak_mode()  { stat -c '%a' "${1:-}" 2>/dev/null || printf '0600'; }
_bak_owner() { stat -c '%U:%G' "${1:-}" 2>/dev/null || printf 'root:root'; }

# An archive path is the absolute path with its leading slash removed, so a tar
# extracted anywhere lands under the directory it went into and never at /.
# Restore composes each destination itself and never trusts a path out of the
# archive — see the refusal in _bak_restore_from.
_bak_rel() { printf '%s' "${1#/}"; }

_bak_hostname() {
    local h
    h="$(hostname 2>/dev/null)" || h=""
    [[ -n "$h" ]] || h="unknown"
    # A hostname becomes a filename. Anything outside this set is replaced
    # rather than escaped.
    printf '%s' "$h" | tr -c 'A-Za-z0-9._-' '-'
}

bak_archive_name() {
    printf 'vpn55-%s-%s.tar.gz.enc' "$(_bak_hostname)" "$(date -u +%Y-%m-%d)"
}


# ─── The passphrase, and why it is not stored on this host ───────────────────
#
# Grin Node Toolkit keeps its backup key in a mode-600 file so cron can run
# unattended. That is right for its threat model and wrong for this one: the
# host is the thing you are protecting against LOSING, so a key stored on it is
# not a second copy of anything — whoever ends up with the disk ends up with
# both halves.
#
# So there is no schedule by default and no key on the box by default. An
# operator who wants either says so out loud with --passfile, and is told once,
# in plain words, what they have just accepted.
#
# Sources, in order:
#   --passfile <path>        the file's first line
#   VPN55_BACKUP_PASS        environment; for automation and the acceptance
#                            harness. Root can read /proc/<pid>/environ, so this
#                            is no worse than the file and no better.
#   the terminal             read -r -s, twice when creating
#
# It is never an argument to anything. /proc/<pid>/cmdline is world-readable for
# the life of the process, which is the whole reason openssl is fed on stdin.
_bak_passphrase() {
    local mode="${1:-open}" pass="" again="" pmode

    if [[ -n "$VPN55_BACKUP_PASSFILE" ]]; then
        if [[ ! -r "$VPN55_BACKUP_PASSFILE" ]]; then
            error "cannot read the passphrase file ${VPN55_BACKUP_PASSFILE}"
            return 1
        fi
        pmode="$(_bak_mode "$VPN55_BACKUP_PASSFILE")"
        case "$pmode" in
            600|400|0600|0400) : ;;
            *) warn "${VPN55_BACKUP_PASSFILE} is mode ${pmode} — anyone who can read it can read the CA key." ;;
        esac
        IFS= read -r pass < "$VPN55_BACKUP_PASSFILE" || pass=""
        if [[ -z "$pass" ]]; then
            error "the passphrase file is empty."
            return 1
        fi
        if [[ "$mode" == "create" ]]; then
            warn "This archive's passphrase is stored on this host, in ${VPN55_BACKUP_PASSFILE}."
            warn "Whoever takes this machine now has both the archive and the key to it."
        fi
        printf '%s' "$pass"
        return 0
    fi

    if [[ -n "${VPN55_BACKUP_PASS:-}" ]]; then
        printf '%s' "$VPN55_BACKUP_PASS"
        return 0
    fi

    if ! ui_interactive; then
        error "no passphrase. Use --passfile <path>, or run this where you can type one."
        return 1
    fi

    printf 'Passphrase for the archive: ' >&2
    IFS= read -r -s pass || { printf '\n' >&2; return 1; }
    printf '\n' >&2

    if [[ "$mode" == "create" ]]; then
        if (( ${#pass} < VPN55_BACKUP_PASS_MIN )); then
            error "too short — at least ${VPN55_BACKUP_PASS_MIN} characters."
            error "This is the only thing between a stolen archive and the CA key."
            return 1
        fi
        printf 'Again: ' >&2
        IFS= read -r -s again || { printf '\n' >&2; return 1; }
        printf '\n' >&2
        if [[ "$pass" != "$again" ]]; then
            error "they do not match."
            return 1
        fi
        warn "This passphrase is written nowhere on this host and cannot be recovered."
        warn "An archive whose passphrase is lost is not a backup."
    fi

    printf '%s' "$pass"
    return 0
}

# ─── Encrypting ──────────────────────────────────────────────────────────────
#
# openssl enc -aes-256-cbc -pbkdf2 -iter N -salt, passphrase piped to STDIN from
# a bash builtin — never in argv, never through a temporary file. `printf` is a
# builtin, so no process ever exists whose command line is the passphrase, and
# nothing is written to disk for another process to read.
#
# ── Why stdin and not `-pass fd:3` ──────────────────────────────────────────
# fd:3 is what Grin Node Toolkit uses and what the first draft of docs/backup.md
# specified. It is equally safe, and it is NOT portable: openssl built for
# Windows has no `fd:` handler and answers
#
#     Invalid password argument, starting with "fd:"
#
# which turned every local test of this file into "encryption failed". That
# matters more than it looks. Nothing in this repository has ever run on a VPS,
# so a channel the maintainer cannot exercise on their own machine is a channel
# whose first real test would be somebody's disaster recovery. `-pass stdin`
# behaves identically on Linux and can be tested here.
#
# The archive is read from -in and written to -out, so stdin is free for the
# passphrase and nothing has to share a pipe.
#
# ── age is deliberately NOT supported ───────────────────────────────────────
# docs/backup.md's first draft preferred `age` where present. It cannot serve
# this design: age's passphrase mode requires a terminal for entry, so it cannot
# cover the unattended path the same document promises, and its non-interactive
# path is identity files — a different key-management story altogether. Two key
# models in one archive format is worse than one, and "the header records which
# was used" is not a substitute for a restore path that always works.
_bak_encrypt() {
    local src="${1:-}" dst="${2:-}" pass="${3:-}"
    [[ -f "$src" ]] || { error "_bak_encrypt: no input"; return 1; }

    if ! printf '%s\n' "$pass" | openssl enc -aes-256-cbc -md sha512 \
            -pbkdf2 -iter "$VPN55_BACKUP_ITER" -salt \
            -in "$src" -out "$dst" -pass stdin 2>/dev/null; then
        error "encryption failed — nothing was written."
        fs_remove "$dst" || true
        return 1
    fi
    chmod 0600 "$dst" || { error "cannot set mode on $dst"; return 1; }
    return 0
}

_bak_decrypt() {
    local src="${1:-}" dst="${2:-}" pass="${3:-}"
    [[ -f "$src" ]] || { error "no archive at ${src}"; return 1; }

    if ! printf '%s\n' "$pass" | openssl enc -d -aes-256-cbc -md sha512 \
            -pbkdf2 -iter "$VPN55_BACKUP_ITER" \
            -in "$src" -out "$dst" -pass stdin 2>/dev/null; then
        error "cannot decrypt ${src##*/} — wrong passphrase, or the file is damaged."
        fs_remove "$dst" || true
        return 1
    fi
    return 0
}


# ─── What goes in ─────────────────────────────────────────────────────────────
#
# Named, one absolute path per line. A path that does not exist is skipped in
# silence: a host with no OpenVPN has no OpenVPN state, and that is the normal
# case rather than a fault.
#
# ── The server private keys ARE included, and that is a correction ──────────
# docs/backup.md's first draft said "no key under pki/private except ca.key".
# Applied literally that breaks the restore it promises: the OpenVPN adapter's
# _ovpn_server_cert_ensure skips reissue when the server certificate is present
# and valid, so an archive holding the certificate but not its key restores a
# host whose daemon has a certificate it cannot use and whose installer sees no
# reason to fix it.
#
# The rule's PURPOSE is "no client private key, ever", and its mechanism is "an
# explicit list, never a glob". Both survive: each adapter names exactly one key
# file, by the CN it recorded for its own server certificate, and _bak_guard
# refuses the whole run if any named key turns out to belong to a credential in
# the user register.
_bak_members() {
    local p

    # The certificate authority, and the database without which revocation
    # cannot be reconstructed and a reissued serial can collide.
    for p in \
        "$VPN55_PKI_CA_CERT" \
        "$VPN55_PKI_CA_KEY" \
        "$VPN55_PKI_INDEX" \
        "${VPN55_PKI_INDEX}.attr" \
        "$VPN55_PKI_SERIAL" \
        "$VPN55_PKI_CRLNUM" \
        "$VPN55_PKI_CRL" \
        "$VPN55_PKI_CONF"
    do
        [[ -f "$p" ]] && printf '%s\n' "$p"
    done

    # The public half of every live credential. Nothing secret, and without it a
    # restored authority cannot say what it has issued.
    if [[ -d "$VPN55_PKI_ISSUED" ]]; then
        for p in "$VPN55_PKI_ISSUED"/*.crt; do
            [[ -f "$p" ]] && printf '%s\n' "$p"
        done
    fi

    # The register: identity, quota, expiry, device cap.
    if [[ -d "$VPN55_USER_DIR" ]]; then
        for p in "$VPN55_USER_DIR"/*.conf "$VPN55_USER_DIR"/*.creds; do
            [[ -f "$p" ]] && printf '%s\n' "$p"
        done
    fi

    # Which address each credential was pinned to. Losing this hands one address
    # to two people the next time both reconnect.
    [[ -f "$VPN55_POOL_CONF" ]] && printf '%s\n' "$VPN55_POOL_CONF"
    if [[ -d "$VPN55_LEASE_DIR" ]]; then
        for p in "$VPN55_LEASE_DIR"/*; do
            [[ -f "$p" ]] && printf '%s\n' "$p"
        done
    fi

    # The panel: its settings, its administrator hashes and TOTP secrets, and
    # the accumulated traffic totals. Every service on the host resets its own
    # counters, so state.json is the only place lifetime usage exists — restore
    # a host without it and every user's quota silently starts again at zero.
    for p in \
        "$VPN55_ETC/panel.conf" \
        "$VPN55_PANEL_STATE/admins.json" \
        "$VPN55_PANEL_STATE/state.json"
    do
        [[ -f "$p" ]] && printf '%s\n' "$p"
    done

    # Everything protocol-specific, from the adapters themselves.
    _bak_adapter_members
    return 0
}

# Each adapter's own answer. The registry is iterated; no protocol is named.
_bak_adapter_members() {
    local i tag out row
    # Count-guarded rather than ${!arr[@]+…} — see vpn_adapter_label in
    # core_adapters.sh for why that idiom skips a POPULATED array entirely.
    [[ ${#VPN55_ADAPTER_TAGS[@]} -gt 0 ]] || return 0
    for i in "${!VPN55_ADAPTER_TAGS[@]}"; do
        tag="${VPN55_ADAPTER_TAGS[$i]}"

        if ! declare -F "vpn_${tag}_backup_paths" >/dev/null 2>&1; then
            # Loud, not quiet. This is "your protocol's state is not in the
            # backup" — exactly the sentence that must not be a footnote
            # discovered on restore day.
            warn "adapter '${tag}' does not implement backup_paths — NOTHING of its state is in this archive."
            continue
        fi

        out="$(vpn_adapter_call "$tag" backup_paths 2>/dev/null)" || {
            warn "adapter '${tag}' could not list its backup paths — its state is NOT in this archive."
            continue
        }
        while IFS= read -r row; do
            [[ -n "$row" ]] || continue
            [[ -f "$row" ]] || continue
            printf '%s\n' "$row"
        done <<< "$out"
    done
    return 0
}

# ─── Archived, never restored ────────────────────────────────────────────────
# The firewall ledger and the backend record describe rules on THAT host. A
# replacement machine has a different interface name, a different provider
# firewall and possibly a different backend; replaying them claims rules the box
# never had, and the ledger is what an uninstall trusts when deciding what it
# may remove. So they travel for forensics — "what did the lost host look like"
# is a real question — in a part of the archive the restore path never places.
_bak_reference_members() {
    local p
    for p in "$VPN55_NET_CONF" "$VPN55_FW_STATE"; do
        [[ -f "$p" ]] && printf '%s\n' "$p"
    done
    return 0
}

# ─── The guard ───────────────────────────────────────────────────────────────
# The enforcement half of "named, never swept". The list above is written by
# hand here and by three adapters over there; this is what makes a mistake in
# any of them fail the backup rather than ship a client key.
_bak_guard() {
    local members="${1:-}" p base cn bad=0

    while IFS= read -r p; do
        [[ -n "$p" ]] || continue

        # A hand-off spool holds client artifacts with a deliberately short
        # life. Nothing from one may be preserved past it.
        #
        # ⚠ The rule is the SPOOL, not a list of file extensions, and that is a
        # deliberate narrowing. An earlier version also refused three artifact
        # suffixes by name — which is protocol vocabulary in a file forbidden to
        # have any, and it slipped past CI's leak check only because the line
        # happened to begin with a `*` that the check reads as a comment marker.
        # Every adapter puts its hand-off artifacts in its own spool, because the
        # key-expiry sweep that erases them depends on it; so the spool is both
        # the neutral test and the accurate one. An adapter that writes a client
        # artifact somewhere else has broken a different rule first.
        case "$p" in
            */spool/*)
                error "refusing to archive a client artifact: ${p}"
                bad=1
                continue ;;
        esac

        case "$p" in
            "$VPN55_PKI_PRIVATE"/*)
                base="${p##*/}"
                [[ "$base" == "ca.key" ]] && continue
                cn="${base%.key}"
                if users_cred_find "$cn" >/dev/null 2>&1; then
                    error "refusing to archive ${base}: '${cn}' is a credential in the user register, not a server."
                    error "Client private keys are shredded after hand-off on purpose and must never outlive it."
                    bad=1
                fi ;;
        esac
    done <<< "$members"

    if [[ "$bad" -eq 1 ]]; then
        error "Backup ABANDONED. Nothing was written."
        return 1
    fi
    return 0
}


# ─── Create ───────────────────────────────────────────────────────────────────
# bak_create [output_dir]
bak_create() {
    local outdir="${1:-$VPN55_BACKUP_DIR}"
    distro_require_root || return 1
    bak_available || return 1

    local members reference
    members="$(_bak_members)" || { error "cannot resolve what to back up"; return 1; }
    if [[ -z "$members" ]]; then
        error "there is nothing to back up — no CA, no users, no adapter state."
        return 1
    fi
    reference="$(_bak_reference_members)" || reference=""

    _bak_guard "$members" || return 1

    local pass
    pass="$(_bak_passphrase create)" || return 1

    fs_ensure_dir "$outdir" 0700 || return 1

    local tmp
    tmp="$(mktemp -d "${TMPDIR:-/tmp}/vpn55-backup.XXXXXX")" \
        || { error "cannot create a working directory"; return 1; }
    chmod 0700 "$tmp" || { error "cannot secure $tmp"; rm -rf "$tmp" 2>/dev/null || true; return 1; }

    local rc=0
    _bak_create_into "$tmp" "$outdir" "$members" "$reference" "$pass" || rc=1

    # The staging tree held a copy of the CA key. It is shredded whether or not
    # the run succeeded, and before the directory itself goes.
    _bak_scrub_tree "$tmp" || true
    rm -rf "$tmp" 2>/dev/null || true
    return "$rc"
}

_bak_create_into() {
    local tmp="$1" outdir="$2" members="$3" reference="$4" pass="$5"
    local stage="$tmp/stage" root="$tmp/stage/root" refdir="$tmp/stage/reference"
    local manifest="$tmp/stage/MANIFEST"

    fs_ensure_dir "$stage"  0700 || return 1
    fs_ensure_dir "$root"   0700 || return 1
    fs_ensure_dir "$refdir" 0700 || return 1

    {
        printf '# %s\n' "$VPN55_BACKUP_FORMAT"
        printf '# version %s\n' "${VPN55_VERSION:-unknown}"
        printf '# host %s\n'    "$(_bak_hostname)"
        printf '# created %s\n' "$(fs_now)"
        printf '# cipher aes-256-cbc pbkdf2 %s\n' "$VPN55_BACKUP_ITER"
    } > "$manifest" || { error "cannot write the manifest"; return 1; }

    local p rel dest count=0
    while IFS= read -r p; do
        [[ -n "$p" && -f "$p" ]] || continue
        rel="$(_bak_rel "$p")"
        dest="$root/$rel"
        mkdir -p "${dest%/*}" || { error "cannot stage ${rel}"; return 1; }
        cp -p "$p" "$dest"    || { error "cannot copy ${p}"; return 1; }
        printf 'file\t%s\t%s\t%s\t%s\n' \
            "$(_bak_sha256 "$p")" "$(_bak_mode "$p")" "$(_bak_owner "$p")" "$rel" >> "$manifest" \
            || { error "cannot record ${rel}"; return 1; }
        count=$(( count + 1 ))
    done <<< "$members"

    if [[ -n "$reference" ]]; then
        while IFS= read -r p; do
            [[ -n "$p" && -f "$p" ]] || continue
            rel="$(_bak_rel "$p")"
            dest="$refdir/$rel"
            mkdir -p "${dest%/*}" || { error "cannot stage ${rel}"; return 1; }
            cp -p "$p" "$dest"    || { error "cannot copy ${p}"; return 1; }
            printf 'ref\t%s\t%s\t%s\t%s\n' \
                "$(_bak_sha256 "$p")" "$(_bak_mode "$p")" "$(_bak_owner "$p")" "$rel" >> "$manifest" \
                || { error "cannot record ${rel}"; return 1; }
        done <<< "$reference"
    fi
    chmod 0600 "$manifest" || { error "cannot set mode on the manifest"; return 1; }

    local tar="$tmp/payload.tar.gz"
    if ! ( umask 077; tar -czf "$tar" -C "$stage" MANIFEST root reference 2>/dev/null; ); then
        error "cannot build the archive."
        return 1
    fi

    local name out
    name="$(bak_archive_name)"
    out="$outdir/$name"

    # A same-day second run replaces the first rather than accumulating. One
    # archive per host per day is the naming contract; a directory that grows a
    # file on every run is a disk that fills silently on the very host this was
    # meant to protect.
    _bak_encrypt "$tar" "${out}.new" "$pass" || return 1
    mv -f "${out}.new" "$out" \
        || { error "cannot place ${out}"; fs_remove "${out}.new" || true; return 1; }

    fs_shred "$tar" || true

    success "Backup written: ${out}"
    info "${count} files · $(stat -c '%s' "$out" 2>/dev/null || printf '?') bytes · AES-256, ${VPN55_BACKUP_ITER} PBKDF2 rounds"
    info "Restore with:  vpn55.sh --restore ${out}"

    bak_push "$out" || true
    return 0
}

# Shred every file under a tree before removing it. The staging tree held the CA
# key; `rm -rf` alone would leave those bytes recoverable on the very host whose
# loss this whole file is about.
_bak_scrub_tree() {
    local dir="${1:-}" f
    [[ -n "$dir" && -d "$dir" ]] || return 0
    while IFS= read -r f; do
        [[ -n "$f" ]] || continue
        fs_shred "$f" || true
    done < <(find "$dir" -type f 2>/dev/null || true)
    return 0
}


# ─── Off the host ─────────────────────────────────────────────────────────────
# An archive that never leaves the box protects against nothing this file is
# about. The push is optional and its ABSENCE is reported as an absence — never
# folded into the success line above, because "backup written" printed beside a
# push that silently did not happen is how a fleet discovers it has no off-host
# copy on the day the host is gone.
#
# Configure with one line in /etc/vpn55/backup.conf:
#     scp_dest=user@host:/path/to/dir
# Authentication is the operator's own SSH key. Nothing here creates one, and
# nothing here stores a password.
bak_push() {
    local archive="${1:-}" dest
    [[ -f "$archive" ]] || return 1

    dest="$(fs_conf_get "$VPN55_BACKUP_CONF" scp_dest 2>/dev/null)" || dest=""
    if [[ -z "$dest" ]]; then
        warn "This archive is ONLY on this host. Losing the host still loses the CA."
        info "Copy it somewhere else now, or set scp_dest= in ${VPN55_BACKUP_CONF}."
        return 1
    fi

    if ! command -v scp >/dev/null 2>&1; then
        warn "scp_dest is set but scp is not installed — the archive did NOT leave this host."
        return 1
    fi

    info "Pushing to ${dest} …"
    if scp -q -o BatchMode=yes "$archive" "$dest" >/dev/null 2>&1; then
        success "Copied off-host to ${dest}."
        return 0
    fi
    warn "The push to ${dest} FAILED — the archive is only on this host."
    warn "Check the destination and the SSH key for it, then copy it by hand."
    return 1
}


# ─── List ─────────────────────────────────────────────────────────────────────
bak_list() {
    if [[ ! -d "$VPN55_BACKUP_DIR" ]]; then
        info "No backups on this host — ${VPN55_BACKUP_DIR} does not exist."
        return 0
    fi
    local f found=0
    for f in "$VPN55_BACKUP_DIR"/*.tar.gz.enc; do
        [[ -f "$f" ]] || continue
        found=1
        printf '%s\t%s\t%s\n' \
            "${f##*/}" \
            "$(stat -c '%s' "$f" 2>/dev/null || printf '?')" \
            "$(stat -c '%y' "$f" 2>/dev/null | cut -d. -f1 || printf '?')"
    done
    if [[ "$found" -eq 0 ]]; then
        info "No backups in ${VPN55_BACKUP_DIR}."
    fi
    return 0
}


# ─── Restore ──────────────────────────────────────────────────────────────────
#
# The order matters and is not negotiable:
#
#   1. decrypt into a 0700 temp directory
#   2. verify the manifest and EVERY digest, before one file is placed. A
#      member that fails its digest abandons the whole restore, because a
#      partial PKI is worse than none: an index.txt that disagrees with the
#      certificates it describes issues colliding serials forever.
#   3. refuse a host that already has a DIFFERENT certificate authority
#   4. place, with each member's recorded mode and ownership
#   5. regenerate the CRL — the archived one may be past its nextUpdate, and a
#      strict verifier rejects every user on an expired list
#   6. say what was NOT restored
#
# ── This does not stop the daemons, and says so ─────────────────────────────
# The adapter contract has `restart` and no `stop`, and inventing one here would
# mean this file learning unit names — the one thing the registry exists to
# prevent. Restore is for a REPLACEMENT host, where nothing is running yet. On a
# live host the files land under running daemons that read them at start-up, so
# nothing is corrupted, but a service will keep serving its old view until it is
# restarted; the closing report says which command does that.
#
# bak_restore <archive> [force]
bak_restore() {
    local archive="${1:-}" force="${2:-0}"
    distro_require_root || return 1
    bak_available || return 1

    [[ -n "$archive" ]] || { error "vpn55.sh --restore <archive>"; return 1; }
    [[ -f "$archive" ]] || { error "no archive at ${archive}"; return 1; }

    local pass
    pass="$(_bak_passphrase open)" || return 1

    local tmp
    tmp="$(mktemp -d "${TMPDIR:-/tmp}/vpn55-restore.XXXXXX")" \
        || { error "cannot create a working directory"; return 1; }
    chmod 0700 "$tmp" || { error "cannot secure $tmp"; rm -rf "$tmp" 2>/dev/null || true; return 1; }

    local rc=0
    _bak_restore_from "$tmp" "$archive" "$pass" "$force" || rc=1

    _bak_scrub_tree "$tmp" || true
    rm -rf "$tmp" 2>/dev/null || true
    return "$rc"
}

_bak_restore_from() {
    local tmp="$1" archive="$2" pass="$3" force="$4"
    local tar="$tmp/payload.tar.gz" x="$tmp/x"

    _bak_decrypt "$archive" "$tar" "$pass" || return 1

    fs_ensure_dir "$x" 0700 || return 1
    if ! tar -xzf "$tar" -C "$x" 2>/dev/null; then
        error "the archive decrypted but could not be unpacked."
        return 1
    fi
    fs_shred "$tar" || true

    local manifest="$x/MANIFEST"
    [[ -f "$manifest" ]] || { error "no MANIFEST in the archive — this is not a VPN55 backup."; return 1; }

    local fmt
    fmt="$(awk '/^# / { print $2; exit }' "$manifest" 2>/dev/null)" || fmt=""
    if [[ "$fmt" != "$VPN55_BACKUP_FORMAT" ]]; then
        error "this archive is format '${fmt:-unknown}'; this VPN55 reads '${VPN55_BACKUP_FORMAT}'."
        error "Restore it with the version that wrote it."
        return 1
    fi

    section "Restoring from ${archive##*/}"
    local line
    while IFS= read -r line; do
        case "$line" in
            '# version '*|'# host '*|'# created '*) info "${line#\# }" ;;
        esac
    done < "$manifest"

    # ── Verify everything first ──────────────────────────────────────────────
    local kind want mode owner rel src got bad=0 n=0
    while IFS=$'\t' read -r kind want mode owner rel; do
        case "$kind" in file|ref) : ;; *) continue ;; esac
        [[ -n "$rel" ]] || continue

        # A path out of an archive is untrusted input. A leading slash and a
        # `..` segment are the two shapes that let a tar write outside the tree
        # it was extracted into; both are refused rather than normalised.
        case "$rel" in
            /*|../*|*/../*|*/..)
                error "refusing a suspicious path in the archive: ${rel}"
                bad=1
                continue ;;
        esac

        if [[ "$kind" == "ref" ]]; then src="$x/reference/$rel"; else src="$x/root/$rel"; fi
        if [[ ! -f "$src" ]]; then
            error "the manifest lists ${rel} but the archive does not contain it."
            bad=1
            continue
        fi
        got="$(_bak_sha256 "$src")" || got=""
        if [[ "$got" != "$want" ]]; then
            error "${rel} does not match its recorded digest."
            bad=1
            continue
        fi
        [[ "$kind" == "file" ]] && n=$(( n + 1 ))
    done < "$manifest"

    if [[ "$bad" -eq 1 ]]; then
        error "This archive is damaged. NOTHING has been restored — a partial PKI is worse than none."
        return 1
    fi
    success "${n} members verified against the manifest."

    # ── Refuse a different live authority ────────────────────────────────────
    # Silently overwriting a live CA is the same catastrophe this file exists to
    # prevent, running the other way: it kills every credential on the fleet the
    # host is currently serving.
    local incoming here there
    incoming="$x/root/$(_bak_rel "$VPN55_PKI_CA_CERT")"
    if [[ -f "$VPN55_PKI_CA_CERT" && -f "$incoming" ]]; then
        here="$(openssl x509 -in "$VPN55_PKI_CA_CERT" -noout -fingerprint -sha256 2>/dev/null)" || here=""
        there="$(openssl x509 -in "$incoming" -noout -fingerprint -sha256 2>/dev/null)" || there=""
        if [[ -n "$here" && -n "$there" && "$here" != "$there" ]]; then
            if [[ "$force" != "1" ]]; then
                error "This host already has a DIFFERENT certificate authority."
                error "  here:    ${here#*=}"
                error "  archive: ${there#*=}"
                error "Restoring would destroy the live CA and every credential signed by it."
                error "If that is genuinely what you want, re-run with --force."
                return 1
            fi
            warn "--force given: replacing a live certificate authority."
            warn "Every credential signed by ${here#*=} stops working now."
        fi
    fi

    # ── Place ────────────────────────────────────────────────────────────────
    # The directories are created with the modes the rest of the toolkit
    # asserts, not with whatever umask happens to be in force — a 0755 directory
    # holding the CA key is readable by every local user on the box.
    fs_ensure_dir "$VPN55_ETC"          0700 || return 1
    fs_ensure_dir "$VPN55_PKI"          0700 || return 1
    fs_ensure_dir "$VPN55_PKI_PRIVATE"  0700 || return 1
    fs_ensure_dir "$VPN55_PKI_ISSUED"   0755 || return 1
    fs_ensure_dir "$VPN55_PKI_REQS"     0700 || return 1
    fs_ensure_dir "$VPN55_PKI_NEWCERTS" 0700 || return 1
    fs_ensure_dir "$VPN55_PKI_HOOKS"    0700 || return 1
    fs_ensure_dir "$VPN55_USER_DIR"     0700 || return 1

    local placed=0
    while IFS=$'\t' read -r kind want mode owner rel; do
        [[ "$kind" == "file" ]] || continue
        [[ -n "$rel" ]] || continue
        _bak_place "$x/root/$rel" "/$rel" "$mode" "$owner" || return 1
        placed=$(( placed + 1 ))
    done < "$manifest"
    success "${placed} files restored."

    # ── The revocation list ──────────────────────────────────────────────────
    if pki_ca_exists; then
        if pki_crl_refresh; then
            success "Revocation list regenerated and the refresh hooks run."
        else
            warn "Could not regenerate the revocation list. Do it before anyone connects:"
            warn "an expired CRL makes a strict verifier reject EVERY user, which on the"
            warn "device looks like a total outage rather than a stale file."
        fi
    fi

    # ── What was not restored ────────────────────────────────────────────────
    section "What this restore did NOT do"
    info "The firewall ledger and the firewall backend record were archived for"
    info "reference and deliberately NOT replayed: they describe rules on the host"
    info "that made the archive, and an uninstall trusts that ledger when deciding"
    info "what it may remove."
    info ""
    info "So this host now has the identities but not the plumbing. Install each"
    info "service once — 'vpn55.sh --install <tag>' — to lay down NAT, firewall"
    info "rules and the daemons' own configuration on THIS machine. That also"
    info "restarts anything already running, which a restore does not do."
    info ""
    info "Then check, in this order:"
    info "  1. vpn55.sh --list-users     the register came back"
    info "  2. vpn55.sh --status         each service sees its credentials"
    info "  3. one real client connects  nothing else proves the keys survived"

    return 0
}

# _bak_place <source> <destination> <mode> <owner:group>
#
# The destination is composed by the caller from a path the verifier has already
# refused a leading slash and `..` for. Ownership is restored BY NAME: a uid is
# meaningless on a replacement host, where vpn55-panel may have been created in
# a different order and hold a different number. When the name does not resolve
# — the panel is not installed here yet — the file lands root-owned and the mode
# still protects it, which is the safe direction to fail in.
_bak_place() {
    local src="${1:-}" dst="${2:-}" mode="${3:-0600}" owner="${4:-root:root}"
    [[ -f "$src" ]] || { error "_bak_place: nothing at ${src}"; return 1; }

    local dir="${dst%/*}"
    if [[ -n "$dir" && ! -d "$dir" ]]; then
        mkdir -p "$dir"   || { error "cannot create ${dir}"; return 1; }
        chmod 0700 "$dir" || { error "cannot set mode on ${dir}"; return 1; }
    fi

    cp -f "$src" "$dst"  || { error "cannot restore ${dst}"; return 1; }
    chmod "$mode" "$dst" || { error "cannot set mode ${mode} on ${dst}"; return 1; }

    local user="${owner%%:*}" group="${owner##*:}"
    if [[ -n "$user" && "$user" != "root" ]]; then
        if id -u "$user" >/dev/null 2>&1; then
            chown "${user}:${group}" "$dst" 2>/dev/null \
                || warn "restored ${dst} but could not give it to ${owner}"
        else
            warn "${dst} was owned by ${owner}, which does not exist here — left root-owned."
        fi
    fi
    return 0
}


# ─── Report ───────────────────────────────────────────────────────────────────
# What this host would lose right now, and whether anything has been done about
# it. Read by the host report, so "never" is visible without being looked for.
bak_report() {
    section "Backup"

    local members count=0
    members="$(_bak_members 2>/dev/null)" || members=""
    if [[ -n "$members" ]]; then
        count="$(printf '%s\n' "$members" | grep -c . || true)"
    fi
    ui_kv "Irreplaceable files" "$count"

    if pki_ca_exists; then
        ui_kv "Certificate authority" "present — every certificate-based credential on this host depends on it"
    else
        ui_kv "Certificate authority" "none on this host"
    fi

    local latest="" f
    if [[ -d "$VPN55_BACKUP_DIR" ]]; then
        for f in "$VPN55_BACKUP_DIR"/*.tar.gz.enc; do
            [[ -f "$f" ]] || continue
            latest="$f"
        done
    fi

    if [[ -z "$latest" ]]; then
        ui_kv "Last backup" "NEVER"
        warn "If this host is lost, every credential on the fleet dies with it."
        warn "Run:  vpn55.sh --backup"
        return 0
    fi

    ui_kv "Last backup" "${latest##*/}  ($(stat -c '%y' "$latest" 2>/dev/null | cut -d. -f1 || printf 'unknown'))"

    local dest
    dest="$(fs_conf_get "$VPN55_BACKUP_CONF" scp_dest 2>/dev/null)" || dest=""
    if [[ -n "$dest" ]]; then
        ui_kv "Off-host copy" "$dest"
    else
        ui_kv "Off-host copy" "NONE — the only copy is on the host it protects"
    fi
    return 0
}
