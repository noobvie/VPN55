# shellcheck shell=bash
#
# lib/core_users.sh — THE user registry. It owns identity, and nothing else does.
#
# One person, one record, N credentials. An adapter owns the credential — the
# keypair, the certificate, the peer entry — and nothing else. If each adapter
# kept its own user list there would be three parallel identity systems, and the
# panel could not answer "who is this"; that failure is invisible on day one and
# surfaces as a person who exists in two protocols and no longer in the third.
#
# The credential rows carry an opaque owner tag supplied by whichever adapter
# created them. NOTHING in this file interprets that tag — it is stored, matched
# and handed back. That is what keeps the registry protocol-neutral while still
# being able to answer which credentials a person holds.
#
# ── On-disk shape ─────────────────────────────────────────────────────────────
#   $VPN55_ETC/users/<name>.conf    key=value, one per line; empty value = null
#   $VPN55_ETC/users/<name>.creds   TAB-separated: cred_id, owner, created, state
#
# Plain text on purpose: the panel reads these files directly, and a format that
# needs a parser dependency on the bash side is a format that drifts. UTF-8, LF,
# no tabs or newlines inside a field — validated on write, because the panel
# trusts the separator.
#
# ── Nulls ─────────────────────────────────────────────────────────────────────
# quota_bytes, expires_at, conn_limit and quota_reset are all nullable, and null
# means unlimited / never. Permissive defaults are what let one codebase serve an
# own-fleet deployment and a paid tier without a fork.
#
# conn_limit (simultaneous devices) and quota_reset (monthly rollover vs a
# lifetime cap) are here because 3x-ui, Marzban and Hiddify converged on both
# independently — docs/prior-art.md §4. They cost a nullable field now and are
# awkward once three adapters and the portal all read this registry.
#
# Sourced, not executed. Every filesystem command below is individually guarded:
# errexit does not cover a ||-guarded function body.

[[ -n "${VPN55_USERS_LOADED:-}" ]] && return 0
VPN55_USERS_LOADED=1

: "${VPN55_ETC:=/etc/vpn55}"
: "${VPN55_USER_DIR:=$VPN55_ETC/users}"

# The registry's own atomic writer, rather than borrowing core_net's. Six
# duplicated lines are cheaper than a load-order dependency between two core
# libs — a lib that only works when another was sourced first is a lib that
# breaks in whichever caller sources them the other way round.
_users_write_atomic() {
    local dest="${1:-}" tmp
    [[ -n "$dest" ]] || { error "_users_write_atomic: no destination"; return 1; }
    tmp="${dest}.tmp.$$"

    cat > "$tmp" || { error "cannot write $tmp"; rm -f "$tmp" 2>/dev/null || true; return 1; }
    chmod 0600 "$tmp" || { error "cannot set mode on $tmp"; rm -f "$tmp" 2>/dev/null || true; return 1; }
    mv -f "$tmp" "$dest" || { error "cannot replace $dest"; rm -f "$tmp" 2>/dev/null || true; return 1; }
    return 0
}

users_init() {
    if [[ ! -d "$VPN55_USER_DIR" ]]; then
        mkdir -p "$VPN55_USER_DIR" || { error "cannot create $VPN55_USER_DIR"; return 1; }
    fi
    chmod 0700 "$VPN55_USER_DIR" || { error "cannot set mode on $VPN55_USER_DIR"; return 1; }
    return 0
}

# Serialise writers. The panel reaches this registry through vpnctl and an
# operator reaches it through vpn55.sh; the two can land at the same moment,
# and a half-applied record is a user who exists with no fields.
_users_locked() {
    local lock="$VPN55_USER_DIR/.lock" rc=0
    users_init || return 1

    if ! command -v flock >/dev/null 2>&1; then
        "$@"
        return $?
    fi

    local fd
    exec {fd}>"$lock" || { error "cannot open the registry lock"; return 1; }
    if ! flock -w 10 "$fd"; then
        error "timed out waiting for the user registry lock"
        exec {fd}>&-
        return 1
    fi
    "$@"
    rc=$?
    exec {fd}>&-
    return $rc
}

# ─── Validation ───────────────────────────────────────────────────────────────
# Strict whitelist. The same discipline vpnctl applies in Phase 6 — the helper
# will validate independently rather than trusting this, but a name that reaches
# disk here is a name the helper has to handle later.
users_validate_name() {
    local name="${1:-}"
    if [[ ! "$name" =~ ^[a-z][a-z0-9_-]{1,31}$ ]]; then
        error "Invalid user name '${name}'."
        error "Names are 2–32 characters: lowercase letter first, then a-z 0-9 _ -"
        return 1
    fi
    return 0
}

users_validate_cred_id() {
    local cred="${1:-}"
    if [[ ! "$cred" =~ ^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$ ]]; then
        error "Invalid credential id '${cred}'."
        return 1
    fi
    return 0
}

# Fields, and what each accepts. An empty string is the null for every nullable
# field; it is not the same as a zero, and nothing here coerces one into the
# other. A quota of 0 bytes means "no traffic allowed"; a quota of null means
# "unlimited", and confusing them turns an unlimited account off.
_users_validate_field() {
    local field="${1:-}" value="${2:-}"

    case "$value" in
        *$'\t'*|*$'\n'*) error "field '${field}' may not contain a tab or newline"; return 1 ;;
    esac

    case "$field" in
        enabled)
            [[ "$value" == "0" || "$value" == "1" ]] \
                || { error "enabled must be 0 or 1"; return 1; } ;;
        quota_bytes)
            [[ -z "$value" || "$value" =~ ^[0-9]+$ ]] \
                || { error "quota_bytes must be a whole number of bytes, or empty for unlimited"; return 1; } ;;
        conn_limit)
            [[ -z "$value" || "$value" =~ ^[1-9][0-9]*$ ]] \
                || { error "conn_limit must be a positive integer, or empty for unlimited"; return 1; } ;;
        expires_at)
            [[ -z "$value" || "$value" =~ ^[0-9]{4}-[0-9]{2}-[0-9]{2}(T[0-9]{2}:[0-9]{2}:[0-9]{2}Z)?$ ]] \
                || { error "expires_at must be YYYY-MM-DD or YYYY-MM-DDTHH:MM:SSZ, or empty for never"; return 1; } ;;
        quota_reset)
            case "$value" in
                ""|daily|weekly|monthly) ;;
                *) error "quota_reset must be daily, weekly, monthly, or empty for a lifetime cap"; return 1 ;;
            esac ;;
        name|created)
            [[ -n "$value" ]] || { error "field '${field}' cannot be empty"; return 1; } ;;
        *)
            error "unknown registry field '${field}'"
            return 1 ;;
    esac
    return 0
}

_users_conf()  { printf '%s/%s.conf'  "$VPN55_USER_DIR" "${1:-}"; }
_users_creds() { printf '%s/%s.creds' "$VPN55_USER_DIR" "${1:-}"; }

_users_now() { date -u +%Y-%m-%dT%H:%M:%SZ; }

users_exists() {
    local name="${1:-}"
    users_validate_name "$name" || return 1
    [[ -f "$(_users_conf "$name")" ]]
}

# ─── Create / destroy ─────────────────────────────────────────────────────────
# users_add <name> [field=value …]
_users_add_locked() {
    local name="${1:-}"; shift
    local conf; conf="$(_users_conf "$name")"

    if [[ -f "$conf" ]]; then
        error "User '${name}' already exists."
        return 1
    fi

    # Every nullable field starts null: unlimited quota, no expiry, no device
    # cap, lifetime accounting.
    local quota_bytes="" expires_at="" conn_limit="" quota_reset="" enabled="1"

    local pair field value
    for pair in "$@"; do
        field="${pair%%=*}"
        value="${pair#*=}"
        _users_validate_field "$field" "$value" || return 1
        case "$field" in
            quota_bytes) quota_bytes="$value" ;;
            expires_at)  expires_at="$value"  ;;
            conn_limit)  conn_limit="$value"  ;;
            quota_reset) quota_reset="$value" ;;
            enabled)     enabled="$value"     ;;
            *) error "field '${field}' cannot be set at creation"; return 1 ;;
        esac
    done

    {
        printf 'name=%s\n'        "$name"
        printf 'created=%s\n'     "$(_users_now)"
        printf 'enabled=%s\n'     "$enabled"
        printf 'quota_bytes=%s\n' "$quota_bytes"
        printf 'expires_at=%s\n'  "$expires_at"
        printf 'conn_limit=%s\n'  "$conn_limit"
        printf 'quota_reset=%s\n' "$quota_reset"
    } | _users_write_atomic "$conf" || return 1

    printf '' | _users_write_atomic "$(_users_creds "$name")" || return 1

    success "User '${name}' created."
    return 0
}

users_add() {
    local name="${1:-}"
    users_validate_name "$name" || return 1
    _users_locked _users_add_locked "$@"
}

# Removing a person removes their credentials FROM THE REGISTRY only. Revoking
# the credential itself is the adapter's job and has to happen first — this
# function deliberately refuses while any credential is still active, because a
# peer entry left behind by a deleted user is access nobody is accountable for.
_users_remove_locked() {
    local name="${1:-}" force="${2:-}"
    local conf creds
    conf="$(_users_conf "$name")"
    creds="$(_users_creds "$name")"

    if [[ ! -f "$conf" ]]; then
        error "No such user '${name}'."
        return 1
    fi

    if [[ "$force" != "force" ]] && [[ -s "$creds" ]]; then
        local active
        active="$(awk -F'\t' '$4 == "active" { n++ } END { print n + 0 }' "$creds" 2>/dev/null || echo 0)"
        if [[ "$active" -gt 0 ]]; then
            error "User '${name}' still holds ${active} active credential(s)."
            error "Revoke them through their adapter first — deleting the record here would"
            error "leave working access on the server with nobody accountable for it."
            return 1
        fi
    fi

    rm -f "$conf" || { error "cannot remove $conf"; return 1; }
    rm -f "$creds" || { error "cannot remove $creds"; return 1; }
    success "User '${name}' removed from the registry."
    return 0
}

users_remove() {
    local name="${1:-}"
    users_validate_name "$name" || return 1
    _users_locked _users_remove_locked "$@"
}

# ─── Read / write fields ──────────────────────────────────────────────────────
users_get() {
    local name="${1:-}" field="${2:-}"
    users_validate_name "$name" || return 1
    local conf; conf="$(_users_conf "$name")"
    [[ -f "$conf" ]] || { error "No such user '${name}'."; return 1; }

    local line
    line="$(grep -m1 "^${field}=" "$conf" 2>/dev/null)" || return 1
    printf '%s' "${line#*=}"
}

_users_set_locked() {
    local name="${1:-}" field="${2:-}" value="${3:-}"
    local conf; conf="$(_users_conf "$name")"
    [[ -f "$conf" ]] || { error "No such user '${name}'."; return 1; }

    case "$field" in
        name|created) error "field '${field}' is immutable"; return 1 ;;
    esac
    _users_validate_field "$field" "$value" || return 1

    local remaining
    remaining="$(grep -v "^${field}=" "$conf" 2>/dev/null || true)"
    {
        if [[ -n "$remaining" ]]; then
            printf '%s\n' "$remaining"
        fi
        printf '%s=%s\n' "$field" "$value"
    } | _users_write_atomic "$conf" || return 1
    return 0
}

users_set() {
    local name="${1:-}"
    users_validate_name "$name" || return 1
    _users_locked _users_set_locked "$@"
}

users_enable()  { users_set "${1:-}" enabled 1; }
users_disable() { users_set "${1:-}" enabled 0; }

# ─── Credentials ──────────────────────────────────────────────────────────────
# <cred_id> <owner_tag> <created> <state>
#
# owner_tag is whatever the adapter calls itself. This file never reads it as
# anything but an opaque string, which is why the registry can list a person's
# credentials without knowing what any of them are.
_users_cred_add_locked() {
    local name="${1:-}" cred_id="${2:-}" owner="${3:-}"
    local creds; creds="$(_users_creds "$name")"

    [[ -f "$(_users_conf "$name")" ]] || { error "No such user '${name}'."; return 1; }
    users_validate_cred_id "$cred_id" || return 1
    if [[ ! "$owner" =~ ^[a-z][a-z0-9_]{0,31}$ ]]; then
        error "Invalid credential owner tag '${owner}'."
        return 1
    fi

    # awk over the file rather than `cut | grep -q`: grep exits on its first
    # match, and the SIGPIPE that kills cut becomes the pipeline's status under
    # pipefail — so an id that IS present reads as absent. See ui.sh.
    if [[ -f "$creds" ]] && awk -F'	' -v c="$cred_id" '$1 == c { hit = 1 } END { exit !hit }' "$creds"; then
        error "Credential '${cred_id}' is already recorded for '${name}'."
        return 1
    fi

    # A credential id is unique across the WHOLE registry, not just one user —
    # the panel resolves a credential back to a person by id alone.
    local clash
    clash="$(users_cred_find "$cred_id" 2>/dev/null || true)"
    if [[ -n "$clash" ]]; then
        error "Credential '${cred_id}' already belongs to '${clash%%$'\t'*}'."
        return 1
    fi

    printf '%s\t%s\t%s\tactive\n' "$cred_id" "$owner" "$(_users_now)" >> "$creds" \
        || { error "cannot record credential for ${name}"; return 1; }
    chmod 0600 "$creds" 2>/dev/null || true
    return 0
}

users_cred_add() {
    local name="${1:-}"
    users_validate_name "$name" || return 1
    _users_locked _users_cred_add_locked "$@"
}

# Marked, not deleted. The row is the audit trail: "this person held access and
# it was taken away" is a different fact from "this person never had access",
# and a VPN needs to be able to tell them apart afterwards.
_users_cred_revoke_locked() {
    local name="${1:-}" cred_id="${2:-}"
    local creds; creds="$(_users_creds "$name")"
    [[ -f "$creds" ]] || { error "No credentials recorded for '${name}'."; return 1; }

    if ! awk -F'	' -v c="$cred_id" '$1 == c { hit = 1 } END { exit !hit }' "$creds"; then
        error "'${name}' holds no credential '${cred_id}'."
        return 1
    fi

    awk -F'\t' -v OFS='\t' -v c="$cred_id" \
        '$1 == c { $4 = "revoked" } { print }' "$creds" \
        | _users_write_atomic "$creds" || return 1
    return 0
}

users_cred_revoke() {
    local name="${1:-}"
    users_validate_name "$name" || return 1
    _users_locked _users_cred_revoke_locked "$@"
}

# Machine-readable, one record per line: cred_id, owner, created, state.
users_cred_list() {
    local name="${1:-}" state_filter="${2:-}"
    users_validate_name "$name" || return 1
    local creds; creds="$(_users_creds "$name")"
    [[ -f "$creds" ]] || return 0

    if [[ -n "$state_filter" ]]; then
        awk -F'\t' -v s="$state_filter" '$4 == s' "$creds" 2>/dev/null || true
    else
        cat "$creds"
    fi
    return 0
}

# "Who is this" — the question the whole one-registry rule exists to answer.
# Prints `name<TAB>owner<TAB>created<TAB>state`; returns 1 when unknown.
users_cred_find() {
    local cred_id="${1:-}"
    [[ -n "$cred_id" ]] || return 1
    [[ -d "$VPN55_USER_DIR" ]] || return 1

    local creds name row
    for creds in "$VPN55_USER_DIR"/*.creds; do
        [[ -f "$creds" ]] || continue
        name="${creds##*/}"
        name="${name%.creds}"
        row="$(awk -F'\t' -v OFS='\t' -v c="$cred_id" -v n="$name" \
            '$1 == c { print n, $2, $3, $4; exit }' "$creds" 2>/dev/null || true)"
        if [[ -n "$row" ]]; then
            printf '%s' "$row"
            return 0
        fi
    done
    return 1
}

# ─── Policy predicates ────────────────────────────────────────────────────────
users_expired() {
    local name="${1:-}" expires
    expires="$(users_get "$name" expires_at)" || return 1
    [[ -n "$expires" ]] || return 1          # null = never expires

    local when now
    when="$(date -u -d "$expires" +%s 2>/dev/null)" || {
        warn "User '${name}' has an unparseable expires_at ('${expires}') — treating as not expired."
        return 1
    }
    now="$(date -u +%s)"
    [[ "$now" -ge "$when" ]]
}

# users_quota_exceeded <name> <used_bytes>
# The caller supplies usage: the registry stores policy, the collector measures.
users_quota_exceeded() {
    local name="${1:-}" used="${2:-0}" quota
    quota="$(users_get "$name" quota_bytes)" || return 1
    [[ -n "$quota" ]] || return 1            # null = unlimited
    [[ "$used" =~ ^[0-9]+$ ]] || { error "used_bytes must be a whole number; got '${used}'"; return 1; }
    [[ "$used" -ge "$quota" ]]
}

# Start of the current accounting window, as an ISO-8601 UTC timestamp. Empty
# when quota_reset is null, which means the cap is a lifetime one and the window
# start is "whenever the account was created".
users_quota_window_start() {
    local name="${1:-}" reset
    reset="$(users_get "$name" quota_reset)" || return 1
    case "$reset" in
        daily)   date -u +%Y-%m-%dT00:00:00Z ;;
        weekly)
            # Day-of-week arithmetic, NOT `date -d "last monday"`: on a Monday
            # GNU date reads that as the PREVIOUS Monday, so one day in seven the
            # window would open a week early and hand out double the quota.
            # %u is 1..7 with Monday = 1, so stepping back (%u - 1) days lands on
            # this week's Monday on every day including Monday itself.
            local dow
            dow="$(date -u +%u)"
            date -u -d "$(date -u +%Y-%m-%d) UTC - $(( dow - 1 )) days" +%Y-%m-%dT00:00:00Z \
                || date -u +%Y-%m-%dT00:00:00Z ;;
        monthly) date -u +%Y-%m-01T00:00:00Z ;;
        *)       printf '' ;;
    esac
    return 0
}

# One word for the panel and the portal, so neither has to reimplement the
# precedence. Returns 0 only when the account is usable.
#
#   disabled        the operator turned it off — beats everything else
#   expired         past expires_at
#   quota-exceeded  used >= quota_bytes, when a usage figure was supplied
#   active          none of the above
users_state() {
    local name="${1:-}" used="${2:-}"
    users_exists "$name" || { error "No such user '${name}'."; return 1; }

    local enabled
    enabled="$(users_get "$name" enabled)" || return 1
    if [[ "$enabled" != "1" ]]; then
        printf 'disabled'
        return 1
    fi
    if users_expired "$name"; then
        printf 'expired'
        return 1
    fi
    if [[ -n "$used" ]] && users_quota_exceeded "$name" "$used"; then
        printf 'quota-exceeded'
        return 1
    fi
    printf 'active'
    return 0
}

# ─── Listing ──────────────────────────────────────────────────────────────────
# Machine-readable, one record per line, TAB-separated:
#   name, created, enabled, quota_bytes, expires_at, conn_limit, quota_reset,
#   active_credential_count
#
# Empty fields are genuine nulls, so a consumer must not read an empty column as
# a zero.
users_list() {
    [[ -d "$VPN55_USER_DIR" ]] || return 0

    local conf name creds active
    for conf in "$VPN55_USER_DIR"/*.conf; do
        [[ -f "$conf" ]] || continue
        name="${conf##*/}"
        name="${name%.conf}"

        creds="$(_users_creds "$name")"
        if [[ -f "$creds" ]]; then
            active="$(awk -F'\t' '$4 == "active" { n++ } END { print n + 0 }' "$creds" 2>/dev/null || echo 0)"
        else
            active=0
        fi

        printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
            "$name" \
            "$(users_get "$name" created)" \
            "$(users_get "$name" enabled)" \
            "$(users_get "$name" quota_bytes)" \
            "$(users_get "$name" expires_at)" \
            "$(users_get "$name" conn_limit)" \
            "$(users_get "$name" quota_reset)" \
            "$active"
    done
    return 0
}

users_count() {
    local n=0 conf
    if [[ -d "$VPN55_USER_DIR" ]]; then
        for conf in "$VPN55_USER_DIR"/*.conf; do
            [[ -f "$conf" ]] && n=$(( n + 1 ))
        done
    fi
    printf '%s' "$n"
}

# Human-readable. "unlimited" and "never" are printed rather than a blank,
# because a blank column reads as a value nobody set and hides the policy.
users_show() {
    local name="${1:-}"
    users_exists "$name" || { error "No such user '${name}'."; return 1; }

    local quota expires conn reset enabled
    quota="$(users_get "$name" quota_bytes)"
    expires="$(users_get "$name" expires_at)"
    conn="$(users_get "$name" conn_limit)"
    reset="$(users_get "$name" quota_reset)"
    enabled="$(users_get "$name" enabled)"

    ui_kv "User"             "$name"
    ui_kv "Created"          "$(users_get "$name" created)"
    ui_kv "Enabled"          "$([[ "$enabled" == "1" ]] && printf 'yes' || printf 'no')"
    ui_kv "Traffic quota"    "${quota:-unlimited}"
    ui_kv "Quota resets"     "${reset:-never — lifetime cap}"
    ui_kv "Expires"          "${expires:-never}"
    ui_kv "Device limit"     "${conn:-unlimited}"

    local rows
    rows="$(users_cred_list "$name")"
    if [[ -n "$rows" ]]; then
        local cred owner created state
        while IFS=$'\t' read -r cred owner created state; do
            [[ -n "$cred" ]] || continue
            ui_kv "  credential" "${cred} · ${owner} · ${state} · ${created}"
        done <<< "$rows"
    else
        ui_kv "Credentials"  "none issued"
    fi
    return 0
}
