# shellcheck shell=bash
#
# lib/panel_deploy.sh — putting the admin panel and its vhost on the host.
#
# Until this file existed, deploying the panel was a page of README: create a
# system user, place a unit, place a sudoers rule, render a vhost, get a
# certificate, write a settings file, create an account. Seven manual steps
# between a working VPN server and the interface that manages it, and an
# operator who stopped after step three had a server they could only administer
# over ssh. screen_panel() said "manual for now" and meant it.
#
# docs/launch.md §M2 is the list this file closes, and it is worth reading
# alongside: every item there is a step whose ABSENCE produced a panel that
# looked installed and would not start.
#
# ── The panel is NOT reachable from the internet, and that is the whole design ─
#
# deploy/nginx/vpn55-panel.conf listens on an ADDRESS — this host's address on
# the tunnel — never on a bare port. Its own header says why at length: a bare
# `listen 443` accepts the packet, completes TLS and parses the request before
# any allow/deny rule is consulted, so everything up to the refusal is attack
# surface. An address-bound socket never accepts the packet at all.
#
# The consequence for this file is the ordering it enforces: the tunnels are
# installed FIRST, because their gateway addresses are what the vhost listens
# on, and the panel cannot be deployed until at least one of them exists.
#
# The consequence for the operator is the chicken-and-egg that setup_run solves
# by handing them their own client configuration before it prints the panel URL.
# Anyone who deploys this without doing that has built an interface nobody can
# open.
#
# ── Why a self-signed certificate, and not Let's Encrypt ──────────────────────
#
# There is no public port here, so HTTP-01 validation cannot work — the vhost
# template says so and points at DNS-01 instead. DNS-01 needs a domain, an API
# credential for its provider and a plugin, none of which a first-time operator
# on a bare VPS has. So the default is a long-lived self-signed certificate over
# every tunnel gateway, and the fingerprint is printed so the one-time browser
# warning can actually be checked rather than clicked through blind.
#
# An operator who later gets a domain replaces two files and reloads; nothing
# else in this arrangement changes.
#
# ── Sourced, not executed ─────────────────────────────────────────────────────
#
# Every consumer calls into here ||-guarded, so errexit is off throughout. Each
# filesystem command carries its own guard; none of them relies on a caller's
# `set -e`, which would not be in force anyway.

[[ -n "${VPN55_PANEL_DEPLOY_LOADED:-}" ]] && return 0
VPN55_PANEL_DEPLOY_LOADED=1

# ⚠ Every path below hangs off VPN55_HOME, never off VPN55_ROOT.
#
# VPN55_ROOT is where the running copy of vpn55.sh happens to be — a git
# checkout in /root/VPN55 during a test. VPN55_HOME is /usr/local/lib/vpn55: the
# path written verbatim into deploy/sudoers.d/vpn55-panel and into
# deploy/vpn55-panel.service, neither of which can be parameterised, because a
# sudoers rule pinned to a path the panel user can WRITE is the escalation that
# file's own header exists to prevent.
#
# So the deployed panel is always the one at VPN55_HOME, and pnl_check_tree
# refuses rather than deploying a unit that points somewhere the operator did
# not install to. docs/launch.md §M2 describes exactly the failure this avoids.
: "${VPN55_HOME:=/usr/local/lib/vpn55}"
: "${VPN55_PANEL_SRC:=${VPN55_HOME}/panel}"
: "${VPN55_PANEL_CONF:=${VPN55_ETC:-/etc/vpn55}/panel.conf}"
: "${VPN55_PANEL_CONF_SRC:=${VPN55_HOME}/deploy/panel.conf.example}"
: "${VPN55_PANEL_UNIT:=vpn55-panel.service}"
: "${VPN55_PANEL_UNIT_SRC:=${VPN55_HOME}/deploy/vpn55-panel.service}"
: "${VPN55_PANEL_UNIT_DEST:=/etc/systemd/system/vpn55-panel.service}"
: "${VPN55_PANEL_SUDOERS_SRC:=${VPN55_HOME}/deploy/sudoers.d/vpn55-panel}"
: "${VPN55_PANEL_SUDOERS_DEST:=/etc/sudoers.d/vpn55-panel}"
: "${VPN55_PANEL_VHOST_SRC:=${VPN55_HOME}/deploy/nginx/vpn55-panel.conf}"
: "${VPN55_PANEL_OFFLINE_SRC:=${VPN55_HOME}/deploy/nginx/vpn55-offline.html}"
: "${VPN55_PANEL_OFFLINE_DEST:=/var/www/vpn55/offline.html}"
: "${VPN55_PANEL_USER:=vpn55-panel}"
: "${VPN55_PANEL_PORT:=8055}"
: "${VPN55_PANEL_TLS_DIR:=${VPN55_ETC:-/etc/vpn55}/panel-tls}"
: "${VPN55_PANEL_TLS_DAYS:=3650}"
: "${VPN55_PANEL_NODE_MIN:=20}"
: "${VPN55_PANEL_STATE_DIR:=/var/lib/vpn55/panel}"
: "${VPN55_PANEL_LOG_DIR:=/var/log/vpn55}"
: "${VPN55_PANEL_NODE_BIN:=/usr/bin/node}"
: "${VPN55_NGINX_CONF:=/etc/nginx/nginx.conf}"

# Where the vhost goes is decided per host by pnl_vhost_paths, not here: Debian
# splits sites-available/sites-enabled, the RHEL family has neither and includes
# conf.d only. See that function.
VPN55_PANEL_VHOST_DEST=""
VPN55_PANEL_VHOST_LINK=""

# Set by panel_install when it creates an account, read by the caller's summary.
# It holds a cleartext password for the rest of the process's life and is never
# written anywhere.
VPN55_PANEL_ADMIN_PASS=""

# ─── Probes ───────────────────────────────────────────────────────────────────

pnl_node_version() {
    local raw
    distro_have node || return 1
    raw="$(node --version 2>/dev/null)" || return 1
    raw="${raw#v}"
    printf '%s' "${raw%%.*}"
}

# The engines field in panel/package.json says >=20.6.0. Debian oldstable ships
# 18, which starts and then fails somewhere inside a route rather than at boot —
# so the version is checked here, up front, where the message can name the fix.
pnl_node_ok() {
    local major
    major="$(pnl_node_version)" || return 1
    [[ "$major" =~ ^[0-9]+$ ]] || return 1
    (( major >= VPN55_PANEL_NODE_MIN ))
}

pnl_installed() {
    [[ -f "$VPN55_PANEL_UNIT_DEST" ]]
}

# Every tunnel gateway on this host, one per line — the addresses the vhost
# listens on.
#
# One per ADAPTER, not one for the host: each adapter claims its own /24 and its
# own gateway, so an operator connected over the second protocol cannot reach a
# vhost bound only to the first one's address. Listening on all of them is what
# makes "connect with any of your configs, then open the panel" true.
pnl_tunnel_addresses() {
    local tag slot addr found=0
    for tag in ${VPN55_ADAPTER_TAGS[@]+"${VPN55_ADAPTER_TAGS[@]}"}; do
        slot="$(net_pool_slot "$tag" 2>/dev/null)" || continue
        addr="$(net_pool_gateway "$slot" 2>/dev/null)" || continue
        [[ -n "$addr" ]] || continue
        printf '%s\n' "$addr"
        found=1
    done
    [[ "$found" -eq 1 ]]
}

# The same claims as /24s, for the firewall.
pnl_tunnel_subnets() {
    local tag slot cidr found=0
    for tag in ${VPN55_ADAPTER_TAGS[@]+"${VPN55_ADAPTER_TAGS[@]}"}; do
        slot="$(net_pool_slot "$tag" 2>/dev/null)" || continue
        cidr="$(net_pool_subnet "$slot" 2>/dev/null)" || continue
        [[ -n "$cidr" ]] || continue
        printf '%s\n' "$cidr"
        found=1
    done
    [[ "$found" -eq 1 ]]
}

# ⚠ The unit and the sudoers rule both name /usr/local/lib/vpn55 as a LITERAL.
# Deploying from anywhere else installs a unit whose ExecStart does not exist
# and a sudo rule pointing at a path that may be writable by the very user the
# rule is written for. panel/lib/privileged-path.js refuses to start in that
# state, which makes the failure loud — but a refusal here names the cause,
# while a refusal there names a path check nobody has read yet.
pnl_check_tree() {
    local here="${VPN55_ROOT:-}" home="$VPN55_HOME"

    # Compared with symlinks resolved on both sides: /usr/local/lib/vpn55 reached
    # through a symlinked /usr/local is the same tree, and refusing it would be a
    # false alarm on a host that is laid out perfectly well.
    if [[ -d "$here" ]]; then here="$(cd -- "$here" && pwd -P)" || here="${VPN55_ROOT:-}"; fi
    if [[ -d "$home" ]]; then home="$(cd -- "$home" && pwd -P)" || home="$VPN55_HOME"; fi
    [[ -n "$here" ]] || return 0          # unresolvable; the checks below still apply

    if [[ "$here" != "$home" ]]; then
        error "This copy of VPN55 is running from ${here}, and the panel's systemd unit"
        error "and sudoers rule both name ${VPN55_HOME} as a fixed path — they cannot be"
        error "pointed elsewhere, because a sudo rule aimed at a writable directory is"
        error "the escalation deploy/sudoers.d/vpn55-panel exists to prevent."
        error ""
        error "Install the tree first, then deploy the panel from there:"
        error "  ${here}/vpn55.sh --install"
        error "  ${VPN55_HOME}/vpn55.sh --setup"
        return 1
    fi

    [[ -d "$VPN55_PANEL_SRC" ]] || { error "no panel at ${VPN55_PANEL_SRC}"; return 1; }

    # The other half of the sudoers control: the pinned files must not be
    # writable by anyone but root, all the way up.
    chown -R root:root "$VPN55_HOME" \
        || { error "cannot take ownership of ${VPN55_HOME} for root"; return 1; }
    chmod -R go-w "$VPN55_HOME" \
        || { error "cannot remove group/other write from ${VPN55_HOME}"; return 1; }
    return 0
}

# ─── The service account ──────────────────────────────────────────────────────
# A system account with no shell and no home. It owns nothing except its own
# state directory: the panel reaches root through helper/vpnctl and the two
# sudoers lines below, and through nothing else.
pnl_ensure_user() {
    if id -u "$VPN55_PANEL_USER" >/dev/null 2>&1; then
        return 0
    fi
    distro_have useradd \
        || { error "useradd is missing — cannot create the panel's service account."; return 1; }
    useradd --system --no-create-home --home-dir /nonexistent \
            --shell /usr/sbin/nologin "$VPN55_PANEL_USER" \
        || { error "cannot create the service account '${VPN55_PANEL_USER}'"; return 1; }
    success "Service account '${VPN55_PANEL_USER}' created."
    return 0
}

# ─── The three directories the unit will not start without ────────────────────
#
# docs/launch.md §M2 item 2. deploy/vpn55-panel.service names /etc/vpn55 and
# /var/log/vpn55 in ReadWritePaths= WITHOUT the `-` prefix, so systemd refuses
# to start the unit when either is missing — and the message it prints is about
# mount namespaces, not about a missing directory. That is a failure an operator
# cannot diagnose, so it is prevented here.
#
# ⚠ /var/log/vpn55 is root:root 0700 deliberately and must NOT become
# LogsDirectory=: systemd would create it owned by the service user, and a log
# the panel can rewrite is not the log that survives a panel compromise, which
# is the only property it has (docs/security-model.md §6E.4).
pnl_ensure_dirs() {
    fs_ensure_dir "${VPN55_ETC:-/etc/vpn55}" 0700 || return 1

    # ⚠ …and then reopened by exactly one degree. The panel runs as
    # vpn55-panel and its FIRST act is to read /etc/vpn55/panel.conf, which it
    # cannot do through a 0700 root:root parent however readable the file is.
    #
    # 0710 with the group set is traverse-only: the panel can open a path it
    # already knows and cannot list the directory, so users/, pki/ and every
    # other 0700 subdirectory stay exactly as unreadable to it as before.
    chgrp "$VPN55_PANEL_USER" "${VPN55_ETC:-/etc/vpn55}" \
        || { error "cannot set the group on ${VPN55_ETC:-/etc/vpn55}"; return 1; }
    chmod 0710 "${VPN55_ETC:-/etc/vpn55}" \
        || { error "cannot set the mode on ${VPN55_ETC:-/etc/vpn55}"; return 1; }

    fs_ensure_dir "$VPN55_PANEL_LOG_DIR" 0700 || return 1
    chown root:root "$VPN55_PANEL_LOG_DIR" \
        || { error "cannot set ownership on ${VPN55_PANEL_LOG_DIR}"; return 1; }

    # StateDirectory= in the unit would create this on first start — but
    # admin.js runs BEFORE the first start and would create it itself, as root,
    # leaving the panel unable to read its own administrator file.
    fs_ensure_dir "$VPN55_PANEL_STATE_DIR" 0750 || return 1
    chown "${VPN55_PANEL_USER}:${VPN55_PANEL_USER}" "$VPN55_PANEL_STATE_DIR" \
        || { error "cannot set ownership on ${VPN55_PANEL_STATE_DIR}"; return 1; }
    return 0
}

# ─── Dependencies ─────────────────────────────────────────────────────────────
# One production dependency, express. There is no package-lock.json in the tree,
# so this resolves fresh against the registry every time — which means a build
# here and a build in six months are not the same build. That is a real gap and
# it is called out in the summary rather than papered over; committing a
# lockfile is the fix, and it is not this file's to make.
pnl_install_deps() {
    [[ -d "$VPN55_PANEL_SRC" ]] || { error "no panel at ${VPN55_PANEL_SRC}"; return 1; }

    if [[ -d "${VPN55_PANEL_SRC}/node_modules/express" ]]; then
        debug "panel dependencies already present"
        return 0
    fi

    if ! distro_have npm; then
        distro_pkg_install npm \
            || { error "npm is missing and could not be installed — the panel needs it once, to fetch express."; return 1; }
    fi

    info "Fetching the panel's one dependency."
    ( cd "$VPN55_PANEL_SRC" && npm install --omit=dev --no-audit --no-fund --loglevel=error ) \
        || { error "npm could not install the panel's dependencies"; return 1; }
    [[ -d "${VPN55_PANEL_SRC}/node_modules/express" ]] \
        || { error "npm reported success but express is not present"; return 1; }

    # npm writes as root and leaves a default umask behind it. The sudoers rule
    # is only worth anything while nothing under VPN55_HOME is group-writable.
    chown -R root:root "${VPN55_PANEL_SRC}/node_modules" \
        || { error "cannot take ownership of the panel's node_modules"; return 1; }
    chmod -R go-w "${VPN55_PANEL_SRC}/node_modules" \
        || { error "cannot remove group/other write from the panel's node_modules"; return 1; }
    return 0
}

# ─── Settings ─────────────────────────────────────────────────────────────────
# Written from the shipped example, then four keys are set. Starting from the
# example rather than emitting a minimal file keeps every OTHER setting's
# documentation in front of the operator who later opens it — a generated
# six-line panel.conf teaches nobody what alert_confirmations does.
pnl_write_conf() {
    local body

    if [[ -f "$VPN55_PANEL_CONF" ]]; then
        debug "panel.conf already present — leaving the operator's file alone"
    else
        [[ -r "$VPN55_PANEL_CONF_SRC" ]] \
            || { error "the shipped panel.conf example is missing at ${VPN55_PANEL_CONF_SRC}"; return 1; }
        body="$(cat "$VPN55_PANEL_CONF_SRC")" \
            || { error "cannot read ${VPN55_PANEL_CONF_SRC}"; return 1; }
        printf '%s\n' "$body" | fs_write_atomic "$VPN55_PANEL_CONF" 0640 \
            || { error "cannot write ${VPN55_PANEL_CONF}"; return 1; }
    fi

    # Loopback bind and trust_proxy=1 go together and the panel refuses any other
    # combination: behind the vhost, X-Real-IP is written by infrastructure and
    # is worth believing; on a reachable bind it is caller-controlled and every
    # lockout bucket becomes forgeable.
    fs_conf_set "$VPN55_PANEL_CONF" bind 127.0.0.1        || return 1
    fs_conf_set "$VPN55_PANEL_CONF" port "$VPN55_PANEL_PORT" || return 1
    fs_conf_set "$VPN55_PANEL_CONF" trust_proxy 1         || return 1

    # Since Phase 6 sign-in exists and 1 here turns it OFF. The example ships 0;
    # setting it explicitly means an operator who copied an older file forward
    # does not silently end up with an unauthenticated panel.
    fs_conf_set "$VPN55_PANEL_CONF" allow_unauthenticated 0 || return 1

    # ⚠ Ownership and mode LAST. fs_conf_set writes through fs_write_atomic at
    # 0600 root:root, so doing this first would be undone four times over and
    # the panel would find a file it cannot read.
    chown "root:${VPN55_PANEL_USER}" "$VPN55_PANEL_CONF" \
        || { error "cannot set ownership on ${VPN55_PANEL_CONF}"; return 1; }
    chmod 0640 "$VPN55_PANEL_CONF" \
        || { error "cannot set mode on ${VPN55_PANEL_CONF}"; return 1; }
    return 0
}

# ─── The certificate ──────────────────────────────────────────────────────────
# Self-signed, covering every tunnel gateway as an IP SAN.
#
# The SAN list is not decoration: a browser verifying an https://<gateway> URL
# checks subjectAltName and will not fall back to the common name, so a
# certificate carrying only a CN produces a hard failure rather than the
# one-time warning this is meant to produce.
pnl_selfsigned() {
    local cert="${VPN55_PANEL_TLS_DIR}/panel.crt"
    local key="${VPN55_PANEL_TLS_DIR}/panel.key"
    local san="" addr

    if [[ -f "$cert" && -f "$key" ]]; then
        debug "panel certificate already present"
        return 0
    fi

    while IFS= read -r addr; do
        [[ -n "$addr" ]] || continue
        if [[ -n "$san" ]]; then san="${san},"; fi
        san="${san}IP:${addr}"
    done < <(pnl_tunnel_addresses)

    [[ -n "$san" ]] || { error "no tunnel address to issue a panel certificate for"; return 1; }

    fs_ensure_dir "$VPN55_PANEL_TLS_DIR" 0700 || return 1

    # umask rather than a chmod afterwards: a private key that is world-readable
    # for the duration of the keygen is a private key that was world-readable.
    ( umask 077
      openssl req -x509 -newkey rsa:2048 -nodes \
              -days "$VPN55_PANEL_TLS_DAYS" \
              -subj "/CN=VPN55 panel" \
              -addext "subjectAltName=${san}" \
              -addext "basicConstraints=critical,CA:FALSE" \
              -addext "keyUsage=critical,digitalSignature,keyEncipherment" \
              -addext "extendedKeyUsage=serverAuth" \
              -keyout "$key" -out "$cert" >/dev/null 2>&1
    ) || { error "cannot issue the panel's certificate"; return 1; }

    chmod 0600 "$key"  || { error "cannot set mode on ${key}"; return 1; }
    chmod 0644 "$cert" || { error "cannot set mode on ${cert}"; return 1; }
    return 0
}

# The SHA-256 the browser will show. Printed at the end of setup so the one-time
# warning can be verified against something instead of clicked through.
pnl_cert_fingerprint() {
    local out
    out="$(openssl x509 -in "${VPN55_PANEL_TLS_DIR}/panel.crt" -noout -fingerprint -sha256 2>/dev/null)" \
        || return 1
    printf '%s' "${out#*=}"
}

# ─── Where a vhost goes on THIS host ──────────────────────────────────────────
#
# ⚠ sites-available/sites-enabled is a Debian packaging convention, not an nginx
# feature. On the RHEL family nginx.conf includes /etc/nginx/conf.d/*.conf and
# NOTHING else, so a file written to sites-available and symlinked into
# sites-enabled is never read — and every signal says success: `nginx -t` parses
# a config that does not contain it, the reload returns 0, and the panel is
# simply unreachable with no error anywhere to explain why.
#
# So the include set is read rather than assumed. Sets the two globals; the link
# is empty when the file is written straight into conf.d.
#
# _pnl_vhost_layout answers the question once — `sites` or `confd` on stdout —
# for the panel's vhost and the portal's alike.
_pnl_vhost_layout() {
    local main="$VPN55_NGINX_CONF"

    if [[ -r "$main" ]] && grep -Eq '^[[:space:]]*include[[:space:]].*sites-enabled' "$main"; then
        printf 'sites'; return 0
    fi
    if [[ -r "$main" ]] && grep -Eq '^[[:space:]]*include[[:space:]].*conf\.d' "$main"; then
        printf 'confd'; return 0
    fi

    error "Neither sites-enabled nor conf.d is included by ${main}, so there is no"
    error "directory a vhost written here would be read from. Add one of them to the"
    error "http block and run this again."
    return 1
}

pnl_vhost_paths() {
    local layout
    layout="$(_pnl_vhost_layout)" || return 1
    if [[ "$layout" == "sites" ]]; then
        VPN55_PANEL_VHOST_DEST=/etc/nginx/sites-available/vpn55-panel.conf
        VPN55_PANEL_VHOST_LINK=/etc/nginx/sites-enabled/vpn55-panel.conf
    else
        VPN55_PANEL_VHOST_DEST=/etc/nginx/conf.d/vpn55-panel.conf
        VPN55_PANEL_VHOST_LINK=""
    fi
    return 0
}

# ─── The vhost ────────────────────────────────────────────────────────────────
# Rendered from the shipped template. Three placeholders are substituted, the
# two certificate paths are repointed at the self-signed pair, and one extra
# `listen` line is inserted per additional tunnel gateway.
pnl_render_vhost() {
    local first="" addr rendered extra=""

    while IFS= read -r addr; do
        [[ -n "$addr" ]] || continue
        if [[ -z "$first" ]]; then
            first="$addr"
        else
            extra="${extra}    listen ${addr}:443 ssl http2;"$'\n'
        fi
    done < <(pnl_tunnel_addresses)

    [[ -n "$first" ]] || { error "no tunnel address for the panel vhost to listen on"; return 1; }
    [[ -r "$VPN55_PANEL_VHOST_SRC" ]] \
        || { error "the shipped vhost template is missing at ${VPN55_PANEL_VHOST_SRC}"; return 1; }

    # server_name never decides anything for a request made to an IP address, so
    # with one block on these addresses the name is cosmetic. It is substituted
    # anyway, so the file reads correctly to whoever opens it next.
    #
    # ⚠ The ssl_certificate expression needs the space after the directive:
    # `ssl_certificate  *` matches one-or-more spaces, so it cannot also match
    # the `ssl_certificate_key` line — which it would, leaving the rendered file
    # with two certificates and no key, and nginx -t refusing it.
    rendered="$(sed \
        -e "s|__TUNNEL_IP__|${first}|g" \
        -e "s|__PANEL_HOST__|${first}|g" \
        -e "s|__PANEL_PORT__|${VPN55_PANEL_PORT}|g" \
        -e "s|^\\( *\\)ssl_certificate  *[^;]*;|\\1ssl_certificate     ${VPN55_PANEL_TLS_DIR}/panel.crt;|" \
        -e "s|^\\( *\\)ssl_certificate_key  *[^;]*;|\\1ssl_certificate_key ${VPN55_PANEL_TLS_DIR}/panel.key;|" \
        "$VPN55_PANEL_VHOST_SRC")" \
        || { error "cannot render the panel vhost"; return 1; }

    if [[ -n "$extra" ]]; then
        rendered="$(printf '%s\n' "$rendered" \
            | awk -v extra="$extra" '
                !seen && /^[[:space:]]*listen[[:space:]]/ { print; printf "%s", extra; seen = 1; next }
                { print }
              ')" || { error "cannot add the extra listen addresses"; return 1; }
    fi

    printf '%s\n' "$rendered"
    return 0
}

# The 502/503/504 page the vhost points at. `try_files … =503` means a missing
# file is not an nginx error — which is exactly why it would never be noticed:
# the operator gets a bare status code in place of the trilingual page the
# template describes, on the one surface that renders when the panel is down.
pnl_install_offline_page() {
    local body
    [[ -r "$VPN55_PANEL_OFFLINE_SRC" ]] || {
        warn "No offline page at ${VPN55_PANEL_OFFLINE_SRC}; nginx will return a bare 503"
        warn "when the panel is down. Not fatal."
        return 0
    }
    body="$(cat "$VPN55_PANEL_OFFLINE_SRC")" \
        || { error "cannot read ${VPN55_PANEL_OFFLINE_SRC}"; return 1; }
    fs_ensure_dir "$(dirname "$VPN55_PANEL_OFFLINE_DEST")" 0755 || return 1
    fs_write_if_changed "$VPN55_PANEL_OFFLINE_DEST" 0644 "$body" \
        || { error "cannot write ${VPN55_PANEL_OFFLINE_DEST}"; return 1; }
    return 0
}

# ⚠ nginx binds the tunnel gateway addresses, and those do not exist until the
# tunnel interfaces are up. That is fine during this install — the tunnels went
# in first — and it is NOT fine at the next reboot, where nginx.service can win
# the race against whatever brings a tunnel up and dies on
# `bind() … (99: Cannot assign requested address)`, taking every other site on
# the box with it.
#
# The alternatives are worse. `net.ipv4.ip_nonlocal_bind=1` is host-wide and
# lets any process on the machine bind any address. An `After=` on the tunnel
# units would teach this file the names of protocols it must not know, and
# systemd cannot express "after that interface has an address" anyway.
#
# So nginx is given the same retry the panel's own unit already uses, for the
# same reason and with the same comment in deploy/vpn55-panel.service. A
# drop-in is additive and reversible.
pnl_nginx_retry_dropin() {
    local dir=/etc/systemd/system/nginx.service.d
    local body
    body="$(cat <<'DROPIN'
# Written by VPN55 (lib/panel_deploy.sh).
#
# The panel's vhost listens on the tunnel gateway addresses, which do not exist
# until the tunnel interfaces are up. systemd cannot order a unit after "that
# interface has an address", so nginx is allowed to fail and come back instead.
# Without this, a reboot where nginx starts first leaves EVERY site on this host
# down until someone restarts it by hand.
#
# Remove this file if you stop serving anything on a tunnel address.
[Unit]
StartLimitIntervalSec=0

[Service]
Restart=on-failure
RestartSec=10s
DROPIN
)" || { error "cannot compose the nginx drop-in"; return 1; }

    fs_ensure_dir "$dir" 0755 || return 1
    fs_write_if_changed "${dir}/vpn55-panel.conf" 0644 "$body" \
        || { error "cannot write the nginx restart drop-in"; return 1; }
    distro_daemon_reload || return 1
    return 0
}

pnl_install_vhost() {
    local rendered

    if ! distro_have nginx; then
        distro_pkg_install nginx || { error "nginx is missing and could not be installed"; return 1; }
    fi

    pnl_vhost_paths || return 1
    rendered="$(pnl_render_vhost)" || return 1
    pnl_install_offline_page || return 1

    fs_ensure_dir "$(dirname "$VPN55_PANEL_VHOST_DEST")" 0755 || return 1
    fs_write_if_changed "$VPN55_PANEL_VHOST_DEST" 0644 "$rendered" \
        || { error "cannot write ${VPN55_PANEL_VHOST_DEST}"; return 1; }

    if [[ -n "$VPN55_PANEL_VHOST_LINK" ]]; then
        fs_ensure_dir "$(dirname "$VPN55_PANEL_VHOST_LINK")" 0755 || return 1
        fs_link "$VPN55_PANEL_VHOST_DEST" "$VPN55_PANEL_VHOST_LINK" || return 1
    fi

    # nginx -t before any reload, always. A vhost that fails validation does not
    # merely fail to load: the reload fails, so every other site on this box
    # keeps serving the old config and — after a restart — none of them serve.
    if ! nginx -t >/dev/null 2>&1; then
        error "nginx rejected the panel vhost, so it has been written but not enabled:"
        nginx -t 2>&1 | sed 's/^/    /' >&2
        if [[ -n "$VPN55_PANEL_VHOST_LINK" ]]; then
            fs_remove "$VPN55_PANEL_VHOST_LINK" || true
        else
            fs_remove "$VPN55_PANEL_VHOST_DEST" || true
        fi
        return 1
    fi

    pnl_nginx_retry_dropin || return 1

    if distro_service_is_active nginx; then
        systemctl reload nginx || { error "nginx would not reload"; return 1; }
    else
        distro_service_enable nginx || return 1
    fi
    return 0
}

# ─── The firewall ─────────────────────────────────────────────────────────────
#
# ⚠ Every adapter calls net_fw_allow_subnet for its own /24, and that is the
# FORWARD path — traffic routed THROUGH this host. A service listening ON this
# host is reached through INPUT, which that verb never touches. On a ufw host
# with the usual `deny (incoming)` default, the tunnel therefore carries a
# client's traffic to the internet perfectly and drops every packet aimed at the
# panel — while `ufw status` shows the subnet allowed, which is the part that
# makes it hard to see.
#
# Scoped to the tunnel subnets rather than opened outright: nginx binds only the
# tunnel addresses, so a world-open 443 would grant nothing today and quietly
# pre-open the port for whatever binds it next.
pnl_open_firewall() {
    local cidr opened=0
    while IFS= read -r cidr; do
        [[ -n "$cidr" ]] || continue
        net_fw_open_port_from panel "$cidr" tcp 443 || return 1
        opened=1
    done < <(pnl_tunnel_subnets)
    [[ "$opened" -eq 1 ]] || { error "no tunnel subnet to open the panel's port for"; return 1; }
    return 0
}

# ─── Unit and sudoers ─────────────────────────────────────────────────────────
pnl_install_unit() {
    local body
    [[ -r "$VPN55_PANEL_UNIT_SRC" ]] \
        || { error "the shipped unit is missing at ${VPN55_PANEL_UNIT_SRC}"; return 1; }

    # ExecStart names /usr/bin/node as a literal, so a Node installed anywhere
    # else — nvm, /usr/local/bin, a distribution that moves it — passes every
    # version check above and then fails at start with a status=203/EXEC that
    # says nothing about paths.
    [[ -x "$VPN55_PANEL_NODE_BIN" ]] || {
        error "The panel's unit runs ${VPN55_PANEL_NODE_BIN}, and there is no executable there."
        error "node is at: $(command -v node 2>/dev/null || printf 'nowhere on PATH')"
        error "Install the distribution's nodejs package, or symlink it:"
        error "  ln -s \"\$(command -v node)\" ${VPN55_PANEL_NODE_BIN}"
        return 1
    }

    body="$(cat "$VPN55_PANEL_UNIT_SRC")" \
        || { error "cannot read ${VPN55_PANEL_UNIT_SRC}"; return 1; }
    fs_write_if_changed "$VPN55_PANEL_UNIT_DEST" 0644 "$body" \
        || { error "cannot write ${VPN55_PANEL_UNIT_DEST}"; return 1; }
    distro_daemon_reload || return 1
    return 0
}

# visudo -c before the file is in place, never after. A malformed sudoers file
# makes EVERY sudo call on the host fail, including the ones needed to repair it
# — so it is validated where it cannot do that, and only then moved.
pnl_install_sudoers() {
    local body tmp="${VPN55_PANEL_SUDOERS_DEST}.new.$$"

    [[ -r "$VPN55_PANEL_SUDOERS_SRC" ]] \
        || { error "the shipped sudoers rule is missing at ${VPN55_PANEL_SUDOERS_SRC}"; return 1; }
    body="$(cat "$VPN55_PANEL_SUDOERS_SRC")" \
        || { error "cannot read ${VPN55_PANEL_SUDOERS_SRC}"; return 1; }

    printf '%s\n' "$body" | fs_write_atomic "$tmp" 0440 \
        || { error "cannot stage the sudoers rule"; return 1; }

    if distro_have visudo; then
        if ! visudo -c -f "$tmp" >/dev/null 2>&1; then
            error "the shipped sudoers rule does not validate — refusing to install it."
            visudo -c -f "$tmp" 2>&1 | sed 's/^/    /' >&2
            fs_remove "$tmp" || true
            return 1
        fi
    else
        warn "visudo is not installed, so the sudoers rule goes in unchecked."
    fi

    mv -f "$tmp" "$VPN55_PANEL_SUDOERS_DEST" \
        || { error "cannot install ${VPN55_PANEL_SUDOERS_DEST}"; fs_remove "$tmp" || true; return 1; }
    chown root:root "$VPN55_PANEL_SUDOERS_DEST" \
        || { error "cannot set ownership on ${VPN55_PANEL_SUDOERS_DEST}"; return 1; }
    chmod 0440 "$VPN55_PANEL_SUDOERS_DEST" \
        || { error "cannot set mode on ${VPN55_PANEL_SUDOERS_DEST}"; return 1; }
    return 0
}

# ─── The first administrator ──────────────────────────────────────────────────
# The password is generated here and fed to admin.js on STDIN, twice, because
# that script asks for it and then asks again to confirm. It is never an
# argument: argv is world-readable in /proc/<pid>/cmdline for the life of the
# process, which is the whole reason admin.js reads a secret the way it does.
#
# The caller prints it once, at the end. Nothing on this host can recover it
# afterwards — the file holds an scrypt hash — so a lost password is reset with
# `admin.js passwd`, not looked up.
pnl_admin_create() {
    local name="${1:-}" pass="${2:-}" out=""
    local admins="${VPN55_PANEL_STATE_DIR}/admins.json"

    [[ -n "$name" ]] || { error "pnl_admin_create: no account name"; return 1; }
    [[ -n "$pass" ]] || { error "pnl_admin_create: no password"; return 1; }

    # ⚠ stderr is captured and printed on failure rather than discarded. admin.js
    # refuses for reasons an operator can act on — a name that already exists, a
    # panel.conf it cannot parse — and a bare "could not create the account" sends
    # them to look for the wrong thing.
    out="$(printf '%s\n%s\n' "$pass" "$pass" \
        | node "${VPN55_PANEL_SRC}/scripts/admin.js" add "$name" 2>&1)" || {
        error "could not create the administrator account '${name}':"
        printf '%s\n' "$out" | sed 's/^/    /' >&2
        return 1
    }

    # panel/README.md's own procedure ends with this line, and it is not
    # cosmetic: admin.js runs as root, so the file it writes is root's, and the
    # panel reads it on every single sign-in.
    [[ -f "$admins" ]] || { error "admin.js reported success but ${admins} is not there."; return 1; }
    chown "${VPN55_PANEL_USER}:${VPN55_PANEL_USER}" "$admins" \
        || { error "cannot hand ${admins} to ${VPN55_PANEL_USER}"; return 1; }
    chmod 0600 "$admins" || { error "cannot set mode on ${admins}"; return 1; }
    return 0
}

# ─── Verifying, rather than assuming ──────────────────────────────────────────
# Two things this install gets wrong silently if a mode or an owner is off, and
# both are cheap to actually test as the user that will do it for real.
# su rather than sudo: the panel's own sudoers rule is deliberately narrow and
# names two commands, so `sudo -u vpn55-panel` is not something this host is set
# up to do. `su -s /bin/sh` overrides the nologin shell, and root needs no
# password for it.
_pnl_can_read() {
    local path="${1:-}"
    su -s /bin/sh -c "test -r '${path}'" "$VPN55_PANEL_USER" >/dev/null 2>&1
}

pnl_verify_access() {
    local rc=0

    distro_have su || {
        warn "su is not installed, so the panel's own access to its files was not verified."
        return 0
    }

    if ! _pnl_can_read "$VPN55_PANEL_CONF"; then
        error "${VPN55_PANEL_USER} cannot read ${VPN55_PANEL_CONF}, so the panel will not start."
        error "$(dirname "$VPN55_PANEL_CONF") must be traversable by that group — see pnl_ensure_dirs."
        rc=1
    fi
    if [[ -f "${VPN55_PANEL_STATE_DIR}/admins.json" ]] \
       && ! _pnl_can_read "${VPN55_PANEL_STATE_DIR}/admins.json"; then
        error "${VPN55_PANEL_USER} cannot read its own administrator file, so every"
        error "sign-in would fail with a message about bad credentials."
        rc=1
    fi
    return "$rc"
}

# ─── Install ──────────────────────────────────────────────────────────────────
# panel_install [admin_name]
#
# Ordering is load-bearing three times over: the service account must exist
# before anything is owned by it, the directories must exist before admin.js
# writes into one, and at least one tunnel must be installed before there is an
# address for the vhost to listen on. The last is why setup_run calls this last,
# and why a missing tunnel is a hard error rather than a prompt.
panel_install() {
    local admin="${1:-}" pass=""

    distro_require_root || return 1
    section "Admin panel"

    pnl_node_ok || {
        error "The panel needs Node.js ${VPN55_PANEL_NODE_MIN} or newer; this host has $(pnl_node_version 2>/dev/null || printf 'none')."
        error "Install a current Node.js and run this again — nothing else here has changed."
        return 1
    }

    pnl_check_tree || return 1

    pnl_tunnel_addresses >/dev/null || {
        error "No tunnel is installed, so there is no address for the panel to listen on."
        error "The panel is reachable over the VPN only, by design — install a tunnel first."
        return 1
    }

    pnl_ensure_user     || return 1
    pnl_ensure_dirs     || return 1
    pnl_install_deps    || return 1
    pnl_write_conf      || return 1
    pnl_install_sudoers || return 1
    pnl_install_unit    || return 1
    pnl_selfsigned      || return 1
    pnl_install_vhost   || return 1
    pnl_open_firewall   || return 1

    if [[ -n "$admin" ]]; then
        pass="$(fs_random_pass 18)" || return 1
        pnl_admin_create "$admin" "$pass" || return 1
        # shellcheck disable=SC2034  # read by lib/ui_screens.sh and lib/core_setup.sh
        VPN55_PANEL_ADMIN_PASS="$pass"
        success "Administrator '${admin}' created."
    fi

    pnl_verify_access || return 1

    distro_service_enable "$VPN55_PANEL_UNIT" || {
        error "The panel's unit would not start. It is enabled, so it will come back on"
        error "its own once the reason is fixed. What it said:"
        journalctl -u "$VPN55_PANEL_UNIT" -n 20 --no-pager 2>/dev/null | sed 's/^/    /' >&2
        return 1
    }

    if distro_service_is_active "$VPN55_PANEL_UNIT"; then
        success "Panel running."
    else
        info "The panel is enabled and retries every 10s; it will come up shortly."
    fi
    return 0
}

# The URL to hand the operator: first tunnel gateway, https, no port — the vhost
# is on 443.
panel_url() {
    local addr
    addr="$(pnl_tunnel_addresses | head -n1)" || true
    [[ -n "$addr" ]] || return 1
    printf 'https://%s/' "$addr"
}

# ─── The self-serve portal's vhost ────────────────────────────────────────────
#
# Until this section existed the portal's vhost was a README step: copy the
# template, edit two placeholders, run certbot, come back and add the https
# half. deploy/nginx/vpn55-portal.conf's header describes that bootstrap and it
# is followed here exactly — the port-80 block first, so that Let's Encrypt can
# reach /.well-known/acme-challenge/, then the certificate, then the https
# block. What this section adds is the one thing a README step cannot do:
#
# ── The vhost is FRONT-AWARE ──────────────────────────────────────────────────
#
# When a tunnel service shares port 443 with nginx (docs/security-model.md
# §6C.8, lib/core_front443.sh), nginx's stream front holds the public 443 and
# every http vhost that used to sit there listens on 127.0.0.1:<web port> with
# `proxy_protocol`. A portal vhost written with the template's `listen 443`
# onto that host does not fail loudly: `nginx -t` passes it, the reload fails
# at bind with EADDRINUSE, nginx keeps the OLD workers serving, and the front's
# guard reports a broken vhost that VPN55 itself just wrote. So with the front
# on, the https block is rendered through front443_render_vhost — the listen
# line becomes `listen 127.0.0.1:<web> ssl http2 proxy_protocol;` in the
# engine's tagged form, the `[::]:443` twin is switched off (the front carries
# v6 itself, where the host has it), and the file is recorded in the front's
# ledger so that removing the front puts the plain `listen 443` back exactly as
# it does for the operator's own sites. The port-80 block is untouched either
# way: the front takes 443 only, and HTTP-01 needs 80.
#
# Deployed FIRST and fronted LATER is the other order, and it needs nothing
# from here: the front's install scans `nginx -T` and rewrites every public-443
# listener it finds, and the template's spelling is one it recognises —
# tests/front443.sh asserts that against the template that ships.
#
# ── certbot is `certonly --webroot`, not `--nginx` ────────────────────────────
#
# The template's header names `certbot --nginx`, and by hand on a host with no
# front that is fine. This path uses the webroot authenticator instead, for
# one reason: `certbot --nginx` on a port-80-only vhost WRITES a `listen 443
# ssl` block into it and reloads — which on a fronted host is drift trap 1 of
# §6C.8, committed by the installer itself, one step before it overwrites the
# file anyway. The webroot authenticator edits nothing; the port-80 block
# already serves the challenge path from /var/www/html, which is exactly what
# it needs. Renewal keeps working the same way, through port 80, which the
# front never touches.

: "${VPN55_PORTAL_VHOST_SRC:=${VPN55_HOME}/deploy/nginx/vpn55-portal.conf}"
: "${VPN55_PORTAL_CONF:=${VPN55_ETC:-/etc/vpn55}/portal.conf}"
: "${VPN55_PORTAL_ACME_ROOT:=/var/www/html}"
: "${VPN55_PORTAL_LE_LIVE:=/etc/letsencrypt/live}"
: "${VPN55_PORTAL_PORT_DEFAULT:=8056}"

VPN55_PORTAL_VHOST_DEST=""
VPN55_PORTAL_VHOST_LINK=""

# Thin wrappers over the host, so tests/panel-deploy.sh can drive every
# decision below without nginx or certbot. Nothing else in this section calls
# the binaries.
_pnl_nginx_test()     { nginx -t >/dev/null 2>&1; }
_pnl_nginx_test_out() { nginx -t 2>&1; }
_pnl_nginx_reload()   { systemctl reload nginx; }
_pnl_certbot()        { certbot "$@"; }
_pnl_link_present()   { [[ -L "${1:-}" ]]; }

# The front's verbs, if the engine is loaded in this process. vpn55.sh sources
# it; a test may not, and a test that does not is a host with no front.
_pnl_front_loaded() {
    declare -F front443_installed >/dev/null 2>&1 \
        && declare -F front443_render_vhost >/dev/null 2>&1 \
        && declare -F front443_adopt_file >/dev/null 2>&1
}
_pnl_front_on() { _pnl_front_loaded && front443_installed; }

pnl_portal_host() { fs_conf_default "$VPN55_PORTAL_CONF" host ""; }
pnl_portal_port() { fs_conf_default "$VPN55_PANEL_CONF" portal_port "$VPN55_PORTAL_PORT_DEFAULT"; }

pnl_portal_vhost_paths() {
    local layout
    layout="$(_pnl_vhost_layout)" || return 1
    if [[ "$layout" == "sites" ]]; then
        VPN55_PORTAL_VHOST_DEST=/etc/nginx/sites-available/vpn55-portal.conf
        VPN55_PORTAL_VHOST_LINK=/etc/nginx/sites-enabled/vpn55-portal.conf
    else
        VPN55_PORTAL_VHOST_DEST=/etc/nginx/conf.d/vpn55-portal.conf
        VPN55_PORTAL_VHOST_LINK=""
    fi
    return 0
}

# Deployed means: a host is recorded AND its vhost is on disk. Either alone is
# a run that stopped halfway.
pnl_portal_installed() {
    [[ -n "$(pnl_portal_host)" ]] || return 1
    pnl_portal_vhost_paths >/dev/null 2>&1 || return 1
    [[ -f "$VPN55_PORTAL_VHOST_DEST" ]]
}

pnl_portal_cert_ready() {
    local host="${1:-}"
    [[ -n "$host" ]] || return 1
    [[ -f "${VPN55_PORTAL_LE_LIVE}/${host}/fullchain.pem" && -f "${VPN55_PORTAL_LE_LIVE}/${host}/privkey.pem" ]]
}

# A hostname, not an address: the certificate is issued to a name, and
# `server_name` is one. Lowercased on the way in — certbot lowercases too, and
# a mixed-case name would render into the vhost as one thing and be issued as
# another.
pnl_portal_host_valid() {
    local host="${1:-}"
    [[ -n "$host" ]] || return 1
    [[ ${#host} -le 253 ]] || return 1
    [[ "$host" =~ ^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+$ ]] || return 1
    # A dotted quad passes the shape above; a top-level label is never numeric.
    [[ ! "${host##*.}" =~ ^[0-9]+$ ]]
}

# pnl_portal_render_vhost <host> <bootstrap|full>
#
# `bootstrap` is the template up to but not including its second server block
# — the port-80 half, exactly as the header's step 1 describes. `full` is the
# whole file, and with the front on it is rendered through the front's own
# rewrite so that the https block lands on the loopback web port already
# tagged. Two placeholders are substituted and nothing else is edited.
pnl_portal_render_vhost() {
    local host="${1:-}" stage="${2:-full}" port rendered
    [[ -n "$host" ]] || { error "pnl_portal_render_vhost <host> <bootstrap|full>"; return 1; }
    case "$stage" in bootstrap|full) ;; *) error "pnl_portal_render_vhost: stage must be bootstrap or full"; return 1 ;; esac
    [[ -r "$VPN55_PORTAL_VHOST_SRC" ]] \
        || { error "the shipped portal vhost template is missing at ${VPN55_PORTAL_VHOST_SRC}"; return 1; }
    port="$(pnl_portal_port)"

    rendered="$(sed \
        -e "s|__PORTAL_HOST__|${host}|g" \
        -e "s|__PORTAL_PORT__|${port}|g" \
        "$VPN55_PORTAL_VHOST_SRC")" \
        || { error "cannot render the portal vhost"; return 1; }

    if [[ "$stage" == "bootstrap" ]]; then
        # Everything before the second `server {` line: the header and the
        # port-80 block. The https block references a certificate that does not
        # exist yet, and nginx -t hard-fails on a missing certificate path.
        rendered="$(printf '%s\n' "$rendered" \
            | awk '/^server[ \t]*\{/ { n++ } n >= 2 { exit } { print }')" \
            || { error "cannot cut the portal vhost down to its port-80 block"; return 1; }
        printf '%s\n' "$rendered"
        return 0
    fi

    if _pnl_front_on; then
        rendered="$(printf '%s\n' "$rendered" | front443_render_vhost)" \
            || { error "cannot render the portal vhost for the shared front"; return 1; }
    fi
    printf '%s\n' "$rendered"
    return 0
}

# _pnl_portal_apply <rendered text>
#
# Write, link, `nginx -t`, then — with the front on — hand the file to the
# front's ledger, then reload. A vhost nginx rejects is put back to what was
# there before it (or removed, if nothing was), so a failed run never leaves
# a config that the next reload of anything else on this host would refuse.
_pnl_portal_apply() {
    local text="${1-}" had=0 prev="" linked=0 changed=0
    local dest="$VPN55_PORTAL_VHOST_DEST" link="$VPN55_PORTAL_VHOST_LINK"

    [[ -n "$dest" ]] || { error "_pnl_portal_apply: pnl_portal_vhost_paths was not run"; return 1; }
    if [[ -f "$dest" ]]; then
        had=1
        prev="$(cat "$dest")" || { error "cannot read ${dest}"; return 1; }
    fi
    if [[ -n "$link" ]] && _pnl_link_present "$link"; then linked=1; fi

    fs_ensure_dir "$(dirname "$dest")" 0755 || return 1
    fs_write_if_changed "$dest" 0644 "$text" || { error "cannot write ${dest}"; return 1; }
    changed="$VPN55_FS_CHANGED"
    if [[ -n "$link" ]]; then
        fs_ensure_dir "$(dirname "$link")" 0755 || return 1
        fs_link "$dest" "$link" || return 1
        [[ "$linked" -eq 1 ]] || changed=1
    fi

    if ! _pnl_nginx_test; then
        error "nginx rejected the portal vhost, so it has been put back as it was:"
        _pnl_nginx_test_out | sed 's/^/    /' >&2
        if [[ "$had" -eq 1 ]]; then
            fs_write_if_changed "$dest" 0644 "$prev" || error "…and the previous ${dest} could not be restored"
        else
            if [[ -n "$link" ]]; then fs_remove "$link" || true; fi
            fs_remove "$dest" || true
        fi
        return 1
    fi

    # Recorded in the front's ledger AFTER nginx accepted it: a row for a file
    # that was then reverted would be harmless (restore is a no-op on a file
    # with no markers) but it would be a row describing nothing.
    if _pnl_front_on; then
        front443_adopt_file "$dest" || return 1
    fi

    if [[ "$changed" -eq 1 ]]; then
        if distro_service_is_active nginx; then
            _pnl_nginx_reload || { error "nginx would not reload"; return 1; }
        else
            distro_service_enable nginx || return 1
        fi
    else
        debug "portal vhost unchanged; nothing reloaded"
    fi
    return 0
}

# Step 3 of the template's bootstrap. The terms of service are Let's Encrypt's
# and accepting them is the operator's act, so it is asked — VPN55_ASSUME_YES
# answers it unattended, which is the documented unattended mode.
_pnl_portal_certbot() {
    local host="${1:-}" email="" out rc=0
    local -a args=()

    if ! distro_have certbot; then
        error "certbot is not installed, so no certificate can be requested from here."
        error "Install it (the distribution's 'certbot' package), then either run this"
        error "again or request one by hand and run this again afterwards:"
        error "  certbot certonly --webroot -w ${VPN55_PORTAL_ACME_ROOT} -d ${host}"
        return 1
    fi

    info "Requesting a certificate for ${host} from Let's Encrypt over HTTP-01 — the"
    info "port-80 block just installed serves the challenge from ${VPN55_PORTAL_ACME_ROOT}."
    info "Doing so accepts Let's Encrypt's subscriber agreement:"
    info "  https://letsencrypt.org/repository/"
    email="${VPN55_PORTAL_EMAIL:-}"
    ask_value email "Email for certificate expiry notices (blank for none)" "$email" || return 1
    if ! ask_proceed "Request the certificate for ${host} now"; then
        info "No certificate was requested."
        return 1
    fi

    args=(certonly --webroot -w "$VPN55_PORTAL_ACME_ROOT" -d "$host" \
          --non-interactive --agree-tos --keep-until-expiring)
    if [[ -n "$email" ]]; then
        args+=(-m "$email")
    else
        args+=(--register-unsafely-without-email)
    fi

    # ⚠ certbot's own words are kept and printed on failure. A rate limit, a
    # DNS name that does not point here, a challenge the firewall blocked —
    # each is named in that output and in nothing VPN55 could say instead.
    out="$(_pnl_certbot "${args[@]}" 2>&1)" || rc=$?
    if [[ "$rc" -ne 0 ]]; then
        error "certbot could not issue the certificate. It said:"
        printf '%s\n' "$out" | sed 's/^/    /' >&2
        return 1
    fi
    success "Certificate issued for ${host}."
    return 0
}

# ─── Install ──────────────────────────────────────────────────────────────────
# portal_install <host>
#
# Idempotent: with the vhost in place and the certificate present it rewrites
# nothing and reloads nothing. A run that stops between the port-80 half and
# the certificate leaves exactly the state the template's header describes
# after its step 2, and says so; the next run picks up at step 3.
portal_install() {
    local host="${1:-}" text web="" k v

    distro_require_root || return 1
    section "Self-serve portal"

    pnl_installed || {
        error "The admin panel is not deployed, and the portal is the second application"
        error "inside the panel's own process — deploy the panel first."
        return 1
    }
    host="${host,,}"
    pnl_portal_host_valid "$host" || {
        error "'${host}' is not a hostname. The portal needs a DNS name that points at"
        error "this host — the certificate is issued to it and the vhost answers to it."
        return 1
    }
    if [[ "$(fs_conf_default "$VPN55_PANEL_CONF" portal_enabled 1)" != "1" ]]; then
        error "portal_enabled is 0 in ${VPN55_PANEL_CONF}, so the panel process is not"
        error "listening for the portal and a vhost would proxy to nothing. Set it to 1"
        error "and restart ${VPN55_PANEL_UNIT} first."
        return 1
    fi

    if ! distro_have nginx; then
        distro_pkg_install nginx || { error "nginx is missing and could not be installed"; return 1; }
    fi
    pnl_portal_vhost_paths || return 1

    if _pnl_front_on; then
        while IFS=$'\t' read -r k v; do
            [[ "$k" == "web" ]] && web="$v"
        done < <(front443_info || true)
        info "Port 443 on this host is shared through nginx's front. The portal's https"
        info "block is written for it: it listens on 127.0.0.1:${web} behind the front,"
        info "and https://${host}/ is reached through the front on 443."
        if ! front443_check >/dev/null 2>&1; then
            warn "The front is installed but currently BROKEN, so https://${host}/ will not"
            warn "answer until it is repaired: ${VPN55_FRONT443_REPAIR_CMD:-vpn55.sh --front443-repair}"
            warn "The vhost is written for the front regardless — it is the arrangement on this host."
        fi
    fi

    fs_conf_set "$VPN55_PORTAL_CONF" host "$host" || return 1
    pnl_install_offline_page || return 1
    fs_ensure_dir "$VPN55_PORTAL_ACME_ROOT" 0755 || return 1

    # Port 80 first: HTTP-01 needs it and so does the redirect. A rule that
    # already existed is recorded as found and never removed.
    net_fw_open_port portal tcp 80 || return 1

    if ! pnl_portal_cert_ready "$host"; then
        info "No certificate for ${host} yet. The port-80 half of the vhost goes in first,"
        info "so Let's Encrypt can reach the challenge path; the https half follows it."
        text="$(pnl_portal_render_vhost "$host" bootstrap)" || return 1
        _pnl_portal_apply "$text" || return 1
        if ! _pnl_portal_certbot "$host"; then
            info "The port-80 vhost for ${host} is in place and stays. Once a certificate"
            info "exists at ${VPN55_PORTAL_LE_LIVE}/${host}/, run this again to add the https half."
            return 1
        fi
        pnl_portal_cert_ready "$host" || {
            error "certbot reported success but ${VPN55_PORTAL_LE_LIVE}/${host}/fullchain.pem is not there."
            return 1
        }
    fi

    text="$(pnl_portal_render_vhost "$host" full)" || return 1
    _pnl_portal_apply "$text" || return 1

    # 443 is opened AFTER the https block exists, and never removed if it was
    # already open — on a fronted host it is the web server's rule already.
    net_fw_open_port portal tcp 443 || return 1

    success "Self-serve portal vhost in place: https://${host}/"
    if _pnl_front_on; then
        info "It listens on 127.0.0.1:${web} behind nginx's shared-443 front, tagged so"
        info "that removing the front puts its plain 'listen 443' back."
    fi
    info "Hand somebody their first access code (shown once):"
    info "  node ${VPN55_PANEL_SRC}/scripts/portal.js link <user> --url https://${host}/"
    return 0
}
