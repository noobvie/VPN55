# shellcheck shell=bash
#
# lib/core_pki.sh — certificate operations shared by the certificate protocols.
#
# Phase 1 published the interface. Phase 3 implements it. Phase 4 reuses it
# rather than pulling in easy-rsa as a second PKI.
#
# ── Protocol neutrality ───────────────────────────────────────────────────────
# Nothing under this line may mention a daemon, a config format or a client
# artifact belonging to one protocol. A certificate is a certificate; the two
# consumers differ in how they PACKAGE it, and packaging is the adapter's job.
# The one exception is pki_bundle_p12, and PKCS#12 is a general format rather
# than any protocol's own.
#
# The one place that neutrality is under real pressure is the server
# certificate's extended key usage: some native clients require an OID that
# belongs to one protocol's world. It is NOT hardcoded here. The adapter sets
# VPN55_PKI_SERVER_EKU before it issues, so this file never learns why.
#
# ── Binding facts from docs/security-model.md §2 ──────────────────────────────
#   - There is ONE certificate authority, shared by both certificate protocols.
#   - The CA private key lives in $VPN55_PKI/private/, mode 0600, root-owned.
#     It is the crown jewel: losing it means reissuing every certificate, and
#     leaking it means an attacker can mint client certs until the CA is
#     replaced. There is no recovery path.
#   - Client private keys are emitted to the user and NOT retained in plaintext.
#     "Resend my config" is therefore not a supported operation anywhere in this
#     project — the answer is always a new credential.
#
# ── The CA key is not passphrase-encrypted, on purpose ────────────────────────
# Encrypting it would require the passphrase to be readable by the same root
# process that reads the key, sitting in a file beside it. That is not a second
# factor; it is the same secret stored twice, plus an install that cannot issue
# a credential unattended. The control that actually protects this key is file
# mode 0600 and root ownership, which is the same control that protects the
# passphrase file would-be. Stated here so nobody "hardens" it later and thinks
# they have added something.
#
# ── Revocation is not instant, and must not pretend to be ─────────────────────
# pki_cert_revoke writes a CRL entry. It does not disconnect anyone, and it does
# not reach any running daemon — publishing the revocation to a daemon is the
# adapter's job, through the refresh hooks below. The contract verb
# _cred_remove hides that behind the same name it uses for an instant
# revocation elsewhere, so the honesty has to live in the return value.
#
# ── A CRL EXPIRES, and a strict verifier fails closed on an expired one ───────
# That is the operational trap this file exists to defuse. A revocation list
# past its nextUpdate is not "a bit stale" to a strict client — it is invalid,
# and every user is refused. So:
#   - the validity window is 30 days by default, not a day,
#   - a timer regenerates it weekly, so four consecutive failures are survivable,
#   - pki_crl_expires_in publishes the remaining seconds, so an adapter can put
#     it in front of an operator before it lapses rather than after.
#
# Sourced, not executed. errexit does not cover a ||-guarded function body, so
# every command here that creates, copies, moves or deletes is guarded on its
# own line — see CLAUDE.md.

[[ -n "${VPN55_PKI_LOADED:-}" ]] && return 0
VPN55_PKI_LOADED=1

: "${VPN55_ETC:=/etc/vpn55}"
: "${VPN55_PKI:=$VPN55_ETC/pki}"

# Layout, fixed here so Phase 3 and Phase 4 cannot disagree about it.
VPN55_PKI_CA_CERT="$VPN55_PKI/ca.crt"
VPN55_PKI_CA_KEY="$VPN55_PKI/private/ca.key"
VPN55_PKI_CRL="$VPN55_PKI/crl.pem"
VPN55_PKI_ISSUED="$VPN55_PKI/issued"
VPN55_PKI_PRIVATE="$VPN55_PKI/private"
VPN55_PKI_REQS="$VPN55_PKI/reqs"
VPN55_PKI_NEWCERTS="$VPN55_PKI/newcerts"
VPN55_PKI_CONF="$VPN55_PKI/openssl.cnf"
VPN55_PKI_INDEX="$VPN55_PKI/index.txt"
VPN55_PKI_SERIAL="$VPN55_PKI/serial"
VPN55_PKI_CRLNUM="$VPN55_PKI/crlnumber"

# Hooks run after every CRL regeneration. An adapter drops one executable in
# here to reload its own daemon; this file never learns what a daemon is, and
# the timer below does not need to either. Root-owned 0700 — anything in it runs
# as root on a schedule.
VPN55_PKI_HOOKS="$VPN55_PKI/refresh.d"

VPN55_PKI_REFRESH_BIN="/usr/local/lib/vpn55/pki-crl-refresh"
VPN55_PKI_REFRESH_UNIT="vpn55-crl-refresh"

# ── Tunables ─────────────────────────────────────────────────────────────────
# RSA 3072 rather than an elliptic curve, and that is a deliberate downgrade of
# elegance for reach. The whole reason a certificate protocol is in this product
# is that operating systems ship a client for it; those built-in clients are
# where ECDSA support is patchiest and where a failure surfaces as an
# unexplained "cannot connect" on the user's phone rather than an error anyone
# can read. 3072 is the RSA size that matches the 128-bit security level of the
# rest of the stack. Set VPN55_PKI_KEY_ALG=ec for P-256 when every client on the
# fleet is known to handle it.
: "${VPN55_PKI_KEY_ALG:=rsa}"
: "${VPN55_PKI_RSA_BITS:=3072}"
: "${VPN55_PKI_EC_CURVE:=prime256v1}"
: "${VPN55_PKI_DIGEST:=sha256}"

: "${VPN55_PKI_CA_DAYS:=3650}"
: "${VPN55_PKI_SERVER_DAYS:=825}"
: "${VPN55_PKI_CLIENT_DAYS:=825}"

# 825 days is not arbitrary: it is the longest lifetime Apple platforms will
# accept for a server certificate they are asked to trust. A longer one is
# rejected outright, which presents as a connection failure with no useful
# message.

: "${VPN55_PKI_CRL_DAYS:=30}"

# What the server certificate claims it may be used for. Overridden by whichever
# adapter is issuing, because the extra OIDs some native clients insist on
# belong to that adapter's knowledge and not to this file's.
: "${VPN55_PKI_SERVER_EKU:=serverAuth}"
: "${VPN55_PKI_CLIENT_EKU:=clientAuth}"

# PKCS#12 encryption. OpenSSL 3 defaults to AES-256-CBC with PBKDF2, which is
# the better cryptography and which several of the client platforms this
# product exists to serve cannot open — the import fails claiming the passphrase
# is wrong, which is the least debuggable error message in the whole flow. The
# compatible form is the PKCS#12 KDF with 3DES, understood everywhere.
#
# This protects a transport container that lives for minutes and is separately
# passphrase-protected, so the trade is worth making. Set
# VPN55_PKI_P12_MODERN=1 to use OpenSSL's defaults on a fleet known to handle
# them.
: "${VPN55_PKI_P12_MODERN:=0}"

# ─── Probes and accessors ─────────────────────────────────────────────────────
pki_available() {
    if ! command -v openssl >/dev/null 2>&1; then
        error "openssl is not installed — certificate operations are unavailable."
        return 1
    fi
    return 0
}

pki_ca_path()  { printf '%s' "$VPN55_PKI_CA_CERT"; }
pki_crl_path() { printf '%s' "$VPN55_PKI_CRL"; }

pki_ca_exists() { [[ -f "$VPN55_PKI_CA_CERT" && -f "$VPN55_PKI_CA_KEY" ]]; }

pki_cert_path() { printf '%s/%s.crt' "$VPN55_PKI_ISSUED"  "${1:-}"; }
pki_key_path()  { printf '%s/%s.key' "$VPN55_PKI_PRIVATE" "${1:-}"; }

# A common name becomes a file name, so it is validated as one. The upper bound
# is X.509's own: a commonName is at most 64 characters, and a certificate whose
# CN was silently truncated matches nothing.
pki_validate_cn() {
    local cn="${1:-}"
    if [[ ! "$cn" =~ ^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$ ]]; then
        error "Invalid certificate common name '${cn}'."
        error "Use 1–64 characters: a letter or digit first, then a-z A-Z 0-9 . _ -"
        return 1
    fi
    return 0
}

pki_cert_exists() {
    local cn="${1:-}"
    [[ -n "$cn" ]] || return 1
    [[ -f "$(pki_cert_path "$cn")" ]]
}

pki_cert_fingerprint() {
    local cn="${1:-}" out
    pki_validate_cn "$cn" || return 1
    pki_cert_exists "$cn" || { error "No certificate issued for '${cn}'."; return 1; }
    out="$(openssl x509 -in "$(pki_cert_path "$cn")" -noout -fingerprint -sha256 2>/dev/null)" \
        || { error "cannot read the certificate for '${cn}'"; return 1; }
    printf '%s' "${out#*=}"
}

# ─── Initialisation ───────────────────────────────────────────────────────────
# The OpenSSL CA database. `openssl ca` is used rather than `openssl x509 -req`
# for one reason: it maintains index.txt, and index.txt is what `-gencrl` reads.
# Hand-rolling revocation without it means hand-rolling the CRL, and a CRL
# assembled by string concatenation is a CRL that fails validation on exactly
# the clients that check it properly.
_pki_write_conf() {
    local conf
    conf="$(cat <<CONF
# Generated by VPN55 lib/core_pki.sh. Edited here, not by hand.
#
# unique_subject = no in index.txt.attr is load-bearing: without it, reissuing a
# certificate for a common name that was revoked is refused, and "revoke and
# issue a new one" is the only recovery path this project has.

[ ca ]
default_ca = vpn55_ca

[ vpn55_ca ]
dir               = ${VPN55_PKI}
database          = \$dir/index.txt
serial            = \$dir/serial
crlnumber         = \$dir/crlnumber
new_certs_dir     = \$dir/newcerts
certificate       = \$dir/ca.crt
private_key       = \$dir/private/ca.key
default_md        = ${VPN55_PKI_DIGEST}
default_days      = ${VPN55_PKI_CLIENT_DAYS}
default_crl_days  = ${VPN55_PKI_CRL_DAYS}
preserve          = no
email_in_dn       = no
rand_serial       = yes
policy            = vpn55_policy
copy_extensions   = none
x509_extensions   = vpn55_ext_client

[ vpn55_policy ]
commonName             = supplied
countryName            = optional
stateOrProvinceName    = optional
localityName           = optional
organizationName       = optional
organizationalUnitName = optional
emailAddress           = optional

[ req ]
default_md         = ${VPN55_PKI_DIGEST}
distinguished_name = vpn55_req_dn
prompt             = no
string_mask        = utf8only
utf8               = yes

[ vpn55_req_dn ]
commonName = VPN55

[ vpn55_ext_ca ]
basicConstraints       = critical,CA:TRUE,pathlen:0
keyUsage               = critical,keyCertSign,cRLSign
subjectKeyIdentifier   = hash

[ vpn55_ext_client ]
basicConstraints       = critical,CA:FALSE
keyUsage               = critical,digitalSignature
extendedKeyUsage       = ${VPN55_PKI_CLIENT_EKU}
subjectKeyIdentifier   = hash
authorityKeyIdentifier = keyid,issuer
CONF
    )" || { error "cannot render the PKI configuration"; return 1; }

    fs_write_if_changed "$VPN55_PKI_CONF" 0600 "$conf" \
        || { error "cannot write $VPN55_PKI_CONF"; return 1; }
    return 0
}

pki_init() {
    pki_available || return 1

    fs_ensure_dir "$VPN55_PKI"          0700 || return 1
    fs_ensure_dir "$VPN55_PKI_PRIVATE"  0700 || return 1
    fs_ensure_dir "$VPN55_PKI_ISSUED"   0755 || return 1
    fs_ensure_dir "$VPN55_PKI_REQS"     0700 || return 1
    fs_ensure_dir "$VPN55_PKI_NEWCERTS" 0700 || return 1
    fs_ensure_dir "$VPN55_PKI_HOOKS"    0700 || return 1

    if [[ ! -f "$VPN55_PKI_INDEX" ]]; then
        : > "$VPN55_PKI_INDEX" || { error "cannot create $VPN55_PKI_INDEX"; return 1; }
        chmod 0600 "$VPN55_PKI_INDEX" || { error "cannot set mode on $VPN55_PKI_INDEX"; return 1; }
    fi
    if [[ ! -f "${VPN55_PKI_INDEX}.attr" ]]; then
        printf 'unique_subject = no\n' | fs_write_atomic "${VPN55_PKI_INDEX}.attr" 0600 \
            || { error "cannot create ${VPN55_PKI_INDEX}.attr"; return 1; }
    fi
    if [[ ! -f "$VPN55_PKI_SERIAL" ]]; then
        printf '01\n' | fs_write_atomic "$VPN55_PKI_SERIAL" 0600 \
            || { error "cannot create $VPN55_PKI_SERIAL"; return 1; }
    fi
    if [[ ! -f "$VPN55_PKI_CRLNUM" ]]; then
        printf '01\n' | fs_write_atomic "$VPN55_PKI_CRLNUM" 0600 \
            || { error "cannot create $VPN55_PKI_CRLNUM"; return 1; }
    fi

    _pki_write_conf || return 1
    return 0
}

# ─── The certificate authority ────────────────────────────────────────────────
_pki_genkey() {
    local dest="${1:-}"
    [[ -n "$dest" ]] || { error "_pki_genkey: no destination"; return 1; }

    local -a args=()
    case "$VPN55_PKI_KEY_ALG" in
        rsa) args=(-algorithm RSA -pkeyopt "rsa_keygen_bits:${VPN55_PKI_RSA_BITS}") ;;
        ec)  args=(-algorithm EC  -pkeyopt "ec_paramgen_curve:${VPN55_PKI_EC_CURVE}" \
                   -pkeyopt ec_param_enc:named_curve) ;;
        *)   error "VPN55_PKI_KEY_ALG must be 'rsa' or 'ec'; got '${VPN55_PKI_KEY_ALG}'."
             return 1 ;;
    esac

    # Written under umask 077 rather than chmod'd afterwards: a private key that
    # is 0644 for the milliseconds it takes to generate is a private key that was
    # 0644, and key generation is not a fast operation.
    ( umask 077; openssl genpkey "${args[@]}" -out "$dest" >/dev/null 2>&1; ) \
        || { error "cannot generate a private key at $dest"; rm -f "$dest" 2>/dev/null || true; return 1; }
    chmod 0600 "$dest" || { error "cannot set mode on $dest"; return 1; }
    return 0
}

pki_ca_create() {
    local cn="${1:-VPN55 Certificate Authority}"

    pki_available || return 1
    pki_init || return 1

    # Overwriting a CA silently invalidates every certificate it ever issued and
    # there is no way back, so this refuses rather than asking.
    if pki_ca_exists; then
        debug "certificate authority already present"
        return 0
    fi

    info "Generating the certificate authority — this takes a moment."
    _pki_genkey "$VPN55_PKI_CA_KEY" || return 1

    if ! openssl req -new -x509 -batch \
            -config "$VPN55_PKI_CONF" \
            -extensions vpn55_ext_ca \
            -key "$VPN55_PKI_CA_KEY" \
            -"${VPN55_PKI_DIGEST}" \
            -days "$VPN55_PKI_CA_DAYS" \
            -subj "/CN=${cn}" \
            -out "$VPN55_PKI_CA_CERT" >/dev/null 2>&1; then
        error "cannot self-sign the certificate authority"
        fs_shred "$VPN55_PKI_CA_KEY" || true
        return 1
    fi
    chmod 0644 "$VPN55_PKI_CA_CERT" || { error "cannot set mode on $VPN55_PKI_CA_CERT"; return 1; }

    pki_crl_refresh || return 1
    success "Certificate authority created — ${VPN55_PKI_CA_CERT}"
    return 0
}

# ─── Issuing ──────────────────────────────────────────────────────────────────
# A SAN entry may be given as an explicit openssl form (DNS:host, IP:1.2.3.4,
# email:a@b) or bare, in which case it is classified here. Getting this wrong is
# the single most common cause of a client rejecting a server it can otherwise
# reach: a verifier that is checking a hostname will not fall back to the CN,
# whatever the CN says.
_pki_san_entry() {
    local raw="${1:-}"
    case "$raw" in
        DNS:*|IP:*|email:*|URI:*) printf '%s' "$raw"; return 0 ;;
    esac
    if [[ "$raw" =~ ^[0-9]{1,3}(\.[0-9]{1,3}){3}$ ]] || [[ "$raw" == *:*:* ]]; then
        printf 'IP:%s' "$raw"
    else
        printf 'DNS:%s' "$raw"
    fi
    return 0
}

# Render a per-issue extension file. Not folded into openssl.cnf because the SAN
# list changes per certificate, and a shared config that is rewritten before
# every issue is a shared config that two concurrent issues corrupt.
_pki_write_extfile() {
    local dest="${1:-}" eku="${2:-}"
    shift 2 || true

    local sans="" entry raw
    for raw in "$@"; do
        [[ -n "$raw" ]] || continue
        entry="$(_pki_san_entry "$raw")"
        if [[ -n "$sans" ]]; then sans="${sans},${entry}"; else sans="$entry"; fi
    done

    {
        printf 'basicConstraints       = critical,CA:FALSE\n'
        printf 'keyUsage               = critical,digitalSignature,keyEncipherment\n'
        printf 'extendedKeyUsage       = %s\n' "$eku"
        printf 'subjectKeyIdentifier   = hash\n'
        printf 'authorityKeyIdentifier = keyid,issuer\n'
        if [[ -n "$sans" ]]; then
            printf 'subjectAltName         = %s\n' "$sans"
        fi
    } | fs_write_atomic "$dest" 0600 || { error "cannot write the extension file"; return 1; }
    return 0
}

# _pki_issue <cn> <days> <eku> [san …]
_pki_issue() {
    local cn="${1:-}" days="${2:-}" eku="${3:-}"
    shift 3 || true

    pki_validate_cn "$cn" || return 1
    pki_ca_exists || { error "There is no certificate authority yet."; return 1; }

    local key csr crt ext
    key="$(pki_key_path "$cn")"
    crt="$(pki_cert_path "$cn")"
    csr="${VPN55_PKI_REQS}/${cn}.csr"
    ext="${VPN55_PKI_REQS}/${cn}.ext"

    _pki_genkey "$key" || return 1

    # The subject is exactly /CN=<cn> and nothing else. Every extra RDN is one
    # more thing that has to match when something later maps a peer identity
    # back to a credential, and none of them carries information this project
    # does not already hold in the registry.
    if ! openssl req -new -batch \
            -config "$VPN55_PKI_CONF" \
            -key "$key" \
            -"${VPN55_PKI_DIGEST}" \
            -subj "/CN=${cn}" \
            -out "$csr" >/dev/null 2>&1; then
        error "cannot build a signing request for '${cn}'"
        fs_shred "$key" || true
        return 1
    fi

    _pki_write_extfile "$ext" "$eku" "$@" || { fs_shred "$key" || true; return 1; }

    if ! openssl ca -batch \
            -config "$VPN55_PKI_CONF" \
            -extfile "$ext" \
            -days "$days" \
            -notext \
            -in "$csr" \
            -out "$crt" >/dev/null 2>&1; then
        error "the certificate authority refused to sign '${cn}'"
        error "If this common name was issued before, revoke it first — a live"
        error "certificate is never replaced silently."
        fs_shred "$key" || true
        fs_remove "$csr" || true
        fs_remove "$ext" || true
        # openssl may have created the output file before failing. Left behind,
        # it makes pki_cert_exists answer yes for a certificate that was never
        # signed, and the adapter above it would then list a credential that
        # cannot authenticate.
        fs_remove "$crt" || true
        return 1
    fi

    chmod 0644 "$crt" || { error "cannot set mode on $crt"; return 1; }
    fs_remove "$csr" || true
    fs_remove "$ext" || true

    printf 'cert\t%s\n' "$crt"
    printf 'key\t%s\n'  "$key"
    return 0
}

# pki_server_cert_issue <common_name> [san …]
#   The SAN list is not optional in practice. Pass every name and address a
#   client might be configured to dial.
pki_server_cert_issue() {
    local cn="${1:-}"
    shift || true
    [[ -n "$cn" ]] || { error "pki_server_cert_issue <common_name> [san …]"; return 1; }

    # With no SAN given, the common name is itself the only name a client has to
    # go on, so it is promoted into the SAN rather than left to a CN fallback
    # that modern verifiers no longer perform.
    if [[ $# -eq 0 ]]; then
        set -- "$cn"
    fi

    _pki_issue "$cn" "$VPN55_PKI_SERVER_DAYS" "$VPN55_PKI_SERVER_EKU" "$@"
}

# pki_client_cert_issue <common_name> [san …]
#   The private key is written for the caller to emit and is not retained in
#   plaintext afterwards — see the security-model note at the top of this file.
#   Erasing it is the CALLER's job, once the artifact is built: this function
#   cannot know when the caller has finished with it.
pki_client_cert_issue() {
    local cn="${1:-}"
    shift || true
    [[ -n "$cn" ]] || { error "pki_client_cert_issue <common_name> [san …]"; return 1; }

    if [[ $# -eq 0 ]]; then
        set -- "$cn"
    fi

    _pki_issue "$cn" "$VPN55_PKI_CLIENT_DAYS" "$VPN55_PKI_CLIENT_EKU" "$@"
}

# pki_client_key_discard <common_name>
#   The other half of the sentence above, so no caller has to reach into the
#   private directory by hand to honour it.
pki_client_key_discard() {
    local cn="${1:-}"
    pki_validate_cn "$cn" || return 1
    fs_shred "$(pki_key_path "$cn")" || return 1
    return 0
}

# pki_bundle_p12 <common_name> <output_path>
#   Package the certificate, its key and the CA chain into one PKCS#12 file.
#   Prints the export passphrase on stdout — shown once, never stored here.
pki_bundle_p12() {
    local cn="${1:-}" out="${2:-}"
    pki_validate_cn "$cn" || return 1
    [[ -n "$out" ]] || { error "pki_bundle_p12 <common_name> <output_path>"; return 1; }

    local key crt
    key="$(pki_key_path "$cn")"
    crt="$(pki_cert_path "$cn")"
    [[ -f "$crt" ]] || { error "No certificate issued for '${cn}'."; return 1; }
    [[ -f "$key" ]] || { error "The private key for '${cn}' is gone — issue a new credential."; return 1; }

    local pass
    pass="$(fs_random_pass 18)" || return 1

    local -a compat=()
    if [[ "$VPN55_PKI_P12_MODERN" != "1" ]]; then
        compat=(-keypbe PBE-SHA1-3DES -certpbe PBE-SHA1-3DES -macalg sha1)
    fi

    # The passphrase reaches openssl through the ENVIRONMENT, never argv.
    # /proc/<pid>/cmdline is world-readable for the whole life of the process,
    # so a -passout pass:… argument hands every local user the key to this
    # user's identity; /proc/<pid>/environ is 0400 to the owner. The export
    # happens inside the subshell so it never enters this shell's environment
    # and cannot be inherited by anything else the caller runs afterwards.
    #
    # An assignment prefix cannot precede a compound command in bash — writing
    # `VAR=x ( … )` is a syntax error, not a scoped assignment — which is
    # exactly why the export is on its own statement inside the parentheses.
    local rc=0
    (
        umask 077
        export VPN55_P12_PASS="$pass"
        openssl pkcs12 -export \
            "${compat[@]}" \
            -inkey "$key" \
            -in "$crt" \
            -certfile "$VPN55_PKI_CA_CERT" \
            -name "$cn" \
            -caname "VPN55" \
            -passout env:VPN55_P12_PASS \
            -out "$out" >/dev/null 2>&1
    ) || rc=$?

    if [[ "$rc" -ne 0 && "${#compat[@]}" -gt 0 ]]; then
        # The compatible cipher needs 3DES, which some builds have moved behind
        # the legacy provider. Falling back is right — an artifact a modern
        # client can open beats no artifact at all — but doing it SILENTLY is
        # not, because the platforms that then cannot import it are exactly the
        # ones this format exists for.
        warn "This OpenSSL build cannot write the widely-compatible PKCS#12 form."
        warn "Falling back to its defaults. Older Windows and Android releases may"
        warn "reject the bundle with a misleading 'wrong password' message."
        rc=0
        (
            umask 077
            export VPN55_P12_PASS="$pass"
            openssl pkcs12 -export \
                -inkey "$key" \
                -in "$crt" \
                -certfile "$VPN55_PKI_CA_CERT" \
                -name "$cn" \
                -caname "VPN55" \
                -passout env:VPN55_P12_PASS \
                -out "$out" >/dev/null 2>&1
        ) || rc=$?
    fi

    if [[ "$rc" -ne 0 ]]; then
        error "cannot build a PKCS#12 bundle for '${cn}'"
        fs_remove "$out" || true
        return 1
    fi

    chmod 0600 "$out" || { error "cannot set mode on $out"; return 1; }
    printf '%s' "$pass"
    return 0
}

# ─── Inspection ───────────────────────────────────────────────────────────────
# pki_cert_list — machine-readable, one record per line:
#
#   common_name  serial  not_after_epoch  state
#
# state is valid | revoked | expired, read from the authority's own database
# rather than from whether a file happens to still be on disk.
#
# ── Why this is awk and not `IFS=$'	' read` ─────────────────────────────────
# index.txt leaves the revocation-date column EMPTY for a certificate that has
# not been revoked, so a valid row contains two consecutive tabs. Bash's `read`
# collapses a run of IFS *whitespace* into a single delimiter, and a tab is IFS
# whitespace — so every field after the gap shifts left by one, the common name
# lands in a variable nobody reads, and the listing comes back EMPTY.
#
# The failure is upside down, which is why it has to be written down: it breaks
# on the VALID rows and works on the revoked ones, so a revocation test passes
# while `pki_cert_list` silently reports that nothing has ever been issued. awk
# with a single-character FS preserves empty fields and has no such rule.
#
# The trailing CR is openssl writing CRLF on some platforms. Stripping it costs
# nothing, and a carriage return glued to a common name matches no file name.
#
# ── Why the epoch conversion is arithmetic and not `date` ────────────────────
# Converting each row's ASN.1 time by shelling out to `date` costs one process
# per certificate, and this function is the one an adapter calls to resolve
# every credential's state at once — so it would be a process per credential on
# every status poll. gawk's mktime() is not available on Debian's default mawk,
# so the days-from-civil arithmetic is inlined instead. It is exact for Unix
# time, which has no leap seconds to account for.
pki_cert_list() {
    [[ -f "$VPN55_PKI_INDEX" ]] || return 0

    local now
    now="$(fs_now_epoch)"

    awk -F'	' -v now="$now" '
        # sprintf("%c", 9) rather than a backslash-t: the separator has to
        # survive being embedded in a shell string inside a bash function, and
        # a literal tab in an awk format string is a parse error nobody sees
        # because the failure is swallowed by the caller.
        BEGIN { TAB = sprintf("%c", 9) }
        function days_from_civil(y, m, d,    era, yoe, doy, doe) {
            if (m <= 2) y -= 1
            era = int((y >= 0 ? y : y - 399) / 400)
            yoe = y - era * 400
            doy = int((153 * (m + (m > 2 ? -3 : 9)) + 2) / 5) + d - 1
            doe = yoe * 365 + int(yoe / 4) - int(yoe / 100) + doy
            return era * 146097 + doe - 719468
        }
        function asn1_epoch(t,    y, mo, d, hh, mm, ss) {
            if (length(t) == 13) {
                y = 2000 + substr(t, 1, 2); mo = substr(t, 3, 2); d = substr(t, 5, 2)
                hh = substr(t, 7, 2); mm = substr(t, 9, 2); ss = substr(t, 11, 2)
            } else if (length(t) == 15) {
                y = substr(t, 1, 4); mo = substr(t, 5, 2); d = substr(t, 7, 2)
                hh = substr(t, 9, 2); mm = substr(t, 11, 2); ss = substr(t, 13, 2)
            } else {
                return 0
            }
            return days_from_civil(y + 0, mo + 0, d + 0) * 86400                    + (hh + 0) * 3600 + (mm + 0) * 60 + (ss + 0)
        }
        {
            sub(/\r$/, "")
            flag = $1; expiry = $2; serial = $4; subject = $6
            if (flag == "") next

            cn = subject
            sub(/^.*\/CN=/, "", cn)
            sub(/\/.*$/, "", cn)
            if (cn == "") next

            state = "unknown"
            if      (flag == "V") state = "valid"
            else if (flag == "R") state = "revoked"
            else if (flag == "E") state = "expired"

            epoch = asn1_epoch(expiry)

            # openssl only marks a row E when it next writes the database, so a
            # V row can be past its date. Reporting that as valid would be a
            # stale answer dressed up as a fresh one.
            if (state == "valid" && epoch > 0 && epoch < now) state = "expired"

            print cn TAB serial TAB epoch TAB state
        }
    ' "$VPN55_PKI_INDEX" 2>/dev/null || true
    return 0
}

# pki_cert_state <common_name> — valid | revoked | expired | absent
pki_cert_state() {
    local cn="${1:-}" state
    [[ -n "$cn" ]] || { printf 'absent'; return 0; }
    state="$(pki_cert_list | awk -F'\t' -v c="$cn" '$1 == c { s = $4 } END { print s }')"
    printf '%s' "${state:-absent}"
    return 0
}

# ─── Revocation ───────────────────────────────────────────────────────────────
# pki_cert_revoke <common_name>
#   Adds the certificate to the CRL and regenerates it. It does NOT disconnect
#   an established session and it does NOT reach any running daemon — the hooks
#   fired by pki_crl_refresh are what publish it, and even those only affect
#   what happens at the next authentication.
pki_cert_revoke() {
    local cn="${1:-}"
    pki_validate_cn "$cn" || return 1
    pki_ca_exists || { error "There is no certificate authority."; return 1; }

    local crt state
    crt="$(pki_cert_path "$cn")"
    state="$(pki_cert_state "$cn")"

    if [[ "$state" == "revoked" ]]; then
        debug "certificate '${cn}' is already revoked"
        pki_crl_refresh || return 1
        return 0
    fi
    if [[ "$state" == "absent" ]]; then
        error "No certificate was ever issued for '${cn}'."
        return 1
    fi
    [[ -f "$crt" ]] || { error "The certificate file for '${cn}' is missing — cannot revoke it."; return 1; }

    if ! openssl ca -batch -config "$VPN55_PKI_CONF" -revoke "$crt" >/dev/null 2>&1; then
        error "the certificate authority could not revoke '${cn}'"
        return 1
    fi

    # The private key goes now, whatever the caller's spool policy is. A revoked
    # credential whose key is still on disk is a credential someone can rebuild
    # an artifact from, which is precisely what revocation is meant to end.
    fs_shred "$(pki_key_path "$cn")" || true

    pki_crl_refresh || return 1
    return 0
}

# pki_crl_refresh
#   Regenerate the CRL and run the refresh hooks. Runs on a schedule as well as
#   after a revocation, because a CRL expires and a strict verifier rejects an
#   expired one — see the header.
pki_crl_refresh() {
    pki_ca_exists || { error "There is no certificate authority."; return 1; }

    local tmp="${VPN55_PKI_CRL}.new.$$"
    if ! openssl ca -batch -config "$VPN55_PKI_CONF" \
            -gencrl -crldays "$VPN55_PKI_CRL_DAYS" -out "$tmp" >/dev/null 2>&1; then
        error "cannot regenerate the revocation list"
        fs_remove "$tmp" || true
        return 1
    fi

    mv -f "$tmp" "$VPN55_PKI_CRL" || { error "cannot replace $VPN55_PKI_CRL"; fs_remove "$tmp" || true; return 1; }
    chmod 0644 "$VPN55_PKI_CRL" || { error "cannot set mode on $VPN55_PKI_CRL"; return 1; }

    _pki_run_hooks || true
    return 0
}

_pki_run_hooks() {
    [[ -d "$VPN55_PKI_HOOKS" ]] || return 0
    local hook
    for hook in "$VPN55_PKI_HOOKS"/*; do
        [[ -f "$hook" && -x "$hook" ]] || continue
        debug "pki: running refresh hook ${hook##*/}"
        "$hook" >/dev/null 2>&1 || warn "revocation-list hook '${hook##*/}' failed"
    done
    return 0
}

# pki_hook_install <name> — hook body on stdin.
# pki_hook_remove  <name>
#   How an adapter says "and then reload me" without this file learning what it
#   is reloading.
pki_hook_install() {
    local name="${1:-}" body
    if [[ ! "$name" =~ ^[a-z][a-z0-9_-]{0,31}$ ]]; then
        error "pki_hook_install: '${name}' is not a valid hook name"
        return 1
    fi
    fs_ensure_dir "$VPN55_PKI_HOOKS" 0700 || return 1

    # This function still takes its body on stdin — that reads well at the one
    # call site — but it reads it into a variable before handing it on, because
    # fs_write_if_changed must not be on the receiving end of a pipe.
    body="$(cat)" || { error "pki_hook_install: cannot read the hook body"; return 1; }
    [[ -n "$body" ]] || { error "pki_hook_install: refusing to install an empty hook"; return 1; }

    fs_write_if_changed "${VPN55_PKI_HOOKS}/${name}" 0700 "$body" \
        || { error "cannot install the revocation-list hook '${name}'"; return 1; }
    return 0
}

pki_hook_remove() {
    local name="${1:-}"
    [[ -n "$name" ]] || return 0
    fs_remove "${VPN55_PKI_HOOKS}/${name}" || return 1
    return 0
}

# pki_crl_expires_in — seconds until the CRL's nextUpdate; negative once lapsed,
# and 0 when there is no CRL at all. The number an adapter puts in front of an
# operator BEFORE a strict verifier starts refusing everyone.
pki_crl_expires_in() {
    local line when
    [[ -f "$VPN55_PKI_CRL" ]] || { printf '0'; return 0; }
    line="$(openssl crl -in "$VPN55_PKI_CRL" -noout -nextupdate 2>/dev/null)" || { printf '0'; return 0; }
    when="$(date -u -d "${line#*=}" +%s 2>/dev/null)" || { printf '0'; return 0; }
    printf '%s' "$(( when - $(fs_now_epoch) ))"
    return 0
}

# ─── The refresh timer ────────────────────────────────────────────────────────
# The generated script deliberately does NOT source these libraries. It has to
# keep working when the checkout it was installed from has been moved, renamed
# or deleted, which is a normal thing to do to a cloned installer and an
# abnormal thing to have break certificate validation for every user.
_pki_refresh_script() {
    cat <<'REFRESH'
#!/bin/sh
# Generated by VPN55 lib/core_pki.sh. Regenerates the certificate revocation
# list and runs the adapters' reload hooks.
#
# Self-contained on purpose: it must survive the installer checkout being moved
# or deleted. A lapsed CRL makes a strict verifier refuse every client, so this
# failing quietly is not an acceptable outcome.
set -eu

PKI="__PKI__"
CRL="$PKI/crl.pem"
CONF="$PKI/openssl.cnf"
DAYS="__DAYS__"

[ -f "$CONF" ] || exit 0
[ -f "$PKI/ca.crt" ] || exit 0

tmp="$CRL.new.$$"
if ! openssl ca -batch -config "$CONF" -gencrl -crldays "$DAYS" -out "$tmp" >/dev/null 2>&1; then
    rm -f "$tmp" || true
    echo "vpn55: could not regenerate the revocation list" >&2
    exit 1
fi
mv -f "$tmp" "$CRL" || { echo "vpn55: could not replace $CRL" >&2; exit 1; }
chmod 0644 "$CRL" || { echo "vpn55: could not set the mode on $CRL" >&2; exit 1; }

for hook in "$PKI"/refresh.d/*; do
    [ -f "$hook" ] || continue
    [ -x "$hook" ] || continue
    "$hook" >/dev/null 2>&1 || echo "vpn55: revocation-list hook ${hook##*/} failed" >&2
done
exit 0
REFRESH
}

pki_crl_timer_install() {
    distro_has_systemd || {
        warn "No systemd on this host — the revocation list will not refresh on a schedule."
        warn "Run 'openssl ca -config ${VPN55_PKI_CONF} -gencrl -out ${VPN55_PKI_CRL}' from cron,"
        warn "at least once a fortnight, or a strict client will start refusing every user."
        return 0
    }

    fs_ensure_dir "$(dirname "$VPN55_PKI_REFRESH_BIN")" 0755 || return 1

    # Each body is built into a variable and passed as an argument. Piping into
    # fs_write_if_changed would put it in a subshell, and the VPN55_FS_CHANGED
    # it sets would never reach the `changed` accounting below — so a freshly
    # written unit file would never be followed by a daemon-reload, and systemd
    # would be asked to enable a timer it has not read yet.
    local changed=0 body

    body="$(_pki_refresh_script \
        | sed -e "s|__PKI__|${VPN55_PKI}|g" -e "s|__DAYS__|${VPN55_PKI_CRL_DAYS}|g")" \
        || { error "cannot render the revocation-list refresh script"; return 1; }
    fs_write_if_changed "$VPN55_PKI_REFRESH_BIN" 0700 "$body" \
        || { error "cannot install $VPN55_PKI_REFRESH_BIN"; return 1; }
    if [[ "$VPN55_FS_CHANGED" == "1" ]]; then changed=1; fi

    body="$(printf '%s\n' \
        "[Unit]" \
        "Description=VPN55 — regenerate the certificate revocation list" \
        "Documentation=https://github.com/noobvie/VPN55" \
        "" \
        "[Service]" \
        "Type=oneshot" \
        "ExecStart=${VPN55_PKI_REFRESH_BIN}")" || return 1
    fs_write_if_changed "/etc/systemd/system/${VPN55_PKI_REFRESH_UNIT}.service" 0644 "$body" \
        || { error "cannot install the revocation-list service unit"; return 1; }
    if [[ "$VPN55_FS_CHANGED" == "1" ]]; then changed=1; fi

    # Weekly against a 30-day validity window, so four consecutive failures are
    # survivable. Persistent=true catches up after the host was off; the random
    # delay keeps a fleet of these from waking at the same instant.
    body="$(printf '%s\n' \
        "[Unit]" \
        "Description=VPN55 — weekly certificate revocation list refresh" \
        "" \
        "[Timer]" \
        "OnCalendar=weekly" \
        "RandomizedDelaySec=1h" \
        "Persistent=true" \
        "" \
        "[Install]" \
        "WantedBy=timers.target")" || return 1
    fs_write_if_changed "/etc/systemd/system/${VPN55_PKI_REFRESH_UNIT}.timer" 0644 "$body" \
        || { error "cannot install the revocation-list timer unit"; return 1; }
    if [[ "$VPN55_FS_CHANGED" == "1" ]]; then changed=1; fi

    if [[ "$changed" == "1" ]]; then
        distro_daemon_reload || return 1
    fi
    if ! distro_service_is_enabled "${VPN55_PKI_REFRESH_UNIT}.timer"; then
        distro_service_enable "${VPN55_PKI_REFRESH_UNIT}.timer" || return 1
    fi
    return 0
}

pki_crl_timer_remove() {
    if distro_has_systemd; then
        distro_service_disable "${VPN55_PKI_REFRESH_UNIT}.timer" >/dev/null 2>&1 || true
    fi
    fs_remove "/etc/systemd/system/${VPN55_PKI_REFRESH_UNIT}.timer"   || return 1
    fs_remove "/etc/systemd/system/${VPN55_PKI_REFRESH_UNIT}.service" || return 1
    fs_remove "$VPN55_PKI_REFRESH_BIN" || return 1
    fs_rmdir_if_empty "$(dirname "$VPN55_PKI_REFRESH_BIN")"
    if distro_has_systemd; then
        distro_daemon_reload || true
    fi
    return 0
}

# pki_in_use — true while any adapter still has a reload hook registered.
# The protocol-neutral way to ask "is another certificate protocol still here",
# which is what decides whether an uninstall may take the timer with it.
pki_in_use() {
    ! fs_dir_is_empty "$VPN55_PKI_HOOKS"
}

# ─── Teardown ─────────────────────────────────────────────────────────────────
# pki_destroy
#   Removes the entire PKI. Unrecoverable, and it invalidates every credential
#   both certificate protocols have ever issued. Callers must confirm first;
#   this function does not ask, because a lib that prompts cannot be scripted.
pki_destroy() {
    if pki_in_use; then
        error "A protocol is still registered against this certificate authority."
        error "Remove that service first — destroying the CA under a running one"
        error "leaves it accepting certificates it can no longer check."
        return 1
    fi

    pki_crl_timer_remove || true

    fs_shred_glob "$VPN55_PKI_PRIVATE" '*.key' || true
    fs_remove_tree "$VPN55_PKI" || return 1
    success "Certificate authority destroyed. Every certificate it issued is now worthless."
    return 0
}

# ─── Report ───────────────────────────────────────────────────────────────────
# What `vpn55.sh --doctor` prints about the PKI. Reporting the layout even
# while it is empty is deliberate: an operator asking "where would my CA key
# live" deserves an answer before the CA exists, not after.
pki_report() {
    if command -v openssl >/dev/null 2>&1; then
        ui_kv "openssl" "$(openssl version 2>/dev/null || printf 'present')"
    else
        ui_kv "openssl" "not installed — certificate protocols unavailable"
    fi

    if ! pki_ca_exists; then
        ui_kv "Certificate authority" "not created"
        ui_kv "  private keys"    "$VPN55_PKI_PRIVATE"
        ui_kv "  issued certs"    "$VPN55_PKI_ISSUED"
        ui_kv "  revocation list" "$VPN55_PKI_CRL"
        return 0
    fi

    local subject expiry
    subject="$(openssl x509 -in "$VPN55_PKI_CA_CERT" -noout -subject 2>/dev/null || true)"
    expiry="$(openssl x509 -in "$VPN55_PKI_CA_CERT" -noout -enddate 2>/dev/null || true)"
    ui_kv "Certificate authority" "${subject#*=}"
    ui_kv "  expires"             "${expiry#*=}"
    ui_kv "  key algorithm"       "$VPN55_PKI_KEY_ALG"

    local valid revoked
    valid="$(pki_cert_list | awk -F'\t' '$4 == "valid"   { n++ } END { print n + 0 }')"
    revoked="$(pki_cert_list | awk -F'\t' '$4 == "revoked" { n++ } END { print n + 0 }')"
    ui_kv "  certificates"        "${valid} valid · ${revoked} revoked"

    local left
    left="$(pki_crl_expires_in)"
    if [[ "$left" -le 0 ]]; then
        ui_kv "  revocation list"  "EXPIRED — a strict client will refuse every user"
    else
        ui_kv "  revocation list"  "valid for another $(( left / 86400 ))d"
    fi
    return 0
}
