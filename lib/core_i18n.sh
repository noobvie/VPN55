# shellcheck shell=bash
#
# lib/core_i18n.sh — the bash half of the i18n layer. Phase 7.
#
# The panel has keyed catalogs in JSON and Intl in the browser. This file is for
# the text the SHELL side produces and hands to an end user: the setup
# instructions that ship beside a credential, and the comment header of a client
# configuration file. Both are read by the person using the VPN, not by the
# operator running the installer, and the market is Vietnam.
#
# ── What is in scope here, and what deliberately is not ──────────────────────
#
#   IN   — client-facing artifacts. Instructions, config comments. Translated.
#   OUT  — vpn55.sh, the menus, every error() and warn() in lib/. English.
#
# The installer stays English on purpose: its audience is an operator with root
# on a Linux box, and translating it multiplies the test surface for no reach.
# That is a decision from the build plan, not an omission.
#
# ── Keyed sections, never a phrase map ───────────────────────────────────────
#
# The same rule the JSON catalogs follow. A translation is looked up by a stable
# section name — `main`, `custody.server` — and never by matching its English
# text. A map keyed on English prose misses every translator who reorders a
# sentence, and the failure is invisible because the two files look parallel.
#
# Layout:
#
#   lib/locales/<adapter tag>/<locale>.txt
#
# and inside each file, sections introduced by a line of the form
#
#   @@ section.name
#
# with `{placeholder}` tokens filled from the caller's variable map. The section
# names and the placeholder set inside each section are the CONTRACT: CI checks
# that every locale of a file carries the same sections, and that each section
# uses the same placeholders. A translator who drops `{endpoint}` from a section
# has removed the server address from the page, which is the sort of thing that
# reads fine and is useless.
#
# ── Fallback, and why it logs ────────────────────────────────────────────────
#
# A missing section falls back to English and warns. A missing file falls back to
# English and warns. Nothing ever renders blank: a blank looks deliberate and is
# never reported, which is precisely how a translation gap survives to release.
#
# Sourced, not executed. Every consumer runs it inside a ||-guarded call, so
# errexit is off throughout — nothing here relies on the caller's `set -e`.

[[ -n "${VPN55_I18N_LOADED:-}" ]] && return 0
VPN55_I18N_LOADED=1

# The three locales, in the order a chooser should offer them: the default
# first. Vietnamese is the default and English is the fallback — that is the
# whole market decision expressed in two lines.
VPN55_LOCALES=(vi en fr)
VPN55_DEFAULT_LOCALE="vi"
VPN55_FALLBACK_LOCALE="en"

# i18n_locales — the supported tags, space separated.
i18n_locales() {
    printf '%s' "${VPN55_LOCALES[*]}"
}

# i18n_known <locale> — true when this is a locale we ship.
i18n_known() {
    local want="${1:-}" have
    [[ -n "$want" ]] || return 1
    for have in "${VPN55_LOCALES[@]}"; do
        [[ "$have" == "$want" ]] && return 0
    done
    return 1
}

# i18n_resolve [requested] — the locale to actually render in.
#
# Accepts a bare tag (`vi`) or a BCP 47 tag with a region (`vi-VN`, `fr-CA`) and
# reduces the second to its language. An unknown or empty request resolves to the
# default rather than failing: a caller that could not work out a locale still
# needs a page of instructions, and the default is the right guess for this
# market.
#
# It does NOT read the environment's LANG. The locale of the root shell running
# the installer is a fact about the operator's terminal; the person who will read
# these instructions is somebody else entirely.
i18n_resolve() {
    local want="${1:-}"
    want="${want,,}"
    want="${want%%.*}"          # vi_VN.UTF-8 -> vi_vn
    want="${want//_/-}"         # vi_vn       -> vi-vn
    if i18n_known "$want"; then
        printf '%s' "$want"
        return 0
    fi
    want="${want%%-*}"          # vi-vn       -> vi
    if i18n_known "$want"; then
        printf '%s' "$want"
        return 0
    fi
    printf '%s' "$VPN55_DEFAULT_LOCALE"
    return 0
}

# i18n_text_dir — where the .txt catalogs live, resolved from this file.
#
# Resolved rather than assumed so an adapter does not have to know where the
# libraries were installed, which differs between the repo and /usr/local/lib.
i18n_text_dir() {
    local dir
    dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)" || {
        error "cannot resolve the library directory"
        return 1
    }
    printf '%s/locales' "$dir"
}

# i18n_catalog_path <tag> <locale> — the file, or empty when it does not exist.
i18n_catalog_path() {
    local tag="${1:-}" locale="${2:-}" dir
    [[ -n "$tag" && -n "$locale" ]] || return 1
    dir="$(i18n_text_dir)" || return 1
    local path="${dir}/${tag}/${locale}.txt"
    [[ -r "$path" ]] || return 1
    printf '%s' "$path"
    return 0
}

# i18n_sections <tag> <locale> — the section names in that file, one per line.
#
# Used by CI to compare locales, and by nothing at runtime. It is here rather
# than in the check script so that the parser which decides what a section IS
# exists once: a check with its own second parser passes on files the renderer
# reads differently, which is a check that agrees with itself and nothing else.
i18n_sections() {
    local tag="${1:-}" locale="${2:-}" path
    path="$(i18n_catalog_path "$tag" "$locale")" || return 1
    sed -n 's/^@@[[:space:]]\{1,\}\([A-Za-z0-9._-]\{1,\}\)[[:space:]]*$/\1/p' "$path"
}

# _i18n_raw_section <tag> <locale> <section> — the section body, untouched.
#
# Prints nothing and returns 1 when the file or the section is absent, so the
# caller can decide whether that is a fallback or a failure.
_i18n_raw_section() {
    local tag="${1:-}" locale="${2:-}" section="${3:-}" path
    path="$(i18n_catalog_path "$tag" "$locale")" || return 1

    local body
    body="$(awk -v want="$section" '
        /^@@[[:space:]]+[A-Za-z0-9._-]+[[:space:]]*$/ {
            name = $2
            inside = (name == want)
            next
        }
        inside { print }
    ' "$path")" || return 1

    [[ -n "$body" ]] || return 1
    printf '%s\n' "$body"
    return 0
}

# i18n_render <tag> <locale> <section> [name=value …] — the translated section.
#
# `{name}` in the text is replaced by the matching value. A placeholder with no
# value is left standing rather than blanked, because `{endpoint}` on the page
# is a bug report and an empty space is not.
#
# Substitution is done with bash parameter expansion over a single string. No
# sed, no eval: a value here can be a passphrase or a server address, and both
# can hold characters that a regex engine or a shell would read as syntax.
i18n_render() {
    local tag="${1:-}" locale="${2:-}" section="${3:-}"
    shift 3 || true

    [[ -n "$tag" && -n "$section" ]] || {
        error "i18n_render <tag> <locale> <section> [name=value …]"
        return 1
    }
    locale="$(i18n_resolve "$locale")"

    local body=""
    if ! body="$(_i18n_raw_section "$tag" "$locale" "$section")"; then
        if [[ "$locale" != "$VPN55_FALLBACK_LOCALE" ]]; then
            warn "no '${section}' section in ${tag}/${locale}.txt — falling back to ${VPN55_FALLBACK_LOCALE}"
            body="$(_i18n_raw_section "$tag" "$VPN55_FALLBACK_LOCALE" "$section")" || {
                error "no '${section}' section in ${tag}/${VPN55_FALLBACK_LOCALE}.txt either"
                return 1
            }
        else
            error "no '${section}' section in ${tag}/${VPN55_FALLBACK_LOCALE}.txt"
            return 1
        fi
    fi

    local pair name value
    for pair in "$@"; do
        [[ "$pair" == *=* ]] || continue
        name="${pair%%=*}"
        value="${pair#*=}"
        [[ "$name" =~ ^[A-Za-z0-9_]+$ ]] || continue
        body="${body//\{${name}\}/${value}}"
    done

    printf '%s\n' "$body"
    return 0
}

# i18n_render_comments <prefix> <tag> <locale> <section> [name=value …]
#
# The same section, with every line prefixed — for the comment header of a
# client configuration file, where the text has to survive being read by a
# parser that only tolerates it behind a `#`.
#
# An empty line gets the prefix trimmed of its trailing space, so a config does
# not carry a column of "# " with nothing after it.
i18n_render_comments() {
    local prefix="${1:-# }"
    shift || true
    local text line
    text="$(i18n_render "$@")" || return 1
    while IFS= read -r line; do
        if [[ -z "$line" ]]; then
            printf '%s\n' "${prefix%"${prefix##*[![:space:]]}"}"
        else
            printf '%s%s\n' "$prefix" "$line"
        fi
    done <<<"$text"
    return 0
}
