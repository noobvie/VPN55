# Locale catalogs — VI (default) · EN · FR

**Keyed catalogs, never phrase maps.** `t('peer.add.button')` resolving against
`vi.json` / `en.json` / `fr.json`. Never a map keyed on English strings.

- **Vietnamese is the default locale.** English is the fallback *and* the
  key-authoring source language. `vi.json` is the file that must never have a
  missing key — it is what most users see.
- A missing key falls back to English **and logs**. Silent blanks are worse than
  an untranslated string.
- A key missing from English too returns **the key itself, visibly**. A blank
  would read as a design decision and would never get reported.

The full contract — the shell side's catalogs, Intl formatting, font coverage,
expansion budget, UTF-8, the locale cookie — is `docs/i18n.md`.

## What CI enforces on these three files

| Script | Refuses |
|---|---|
| `check-locales.mjs` | key sets that diverge; a blank value; a catalog that does not parse |
| `check-i18n-usage.mjs` | a key the panel **looks up** that exists in none of them |
| `check-expansion.mjs` | a laid-out string past its ceiling in any locale |

The second one exists because key parity cannot see the other direction. All
three files can agree perfectly while the panel asks for a key nobody ever
authored — which is what it found on its first run, in `panel/lib/auth.js`.

## Editing

Keys are flat and dotted, grouped by the screen they serve. Do not reorder or
rename a key to suit a translation: **the key is the contract and the English
text is not.** Renaming one is a code change in the same commit, and the usage
check is what will tell you if you missed a site.

`{name}` placeholders are filled at render time. Keep every one that the English
value carries — dropping one removes a fact from the sentence and leaves the
prose intact, which is the failure nobody reports.

There is **no plural machinery**, deliberately. Vietnamese has no plural
inflection and French pluralises differently from English, so a phrasing here has
to work for any count in its own language; the number itself is rendered by
`Intl.NumberFormat`. Never write a string that only reads correctly at n = 1.
