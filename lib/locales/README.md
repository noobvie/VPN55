# Shell-side translated text — VI (default) · EN · FR

The text `lib/proto_*.sh` hands to an **end user**: setup instructions that ship
beside a credential, and the comment header of a client configuration file. Both
are read by the person using the VPN, not by the operator running the installer.

Everything else on the shell side stays English — `vpn55.sh`, every menu, every
`error()` and `warn()`, `helper/vpnctl`. See `docs/i18n.md` §1 for why.

```
lib/locales/<adapter tag>/<locale>.txt
```

## Format

```
@@ section.name
Prose with {placeholder} tokens.

@@ another.section
More prose.
```

A section is looked up by **name**, never by matching its English text. That is
the same rule the JSON catalogs follow, and for the same reason: a map keyed on
English word order misses every translator who reorders the sentence, and the two
files still look parallel afterwards.

Placeholders are filled by the adapter through `i18n_render`. Substitution is
bash parameter expansion over one string — no `sed`, no `eval` — because a value
here can be a passphrase or a server address, and both can hold characters a
regex engine or a shell would read as syntax.

## The two things that are the contract

**Section names.** A section the renderer asks for and this file does not carry
falls back to English *in the middle of a translated page* — one paragraph in the
wrong language, which reads as a glitch rather than as a missing translation.

**The placeholder set inside each section.** This is the one that costs a user
their connection. A translator who drops `{endpoint}` has removed the server
address from a page whose entire purpose is to carry it, and the sentence still
reads perfectly well.

Both are checked by `.github/scripts/check-locale-text.mjs`, in CI, in both
directions — a section invented in `vi.txt` and authored nowhere else fails too.

## Translating

- Keep every `@@ section` name and every `{placeholder}` exactly as they are.
- Translate the prose. Do not translate **commands**. The IKEv2 page carries a
  PowerShell block: translate the `#` comments inside it, never the cmdlets, the
  parameter names or the values.
- Do not translate file names (`vpn55-<cred>.ovpn`), protocol identifiers
  (`IKEv2 Certificate`), or the labels of fields in a third-party app's UI — a
  reader has to find those strings on their own screen, in whatever language that
  app is in.
- Line length: keep it under about 78 columns. These are plain-text files read in
  a terminal or a mail client, with no reflow.

## Adding an adapter

Create `lib/locales/<your tag>/{vi,en,fr}.txt` with matching sections. The check
requires all three the moment one exists — a missing `fr.txt` means a French user
silently gets the English page, which is exactly the failure that never gets
reported.
