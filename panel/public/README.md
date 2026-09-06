# Admin UI assets

```
css/vendor/office-tools.css   PINNED copy of the Office Tools stylesheet
css/panel.css                 the panel's own layer
css/brand.css                 the footer signature + the flag; SHARED with the portal
js/theme.js                   PINNED four-theme switcher (light/dark/matrix/anime)
js/i18n.js                    catalog lookup, locale switching
js/format.js                  Intl formatting — bytes, dates, durations
js/app.js                     the four views
```

## The vendored files are never edited

`css/vendor/office-tools.css` is byte-identical to upstream below its header, and
`js/theme.js` carries two deltas documented in its own header. Both are pinned to
a recorded commit and sha256 (`ATTRIBUTIONS.md`). Pinning is the point: the admin
UI must not shift the day the tools site is restyled.

**Panel styling goes in `panel.css`**, which loads second and overrides by
cascade. If you find yourself wanting to change a line in `vendor/`, the answer
is a rule in `panel.css`.

## `brand.css` is the one deliberate exception

It is loaded by the admin panel **and** by the self-serve portal, which does not
load `panel.css` at all. It carries no layout — only the "made in" line at the
bottom of every page and the flag drawn beside it — and it is the only file here
that contains a hex value on purpose: a flag is not a theme colour, and it is the
same yellow and the same red on all four themes. `site/index.html` repeats the
same six percentages inline, because that page makes no external request of any
kind; those two are kept in step by hand.

## Every colour is a token

`--bg`, `--text`, `--primary` and the rest are defined four times over by the
vendored file — once at `:root` and once per `[data-theme]` — so a rule written
against the tokens is correct in all four themes for free. `panel.css` contains
no hex value at all.

The corollary is the part that actually gets missed: **wherever a rule sets
`background`, it sets `color` too**, and the other way round. A quiet element
that overrides only its background inherits ink chosen for a different surface,
and these four themes range from a near-white page to a near-black one.

## Layout is sized against French

French runs 15–25% longer than English, and Vietnamese has taller diacritics.
Nothing is a fixed width sized to an English word: labels wrap, table columns are
content-sized, buttons are padded rather than measured, and wide tables scroll
inside their own box so the page body never scrolls sideways.

## No `innerHTML`, anywhere

Every node is created and every string goes in as a text node. User names,
credential ids and adapter notes are all values from the host. The CSP is the
second line of defence, not the first.
