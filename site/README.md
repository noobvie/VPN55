# The landing page

One file, `index.html`, with **no external requests of any kind** — no web fonts, no
analytics, no CDN, no build step.

That is a constraint, not an omission:

1. It has to render from an onion service and from a plain static mirror, where a
   request to `fonts.googleapis.com` does not fail, it *hangs*.
2. Every external request puts another hostname in the TLS SNI — one more thing for a
   filter to key on, attached to a page whose entire subject is filtering.
3. A privacy tool that phones a third party on its own front page has already lost the
   argument it is making.

If this page ever needs a build step, it is doing too much.

---

## Publishing it

It must be live at **both** addresses. A DNS block on the custom domain does not touch
the `github.io` hostname, and that is the whole point of having two.

### `noobvie.github.io/VPN55` — GitHub Pages

Either route works; pick one and write down which.

**From a branch.** Settings → Pages → *Deploy from a branch* → `main` / `/docs`, then
symlink or copy `site/index.html` to `docs/index.html`. Simplest, but it puts a second
copy of the page in the tree and the two drift.

**From an action.** Settings → Pages → *GitHub Actions*, then add a workflow that
uploads `site/` as the Pages artifact. No second copy, and the page is deployed from the
same commit as the code.

> No Pages workflow is committed here on purpose. Enabling Pages publishes a page under
> an account name, which is part of the publishing-identity decision (`docs/launch.md`
> §4) — not something a build should do as a side effect.

### `vpn55.org` — the custom domain

Behind Cloudflare, so that blackholing the IP carries collateral damage. Point it at the
same static file; there is no server-side anything.

---

## Keeping it honest

The page repeats four things from the README, and they have to stay in step:

- **the install command** — the canonical `raw.githubusercontent.com` URL;
- **`VPN55_MIRROR`** — the escape hatch, with a worked example;
- **the verify steps** — and the plain statement that `curl | bash` cannot verify
  itself. Never soften that. Claiming signing makes the one-liner safe is worse than not
  signing at all;
- **the pre-release banner** — it comes off when the distribution matrix has rows in it,
  not before.

**The mirror list is deliberately NOT on this page.** It lives in the repository README,
which is the root of trust. A site that lists its own mirrors disappears together with
them — which is exactly when someone needs the list.
