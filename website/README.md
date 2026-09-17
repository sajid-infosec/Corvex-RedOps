# Corvex — marketing website

A self-contained, single-file marketing site for Corvex with **Community (free)**
and **Premium** tiers. No build step, no dependencies (fonts load from Google
Fonts; everything else is inline).

## Host it on your PC (localhost)

```bash
cd website
python3 -m http.server 8080
# open http://localhost:8080
```

Or just open `website/index.html` directly in a browser.

## When you're ready to go public

`index.html` is fully static — drop it on any static host (Netlify, Cloudflare
Pages, GitHub Pages, an Nginx box) as-is.

## Editing the tiers

The **Free vs Premium** split in the pricing section is a starting proposal
(open-core): Community = the full self-hosted engine under Apache-2.0; Premium =
the managed / multi-tenant / at-scale / support layer. Adjust the two `.plan`
blocks in `index.html` to match your final packaging and pricing. The Premium
"Request access" button points to `mailto:sajid@aurko.org` — change it to your
signup or contact flow.
