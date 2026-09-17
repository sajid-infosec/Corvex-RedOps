# Corvex — marketing website

A self-contained, single-file marketing site for Corvex with **Free** and
**Premium** tiers. No build step, no dependencies (fonts load from Google Fonts;
everything else is inline).

> **This is separate from the Corvex tool.** The SaaS/tool (console, scanning,
> reports) is deployed from the repo root with `./install.sh` and runs on
> **:8080** (Docker) or **:8000** (`corvex serve`). This website is just the
> brochure — it lives in its own directory and runs on **:9090**, so the two
> never collide.

## Run the website (standalone, port 9090)

**Quick / local:**
```bash
cd website
./serve.sh                 # → http://localhost:9090
./serve.sh 9091            # pick another port
```

**As a container (separate from the SaaS stack):**
```bash
cd website
docker compose up -d       # → http://localhost:9090
docker compose down        # stop
```

Both are independent of `install.sh` — starting or stopping the website never
touches the Corvex tool, and vice-versa.

## Deploy it publicly

`index.html` is fully static — drop it on any static host (Netlify, Cloudflare
Pages, GitHub Pages, an Nginx box) as-is, or run the container above behind your
reverse proxy.

## Which is which

| | URL | What it is |
|---|---|---|
| **Website** (this folder) | http://localhost:9090 | The marketing brochure — hero, coverage, Free/Premium pricing |
| **Tool console** (repo root) | http://localhost:8080 | The actual Corvex app — log in, run scans, get reports |

## Editing the tiers

The **Free vs Premium** split in the pricing section is a starting proposal
(open-core): Free = the full self-hosted engine under Apache-2.0; Premium = the
managed / multi-tenant / at-scale / support layer. Adjust the two `.plan` blocks
in `index.html` to match your final packaging and pricing. The Premium "Request
access" button points to `mailto:sajid@aurko.org` — change it to your signup or
contact flow.
