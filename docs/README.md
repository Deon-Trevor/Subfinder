# Documentation site

The site in this directory is a separate static Cloudflare Pages project. It does not share the Subfinder read Worker's asset bundle or deployment.

## Preview locally

Run these commands from `docs/`:

```bash
npm ci
npm run build
npm run preview
```

Open the local URL printed by VitePress. Use `npm run dev` when editing pages.

## Configure Cloudflare Pages

Create a Pages project connected to this repository with these settings:

| Setting | Value |
| --- | --- |
| Root directory | `docs` |
| Framework preset | VitePress |
| Build command | `npm run build` |
| Build output directory | `.vitepress/dist` |

Keep this Pages project separate from the read Worker and the ingestion Workers. The docs build needs no API credentials or production data. Pushing the repository does not deploy this site until a Pages project is connected to it.

The source pages use VitePress local search. Cloudflare Pages serves the generated static files; no search backend or Worker secret is required for documentation search.
