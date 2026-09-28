# Documentation site

The site in this directory is a separate static Cloudflare Pages project. The read Worker serves it at `https://subfinder.pundit.workers.dev/docs/` by proxying `/docs/*` to the Pages project. It does not share the read Worker's asset bundle.

## Preview locally

Run these commands from `docs/`:

```bash
npm ci
npm run build
npm run preview
```

Open the local URL printed by VitePress. Use `npm run dev` when editing pages.

## Deploy to Cloudflare Pages

Build the site, then upload `.vitepress/dist` to the `subfinder-docs` Pages project. The VitePress base path is `/docs/`, so the Worker strips `/docs` when it fetches a Pages asset. The Pages project must remain available at `https://subfinder-docs.pages.dev` for the Worker route to work. Pages rewrites `/docs/*` to the built assets so its direct site also works.

```bash
cd docs
npm run check
../cloudflare/index-worker/node_modules/.bin/wrangler pages deploy .vitepress/dist --project-name subfinder-docs --branch main
```

Keep this Pages project separate from the read Worker and the ingestion Workers. The docs build needs no API credentials or production data. Pushing the repository does not deploy a Direct Upload Pages project.

The source pages use VitePress local search. Cloudflare Pages serves the generated static files; no search backend or Worker secret is required for documentation search.
