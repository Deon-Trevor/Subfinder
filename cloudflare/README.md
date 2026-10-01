# Cloudflare deployment

See [the Cloudflare operations guide](../docs/operations/cloudflare.md) for the Worker layout, ingestion setup, and generation publication.

Each Worker has a public `wrangler.example.jsonc`. Copy it to an ignored
`wrangler.local.jsonc` in the same directory and replace the example resource
names before deployment. From the repository root, run
`node scripts/check_cloudflare_bindings.mjs --examples` to check the templates.
Pass your local config paths to the same script to check that the selected
Workers share the intended catalog and compaction Queue.

There is no implicit `npm run deploy`. `npm run deploy:configured` uses the
local config in that Worker directory. A dry run shows the bindings before a
live deploy. Keep configured files and recovery procedures in your own private
version control; the deployed Cloudflare resources are not their backup.
