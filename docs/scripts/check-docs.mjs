import { existsSync, readFileSync } from 'node:fs'
import { resolve, dirname } from 'node:path'
import { fileURLToPath } from 'node:url'

const docs = resolve(dirname(fileURLToPath(import.meta.url)), '..')
const repo = resolve(docs, '..')
const pages = [
  'index.md',
  'getting-started.md',
  'reference/api.md',
  'reference/sources.md',
  'how-to/ingestion.md',
  'operations/compose.md',
  'operations/cloudflare.md',
  'operations/source-refresh.md',
  'operations/staging-reconciliation.md',
  'operations/staging-compaction.md',
  'operations/staging-cost.md',
  'operations/next-czds-batch.md',
  'operations/cutover-acceptance.md',
  'explanation/web-interface.md'
]
const requiredFacts = new Map([
  ['reference/api.md', ['POST /internal/v1/record-batches', 'POST /mcp', 'X-Next-Cursor']],
  ['operations/compose.md', ['CTLOGS_PUBLIC_INFLIGHT_LIMIT', 'CTLOGS_FORWARDED_ALLOW_IPS']],
  ['how-to/ingestion.md', ['CTLOGS_CZDS_MAX_ZONES', 'CTLOGS_URLSCAN_APEXES']],
  ['operations/cloudflare.md', ['catalog/root.json', 'PUBLISH_TOKEN', 'CZDS_PASSWORD']]
])
const errors = []

function checkLink(source, target) {
  if (/^(?:https?:|mailto:|#)/.test(target)) return
  const pathname = decodeURIComponent(target.split(/[?#]/, 1)[0])
  if (!pathname) return
  const base = pathname.startsWith('/') ? docs : dirname(source)
  const resolved = resolve(base, pathname.replace(/^\//, ''))
  const candidates = [resolved, `${resolved}.md`, resolve(resolved, 'index.md')]
  if (!candidates.some(existsSync)) errors.push(`${source}: missing link ${target}`)
}

for (const name of pages) {
  const path = resolve(docs, name)
  if (!existsSync(path)) {
    errors.push(`missing page ${name}`)
    continue
  }
  const content = readFileSync(path, 'utf8')
  for (const fact of requiredFacts.get(name) ?? []) {
    if (!content.includes(fact)) errors.push(`${name}: missing ${fact}`)
  }
  for (const [, target] of content.matchAll(/\]\(([^)]+)\)/g)) checkLink(path, target)
}

for (const name of ['README.md', 'SOURCES.md', 'cloudflare/README.md']) {
  const path = resolve(repo, name)
  const content = readFileSync(path, 'utf8')
  for (const [, target] of content.matchAll(/\]\(([^)]+)\)/g)) checkLink(path, target)
}

const readme = readFileSync(resolve(repo, 'README.md'), 'utf8')
if (readme.split('\n').length > 90) errors.push('README.md is longer than 90 lines')

if (errors.length) {
  for (const error of errors) process.stderr.write(`${error}\n`)
  process.exitCode = 1
} else {
  process.stdout.write(`Checked ${pages.length} documentation pages and repository entry points.\n`)
}
