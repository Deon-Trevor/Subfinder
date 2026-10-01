import { existsSync, readFileSync, readdirSync } from 'node:fs'
import { resolve, dirname, extname } from 'node:path'
import { fileURLToPath } from 'node:url'

const docs = resolve(dirname(fileURLToPath(import.meta.url)), '..')
const dist = resolve(docs, '.vitepress/dist')
const publicPages = [
  'index.html',
  'getting-started.html',
  'reference/api.html',
  'reference/sources.html',
  'how-to/ingestion.html',
  'operations/compose.html',
  'operations/cloudflare.html',
  'explanation/web-interface.html'
]
const internalPages = [
  'operations/source-refresh',
  'operations/staging-reconciliation',
  'operations/staging-compaction',
  'operations/staging-cost',
  'operations/next-czds-batch',
  'operations/czds-stage-sweep',
  'operations/cutover-acceptance'
]
const privateMarkers = [
  'subfinder-index-stage.pundit.workers.dev',
  'subfinder-catalog-stage',
  'subfinder-urlscan-prod',
  '0003_public_bulk_source.sql',
  'subfinder-migration-backup'
]
const errors = []

for (const page of publicPages) {
  if (!existsSync(resolve(dist, page))) errors.push(`missing public page ${page}`)
}
for (const page of internalPages) {
  if (existsSync(resolve(dist, `${page}.html`))) {
    errors.push(`internal page published: ${page}`)
  }
}

function checkTree(directory) {
  for (const entry of readdirSync(directory, { withFileTypes: true })) {
    const path = resolve(directory, entry.name)
    if (entry.isDirectory()) {
      checkTree(path)
    } else if (['.html', '.js', '.json'].includes(extname(entry.name))) {
      const contents = readFileSync(path, 'utf8')
      for (const marker of [...internalPages, ...privateMarkers]) {
        if (contents.includes(marker)) errors.push(`${path}: published ${marker}`)
      }
    }
  }
}

if (existsSync(dist)) checkTree(dist)
else errors.push('missing built documentation')

if (errors.length) {
  for (const error of errors) process.stderr.write(`${error}\n`)
  process.exitCode = 1
} else {
  process.stdout.write(`Checked ${publicPages.length} public pages and excluded ${internalPages.length} internal pages.\n`)
}
