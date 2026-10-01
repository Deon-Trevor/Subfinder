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
const publicOperations = new Set(['compose', 'cloudflare'])
const privateMarkers = [
  /subfinder-[a-z-]+-stage\b/,
  /subfinder-[a-z-]+-prod\b/,
  /migration-backup/,
  /\b000\d+_[a-z_]+\.sql\b/,
  /\/Users\/[^/]+\//
]
const errors = []

for (const page of publicPages) {
  if (!existsSync(resolve(dist, page))) errors.push(`missing public page ${page}`)
}
const operationsDir = resolve(dist, 'operations')
if (existsSync(operationsDir)) {
  for (const entry of readdirSync(operationsDir)) {
    if (!entry.endsWith('.html') || !publicOperations.has(entry.slice(0, -5))) {
      errors.push(`unexpected operations page: ${entry}`)
    }
  }
}

function checkTree(directory) {
  for (const entry of readdirSync(directory, { withFileTypes: true })) {
    const path = resolve(directory, entry.name)
    if (entry.isDirectory()) {
      checkTree(path)
    } else if (['.html', '.js', '.json'].includes(extname(entry.name))) {
      const contents = readFileSync(path, 'utf8')
      for (const marker of privateMarkers) {
        if (marker.test(contents)) errors.push(`${path}: published ${marker}`)
      }
      for (const match of contents.matchAll(/operations\/([a-z][a-z0-9-]+)/g)) {
        if (!publicOperations.has(match[1])) {
          errors.push(`${path}: linked unpublished operations page ${match[1]}`)
        }
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
  process.stdout.write(`Checked ${publicPages.length} public pages and excluded private operations pages.\n`)
}
