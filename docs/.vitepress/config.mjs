import { defineConfig } from 'vitepress'

export default defineConfig({
  base: '/docs/',
  title: 'Subfinder',
  description: 'Passive subdomain index documentation',
  cleanUrls: true,
  srcExclude: [
    'README.md',
    'operations/source-refresh.md',
    'operations/staging-reconciliation.md',
    'operations/staging-compaction.md',
    'operations/staging-cost.md',
    'operations/next-czds-batch.md',
    'operations/czds-stage-sweep.md',
    'operations/cutover-acceptance.md'
  ],
  head: [
    ['link', { rel: 'icon', href: '/docs/mark.svg', type: 'image/svg+xml' }],
    ['meta', { name: 'theme-color', content: '#101a26' }]
  ],
  themeConfig: {
    logo: '/mark.svg',
    siteTitle: 'Subfinder Docs',
    search: { provider: 'local' },
    nav: [
      { text: 'Get started', link: '/getting-started' },
      { text: 'API', link: '/reference/api' },
      { text: 'Operations', link: '/operations/compose' },
      { text: 'GitHub', link: 'https://github.com/Deon-Trevor/Subfinder' }
    ],
    sidebar: [
      {
        text: 'Start here',
        items: [
          { text: 'Overview', link: '/' },
          { text: 'Get started', link: '/getting-started' }
        ]
      },
      {
        text: 'Use Subfinder',
        items: [
          { text: 'API and MCP', link: '/reference/api' },
          { text: 'Source catalog', link: '/reference/sources' },
          { text: 'Ingest source data', link: '/how-to/ingestion' },
          { text: 'Web interface', link: '/explanation/web-interface' }
        ]
      },
      {
        text: 'Deploy Subfinder',
        items: [
          { text: 'Compose service', link: '/operations/compose' },
          { text: 'Cloudflare deployment', link: '/operations/cloudflare' }
        ]
      }
    ],
    socialLinks: [
      { icon: 'github', link: 'https://github.com/Deon-Trevor/Subfinder' }
    ],
    footer: {
      message: 'Passive collection. Exact-apex lookups. No live probing on search.'
    }
  }
})
