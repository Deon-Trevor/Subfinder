# Next CZDS staging batch

Stage three zones in sequence while `.com` compaction continues. Set
`CZDS_STAGE_ONLY=true` on the staging CZDS Worker before starting a job. A
staged Workflow must leave its job in `staged` state and send no delta-ready
messages to the shared compaction Queue. Do not publish these zones or start
their catalog generations until the `.com` chain is verified and idle. Keep
the production hostname unchanged.

| Order | Zone | Old local gzip size | Parser path to exercise |
| --- | --- | ---: | --- |
| 1 | `aaa` | 3,474 bytes | Worker parser and near-empty output |
| 2 | `business` | 1,773,198 bytes | Worker parser with a modest zone |
| 3 | `biz` | 43,854,672 bytes | Container parser at a medium size |

These are sizes from the 2026-09-26 local CZDS manifest, not current ICANN
download sizes. The manifest contains 166 completed artifacts, only through
`.com`; it is not a list of every zone available to this account. Its three
entries have SHA-256 digests
`7ee2015cbe004d782e8d11b7c96510151e52b860535f720b7569628d2b7721cd`,
`56e19787a71afecde9eaa7ff29a2edef6392ef5a14cf797a0c13a7c83e31faf4`,
and `128103f6c3741799c49541ff47b38c285c2b10ae9cb4e707e91ed4148cd1a7b8`
in that order. They identify the old local artifacts only. Each staging run
must use a fresh approved CZDS link and its own fingerprint.

For each zone, set `CZDS_ONLY_ZONE` to that exact zone and keep
`CZDS_MAX_ZONES=1` in the staging configuration. For `biz`, add `biz` to
`CZDS_CONTAINER_ZONES` before deploying; do not remove `com` until its job
and any recovery work are fully closed. Start one zone with a temporary
staging Cron, then remove the trigger as soon as its D1 job and Workflow
instance exist. Confirm the deployed Cron list is empty before changing zones.
The scheduler fails closed if the requested zone is absent from the current
approved link feed. Do not copy a download URL into configuration.

Before moving to the next zone, require a successful Workflow, a `staged` D1
job, contiguous chunk indices, equal D1 and R2 chunk counts, and matching
record totals. Confirm the shared compaction Queue received no messages from
the staged job. A failed or partial zone must not enter a generation. After
`.com` compaction is finished, publish each staged job under a separate
controlled gate, run [staging reconciliation](/operations/staging-reconciliation)
and [compaction](/operations/staging-compaction), then compare representative
exact-apex results after activation.

Staging is not publication. Do not turn off `CZDS_STAGE_ONLY` while a zone is
being parsed. Keep the temporary Cron removed between runs and after the batch.

## Staged on 2026-09-29

All three Workflows finished successfully. Each job remains `staged`, every
contiguous D1 chunk was retrieved from private R2 and checked against its
record count, and none of these deltas appears in the generation ledger.
The deployed CZDS Cron list is empty.

| Zone | Job ID | Chunks | Records |
| --- | --- | ---: | ---: |
| `aaa` | `455cb80b5989d32aa723a774d7fc751e017d6f306fc64d0afafd45061e01bfae` | 1 | 5 |
| `business` | `69f0f6c0c7e85dcaea9de98e19e87811a441f15afc6b3907d3e778bca0f8d6ed` | 3 | 42,508 |
| `biz` | `8a0cedb04cf7e2481ec29730a6fd3dc2d7863afe6d7b13163c04aa631566c887` | 68 | 1,351,214 |

Rerun `node scripts/verify_staged_czds.mjs JOB_ID` for any row before its
later publication gate. Do not call a staged zone searchable yet.

## Next batch: largest unstaged gTLD zones

The [2026-09-28 gTLD zone-count ranking](https://ntlddata.com/?scope=all)
puts `.com`, `.net`, `.org`, `.xyz`, `.top`, `.info`, `.shop`, `.online`,
`.store`, `.vip`, `.site`, `.app`, `.biz`, `.bond`, and `.pro` in the first
15. This is a count of domains in zone files, not DNS traffic or a promise
about which links this account may download. The [Q2 2026 Domain Name Industry
Brief](https://www.dnib.com/articles/the-domain-name-industry-brief-q2-2026)
independently identifies the first ten gTLDs. The final three were checked
against the individual [`.biz`](https://www.ntlddata.com/tld/biz?scope=all),
[`.bond`](https://www.ntlddata.com/tld/bond?scope=all), and
[`.pro`](https://www.ntlddata.com/tld/pro?scope=all) counts. `.com` ingestion is complete
and `.biz` is staged, so the next batch has 13 jobs, in this order:

`net`, `org`, `xyz`, `top`, `info`, `shop`, `online`, `store`, `vip`, `site`,
`app`, `bond`, `pro`.

The ranking is frozen in `scripts/czds_top15_batch.json`. Run
`node scripts/plan_czds_stage_batch.mjs` to compare it with the live staging
ledger. That command only reads D1. It fails if a CZDS job is active, a
ranked zone has a failed job requiring review, or the local stage-only,
single-zone, Cron-free, single-Container settings have drifted. The staging
config prepares all 15 zones for the Container parser, but retains
`CZDS_ONLY_ZONE=biz` and no Cron. **Preparation does not start ingestion.**

Before starting any row, confirm its exact name is in this account's fresh
approved CZDS link feed. The scheduler enforces this at job creation; public
zone counts do not confer CZDS access. Keep `CZDS_STAGE_ONLY=true`,
`CZDS_MAX_ZONES=1`, and one active parser job at a time. Set
`CZDS_ONLY_ZONE` to the next exact zone, deploy the staging CZDS Worker,
temporarily enable the staging Cron to create one Workflow, then remove the
Cron as soon as the D1 job and Workflow exist. Check the deployed Cron list
is empty. Do not change the production hostname or enable compaction Cron.

For every job, wait for Workflow success and run
`node scripts/verify_staged_czds.mjs JOB_ID`. That verifier checks contiguous
chunks, all private R2 objects, record totals, and zero generation-ledger
registrations. Do not start the next zone until this check passes. Do not
publish these staged jobs until the `.com` generation chain has finished and
the separate publication gate has been reviewed. At roughly 63 million
domains across the 13 public zone-count estimates, this is a substantial
Container and R2 batch, not a free background task; measure the first large
zone before committing to the rest.
