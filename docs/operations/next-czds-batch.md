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
