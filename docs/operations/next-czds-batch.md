# Next CZDS staging batch

Prepare three zones in sequence after the `.com` generation is reduced,
verified, and serving from the staging Worker. Do not start these jobs while
the first generation is still reducing. Keep the staging Cron empty and the
production hostname unchanged.

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
and any recovery work are fully closed. Leave Cron disabled. The scheduler
fails closed if the requested zone is absent from the current approved link
feed. Do not copy a download URL into configuration.

Before moving to the next zone, require a successful Workflow, a complete
staging D1 job, contiguous chunk indices, equal D1 and R2 chunk counts,
effective-record validation, an empty dead-letter Queue, and registration in
the generation ledger. Run the [staging reconciliation](/operations/staging-reconciliation)
and [compaction](/operations/staging-compaction) checks for each zone. A failed
or partial zone must not enter a published generation. Compare representative
exact-apex results on the staging Worker after activation; do not change
`subfinder.syncpundit.io`.

This page is a prepared batch, not authorization to start it. The live
configuration remains restricted to `.com` until the current compaction is
finished and reviewed.
