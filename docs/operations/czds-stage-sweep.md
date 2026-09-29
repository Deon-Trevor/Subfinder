# Stage the remaining CZDS zones

The local CZDS manifest lists 166 artifacts downloaded in September 2026.
It covers only the alphabetical range through `.com`. Its sizes help choose
short staging runs, but they do not prove that an artifact is still available
or approved. The CZDS scheduler obtains a fresh approved link for each job.

The first small batch is `scripts/czds_small_batch_01.json`. Its 20 historical
gzip files were each smaller than 2.3 KB. These zones use the Worker parser;
none is in `CZDS_CONTAINER_ZONES`. Generate the next candidate list with:

```sh
node scripts/select_czds_small_batch.mjs \
  /Users/pancake/Documents/subfinder-migration-backup/20260926T212817Z/evidence/czds-manifest.jsonl \
  --limit 20 --max-bytes 100000
```

The selector reads staging D1 and excludes staged, completed, active, and
Container-reserved zones. It stops on an unreviewed failed job. Raise
`--max-bytes` only after the smaller candidates are staged. The manifest
does not include zones after `.com`; obtain a fresh approved-link inventory
before claiming that every CZDS zone is covered.

## Run one zone

1. If a Container parser job is active, wait for its Workflow to finish.
   Deploying the CZDS Worker during that job can reset its Durable Object.
2. Run `node scripts/plan_czds_stage_batch.mjs czds_small_batch_01.json`.
   Resolve any active or failed job before continuing.
3. Set `CZDS_ONLY_ZONE` to the next pending zone. Keep
   `CZDS_STAGE_ONLY=true`, `CZDS_MAX_ZONES=1`, and the Cron list empty.
4. Deploy only the staging CZDS Worker with `--containers-rollout none`.
   Add the one-minute staging Cron with `wrangler triggers deploy`.
5. As soon as D1 has one job and the Workflow exists, remove the Cron and
   verify that the deployed trigger list has no schedule.
6. Wait for Workflow success. Run `node scripts/verify_staged_czds.mjs JOB_ID`.
   The verifier checks every R2 object, chunk order, record count, and the
   absence of generation-ledger registration. Do not advance on failure.

Keep one staging job active at a time. Do not publish its deltas or change
`catalog/root.json`. If `.com` compaction finishes and its active chain
includes all 8,760 effective `.com` chunks, stop starting new zones. Use
the staged-job publication and reconciliation gate before adding those zones
to a generation. Do not enable compaction Cron or switch production as part
of this sweep.
