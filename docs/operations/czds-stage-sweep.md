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

## Run a small batch

Preview the remaining zones and the `.com` gate:

```sh
node scripts/run_czds_stage_sweep.mjs czds_small_batch_01.json --limit 20
```

To stage them, run the same command with `--execute`. The runner deploys a
staging-only Worker configuration for one zone at a time. It arms a one-minute
Cron only until one job appears, removes the Cron, waits for the job, and checks
every staged R2 chunk before advancing. It stops when the batch is exhausted
or the `.com` compaction gate is reached. If a run fails, check the remote Cron,
job, and Workflow state before retrying. Staging does not register the zone's
deltas for compaction or publish a catalog root. A new Cron can take up to
[15 minutes to propagate](https://developers.cloudflare.com/workers/configuration/cron-triggers/),
so the runner allows 18 minutes for the first job before it disarms the Cron
and reports a timeout.

## Run one zone

1. If a Container parser job is active, wait for its Workflow to finish.
   Deploying the CZDS Worker during that job can reset its Durable Object.
2. Run `node scripts/plan_czds_stage_batch.mjs czds_small_batch_01.json`.
   Resolve any active or failed job before continuing.
3. In `cloudflare/czds-worker/wrangler.staging.jsonc`, set
   `CZDS_ONLY_ZONE` to the next pending zone. Keep `CZDS_STAGE_ONLY=true`,
   `CZDS_MAX_ZONES=1`, and `triggers.crons=[]`. From `cloudflare/czds-worker`,
   deploy with:

   ```sh
   ./node_modules/.bin/wrangler deploy \
     --config wrangler.staging.jsonc --containers-rollout none
   ```

4. Check D1 for a job in the selected zone after the Worker deployment. If
   exactly one job exists, do not arm Cron. If more than one exists, stop and
   investigate. If no job exists, temporarily set
   `triggers.crons=["* * * * *"]` in the same config and deploy only its triggers:

   ```sh
   ./node_modules/.bin/wrangler triggers deploy \
     --config wrangler.staging.jsonc
   ```

5. If you armed Cron, wait until D1 shows exactly one new job and its Workflow
   exists. Set `triggers.crons=[]` and run the same `wrangler triggers deploy`
   command.
   Confirm that its output has no `schedule:` line. Leave the local config
   Cron-free before checking the job or changing zones.
6. Wait for Workflow success. Run `node scripts/verify_staged_czds.mjs JOB_ID`.
   The verifier checks every R2 object, chunk order, record count, and the
   absence of generation-ledger registration. Do not advance on failure.

Keep one staging job active at a time. Do not publish its deltas or change
`catalog/root.json`. If `.com` compaction finishes and its active chain
includes all 8,760 effective `.com` chunks, stop starting new zones. Use
the staged-job publication and reconciliation gate before adding those zones
to a generation. Do not enable compaction Cron or switch production as part
of this sweep.
