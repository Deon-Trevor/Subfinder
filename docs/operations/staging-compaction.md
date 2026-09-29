# Compact the staging `.com` deltas

This procedure changes only `subfinder-catalog-stage` and the staging generation
ledger. It does not change `subfinder.syncpundit.io`.

The staging compaction Worker consumes Queue messages but has no Cron trigger.
Use the local admin configuration to advance one generation at a time. Its R2
and D1 bindings point to staging; its Queue binding is local. Publish the real
Queue messages with `scripts/dispatch_staging_compaction.mjs`.

## Check the current state

From the repository root, inspect the active preview generation:

```sh
curl -fsS https://subfinder.pundit.workers.dev/ready
```

Check the staging generation and delta states:

```sh
cd cloudflare/compaction-worker
npx wrangler d1 execute subfinder-generation-stage-ledger --remote \
	--config wrangler.staging.jsonc \
	--command "SELECT generation_id, base_generation, state, delta_count, partition_count FROM catalog_generations ORDER BY created_at DESC LIMIT 3"
npx wrangler d1 execute subfinder-generation-stage-ledger --remote \
	--config wrangler.staging.jsonc \
	--command "SELECT state, count(*) AS chunks, sum(record_count) AS records FROM catalog_deltas GROUP BY state"
```

Do not start a second generation while one is `mapping`, `mapped`, `reducing`,
or `published`. If the main Queue or dead-letter Queue contains messages,
inspect them before dispatching more work.

## Map one generation

From the repository root, inspect the next action, then run its local scheduled
handler once:

```sh
node scripts/schedule_staging_compaction.mjs
node scripts/schedule_staging_compaction.mjs --execute
```

The command prints the new `generation_id`. Its local Queue binding does not
publish to the staging Queue. Inspect and then dispatch the assigned map jobs:

```sh
node scripts/dispatch_staging_compaction.mjs map GENERATION_ID
node scripts/dispatch_staging_compaction.mjs map GENERATION_ID --execute
```

The dispatcher refuses to publish while either staging Queue has a backlog.
If delivery stops and both Queues are empty, run the dispatcher again. Mapping
is idempotent, and the dispatcher selects only deltas still in `assigned` state.

Wait until all assigned deltas are `mapped` and the generation state becomes
`mapped`. Check `catalog_deltas.error` and the dead-letter Queue if progress
stops. Do not start reduction with missing map work.

## Reduce and activate

Invoke `schedule_staging_compaction.mjs` again with `--execute`. It changes the
generation state to `reducing` and identifies the changed partitions. Then
dispatch their remote Queue jobs:

```sh
node scripts/dispatch_staging_compaction.mjs reduce GENERATION_ID
node scripts/dispatch_staging_compaction.mjs reduce GENERATION_ID --execute
```

Wait for every changed partition to reach `reduced` and the generation to
reach `published`. The candidate at `catalog/candidates/GENERATION_ID.json`
does not affect searches. Inspect its stats and partition metadata before
activation. If a partition fails, leave the active root alone and inspect
`generation_partitions.error` and the dead-letter Queue.

Verify the candidate against the ledger and active base root, then stream and
hash every index and bundle object without creating a local copy:

```sh
node scripts/verify_staging_generation.mjs GENERATION_ID
```

The command checks candidate identity, source metadata, totals, partition
metadata, object sizes, and SHA-256 hashes. Do not activate on a mismatch.

When the candidate checks pass, use the protected publication route through
the local admin Worker. The script creates a temporary local token, verifies the
staging ledger, and checks `/ready` after activation:

```sh
node scripts/staging_generation_admin.mjs activate GENERATION_ID
node scripts/staging_generation_admin.mjs activate GENERATION_ID --execute
```

After activation, compare representative exact-apex results and `/v1/stats`
with the seed and the expected `.com` data. If the result is wrong, stop before
starting another generation. The protected rollback route is available through
`staging_generation_admin.mjs rollback GENERATION_ID --execute`.

Repeat this sequence until no `.com` deltas remain `registered`. Each new
generation uses the currently active generation as its base. Keep the staging
Cron disabled. Do not switch the production hostname as part of this run.
