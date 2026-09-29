# Staging `.com` compaction evidence

This file records observed staging state. It is not an account invoice or proof
that the full `.com` backlog has been compacted. Production was not changed.

## Source and first generation

- The pre-compaction reconciliation reported 8,760 effective contiguous chunks,
  175,195,530 valid records, no missing ledger entries, and empty staging Queues.
- D1 generation `766d9f3c333a28f7eaeabfc42b859eecb081c2c0d839053df50297e48e0df16b`
  was created from `seed-20260927` with 500 assigned deltas. Another 8,260
  remained registered.
- The local Wrangler Queue binding did not publish remote notifications.
  Map notifications were sent through the Cloudflare Queue API. At
  2026-09-29T08:43Z, staging D1 showed 408 mapped and 92 assigned deltas for
  this generation. This confirms live processing, not full completion.

## Dead-letter recovery

At 2026-09-29T08:32Z, Queue metrics reported two dead letters. A read-only
Queue peek showed two `subfinder.map-job.v1` messages for the same generation:

- Message `3b2572d7de1d091ad61b3fe7ddc38e79`, delta
  `1f73c1d666c3bc95543247f92e7a60f2895123bb57a0c68d890fd37675732e8a`.
- Message `0dcad828f59a84c7f8b9d5141de1221b`, delta
  `20b998ff300cea407d93dc7aa4388578ded19bb6479d8f90751e73af3833c0fa`.

D1 showed the first delta already `mapped` with 256 fragments and 20,000
records. The second was `assigned`; its map job was sent again through the
Queue API and D1 then showed it `mapped` at `2026-09-29T08:36:10.421Z`.
Only after both rows were `mapped`, a fresh Queue peek confirmed exactly those
two messages and their current references. The precise purge returned
`{"purged":2,"verified_mapped":true}`. Queue metrics at
2026-09-29T08:38:19Z showed dead-letter backlog 0.

The original reason those two messages exhausted retries was not available
from the later tail sample. D1 overload was observed earlier at concurrency
16, but it is an inference, not a confirmed cause for these two messages.

## Local checks

- `npm test` in `cloudflare/compaction-worker`: 11 passed, 2 optional tests
  skipped.
- `SUBFINDER_STRESS=1 npm test`: 12 passed, 1 real-data test skipped. The
  20,000-record test mapped 256 partitions and reduced one partition.
- `npm run build` in `docs`: passed.
- `git diff --check` and `node --check` on the three staging control scripts:
  passed.
