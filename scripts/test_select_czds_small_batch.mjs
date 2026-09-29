import assert from "node:assert/strict";
import { test } from "node:test";

import { selectSmallBatch } from "./select_czds_small_batch.mjs";

const digest = "a".repeat(64);
const artifact = (zone, bytes) => ({ relative_filename: `${zone}.zone.gz`, bytes, sha256: digest });

test("selects small unattempted zones without consuming reserved or staged zones", () => {
  const records = [artifact("later", 300), artifact("done", 100),
    artifact("small", 200), artifact("reserved", 150), artifact("large", 100001)];
  const jobs = [{ zone: "done", state: "staged" }, { zone: "running", state: "running" }];
  assert.deepEqual(selectSmallBatch(records, jobs, new Set(["reserved"]), 20, 100000), [
    { zone: "small", bytes: 200 }, { zone: "later", bytes: 300 },
  ]);
  assert.deepEqual(selectSmallBatch(records, jobs, new Set(["reserved"]), 1, 100000), [
    { zone: "small", bytes: 200 },
  ]);
});

test("fails closed on a failed eligible zone or malformed manifest", () => {
  assert.throws(() => selectSmallBatch([artifact("failed", 10)],
    [{ zone: "failed", state: "failed" }], new Set(), 20, 100000), /review failed/);
  assert.throws(() => selectSmallBatch([artifact("a", 10), artifact("a", 11)],
    [], new Set(), 20, 100000), /duplicate/);
  assert.throws(() => selectSmallBatch([artifact("a", 10)],
    [], new Set(), 101, 100000), /limits/);
});
