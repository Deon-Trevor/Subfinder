import assert from "node:assert/strict";
import { test } from "node:test";

import { retryR2Read } from "./retry_r2_read.mjs";

test("retries an R2 transport failure without retrying a checksum mismatch", async () => {
  let reads = 0;
  const bytes = await retryR2Read(async () => {
    reads += 1;
    if (reads === 1) throw new Error("R2 read failed for key: ECONNRESET");
    return 42;
  }, 0);
  assert.equal(bytes, 42);
  assert.equal(reads, 2);

  reads = 0;
  await assert.rejects(retryR2Read(async () => {
    reads += 1;
    throw new Error("R2 size or checksum mismatch for key");
  }, 0), /checksum mismatch/);
  assert.equal(reads, 1);
});

test("stops after three failed R2 reads", async () => {
  let reads = 0;
  await assert.rejects(retryR2Read(async () => {
    reads += 1;
    throw new Error("R2 read failed for key: terminated");
  }, 0), /terminated/);
  assert.equal(reads, 3);
});
