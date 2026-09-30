import assert from "node:assert/strict";
import { test } from "node:test";

import { needsStageCron } from "./czds_stage_cron_decision.mjs";

test("arm Cron only when deployment has not already produced a job", () => {
  assert.equal(needsStageCron([]), true);
  assert.equal(needsStageCron([{ job_id: "a" }]), false);
  assert.throws(() => needsStageCron([{ job_id: "a" }, { job_id: "b" }]), /multiple CZDS jobs/);
});
