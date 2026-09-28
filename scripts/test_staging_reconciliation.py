"""Contract tests for staged CZDS coverage states."""

import unittest
import hashlib

from staging_reconciliation import reconcile


JOB = {"job_id": "1" * 64, "zone": "com", "state": "complete",
       "delta_count": 2, "hostname_count": 4}
SOURCE = [
    {"chunk_index": 0, "delta_id": "a" * 64, "object_key": "a", "record_count": 2},
    {"chunk_index": 1, "delta_id": "b" * 64, "object_key": "b", "record_count": 2},
]
LEDGER = [
    {"delta_id": row["delta_id"], "source_kind": "czds", "object_key": row["object_key"],
     "record_count": row["record_count"], "object_sha256": "c" * 64,
     "object_bytes": 100, "state": "registered", "error": None}
    for row in SOURCE
]
REPAIR = {
    "chunk_index": 0,
    "original_delta_id": SOURCE[0]["delta_id"],
    "original_object_key": SOURCE[0]["object_key"],
    "original_record_count": 2,
    "original_document_sha256": "d" * 64,
    "replacement_delta_id": hashlib.sha256(f"{'a' * 64}:{'f' * 64}".encode()).hexdigest(),
    "replacement_object_key": f"ingest/czds/com/{'1' * 64}-0-repair-{'f' * 64}.json.gz",
    "replacement_record_count": 1,
    "replacement_document_sha256": "f" * 64,
    "excluded_record_count": 1,
}


class ReconciliationTests(unittest.TestCase):
    def test_complete_requires_every_chunk(self):
        result = reconcile(JOB, SOURCE, LEDGER, require_complete=True)
        self.assertEqual(result["status"], "complete")
        self.assertEqual(result["missing_chunks"], 0)

    def test_draining_is_pending_not_empty(self):
        result = reconcile(JOB, SOURCE, LEDGER[:1])
        self.assertEqual(result["status"], "pending")
        self.assertEqual(result["missing_chunk_sample"], [1])

    def test_required_completion_rejects_missing_chunk(self):
        result = reconcile(JOB, SOURCE, LEDGER[:1], require_complete=True)
        self.assertEqual(result["status"], "failed")

    def test_identity_mismatch_fails_even_during_drain(self):
        changed = [dict(LEDGER[0], object_key="wrong")]
        result = reconcile(JOB, SOURCE, changed)
        self.assertEqual(result["status"], "failed")
        self.assertIn("mismatch", result["issues"][0])

    def test_noncontiguous_source_fails(self):
        changed = [SOURCE[0], dict(SOURCE[1], chunk_index=2)]
        result = reconcile(JOB, changed, LEDGER)
        self.assertEqual(result["status"], "failed")

    def test_source_job_unavailable_does_not_pass(self):
        result = reconcile(dict(JOB, state="running"), SOURCE, LEDGER)
        self.assertEqual(result["status"], "failed")

    def test_audited_replacement_counts_as_source_chunk(self):
        replacement = dict(LEDGER[0], delta_id=REPAIR["replacement_delta_id"],
                           object_key=REPAIR["replacement_object_key"], record_count=1)
        result = reconcile(JOB, SOURCE, [replacement, LEDGER[1]],
                           require_complete=True, repairs=[REPAIR])
        self.assertEqual(result["status"], "complete")
        self.assertEqual(result["expected_index_records"], 3)
        self.assertEqual(result["excluded_records"], 1)

    def test_audited_replacement_does_not_hide_original_registration(self):
        replacement = dict(LEDGER[0], delta_id=REPAIR["replacement_delta_id"],
                           object_key=REPAIR["replacement_object_key"], record_count=1)
        result = reconcile(JOB, SOURCE, [replacement, *LEDGER], repairs=[REPAIR])
        self.assertEqual(result["status"], "failed")
        self.assertIn("absent", " ".join(result["issues"]))

    def test_repair_cannot_claim_to_drop_unaccounted_records(self):
        changed = dict(REPAIR, excluded_record_count=2)
        result = reconcile(JOB, SOURCE, LEDGER[1:], repairs=[changed])
        self.assertEqual(result["status"], "failed")
        self.assertIn("repair audit mismatch", " ".join(result["issues"]))


if __name__ == "__main__":
    unittest.main()
