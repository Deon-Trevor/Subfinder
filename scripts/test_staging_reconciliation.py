"""Contract tests for staged CZDS coverage states."""

import unittest

from staging_reconciliation import reconcile


JOB = {"state": "complete", "delta_count": 2, "hostname_count": 4}
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


if __name__ == "__main__":
    unittest.main()
