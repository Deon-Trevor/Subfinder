"""Focused checks for staging scorecard classification and rates."""

import sys
from pathlib import Path
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parent))
import staging_cost_scorecard as scorecard


class StagingCostScorecardTests(unittest.TestCase):
    def test_r2_classifies_only_successful_known_actions(self):
        operations = [
            {"sum": {"requests": 10}, "dimensions": {
                "actionType": "PutObject", "actionStatus": "success"}},
            {"sum": {"requests": 4}, "dimensions": {
                "actionType": "GetObject", "actionStatus": "success"}},
            {"sum": {"requests": 2}, "dimensions": {
                "actionType": "PutObject", "actionStatus": "userError"}},
            {"sum": {"requests": 3}, "dimensions": {
                "actionType": "NewAction", "actionStatus": "success"}},
        ]
        storage = [{"dimensions": {"datetime": "2026-09-29T00:00:00Z"},
                    "max": {"payloadSize": 100, "objectCount": 2}}]
        with patch.object(scorecard, "graphql_rows", side_effect=[operations, storage]):
            result = scorecard.r2_usage("hidden", "2026-09-29T00:00:00Z",
                                        "2026-09-29T01:00:00Z")
        self.assertEqual(result["successful_operations_by_price_class"],
                         {"class_a": 10, "class_b": 4, "free": 0})
        self.assertEqual(result["successful_operations_unclassified"], {"NewAction": 3})
        self.assertEqual(result["operations_by_action_status"]["PutObject:userError"], 2)

    def test_gross_rate_is_partial_and_never_calls_it_an_invoice(self):
        usage = {
            "queues": {"status": "measured", "main": {"billable_operations": 1_000_000},
                       "dead_letter": {"billable_operations": 0}},
            "d1": {"status": "measured", "databases": {
                "ledger": {"rows_read": 1_000_000, "rows_written": 1_000_000}}},
            "r2": {"status": "measured", "successful_operations_by_price_class": {
                "class_a": 1_000_000, "class_b": 1_000_000}},
            "container": {"status": "measured", "cpu_seconds": 1000,
                          "memory_byte_seconds": 0, "disk_byte_seconds": 0},
        }
        result = scorecard.gross_list_rate(usage)
        self.assertEqual(result["usd_before_account_allowances"], 6.281)
        self.assertEqual(result["components"]["czds_container_compute_usd"], 0.02)
        self.assertEqual(result["status"], "partial_list_rate_estimate")
        self.assertIn("Not an invoice", result["note"])
        self.assertIsNone(scorecard.gross_list_rate({})["usd_before_account_allowances"])

    def test_wall_rates_keep_registered_work_distinct(self):
        job = {"zone": "com", "state": "complete", "delta_count": 2,
               "hostname_count": 100, "created_at": "2026-09-29T00:00:00Z",
               "updated_at": "2026-09-29T00:00:10Z"}
        generations = [{"generation_id": "g", "base_generation": "seed", "state": "reducing",
                        "delta_count": 1, "partition_count": 2,
                        "created_at": "2026-09-29T00:00:10Z"}]
        deltas = [
            {"generation_id": "g", "state": "mapped", "count": 1, "records": 60,
             "last_updated_at": "2026-09-29T00:00:20Z"},
            {"generation_id": None, "state": "registered", "count": 1,
             "records": 40, "last_updated_at": "2026-09-29T00:00:20Z"},
        ]
        partitions = [{"generation_id": "g", "state": "reduced", "count": 1},
                      {"generation_id": "g", "state": "reducing", "count": 1}]
        result = scorecard.throughput(job, generations, deltas, partitions)
        self.assertEqual(result["source_job"]["source_records_per_wall_second"], 10)
        self.assertEqual(result["generations"][0]["mapped_records_per_wall_second"], 6)
        self.assertEqual(result["registered_not_assigned"], {"chunks": 1, "records": 40})
        self.assertEqual(result["generations"][0]["partition_states"],
                         {"reduced": 1, "reducing": 1})


if __name__ == "__main__":
    unittest.main()
