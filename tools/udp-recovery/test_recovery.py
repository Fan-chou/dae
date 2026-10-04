import argparse
import copy
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import analyze
import collect


def empty_page(process="1"):
    return {"schema": "kdae-udp-recovery-v1", "process": process,
            "next_sequence": 0, "records": [], "has_more": False,
            "lost_records": 0, "execution_implemented": False,
            "coverage": {"truncated": False, "missing_events_dedup_full": False, "flows": []},
            "observation": None}


class CollectionTests(unittest.TestCase):
    def test_empty_generation_page_updates_both_cursors(self):
        with tempfile.TemporaryDirectory() as root:
            args = argparse.Namespace(output=Path(root), router="test", reader="/reader", max_pages=2, max_bytes=1000000)
            old = {"udp-recovery": {"process": "old", "after": 99}, "capture": {"generation": "a", "after": 99}}
            def read(_args, endpoint, after=0, process=""):
                if endpoint == "udp-recovery":
                    page = empty_page()
                    page["cursor_reset"] = "process_changed"
                elif endpoint == "capture":
                    page = {"enabled": True, "generation": "b", "records": [], "next_sequence": after, "oldest_sequence": 0}
                else:
                    page = [] if endpoint == "groups" else {}
                return page, {}
            with patch.object(collect, "ssh", return_value={"binary_sha256": "a"}), patch.object(collect, "read_page", side_effect=read):
                state, value = collect.collect_once(args, old)
            self.assertEqual(state["capture"], {"generation": "b", "after": 0})
            self.assertEqual(state["udp-recovery"], {"process": "1", "after": 0})
            self.assertEqual(json.loads((Path(root)/"cursor.json").read_text()), state)
            self.assertEqual(analyze.load(Path(root)), [value])

    def test_publish_interruption_does_not_advance_cursor_and_is_repairable(self):
        with tempfile.TemporaryDirectory() as root:
            path = Path(root)
            value = {"schema": collect.SCHEMA, "kind": "phase", "phase": "playing"}
            original = collect.atomic_write
            def interrupted(file, data):
                if file.name.endswith(".manifest.json"):
                    raise OSError("interrupted")
                original(file, data)
            with patch.object(collect, "atomic_write", side_effect=interrupted):
                with self.assertRaises(OSError):
                    collect.publish(path, value, 10000)
            self.assertFalse((path/"cursor.json").exists())
            collect.publish(path, value, 10000)
            self.assertEqual(analyze.load(path), [value])

    def test_archive_hash_tampering_and_budget(self):
        with tempfile.TemporaryDirectory() as root:
            path = Path(root)
            with self.assertRaisesRegex(ValueError, "budget"):
                collect.publish(path, {"schema": collect.SCHEMA}, 1)
            file = collect.publish(path, {"schema": collect.SCHEMA, "kind": "phase"}, 10000)
            file.write_text("{}")
            with self.assertRaisesRegex(ValueError, "hash"):
                analyze.load(path)

    def test_bad_or_old_cursor_not_silently_accepted(self):
        page = empty_page()
        page["next_sequence"] = 5
        with self.assertRaisesRegex(ValueError, "cursor"):
            collect.recovery_cursor(page, {"process": "1", "after": 0})
        page["records"] = [{"sequence": True, "kind": "qualified"}]
        with self.assertRaisesRegex(ValueError, "sequence"):
            collect.recovery_cursor(page, {})

    def test_changed_binary_retains_all_cursors(self):
        with tempfile.TemporaryDirectory() as root:
            args = argparse.Namespace(output=Path(root), router="test", reader="/reader", max_pages=2, max_bytes=1000000)
            old = {"udp-recovery": {"process": "old", "after": 99}}
            with patch.object(collect, "ssh", side_effect=[{"binary": "a"}, {"binary": "b"}]), patch.object(collect, "read_page", return_value=(empty_page(), {})):
                state, value = collect.collect_once(args, old)
            self.assertEqual(state, old)
            self.assertFalse(value["provenance_stable"])
            self.assertEqual(json.loads((Path(root)/"cursor.json").read_text()), old)

    def test_group_list_has_clock_bracket_without_dict_assumption(self):
        args = argparse.Namespace(router="test", reader="/reader")
        with patch.object(collect, "ssh", return_value=[]):
            page, bracket = collect.read_page(args, "groups")
        self.assertEqual(page, [])
        self.assertIn("start_ms", bracket)


class EvidenceTests(unittest.TestCase):
    def setUp(self):
        self.thresholds = {"required_full_buckets": 6, "bucket_ms": 5000,
                           "nonempty_writes_per_bucket": 10, "required_reply_history": 3,
                           "reply_drought_ms": 30000, "recent_write_ms": 5000}
        self.row = {"windows": [{"start_ms": 100000+i*5000, "end_ms": 105000+i*5000,
                                 "complete": i < 6, "present": i < 6, "invalid": False,
                                 "nonempty_successful_writes": 10} for i in range(7)],
                    "first_observed_ms": 99000, "invalidated_at_ms": 0,
                    "replies": 3, "last_reply_ms": 99000, "at_ms": 130000,
                    "last_write_ms": 126000, "write_completion": "local_write_completed",
                    "reply_contract": "configured_request_reply"}

    def test_candidates_require_complete_consecutive_evidence(self):
        self.assertEqual(analyze.candidate_errors(self.row, self.thresholds), [])
        for field, value in (("complete", False), ("present", False), ("invalid", True), ("nonempty_successful_writes", 9)):
            row = copy.deepcopy(self.row)
            row["windows"][2][field] = value
            self.assertIn("insufficient_full_bucket", analyze.candidate_errors(row, self.thresholds))

    def test_unknown_reply_acceptance_pause_and_reply_resume_fail_proof(self):
        for field, value, error in (("reply_contract", "unknown", "unknown_reply_semantics"),
                ("write_completion", "transport_acceptance_only", "write_completion"),
                ("last_write_ms", 124000, "paused_or_clock_uncertain"),
                ("last_reply_ms", 110000, "recent_reply"),
                ("invalidated_at_ms", 131000, "incomplete_history")):
            row = dict(self.row)
            row[field] = value
            self.assertIn(error, analyze.candidate_errors(row, self.thresholds))

    def test_no_data_never_becomes_successful_recovery(self):
        result = analyze.summarize([])
        self.assertEqual(result["execution_acceptance"], "not_evaluated")
        self.assertFalse(result["execution_implemented"])
        self.assertEqual(result["node_flow_comparable_windows"], 0)

    def test_missing_splice_reference_has_no_fabricated_bias(self):
        page = empty_page()
        value = {"kind": "poll", "started_at_ms": 0, "gaps": [], "errors": [],
                 "fetch_brackets": [], "provenance_stable": True, "provenance_before": {},
                 "pages": {"udp-recovery": [page], "capture": [{"enabled": True,
                    "generation": "a", "stats": {"queue_dropped": 0, "invalid_window": 0},
                    "records": [{"sequence": 1, "stage": "relay", "measurement_mode": "offload_or_unmeasured",
                                 "up_bytes": None, "down_bytes": None}]}]}}
        result = analyze.summarize([value])
        self.assertEqual(result["capture"][0]["offload_fraction_of_archived_relay_windows"], 1)
        self.assertEqual(result["node_flow_counter_differences"], [])

    def test_quality_counter_frequency_keeps_generation_separate(self):
        values = []
        for at, epoch, count in ((1000, 1, 5), (61000, 1, 7), (62000, 2, 0)):
            values.append({"kind": "poll", "started_at_ms": at, "gaps": [], "errors": [],
                "fetch_brackets": [], "provenance_stable": True, "provenance_before": {},
                "pages": {"quality": [{"recovery_diagnostics": [{"group": "proxy", "policy_epoch": epoch,
                    "quality_reasons": {"verify_alternative_windows": count}}]}]}})
        result = analyze.summarize(values)
        history = result["quality_budget_history_by_generation"]
        self.assertEqual(len(history), 2)
        self.assertEqual(history[0]["verification_windows_per_minute"], 2)
        self.assertIsNone(history[1]["verification_windows_per_minute"])
        self.assertTrue(result["quality_budget_channel_available"])


if __name__ == "__main__":
    unittest.main()
