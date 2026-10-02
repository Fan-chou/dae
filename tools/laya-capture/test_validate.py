import copy
import unittest
from validate import audit, validate


def sample():
    return dict(schema="kdae-capture-v1", generation="a" * 32, id="a-1", episode_id="a-1", sequence=1,
                scope=dict(site_id="b" * 32, node_id="c" * 32, group_id="d" * 32, network="tcp4", path="proxy", policy_epoch=1),
                start_ms=1000, duration_ms=15000, partial=False, measurement_mode="userspace_accounting", stage="relay", outcome="open",
                up_bytes=10, down_bytes=20, node_up_bytes=30, node_down_bytes=40, active_ms=None, read_paused_ms=None,
                control=None, dependency=None, demand=None, missing_reason=dict(control="unavailable", dependency="unavailable", demand="unobserved", active_ms="unobserved", read_paused_ms="unobserved", node_bytes="", flow_bytes=""),
                inclusion_probability=.025, trigger="uniform_flow", counter_alignment="best_effort_non_atomic_snapshots", adapter_status="adapter_abstain", first_downstream_callback_ms=20)


class CaptureValidation(unittest.TestCase):
    def test_valid_missing_evidence_abstains(self):
        r = sample()
        validate(r)
        result = audit([r])
        self.assertEqual(result["v4_adapter_accepted"], 0)
        self.assertEqual(result["missing_rates"]["demand"], 1)
        self.assertEqual(result["root_cause_independence"], "unreviewed")

    def test_reject_fabricated_fields_and_private_data(self):
        for key, value in [("active_ms", 15000), ("dependency", {"gateway_drops": 0}), ("control", {"attempts": 0}), ("adapter_status", "accepted"), ("up_bytes", -1), ("node_down_bytes", 1), ("inclusion_probability", float("nan")), ("sequence", True), ("raw_url", "secret")]:
            r = sample()
            r[key] = value
            with self.subTest(key=key), self.assertRaises(ValueError):
                validate(r)
        r = sample()
        r["scope"]["site_id"] = "private.example"
        with self.assertRaises(ValueError):
            validate(r)

    def test_duplicate_and_unmeasured_counters(self):
        r = sample()
        with self.assertRaises(ValueError):
            audit([r, copy.deepcopy(r)])
        r["measurement_mode"] = "offload_or_unmeasured"
        with self.assertRaises(ValueError):
            validate(r)



class ArchiveTests(unittest.TestCase):
    def test_archive_budget_hash_and_idempotence(self):
        import hashlib
        import json
        from pathlib import Path
        import tempfile
        from archive import archive
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "snapshot.json"
            source.write_text(json.dumps({"generation": "a"*32, "records": [sample()], "stats": {}}))
            with self.assertRaises(ValueError):
                archive(source, root / "limited", daily_limit=1)
            empty = root / "empty.json"
            empty.write_text(json.dumps({"records": []}))
            with self.assertRaises(ValueError):
                archive(empty, root / "empty-archive")
            path = archive(source, root / "archive")
            self.assertEqual(archive(source, root / "archive"), path)
            meta = json.loads(path.with_suffix(".manifest.json").read_text())
            self.assertEqual(meta["artifact_sha256"], hashlib.sha256(path.read_bytes()).hexdigest())
            self.assertIsNone(meta["gold"])

class ProvenanceValidationTests(unittest.TestCase):
    def test_scope_time_and_stage_consistency(self):
        for changes in (dict(scope=[]), dict(scope=None), dict(start_ms=253402300800000),
                        dict(start_ms=253402300799999), dict(trigger='uniform_route'),
                        dict(stage='route_resolve_dial'), dict(measurement_mode='stage_only'),
                        dict(counter_alignment='not_applicable')):
            r=sample();r.update(changes)
            with self.subTest(changes=changes), self.assertRaises(ValueError):validate(r)

if __name__ == "__main__":
    unittest.main()
