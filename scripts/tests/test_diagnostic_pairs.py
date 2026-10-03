"""GitHub-only tests: mismatched/noisy measurements must not imply a gain."""
import copy
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from diagnostic_pairs import schedule, summarize


def blocks():
    forward = ["fp_hash", "fp_metadata", "fp_clock", "fp_map", "fp_hash"]
    reverse = ["fp_hash", "fp_map", "fp_clock", "fp_metadata", "fp_hash"]
    return [[{"profile": name, "packets": {"fp_hash": 1000, "fp_metadata": 900,
               "fp_clock": 810, "fp_map": 729}[name], "elapsed_ns": 10_000_000_000,
              "duration_complete": True, "forwarding_intact": True,
              "packet_drop_delta": 0, "packet_error_delta": 0}
             for name in order] for order in [forward, reverse, forward, reverse, forward]]


class DiagnosticPairs(unittest.TestCase):
    def test_balanced_bounded_schedule_has_same_stage_anchors(self):
        self.assertEqual(schedule(), [
            ["fp_hash", "fp_metadata", "fp_clock", "fp_map", "fp_hash"],
            ["fp_hash", "fp_map", "fp_clock", "fp_metadata", "fp_hash"],
            ["fp_hash", "fp_metadata", "fp_clock", "fp_map", "fp_hash"],
            ["fp_hash", "fp_map", "fp_clock", "fp_metadata", "fp_hash"],
            ["fp_hash", "fp_metadata", "fp_clock", "fp_map", "fp_hash"],
        ])

    def test_consistent_cost_above_anchor_noise_is_resolved(self):
        result = summarize(blocks())
        self.assertEqual(result.get("noise_fraction"), 0.01)
        for pair in result.get("comparisons", []):
            self.assertAlmostEqual(pair["median_ratio"], 0.9)
            self.assertEqual(pair["classification"], "resolved_lower_throughput")
        self.assertEqual(len(result.get("comparisons", [])), 3)

    def test_anchor_drift_prevents_claiming_a_small_difference(self):
        rows = blocks()
        rows[0][-1]["packets"] = 1200
        result = summarize(rows)
        self.assertAlmostEqual(result.get("noise_fraction", -1), 0.2)
        self.assertEqual([p["classification"] for p in result.get("comparisons", [])],
                         ["unresolved"] * 3)

    def test_one_opposite_pair_prevents_consistent_cost_claim(self):
        rows = blocks()
        rows[0][1]["packets"] = 1100
        result = summarize(rows)
        self.assertEqual(result.get("comparisons", [{}])[0].get("classification"), "unresolved")

    def test_incomplete_reordered_or_censored_input_is_rejected(self):
        bad = [blocks()[:-1], blocks() + [blocks()[0]]]
        changed = blocks(); changed[0][1], changed[0][2] = changed[0][2], changed[0][1]; bad.append(changed)
        for field, value in [("duration_complete", False), ("forwarding_intact", False),
                             ("packet_drop_delta", 1), ("packet_error_delta", 1),
                             ("packets", 0), ("packets", True), ("elapsed_ns", float("nan")),
                             ("elapsed_ns", 0), ("elapsed_ns", 1), ("packets", -1)]:
            rows = blocks(); rows[0][0][field] = value; bad.append(rows)
        for rows in bad:
            with self.subTest(rows=rows[0] if rows else []):
                with self.assertRaises(ValueError):
                    summarize(rows)

    def test_summary_never_mutates_or_removes_input(self):
        rows = blocks(); before = copy.deepcopy(rows)
        result = summarize(rows)
        self.assertEqual(rows, before)
        self.assertEqual(result.get("trial_count"), 25)
        self.assertIs(result.get("deployment_gate_evidence"), False)


if __name__ == "__main__":
    unittest.main()
