"""Behavioral tests; run on GitHub, never send network traffic."""
import importlib.util
from pathlib import Path
import unittest
import subprocess
import sys

PATH = Path(__file__).resolve().parents[1] / "diagnostic_traffic.py"
MODULE = None
if PATH.is_file():
    SPEC = importlib.util.spec_from_file_location("diagnostic_traffic", PATH)
    MODULE = importlib.util.module_from_spec(SPEC)
    SPEC.loader.exec_module(MODULE)


class SimulatedIo:
    def __init__(self, step=10):
        self.now = 1000
        self.step = step
        self.sent = []

    def clock(self):
        return self.now

    def send(self, frame):
        self.sent.append(frame)
        self.now += self.step
        return len(frame)


class DiagnosticTrafficTests(unittest.TestCase):
    def setUp(self):
        self.assertIsNotNone(MODULE, "persistent diagnostic sender is not implemented")
        self.m = MODULE
        self.run = "0123456789abcdef0123456789abcdef"

    def test_generated_targets_reject_arbitrary_interfaces_and_bad_run_ids(self):
        self.assertEqual(self.m.generated_interface(self.run, "host"), "l2h0123456789")
        self.assertEqual(self.m.generated_interface(self.run, "peer"), "l2n0123456789")
        for run, side in [("../bad", "host"), (self.run.upper(), "host"),
                          (self.run, "eth0"), ("0" * 31, "peer")]:
            with self.subTest(run=run, side=side), self.assertRaises(ValueError):
                self.m.generated_interface(run, side)

    def test_only_exact_unshared_veth_identity_is_accepted(self):
        good = {"ifindex": 42, "ifname": "l2h0123456789", "flags": ["UP"],
                "linkinfo": {"info_kind": "veth"}}
        self.m.validate_link(good, self.run, "host", 42)
        changes = [{"ifindex": 43}, {"ifname": "eth0"}, {"master": "br-int"},
                   {"linkinfo": {"info_kind": "dummy"}}, {"linkinfo": {}},
                   {"flags": []}]
        for change in changes:
            with self.subTest(change=change), self.assertRaises(ValueError):
                self.m.validate_link(dict(good, **change), self.run, "host", 42)

    def test_peer_cannot_run_in_initial_or_foreign_namespace(self):
        self.m.validate_namespace(self.run, "peer", (4, 20), (4, 10), (4, 20))
        self.m.validate_namespace(self.run, "host", (4, 10), (4, 10), (4, 20))
        for side, current, initial, generated in [
            ("peer", (4, 10), (4, 10), (4, 20)),
            ("host", (4, 20), (4, 10), (4, 20)),
            ("peer", (4, 30), (4, 10), (4, 20)),
            ("host", (4, 10), (4, 10), (4, 10))]:
            with self.subTest(side=side, current=current), self.assertRaises(ValueError):
                self.m.validate_namespace(self.run, side, current, initial, generated)

    def test_cli_rejects_arbitrary_interface_flag_before_network_io(self):
        result = subprocess.run([sys.executable, str(PATH), "--run-id", self.run,
                                 "--side", "host", "--ifindex", "1", "--profile", "mixed",
                                 "--interface", "eth0"], capture_output=True, timeout=5)
        self.assertEqual(result.returncode, 2)
        self.assertEqual(result.stdout, b"")

    def test_corpus_has_fixed_sizes_and_kernel_arp_receiver(self):
        frames = self.m.build_corpus("mixed")
        self.assertEqual(len(frames), 768)
        self.assertEqual({len(f) for f in frames}, {64, 512, 1514})
        self.assertEqual(len(set(frames)), 768)
        for frame in frames:
            self.assertEqual(frame[:14], bytes.fromhex("0200000000020200000000010806"))
            self.assertEqual(frame[14:22], bytes.fromhex("0001080006040001"))
            self.assertEqual(frame[28:32], bytes(4))
            self.assertEqual(frame[38:42], bytes(4))

    def test_selection_profiles_are_content_deterministic(self):
        # Independent reference contract: length big-endian + first 60 bytes, FNV-1a.
        def selected(frame):
            value = 0xcbf29ce484222325
            for byte in len(frame).to_bytes(2, "big") + frame[:60]:
                value = ((value ^ byte) * 0x100000001b3) % (1 << 64)
            return (value & 15) == 0
        for profile, expected in [("selected", True), ("unselected", False)]:
            frames = self.m.build_corpus(profile)
            self.assertEqual({len(f) for f in frames}, {64, 512, 1514})
            self.assertTrue(all(selected(f) == expected for f in frames))
            self.assertTrue(all(self.m.fingerprint_selected(f) == expected for f in frames))
        with self.assertRaises(ValueError):
            self.m.build_corpus("random")

    def test_packet_bound_and_exact_bytes(self):
        io = SimulatedIo()
        result = self.m.measure_window(io.send, [bytes(64)], io.clock, 1000, 3)
        self.assertEqual(result["packets"], 3)
        self.assertEqual(result["bytes"], 192)
        self.assertEqual(result["elapsed_ns"], 30)
        self.assertEqual(result["packets_per_second"], 100000000)
        self.assertEqual(result["stop_reason"], "packet_limit")
        self.assertEqual(len(io.sent), 3)

    def test_duration_bound_does_not_send_after_deadline(self):
        io = SimulatedIo()
        result = self.m.measure_window(io.send, [bytes(64)], io.clock, 30, 100)
        self.assertEqual(result["packets"], 3)
        self.assertEqual(result["stop_reason"], "duration")
        self.assertEqual(len(io.sent), 3)

    def test_actual_selection_counts_not_assumed_one_in_sixteen(self):
        io = SimulatedIo()
        frame = self.m.build_corpus("selected")[0]
        result = self.m.measure_window(io.send, [frame], io.clock, 1000, 7)
        self.assertEqual(result["selected_packets"], 7)
        self.assertEqual(result["selected_ratio_permille"], 1000)

    def test_warmup_is_not_counted_in_measurement(self):
        io = SimulatedIo(step=100000000)
        result = self.m.run_windows(io.send, [bytes(64)], io.clock)
        self.assertEqual(result["warmup"]["packets"], 5)
        self.assertEqual(result["measurement"]["packets"], 50)
        self.assertEqual(result["measurement"]["bytes"], 3200)
        self.assertEqual(result["measurement"]["elapsed_ns"], 5000000000)
        self.assertEqual(result["measurement"]["packets_per_second"], 10)
        self.assertEqual(len(io.sent), 55)
        self.assertFalse(result["deployment_gate_evidence"])

    def test_identity_failure_after_warmup_prevents_measurement(self):
        io = SimulatedIo(step=100000000)
        def changed():
            raise ValueError("identity changed")
        with self.assertRaises(ValueError):
            self.m.run_windows(io.send, [bytes(64)], io.clock, changed)
        self.assertEqual(len(io.sent), 5)

    def test_short_send_is_not_success(self):
        io = SimulatedIo()
        with self.assertRaises(RuntimeError):
            self.m.measure_window(lambda frame: 1, [bytes(64)], io.clock, 100, 1)

    def test_send_failure_is_not_success(self):
        def failed(frame):
            raise OSError("send unavailable")
        with self.assertRaises(OSError):
            self.m.measure_window(failed, [bytes(64)], lambda: 1, 100, 1)

    def test_clock_rollback_and_zero_elapsed_are_rejected(self):
        for step in [-10, 0]:
            io = SimulatedIo(step)
            with self.subTest(step=step), self.assertRaises(RuntimeError):
                self.m.measure_window(io.send, [bytes(64)], io.clock, 100, 1)

    def test_invalid_bounds_and_empty_corpus_send_nothing(self):
        for frames, duration, count in [([], 100, 1), ([bytes(64)], 0, 1),
                                        ([bytes(64)], 100, 0), ([b""], 100, 1),
                                        ([bytes(64)], 5000000001, 1),
                                        ([bytes(64)], 100, 2000001)]:
            io = SimulatedIo()
            with self.subTest(duration=duration, count=count), self.assertRaises(ValueError):
                self.m.measure_window(io.send, frames, io.clock, duration, count)
            self.assertEqual(io.sent, [])


if __name__ == "__main__":
    unittest.main()
