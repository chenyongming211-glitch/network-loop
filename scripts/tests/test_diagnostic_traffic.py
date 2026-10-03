"""Behavioral tests; run on GitHub, never send network traffic."""
import importlib.util
from pathlib import Path
import unittest
import subprocess
import sys
import socket

PATH = Path(__file__).resolve().parents[1] / "diagnostic_traffic.py"
sys.path.insert(0, str(PATH.parent))
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
                                 "--destination-mac", "02:00:00:00:00:02",
                                 "--interface", "eth0"], capture_output=True, timeout=5)
        self.assertEqual(result.returncode, 2)
        self.assertEqual(result.stdout, b"")
        self.assertIn(b"unrecognized arguments: --interface eth0", result.stderr)

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

    def test_corpus_binds_both_ethernet_and_arp_to_generated_peer_macs(self):
        source, destination = "02:ab:cd:ef:12:34", "06:12:34:56:78:90"
        src, dst = bytes.fromhex(source.replace(":", "")), bytes.fromhex(destination.replace(":", ""))
        for frame in self.m.build_corpus("mixed", source, destination):
            self.assertEqual(frame[:12], dst + src)
            self.assertEqual(frame[22:28], src)
            self.assertEqual(frame[32:38], dst)
        for bad in ["00:00:00:00:00:00", "ff:ff:ff:ff:ff:ff", "01:00:5e:00:00:01",
                    "02:00:00:00:00", "020000000001", "../../eth0", None]:
            with self.subTest(mac=bad), self.assertRaises(ValueError):
                self.m.build_corpus("mixed", source, bad)
            with self.subTest(source=bad), self.assertRaises(ValueError):
                self.m.build_corpus("mixed", bad, destination)

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

    def test_noise_brackets_only_measured_loop_and_preserves_packet_contract(self):
        self.assertIn("noise", __import__('inspect').signature(self.m.measure_window).parameters,
                      "window lacks boundary-only telemetry")
        io = SimulatedIo()
        samples = []
        def noise():
            samples.append(len(io.sent))
            n = len(samples) - 1
            return dict(cpu_ns=100+n*20, user_ns=60+n*10, system_ns=40+n*10,
                        voluntary=2+n, involuntary=3+n, minor_faults=4+n, major_faults=0,
                        observed_start_ns=900+n*50, observed_end_ns=901+n*50,
                        runqueue_ns=None, migrations=None, cpu_id=0)
        result = self.m.measure_window(io.send, [bytes(64)], io.clock, 1000, 3, noise=noise)
        self.assertEqual(samples, [0, 3])
        self.assertEqual(result['packets'], 3)
        self.assertEqual(result['noise']['cpu_ns'], 20)
        self.assertIsNone(result['noise']['runqueue_ns'])

    def test_send_modes_use_real_socket_and_nonblocking_backpressure_fails_closed(self):
        configure = getattr(self.m, 'configure_socket', None)
        self.assertIsNotNone(configure, 'bounded socket-mode selection missing')
        channel, peer = socket.socketpair()
        with channel, peer:
            configure(channel, 'timeout')
            self.assertEqual(channel.gettimeout(), 1.0)
            configure(channel, 'nonblocking')
            self.assertEqual(channel.gettimeout(), 0.0)
            with self.assertRaises(ValueError): configure(channel, 'blocking')
        def full(frame):
            raise BlockingIOError('backpressure')
        with self.assertRaises(BlockingIOError):
            self.m.measure_window(full, [bytes(64)], lambda: 1, 100, 1)

    def test_noise_delta_never_treats_unavailable_schedstats_as_zero(self):
        sys.path.insert(0, str(PATH.parent))
        import diagnostic_noise as noise
        before = dict(cpu_ns=100, user_ns=60, system_ns=40, voluntary=2,
                      involuntary=3, minor_faults=4, major_faults=0,
                      observed_start_ns=1000, observed_end_ns=1010,
                      runqueue_ns=None, migrations=5, cpu_id=0)
        after = dict(before, cpu_ns=180, user_ns=90, system_ns=90, voluntary=3,
                     involuntary=5, minor_faults=6, observed_start_ns=1100,
                     observed_end_ns=1110, migrations=7, cpu_id=1)
        result = noise.delta(before, after, 90)
        self.assertEqual(result.get('cpu_ns'), 80)
        self.assertEqual(result.get('involuntary'), 2)
        self.assertEqual(result.get('migrations'), 2)
        self.assertIsNone(result.get('runqueue_ns'))
        self.assertEqual(result.get('boundary_overhead_upper_ns'), 20)
        for change in [dict(cpu_ns=99), dict(involuntary=2), dict(migrations=4),
                       dict(runqueue_ns=0)]:
            with self.subTest(change=change), self.assertRaises(ValueError):
                noise.delta(before, dict(after, **change), 90)

    @unittest.skipUnless(sys.platform == 'linux', 'Linux telemetry only')
    def test_real_boundary_snapshot_has_own_cpu_counters_and_bounded_read_span(self):
        sys.path.insert(0, str(PATH.parent))
        import diagnostic_noise as noise
        row = noise.snapshot()
        self.assertGreater(row.get('cpu_ns', 0), 0)
        self.assertGreaterEqual(row.get('observed_end_ns', 0), row.get('observed_start_ns', 1))
        self.assertGreaterEqual(row.get('voluntary', -1), 0)


class AlignedAccountingTests(unittest.TestCase):
    def setUp(self):
        try:
            import diagnostic_accounting
        except ImportError:
            diagnostic_accounting = None
        self.assertIsNotNone(diagnostic_accounting, 'aligned accounting missing')
        self.m = diagnostic_accounting

    def test_cpu_parser_selects_exact_cpu_and_never_double_counts_guest(self):
        text = 'cpu 900 0 0 0 0 0 0 0 0 0\ncpu2 100 2 30 40 5 6 7 8 20 1\n'
        ticks = self.m.cpu_ticks(text, 2)
        self.assertEqual(ticks, [100, 2, 30, 40, 5, 6, 7, 8, 20, 1])
        result = self.m.cpu_delta([0]*10, ticks)
        self.assertEqual(result['total_ticks'], 198)
        self.assertEqual(result['softirq_ticks'], 7)
        for bad in [text.replace('cpu2', 'cpu3'), text+text,
                    'cpu2 1 2', text.replace('100 2', '-1 2')]:
            with self.subTest(text=bad), self.assertRaises(ValueError):
                self.m.cpu_ticks(bad, 2)
        with self.assertRaises(ValueError):
            self.m.cpu_delta(ticks, [0]*10)

    def test_perf_delta_preserves_multiplexing_and_unavailable_values(self):
        good = self.m.perf_delta([10, 100, 100], [70, 300, 300])
        self.assertEqual(good['value'], 60)
        self.assertEqual(good['enabled_ns'], 200)
        self.assertTrue(good['usable'])
        partial = self.m.perf_delta([10, 100, 100], [70, 300, 200])
        self.assertEqual(partial['coverage'], 0.5)
        self.assertFalse(partial['usable'])
        self.assertIsNone(self.m.perf_delta(None, None))
        for end in [[9, 300, 300], [70, 99, 100], [70, 300, 301], None]:
            with self.subTest(end=end), self.assertRaises(ValueError):
                self.m.perf_delta([10, 100, 100], end)

    @unittest.skipUnless(sys.platform == 'linux', 'Linux syscall boundary')
    def test_counter_open_is_current_thread_only_without_sampling_or_inheritance(self):
        import ctypes, struct
        calls = []
        def syscall(number, attr, pid, cpu, group, flags):
            calls.append((number, ctypes.string_at(attr, 64), pid, cpu, group, flags))
            return 17
        self.assertEqual(self.m.open_counter(0, 1, syscall=syscall), 17)
        number, attr, pid, cpu, group, flags = calls[0]
        self.assertEqual((number, pid, cpu, group, flags), (298, 0, -1, -1, 8))
        self.assertEqual(struct.unpack_from('=IIQQQQQ', attr), (0,64,1,0,0,3,0))

    def test_aligned_delta_rejects_identity_and_boundary_disagreement(self):
        before = dict(cpu=2, ticks=[0]*10, perf={'cycles':[10,100,100]},
                      start_ns=100, end_ns=110, hz=100)
        after = dict(cpu=2, ticks=[2,0,3,0,0,1,4,0,0,0],
                     perf={'cycles':[70,300,300]}, start_ns=300, end_ns=310, hz=100)
        result = self.m.aligned_delta(before, after)
        self.assertEqual(result['cpu']['total_ticks'], 10)
        self.assertEqual(result['cpu']['softirq_ticks'], 4)
        self.assertEqual(result['perf']['cycles']['value'], 60)
        self.assertEqual(result['boundary_read_spans_ns'], [10,10])
        for change in [dict(cpu=3),dict(hz=1000),dict(start_ns=99),dict(perf={})]:
            with self.subTest(change=change), self.assertRaises(ValueError):
                self.m.aligned_delta(before, dict(after, **change))


if __name__ == "__main__":
    unittest.main()
