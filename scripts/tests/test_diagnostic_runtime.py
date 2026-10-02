"""GitHub-only privileged generated-veth tests of the separate diagnostic binary."""
import json
import os
from pathlib import Path
import selectors
import signal
import shutil
import subprocess
import struct
import unittest
import uuid

from fingerprint_kernel_fixture import SENDER, expected_fingerprints, read_fingerprints


def command(*args):
    return subprocess.check_output(args, text=True, timeout=15)


class DiagnosticRuntime(unittest.TestCase):
    def exercise(self, profile, stop, reject=None):
        run = uuid.uuid4().hex
        host, peer, ns = "l2h" + run[:10], "l2n" + run[:10], "l2ns-" + run[:12]
        root = Path("/run/l2-loop/accept") / run
        binary = Path(os.environ["L2_DIAGNOSTIC_BINARY"]).resolve()
        artifacts = Path(os.environ["L2_DIAGNOSTIC_OBJECTS"]).resolve()
        root.mkdir(parents=True, mode=0o700)
        process = None
        namespace_created = False
        link_created = False
        try:
            command("ip", "netns", "add", ns)
            namespace_created = True
            command("ip", "link", "add", host, "type", "veth", "peer", "name", peer)
            link_created = True
            command("ip", "link", "set", peer, "netns", ns)
            command("ip", "link", "set", host, "addrgenmode", "none")
            command("ip", "-n", ns, "link", "set", peer, "addrgenmode", "none")
            a = json.loads(command("ip", "-j", "-d", "link", "show", "dev", host))[0]
            b = json.loads(command("ip", "-n", ns, "-j", "-d", "link", "show", "dev", peer))[0]
            identity = Path("/run/netns", ns).stat()
            request = {"schema_version": 1, "run_id": run, "profile": profile,
                       "ifindex": a["ifindex"], "peer_ifindex": b["ifindex"],
                       "host_mac": a["address"], "peer_mac": b["address"],
                       "namespace_device": identity.st_dev, "namespace_inode": identity.st_ino,
                       "duration_seconds": 2 if stop == "deadline" else 30}
            (root / "diagnostic-request.json").write_text(json.dumps(request))
            shutil.copytree(artifacts / profile, root / "object")
            if reject == "digest":
                obj = next((root / "object").glob("*.o"))
                obj.write_bytes(obj.read_bytes() + b"changed")
            if reject == "lease":
                (root / "diagnostic-lease.json").write_text("foreign lease")
            process = subprocess.Popen([str(binary), "--run-id", run], stdin=subprocess.PIPE,
                                       stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            if reject:
                stdout, stderr = process.communicate(timeout=20)
                self.assertNotEqual(process.returncode, 0, stdout)
                self.assertIn("DX_", stderr)
                link = json.loads(command("ip", "-j", "-d", "link", "show", "dev", host))[0]
                self.assertNotIn("xdp", link)
                if reject == "lease":
                    self.assertEqual((root / "diagnostic-lease.json").read_text(), "foreign lease")
                else:
                    self.assertFalse((root / "diagnostic-lease.json").exists())
                return
            selector = selectors.DefaultSelector()
            selector.register(process.stdout, selectors.EVENT_READ)
            self.assertTrue(selector.select(20), "loader did not return bounded ready state")
            line = process.stdout.readline()
            self.assertTrue(line, process.stderr.read() if process.poll() is not None else "no ready state")
            ready = json.loads(line)
            self.assertEqual(ready["state"], "ready")
            self.assertFalse(ready["deployment_gate_evidence"])
            self.assertEqual(len(ready["map_ids"]), 6)
            self.assertTrue((root / "diagnostic-lease.json").is_file())
            link = json.loads(command("ip", "-j", "-d", "link", "show", "dev", host))[0]
            self.assertIn("xdp", link)
            if stop == "foreign_tc":
                command("tc", "filter", "add", "dev", host, "egress", "protocol", "all",
                        "pref", "10", "handle", "1", "matchall", "action", "pass")
                process.stdin.write("stop\n")
                process.stdin.flush()
                stdout, stderr = process.communicate(timeout=20)
                self.assertNotEqual(process.returncode, 0, stdout)
                self.assertIn("DX_SESSION", stderr)
                self.assertTrue((root / "diagnostic-lease.json").is_file())
                filters = json.loads(command("tc", "-j", "filter", "show", "dev", host, "egress"))
                self.assertTrue(any(f.get("pref") == 10 for f in filters))
                self.assertFalse(any(f.get("pref") == 49600 for f in filters))
                link = json.loads(command("ip", "-j", "-d", "link", "show", "dev", host))[0]
                self.assertNotIn("xdp", link)
                return
            fingerprint_case = stop == "fingerprint_contract"
            if fingerprint_case:
                command("ip", "link", "set", host, "up")
                command("ip", "-n", ns, "link", "set", peer, "up")
                fixture_path = str(Path(__file__).resolve().parent)
                command("env", "PYTHONPATH=" + fixture_path, "python3", "-c", SENDER,
                        host, a["address"], b["address"])
                command("ip", "netns", "exec", ns, "env", "PYTHONPATH=" + fixture_path,
                        "python3", "-c", SENDER, peer, b["address"], a["address"])
                actual = read_fingerprints(ready["map_ids"]["FINGERPRINTS"])
                expected = expected_fingerprints(a["ifindex"], a["address"], b["address"])
                self.assertEqual(actual.keys(), expected.keys())
                self.assertEqual(len(actual), 192)
                for key, value in actual.items():
                    first, last = struct.unpack_from("<QQ", value)
                    self.assertGreater(first, 0)
                    self.assertGreaterEqual(last, first)
                    self.assertEqual(value[16:], expected[key])
                stop = "stop"
                process.stdin.write("stop\n")
                process.stdin.flush()
            elif stop == "stop":
                command("ip", "link", "set", host, "up")
                command("ip", "-n", ns, "link", "set", peer, "up")
                sender = ("import socket,sys;src=bytes.fromhex(sys.argv[2].replace(':',''));"
                          "dst=bytes.fromhex(sys.argv[3].replace(':',''));"
                          "frame=dst+src+bytes.fromhex('08060001080006040001')+src+bytes(4)+dst+bytes(4)+bytes(22);"
                          "s=socket.socket(socket.AF_PACKET,socket.SOCK_RAW);s.bind((sys.argv[1],0));"
                          "assert len(frame)==64;"
                          "assert all(s.send(frame)==64 for _ in range(8))")
                command("python3", "-c", sender, host, a["address"], b["address"])
                command("ip", "netns", "exec", ns, "python3", "-c", sender, peer, b["address"], a["address"])
                process.stdin.write("stop\n")
                process.stdin.flush()
            elif stop == "eof":
                process.stdin.close()
                process.stdin = None
            elif stop == "signal":
                process.send_signal(signal.SIGTERM)
                # Keep stdin open so this tests the signal, not a racing EOF
                # introduced by communicate() closing the input pipe.
                process.wait(timeout=15)
            elif stop == "deadline":
                process.wait(timeout=15)
            stdout, stderr = process.communicate(timeout=20)
            self.assertEqual(process.returncode, 0, stderr)
            final = json.loads(stdout.strip())
            self.assertEqual(final["state"], "cleaned")
            self.assertEqual(final["stop_reason"], stop)
            expected_packets = 3072 if fingerprint_case else 8 if stop == "stop" and profile in ("counters", "fingerprints") else 0
            self.assertEqual([row["packets"] for row in final["counters"]], [expected_packets] * 2)
            expected_bytes = 2140160 if fingerprint_case else expected_packets * 64
            self.assertEqual([row["bytes"] for row in final["counters"]], [expected_bytes] * 2)
            self.assertFalse((root / "diagnostic-lease.json").exists())
            link = json.loads(command("ip", "-j", "-d", "link", "show", "dev", host))[0]
            self.assertNotIn("xdp", link)
            qdiscs = json.loads(command("tc", "-j", "qdisc", "show", "dev", host))
            self.assertFalse(any(q["kind"] == "clsact" for q in qdiscs))
        finally:
            if process is not None and process.poll() is None:
                process.terminate()
                process.wait(timeout=15)
            if link_created:
                command("ip", "link", "delete", "dev", host)
            if namespace_created:
                command("ip", "netns", "delete", ns)
            # This test owns a fresh UUID root on the ephemeral GitHub runner.
            shutil.rmtree(root)

    def test_real_profiles_load_and_rollback(self):
        for profile in ("hooks_only", "config_lookup", "counters", "fingerprints"):
            with self.subTest(profile=profile):
                self.exercise(profile, "stop")

    def test_eof_rolls_back(self):
        self.exercise("counters", "eof")

    def test_actual_selected_fingerprints_preserve_keys_metadata_and_update_counts(self):
        self.exercise("fingerprints", "fingerprint_contract")

    def test_deadline_rolls_back(self):
        self.exercise("counters", "deadline")

    def test_signal_rolls_back(self):
        self.exercise("counters", "signal")

    def test_changed_bytes_never_attach(self):
        self.exercise("counters", "stop", "digest")

    def test_foreign_lease_is_never_overwritten(self):
        self.exercise("counters", "stop", "lease")

    def test_foreign_tc_is_retained_and_other_cleanup_continues(self):
        self.exercise("counters", "foreign_tc")


if __name__ == "__main__":
    unittest.main()
