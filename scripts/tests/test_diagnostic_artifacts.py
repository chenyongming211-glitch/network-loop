"""GitHub-only integration against real compiled eBPF objects; never loads BPF."""

import hashlib
import json
import os
from pathlib import Path
import shutil
import struct
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[2]
XTASK = ROOT / "target/debug/xtask"
ORDINARY = ROOT / "target/bpfel-unknown-none/release/l2-loop-ebpf"
COMMIT = os.environ.get("GITHUB_SHA", "0123456789abcdef0123456789abcdef01234567")
PROFILES = {
    "hooks_only": ("hooks-only", "l2d_hooks_xdp", "l2d_hooks_tc"),
    "config_lookup": ("config-lookup", "l2d_config_xdp", "l2d_config_tc"),
    "counters": ("counters", "l2d_count_xdp", "l2d_count_tc"),
    "fingerprints": ("fingerprints", "l2d_full_xdp", "l2d_full_tc"),
    "fp_hash": ("fp-hash", "l2d_hash_xdp", "l2d_hash_tc"),
    "fp_metadata": ("fp-metadata", "l2d_meta_xdp", "l2d_meta_tc"),
    "fp_clock": ("fp-clock", "l2d_clock_xdp", "l2d_clock_tc"),
    "fp_map": ("fp-map", "l2d_map_xdp", "l2d_map_tc"),
}


def run(*args):
    return subprocess.run(
        [str(XTASK), *map(str, args)], cwd=ROOT,
        capture_output=True, text=True, timeout=300, check=False,
    )


def symbol_range(elf, name):
    """Independently locate symbol bytes and its name using the ELF64 table."""
    shoff = struct.unpack_from("<Q", elf, 40)[0]
    shsize, count = struct.unpack_from("<HH", elf, 58)
    sections = [struct.unpack_from("<IIQQQQIIQQ", elf, shoff + index * shsize)
                for index in range(count)]
    for section in sections:
        if section[1] != 2:
            continue
        strings = sections[section[6]]
        names = elf[strings[4]:strings[4] + strings[5]]
        for offset in range(section[4], section[4] + section[5], section[9]):
            label, _, _, index, address, size = struct.unpack_from("<IBBHQQ", elf, offset)
            if names[label:].split(b"\0", 1)[0] == name.encode():
                return sections[index][4] + address, size, strings[4] + label
    raise AssertionError(f"missing ELF symbol {name}")


class DiagnosticArtifacts(unittest.TestCase):
    def test_four_real_profiles_have_exact_inventory_and_identity(self):
        ordinary_before = ORDINARY.read_bytes()
        published = ROOT / ".artifacts/layered-diagnostics"
        self.assertFalse(published.exists(), "never overwrite prior diagnostic artifacts")
        with tempfile.TemporaryDirectory(prefix="l2-diag-build-") as temporary:
            root = Path(temporary)
            for profile, (stem, xdp, tc) in PROFILES.items():
                output = root / profile
                result = run("build-diagnostic-ebpf", "--profile", profile,
                             "--commit-sha", COMMIT, "--output", output)
                self.assertEqual(result.returncode, 0, result.stderr)
                filename = f"l2-loop-diag-{stem}.o"
                self.assertEqual(sorted(p.name for p in output.iterdir()),
                                 sorted([filename, "diagnostic.json"]))
                manifest = json.loads((output / "diagnostic.json").read_text())
                self.assertEqual(manifest["commit_sha"], COMMIT)
                self.assertEqual(manifest["profile"], profile)
                self.assertEqual(manifest["programs"], {"xdp": xdp, "tc": tc})
                self.assertIs(manifest["deployment_gate_evidence"], False)
                self.assertEqual(manifest["object_sha256"],
                                 hashlib.sha256((output / filename).read_bytes()).hexdigest())
                verified = run("verify-diagnostic-identity", "--manifest",
                               output / "diagnostic.json", "--object", output / filename,
                               "--commit-sha", COMMIT, "--profile", profile)
                self.assertEqual(verified.returncode, 0, verified.stderr)
                inspected = run("verify-diagnostic-elf", "--object", output / filename,
                                "--profile", profile)
                self.assertEqual(inspected.returncode, 0, inspected.stderr)
                report = json.loads(inspected.stdout)
                print(f"verified {profile}: {inspected.stdout.strip()}", flush=True)
                self.assertEqual(report["programs"], sorted([xdp, tc]))
                expected_maps = ["FINGERPRINTS", "HOOK_STATS", "IFACE_CONFIG",
                                 "PROBE_REGISTRY", "PROBE_STATS", "RATE_POLICY"]
                if profile.startswith("fp_"):
                    expected_maps.insert(0, "DIAG_RESULTS")
                self.assertEqual(report["maps"], expected_maps)
                self.assertIs(report["load_authorized"], False)
                self.assertIs(report["deployment_gate_evidence"], False)
                self.assertIs(report["elf_inventory_verified"], True)
                original = (output / filename).read_bytes()
                start, length, _ = symbol_range(original, xdp)
                mutations = []
                map_start, _, _ = symbol_range(original, "HOOK_STATS")
                wrong_map_layout = bytearray(original)
                struct.pack_into("<I", wrong_map_layout, map_start + 8, 17)
                mutations.append(wrong_map_layout)
                if profile.startswith("fp_"):
                    observer_start, _, _ = symbol_range(original, "DIAG_RESULTS")
                    wrong_observer = bytearray(original)
                    struct.pack_into("<I", wrong_observer, observer_start + 8, 8)
                    mutations.append(wrong_observer)
                _, _, support_name = symbol_range(original, "memcpy")
                wrong_support = bytearray(original)
                wrong_support[support_name:support_name + 6] = b"evilxx"
                mutations.append(wrong_support)
                wrong_header = bytearray(original)
                wrong_header[18] = 62  # x86-64 is not BPF
                mutations.append(wrong_header)
                for offset in range(start, start + length, 8):
                    code = original[offset]
                    if code == 0x85:
                        wrong_helper = bytearray(original)
                        struct.pack_into("<i", wrong_helper, offset + 4, 127)
                        mutations.append(wrong_helper)
                        break
                for offset in range(start, start + length, 8):
                    if original[offset] == 0x95:
                        wrong_verdict = bytearray(original)
                        struct.pack_into("<i", wrong_verdict, offset - 4, 1)
                        mutations.append(wrong_verdict)
                        break
                damaged = root / "damaged.o"
                for mutation in mutations:
                    damaged.write_bytes(mutation)
                    result = run("verify-diagnostic-elf", "--object", damaged,
                                 "--profile", profile)
                    self.assertEqual(result.returncode, 1, result.stderr)
                    self.assertIn("DX_ELF", result.stderr)
                damaged.unlink()
                for wrong in PROFILES:
                    if wrong != profile:
                        rejected = run("verify-diagnostic-elf", "--object", output / filename,
                                       "--profile", wrong)
                        self.assertEqual(rejected.returncode, 1, rejected.stderr)
                        self.assertEqual(rejected.stdout, "")
                before = {p.name: p.read_bytes() for p in output.iterdir()}
                again = run("build-diagnostic-ebpf", "--profile", profile,
                            "--commit-sha", COMMIT, "--output", output)
                self.assertEqual(again.returncode, 1, again.stderr)
                self.assertEqual(before, {p.name: p.read_bytes() for p in output.iterdir()})
            self.assertEqual(ORDINARY.read_bytes(), ordinary_before)
            forbidden = subprocess.run(
                ["cargo", "+nightly-2026-08-10", "build", "--locked", "-Z", "build-std=core",
                 "--release", "--target", "bpfel-unknown-none", "--package", "l2-loop-ebpf",
                 "--features", "diagnostics", "--bin", "l2-loop-ebpf",
                 "--target-dir", ".artifacts/diagnostic-target"], cwd=ROOT,
                capture_output=True, text=True, timeout=300, check=False,
            )
            self.assertNotEqual(forbidden.returncode, 0)
            self.assertIn("diagnostic features must never build the ordinary product binary",
                          forbidden.stderr)
            published.parent.mkdir(exist_ok=True)
            shutil.copytree(root, published)

    def test_rejects_ordinary_object_for_every_profile(self):
        for profile in PROFILES:
            result = run("verify-diagnostic-elf", "--object", ORDINARY, "--profile", profile)
            self.assertEqual(result.returncode, 1, result.stderr)
            self.assertIn("DX_ELF", result.stderr)
            self.assertEqual(result.stdout, "")

    def test_rejects_invalid_empty_oversized_and_symlink_objects(self):
        with tempfile.TemporaryDirectory(prefix="l2-diag-invalid-") as temporary:
            path = Path(temporary) / "payload.o"
            for value in (b"", b"abc", b"\x7fELF" + b"\0" * 60):
                path.write_bytes(value)
                result = run("verify-diagnostic-elf", "--object", path, "--profile", "hooks_only")
                self.assertEqual(result.returncode, 1, result.stderr)
                self.assertEqual(result.stdout, "")
            with path.open("wb") as handle:
                handle.truncate(16 * 1024 * 1024 + 1)
            self.assertEqual(run("verify-diagnostic-elf", "--object", path,
                                 "--profile", "hooks_only").returncode, 1)
            path.unlink()
            path.symlink_to(ORDINARY)
            self.assertEqual(run("verify-diagnostic-elf", "--object", path,
                                 "--profile", "hooks_only").returncode, 1)

    def test_bad_commit_and_existing_destination_never_write(self):
        with tempfile.TemporaryDirectory(prefix="l2-diag-output-") as temporary:
            root = Path(temporary)
            output = root / "new"
            result = run("build-diagnostic-ebpf", "--profile", "hooks_only",
                         "--commit-sha", "invalid", "--output", output)
            self.assertEqual(result.returncode, 1, result.stderr)
            self.assertFalse(output.exists())
            marker = root / "sentinel"
            marker.write_bytes(b"preserve")
            result = run("build-diagnostic-ebpf", "--profile", "hooks_only",
                         "--commit-sha", COMMIT, "--output", root)
            self.assertEqual(result.returncode, 1, result.stderr)
            self.assertEqual(marker.read_bytes(), b"preserve")
            self.assertEqual(list(root.iterdir()), [marker])


if __name__ == "__main__":
    unittest.main()
