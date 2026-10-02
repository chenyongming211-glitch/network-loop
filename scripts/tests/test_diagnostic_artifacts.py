"""GitHub-only integration against real compiled eBPF objects; never loads BPF."""

import hashlib
import json
import os
from pathlib import Path
import shutil
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
}


def run(*args):
    return subprocess.run(
        [str(XTASK), *map(str, args)], cwd=ROOT,
        capture_output=True, text=True, timeout=300, check=False,
    )


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
                self.assertEqual(report["programs"], sorted([xdp, tc]))
                self.assertEqual(report["maps"], ["FINGERPRINTS", "HOOK_STATS", "IFACE_CONFIG",
                                                 "PROBE_REGISTRY", "PROBE_STATS", "RATE_POLICY"])
                self.assertIs(report["load_authorized"], False)
                self.assertIs(report["deployment_gate_evidence"], False)
                self.assertIs(report["elf_inventory_verified"], True)
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
