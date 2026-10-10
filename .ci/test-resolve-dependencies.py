#!/usr/bin/env python3
"""Exercise lock retention without fetching dependencies or invoking Cargo."""
import hashlib
import os
from pathlib import Path
import subprocess
import tempfile
import unittest


SCRIPT = Path(__file__).resolve().with_name("resolve-dependencies.sh")


class ResolutionTests(unittest.TestCase):
    def run_resolution(self, status=0, destination=True):
        with tempfile.TemporaryDirectory(prefix="dependency resolution ") as directory:
            root = Path(directory)
            binary = root / "bin"
            binary.mkdir()
            cargo = binary / "cargo"
            cargo.write_text(
                '#!/usr/bin/env bash\nset -eu\n'
                'printf "%s\\n" "$@" > arguments\n'
                'printf "resolved fixture\\n" > Cargo.lock\n'
                'exit "$RESOLVER_TEST_STATUS"\n'
            )
            cargo.chmod(0o755)
            artifacts = root / "retained artifacts"
            artifacts.mkdir()
            retained = artifacts / "resolve-dependencies-Cargo.lock"
            retained.write_bytes(b"previous fixture\n")
            env = {**os.environ, "PATH": f"{binary}:{os.environ['PATH']}",
                   "RESOLVER_TEST_STATUS": str(status)}
            env.pop("ARTIFACT_ROOT", None)
            if destination:
                env["ARTIFACT_ROOT"] = str(artifacts)
            result = subprocess.run(["bash", str(SCRIPT)], cwd=root, env=env,
                                    text=True, capture_output=True, timeout=10)
            arguments = root / "arguments"
            return result, retained.read_bytes(), (
                arguments.read_text().splitlines() if arguments.exists() else None)

    def test_success_retains_exact_lock_and_identifies_it(self):
        result, retained, arguments = self.run_resolution()
        self.assertEqual(result.returncode, 0, result.stdout)
        self.assertEqual(retained, b"resolved fixture\n")
        self.assertIn(hashlib.sha256(retained).hexdigest(), result.stdout)
        self.assertEqual(arguments, ['update', '-p', 'cblc', '-p', 'cvfy', '-p', 'czkp', '-p', 'cgts', '-p', 'cplc', '-p', 'cmbr'])

    def test_resolution_failure_never_replaces_retained_lock(self):
        result, retained, _ = self.run_resolution(status=7)
        self.assertEqual(result.returncode, 7)
        self.assertEqual(retained, b"previous fixture\n")
        self.assertNotIn("Resolved dependency lock only", result.stdout)

    def test_missing_destination_refuses_before_resolution(self):
        result, retained, arguments = self.run_resolution(destination=False)
        self.assertNotEqual(result.returncode, 0)
        self.assertIsNone(arguments)
        self.assertEqual(retained, b"previous fixture\n")


if __name__ == "__main__":
    unittest.main()
