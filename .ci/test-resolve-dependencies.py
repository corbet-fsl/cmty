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
    def run_resolution(self, status=0, destination=True, metadata_status=0, revision="a" * 40):
        with tempfile.TemporaryDirectory(prefix="dependency resolution ") as directory:
            root = Path(directory)
            binary = root / "bin"
            binary.mkdir()
            cargo = binary / "cargo"
            cargo.write_text(
                '#!/usr/bin/env bash\nset -eu\n'
                'printf "%s\\n" "$@" >> arguments\n'
                'if [ "$1" = update ]; then\n'
                '  printf "resolved fixture\\n" > Cargo.lock\n'
                '  exit "$RESOLVER_TEST_STATUS"\n'
                'fi\n'
                'printf "{\\"packages\\": []}\\n"\n'
                'exit "$METADATA_TEST_STATUS"\n'
            )
            cargo.chmod(0o755)
            artifacts = root / "retained artifacts"
            artifacts.mkdir()
            retained_dir = artifacts / ("a" * 40) / "resolve-dependencies"
            retained_dir.mkdir(parents=True)
            retained = retained_dir / "Cargo.lock"
            retained.write_bytes(b"previous fixture\n")
            env = {**os.environ, "PATH": f"{binary}:{os.environ['PATH']}",
                   "RESOLVER_TEST_STATUS": str(status),
                   "METADATA_TEST_STATUS": str(metadata_status)}
            env.pop("ARTIFACT_ROOT", None)
            if destination:
                env["ARTIFACT_ROOT"] = str(artifacts)
            env.pop("CI_COMMIT_SHA", None)
            if revision is not None:
                env["CI_COMMIT_SHA"] = revision
            result = subprocess.run(["bash", str(SCRIPT)], cwd=root, env=env,
                                    text=True, capture_output=True, timeout=10)
            arguments = root / "arguments"
            metadata = retained_dir / "dependency-metadata.json"
            if result.returncode == 0:
                self.assertEqual(metadata.read_bytes(), b'{"packages": []}\n')
                self.assertIn(hashlib.sha256(metadata.read_bytes()).hexdigest(), result.stdout)
            return result, retained.read_bytes(), (
                arguments.read_text().splitlines() if arguments.exists() else None)

    def test_success_retains_exact_lock_and_identifies_it(self):
        result, retained, arguments = self.run_resolution()
        self.assertEqual(result.returncode, 0, result.stdout)
        self.assertEqual(retained, b"resolved fixture\n")
        self.assertIn(hashlib.sha256(retained).hexdigest(), result.stdout)
        self.assertEqual(arguments, ['update', '-p', 'cblc', '-p', 'cpmt', '-p', 'cvfy', '-p', 'czkp', '-p', 'cgts', '-p', 'cplc', '-p', 'cmbr', 'metadata', '--locked', '--format-version', '1'])

    def test_resolution_failure_never_replaces_retained_lock(self):
        result, retained, _ = self.run_resolution(status=7)
        self.assertEqual(result.returncode, 7)
        self.assertEqual(retained, b"previous fixture\n")
        self.assertNotIn("Resolved inputs only", result.stdout)

    def test_metadata_failure_never_replaces_retained_lock(self):
        result, retained, _ = self.run_resolution(metadata_status=8)
        self.assertEqual(result.returncode, 8)
        self.assertEqual(retained, b"previous fixture\n")

    def test_missing_or_malformed_revision_refuses_before_resolution(self):
        for revision in [None, "short", "/bad", "F" * 40]:
            result, retained, arguments = self.run_resolution(revision=revision)
            self.assertNotEqual(result.returncode, 0)
            self.assertIsNone(arguments)
            self.assertEqual(retained, b"previous fixture\n")

    def test_missing_destination_refuses_before_resolution(self):
        result, retained, arguments = self.run_resolution(destination=False)
        self.assertNotEqual(result.returncode, 0)
        self.assertIsNone(arguments)
        self.assertEqual(retained, b"previous fixture\n")


if __name__ == "__main__":
    unittest.main()
