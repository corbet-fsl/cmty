#!/usr/bin/env python3
"""Check the independently pinned real CBLC test fixture; never execute it."""
import argparse
import hashlib
import json
from pathlib import Path
import platform
import shutil
import stat


def digest(path):
    with path.open("rb") as source:
        return hashlib.file_digest(source, "sha256").hexdigest()



def check(directory, expected_source, expected_metadata, output):
    metadata_path = directory / "worker.json"
    with metadata_path.open("rb") as source:
        metadata_bytes = source.read(65537)
    if len(metadata_bytes) > 65536 or hashlib.sha256(metadata_bytes).hexdigest() != expected_metadata:
        raise ValueError("Worker metadata differs from the independently pinned capture")
    metadata = json.loads(metadata_bytes)
    if metadata["version"] != 1 or metadata["sourceCommit"] != expected_source:
        raise ValueError("Worker source identity is unavailable or mismatched")
    if metadata["platform"] != {"system": platform.system(), "machine": platform.machine()}:
        raise ValueError("Native worker platform is incompatible")
    worker = directory / "worker"
    info = worker.stat()
    if not stat.S_ISREG(info.st_mode) or stat.S_IMODE(info.st_mode) != metadata["workerMode"]:
        raise ValueError("Worker executable metadata differs")
    if info.st_size != metadata["workerBytes"] or digest(worker) != metadata["workerSha256"]:
        raise ValueError("Worker bytes differ from the independently pinned capture")
    if not Path(metadata["runtime"]["interpreter"]).is_file():
        raise ValueError("Native interpreter is unavailable")
    for item in metadata["runtime"]["files"]:
        path = Path(item["path"])
        if not path.is_file() or digest(path) != item["sha256"]:
            raise ValueError("Required native runtime bytes are unavailable or mismatched")
    limits = {"gather-record-fixture.json": 1024 * 1024, "config.json": 65536,
              "manifest.json": 65536, "circuits.json": 64 * 1024 * 1024,
              "keys.json": 1024 * 1024, "setup/g1.dat": 128 * 1024 * 1024,
              "setup/g2.dat": 1024}
    if set(metadata["artifactFiles"]) != set(limits):
        raise ValueError("Unexpected native fixture artifact list")
    # Each job takes its own verified snapshot. A later producer cannot change
    # the cached binary or proof inputs between validation and native execution.
    output.mkdir(parents=True, exist_ok=False)
    target = output / "worker"
    shutil.copy2(worker, target)
    copied = target.stat()
    if (not stat.S_ISREG(copied.st_mode) or stat.S_IMODE(copied.st_mode) != metadata["workerMode"]
            or copied.st_size != metadata["workerBytes"] or digest(target) != metadata["workerSha256"]):
        raise ValueError("Worker changed during the consuming snapshot")
    for name, maximum in limits.items():
        source = directory / name
        if source.stat().st_size > maximum:
            raise ValueError("Fixture artifact exceeds its existing input bound")
        target = output / name
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, target)
        if digest(target) != metadata["artifactFiles"][name]:
            raise ValueError("Fixture artifact differs from the pinned capture")
    fixture = json.loads((output / "gather-record-fixture.json").read_text())
    if fixture["fixtureSource"] != expected_source:
        raise ValueError("Proof fixture and worker source identities differ")
    print((output / "worker").resolve())


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--directory", type=Path, required=True)
    parser.add_argument("--source", required=True)
    parser.add_argument("--metadata-sha256", required=True)
    parser.add_argument("--output", type=Path, required=True)
    arguments = parser.parse_args()
    check(arguments.directory, arguments.source, arguments.metadata_sha256, arguments.output)
