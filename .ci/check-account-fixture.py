#!/usr/bin/env python3
"""Snapshot the pinned original account artifacts without changing capture bytes."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import shutil
import stat

LIMITS = {
    "account/config.json": 65536, "account/manifest.json": 65536,
    "account/circuit.json": 64 * 1024 * 1024, "account/vk.bin": 1024 * 1024,
    "account/records.json": 16 * 1024 * 1024,
    "account/ledger-records.json": 16 * 1024 * 1024,
    "account/setup/g1.dat": 128 * 1024 * 1024, "account/setup/g2.dat": 1024,
    "init.json": 4 * 1024 * 1024, "account-generation.txt": 1024,
}


def digest(path):
    with path.open("rb") as source:
        return hashlib.file_digest(source, "sha256").hexdigest()


def read(path, maximum):
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_size > maximum:
        raise ValueError("Account artifact is not a bounded regular file")
    with path.open("rb") as source:
        data = source.read(maximum + 1)
    if len(data) > maximum or len(data) != info.st_size:
        raise ValueError("Account artifact changed during its bounded read")
    return data


def check(directory, expected_source, expected_metadata, record_manifest, output):
    raw = read(directory / "startup-artifacts.json", 65536)
    if hashlib.sha256(raw).hexdigest() != expected_metadata:
        raise ValueError("Startup metadata differs from the independently pinned capture")
    metadata = json.loads(raw)
    if (metadata["version"] != 1 or metadata["purpose"] != "cblc.native-startup-test.v1"
            or metadata["sourceCommit"] != expected_source
            or metadata["accountGenerationCommit"] != expected_source
            or set(metadata["files"]) != set(LIMITS)):
        raise ValueError("Account capture identity or complete file list differs")
    record_raw = read(record_manifest, 65536)
    if hashlib.sha256(record_raw).hexdigest() != metadata["extensionManifestSha256"]:
        raise ValueError("Account startup and verified native group captures differ")
    record = json.loads(record_raw)
    if metadata["extensionScope"] != {
            "circuitDigest": list(bytes.fromhex(record["circuitSha256"])),
            "verifyingKeyDigest": list(bytes.fromhex(record["vkSha256"]))}:
        raise ValueError("Account startup's actual extension scope differs")
    # Check every original byte before creating a destination; a partial or
    # changed capture is never interpreted as an empty/default account fixture.
    for name, maximum in LIMITS.items():
        item = metadata["files"][name]
        info = (directory / name).lstat()
        if (not stat.S_ISREG(info.st_mode) or info.st_size != item["bytes"]
                or info.st_size > maximum or digest(directory / name) != item["sha256"]):
            raise ValueError("Account artifact bytes differ from the pinned capture")
    configuration = json.loads(read(directory / "account/config.json", LIMITS["account/config.json"]))
    if (set(configuration) != {"directory", "manifestSha256"}
            or configuration["manifestSha256"] != metadata["accountManifestSha256"]):
        raise ValueError("Original account config and startup manifest differ")
    manifest_raw = read(directory / "account/manifest.json", LIMITS["account/manifest.json"])
    if hashlib.sha256(manifest_raw).hexdigest() != metadata["accountManifestSha256"]:
        raise ValueError("Original account artifact manifest pin differs")
    manifest = json.loads(manifest_raw)
    if (manifest["version"] != 1 or manifest["accountingMode"] != "account-state-v2"
            or manifest["compiler"] != "1.0.0-beta.26" or manifest["backend"] != "5.0.0"
            or manifest["verifierTarget"] != "noir-recursive"
            or manifest["hashScheme"] != "poseidon2-bn254-fixed-128-v1"
            or metadata["files"]["account/circuit.json"]["sha256"] != manifest["circuitSha256"]
            or metadata["files"]["account/vk.bin"]["sha256"] != manifest["vkSha256"]
            or sorted(item["name"] for item in manifest["setup"]) != ["g1.dat", "g2.dat"]):
        raise ValueError("Original account artifact relation or key differs")
    for item in manifest["setup"]:
        if metadata["files"]["account/setup/" + item["name"]] != {
                "sha256": item["sha256"], "bytes": item["bytes"]}:
            raise ValueError("Original account setup linkage differs")
    generation = read(directory / "account-generation.txt", LIMITS["account-generation.txt"])
    if not re.fullmatch(expected_source.encode() + rb"\n[0-9a-f]{64}  package-lock\.json\n", generation):
        raise ValueError("Original account generation identity differs")
    # Only unsigned consumer path configuration is derived. All ten original
    # capture files stay byte-identical; no VK, proof, statement or key is rebuilt.
    output.mkdir(parents=True, exist_ok=False)
    try:
        capture = output / "capture"
        for name, maximum in LIMITS.items():
            target = capture / name
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(directory / name, target)
            info = target.lstat()
            item = metadata["files"][name]
            if (not stat.S_ISREG(info.st_mode) or info.st_size != item["bytes"]
                    or info.st_size > maximum or digest(target) != item["sha256"]):
                raise ValueError("Account artifact changed during the consuming snapshot")
        (capture / "startup-artifacts.json").write_bytes(raw)
        input_directory = output / "input"
        input_directory.mkdir()
        (input_directory / "config.json").write_text(json.dumps({
            "directory": str((capture / "account").resolve()),
            "manifestSha256": configuration["manifestSha256"],
        }))
        print(input_directory.resolve())
    except BaseException:
        shutil.rmtree(output)
        raise


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--directory", type=Path, required=True)
    parser.add_argument("--source", required=True)
    parser.add_argument("--metadata-sha256", required=True)
    parser.add_argument("--record-manifest", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    arguments = parser.parse_args()
    check(arguments.directory, arguments.source, arguments.metadata_sha256,
          arguments.record_manifest, arguments.output)
