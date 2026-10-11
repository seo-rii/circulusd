#!/usr/bin/env python3
"""Apply the native proof fork only to the exact celld v0.3.0 source snapshot."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess

COMMIT = "89e4ffc53a14ecb496d2ca5014ff9d19b0061ad9"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", required=True, type=Path)
    args = parser.parse_args()
    source = args.source.resolve(strict=True)
    package = Path(__file__).resolve().parent
    actual = subprocess.check_output(["git", "-C", str(source), "rev-parse", "HEAD"], text=True).strip()
    if actual != COMMIT:
        raise SystemExit("source is not the pinned celld commit")
    if subprocess.check_output(["git", "-C", str(source), "status", "--porcelain"], text=True):
        raise SystemExit("source must be clean before applying native patch")
    payload = source / "crates" / "circulusd-native-proof"
    if payload.exists():
        raise SystemExit("native proof payload already exists")
    patch = package / "celld-native.patch"
    subprocess.run(["git", "-C", str(source), "apply", "--check", str(patch)], check=True)
    subprocess.run(["git", "-C", str(source), "apply", str(patch)], check=True)
    payload.mkdir(mode=0o700)
    (payload / "src").mkdir(mode=0o700)
    (payload / "fixtures").mkdir(mode=0o700)
    manifest = (package / "Cargo.toml").read_text()
    # The copied proof crate participates in the pinned upstream workspace.
    manifest = manifest.replace("\n[workspace]\n", "\n")
    (payload / "Cargo.toml").write_text(manifest)
    shutil.copyfile(package / "src" / "lib.rs", payload / "src" / "lib.rs")
    shutil.copyfile(package / "fixtures/state-production-probe-v1alpha1.json", payload / "fixtures/state-production-probe-v1alpha1.json")
    result = {
        "schemaVersion": 1,
        "celldCommit": COMMIT,
        "patchDigest": "sha256:" + hashlib.sha256(patch.read_bytes()).hexdigest(),
        "nativeProofSourceDigest": "sha256:" + hashlib.sha256((package / "src" / "lib.rs").read_bytes()).hexdigest(),
        "result": "SOURCE_PATCHED_BUILD_PENDING",
        "admissionReady": False,
    }
    output = source / "circulusd-native-source.json"
    fd = os.open(output, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w") as handle:
        json.dump(result, handle, sort_keys=True)
        handle.write("\n")
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
