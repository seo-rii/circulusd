#!/usr/bin/env python3
"""Build the selected native fork with private persistent logs and a RAM bound."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import signal
import subprocess
import sys
import tempfile
import time
import tomllib

COMMIT = "89e4ffc53a14ecb496d2ca5014ff9d19b0061ad9"


def digest(path):
    value = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(65536), b""):
            value.update(block)
    return "sha256:" + value.hexdigest()


def validate_source(source):
    actual = subprocess.check_output(["git", "-C", str(source), "rev-parse", "HEAD"], text=True).strip()
    if actual != COMMIT:
        raise ValueError("not the pinned source commit")
    package = Path(__file__).resolve().parent
    payload = source / "crates/circulusd-native-proof/src/lib.rs"
    if digest(payload) != digest(package / "src/lib.rs"):
        raise ValueError("native proof payload differs from reviewed source")
    manifest = (package / "Cargo.toml").read_text().replace("\n[workspace]\n", "\n")
    if (source / "crates/circulusd-native-proof/Cargo.toml").read_text() != manifest:
        raise ValueError("native proof manifest differs from reviewed source")
    fixture = "fixtures/state-production-probe-v1alpha1.json"
    if digest(source / "crates/circulusd-native-proof" / fixture) != digest(package / fixture):
        raise ValueError("native proof fixture differs from reviewed source")
    patch = subprocess.check_output([
        "git", "-C", str(source), "diff", COMMIT, "--", "crates/celld/Cargo.toml",
        "crates/celld/lib.rs", "crates/celld/fleet.rs", "crates/celld/main.rs",
        "crates/celld/control_plane.rs", "crates/celld/js/harness.js",
    ])
    if patch != (package / "celld-native.patch").read_bytes():
        raise ValueError("native source patch differs from reviewed patch")
    changed = set(subprocess.check_output(["git", "-C", str(source), "diff", COMMIT, "--name-only"], text=True).splitlines())
    allowed = {"Cargo.lock", "crates/celld/Cargo.toml", "crates/celld/lib.rs", "crates/celld/fleet.rs", "crates/celld/main.rs", "crates/celld/control_plane.rs", "crates/celld/js/harness.js"}
    if not changed <= allowed:
        raise ValueError("unexpected source edits")
    # `git diff` ignores untracked files, yet Cargo builds any new module, build script or
    # .cargo/config it finds. Only the copied proof crate and apply.py's record may be new.
    untracked = set(subprocess.check_output(["git", "-C", str(source), "ls-files", "--others", "--exclude-standard"], text=True).splitlines())
    expected = {"circulusd-native-source.json", "crates/circulusd-native-proof/Cargo.toml", "crates/circulusd-native-proof/src/lib.rs", "crates/circulusd-native-proof/" + fixture}
    if not untracked <= expected:
        raise ValueError("unexpected untracked source files")
    return {"patchDigest": digest(package / "celld-native.patch"), "nativeProofSourceDigest": digest(payload), "cargoLockDigest": digest(source / "Cargo.lock")}


def build(source, output, build_root, status):
    result = {"pid": os.getpid(), "exitCode": 1, "buildRoot": str(build_root)}
    process = None
    try:
        expected = validate_source(source)
        os.nice(10)
        affinity = sorted(os.sched_getaffinity(0))
        os.sched_setaffinity(0, set(affinity[:1]))
        # Inherited Cargo and rustc settings (RUSTFLAGS, CARGO_PROFILE_*, wrappers) would change
        # the binary without changing its provenance. Only network transport settings pass.
        environment = {
            name: value for name, value in os.environ.items()
            if not name.startswith(("CARGO_", "RUSTC", "RUSTDOC", "RUSTFLAGS"))
            or name.startswith(("CARGO_NET_", "CARGO_HTTP_"))
        }
        environment.update({
            "CARGO_HOME": str(build_root / "cargo"),
            "CARGO_TARGET_DIR": str(build_root / "target"),
            "CARGO_INCREMENTAL": "0", "CARGO_BUILD_JOBS": "1",
            "CARGO_PROFILE_RELEASE_DEBUG": "0", "CARGO_PROFILE_RELEASE_LTO": "false",
            "CARGO_PROFILE_RELEASE_CODEGEN_UNITS": "1",
            "RUSTY_V8_CACHE": str(build_root / "v8cache"),
        })
        compiler = subprocess.check_output(["rustc", "+1.97.0", "--version"], text=True).strip()
        command = ["cargo", "+1.97.0", "build", "--locked", "--release", "--package", "celld", "--jobs", "1"]
        print("compiler", compiler, flush=True)
        process = subprocess.Popen(command, cwd=source, env=environment, start_new_session=True)
        result["cargoPid"] = process.pid
        while process.poll() is None:
            time.sleep(5)
            memory = {row.split(":")[0]: int(row.split()[1]) * 1024
                      for row in Path("/proc/meminfo").read_text().splitlines()
                      if row.startswith("MemAvailable:")}
            free = os.statvfs(build_root).f_bavail * os.statvfs(build_root).f_frsize
            if memory["MemAvailable"] < 1536 * 1024 * 1024 or free < 6 * 1024**3:
                result["reason"] = "resource-budget-exhausted"
                os.killpg(process.pid, signal.SIGTERM)
                try:
                    process.wait(timeout=30)
                except subprocess.TimeoutExpired:
                    os.killpg(process.pid, signal.SIGKILL)
                break
        result["exitCode"] = process.wait()
        if result["exitCode"]:
            return result["exitCode"]
        # Freeze validation is repeated after compilation. A concurrent source
        # edit produces no publishable artifact even if Cargo exits successfully.
        if validate_source(source) != expected:
            raise ValueError("source changed during build")
        binary = build_root / "target/release/celld"
        available = os.statvfs(output).f_bavail * os.statvfs(output).f_frsize
        if available < 256 * 1024 * 1024 + binary.stat().st_size:
            raise ValueError("insufficient artifact publication space")
        candidate = output / "celld-native"
        with binary.open("rb") as source_file:
            fd = os.open(candidate, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o700)
            with os.fdopen(fd, "wb") as destination:
                shutil.copyfileobj(source_file, destination)
                destination.flush()
                os.fsync(destination.fileno())
        version = subprocess.check_output([str(candidate), "--version"], text=True).strip()
        provenance = {
            "schemaVersion": 1, "kind": "circulusd.native-celld-fork-build.v1",
            "celldCommit": COMMIT, **expected, "compiler": compiler,
            "artifactRecipe": "raw-executable-v1", "buildDigest": digest(candidate),
            "executableDigest": digest(candidate), "artifactBytes": candidate.stat().st_size,
            "cargoLockDigest": digest(source / "Cargo.lock"), "version": version,
            "profile": {"release": True, "lto": False, "debug": 0, "codegenUnits": 1, "jobs": 1},
            "qualification": "not-run", "admissionReady": False,
        }
        fd = os.open(output / "provenance.json", os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w") as handle:
            json.dump(provenance, handle, sort_keys=True)
            handle.write("\n")
        result["artifact"] = str(candidate)
        result["provenance"] = str(output / "provenance.json")
        print(json.dumps(provenance, sort_keys=True), flush=True)
    except Exception as error:
        result["exitCode"] = 1
        result["reason"] = type(error).__name__
        print("native build failed:", type(error).__name__, flush=True)
        if process is not None and process.poll() is None:
            os.killpg(process.pid, signal.SIGTERM)
            process.wait()
    finally:
        fd = os.open(status, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w") as handle:
            json.dump(result, handle, sort_keys=True)
            handle.write("\n")
    return result["exitCode"]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--build-root", type=Path)
    parser.add_argument("--status", type=Path, help=argparse.SUPPRESS)
    arguments = parser.parse_args()
    source = arguments.source.resolve(strict=True)
    if arguments.status:
        code = build(source, arguments.output, arguments.build_root, arguments.status)
        sys.exit(code if code >= 0 else 128-code)
    validate_source(source)
    output = arguments.output.absolute()
    output.mkdir(mode=0o700)
    build_root = arguments.build_root
    if build_root is None:
        build_root = Path(tempfile.mkdtemp(prefix="circulusd-native-celld-build-", dir="/dev/shm"))
        build_root.chmod(0o700)
        home = build_root / "cargo"
        cache = home / "registry/cache/index.crates.io-1949cf8c6b5b557f"
        cache.mkdir(parents=True)
        original = Path.home() / ".cargo/registry/cache/index.crates.io-1949cf8c6b5b557f"
        for package in tomllib.loads((source / "Cargo.lock").read_text())["package"]:
            if package.get("source", "").startswith("registry+"):
                name = package["name"] + "-" + package["version"] + ".crate"
                if (original / name).exists():
                    shutil.copyfile(original / name, cache / name)
        shutil.copytree(Path.home() / ".cargo/registry/index", home / "registry/index")
    else:
        build_root = build_root.resolve(strict=True)
        metadata = build_root.stat()
        allowed_parents = {Path("/dev/shm"), source.parent}
        if build_root.parent not in allowed_parents or not build_root.name.startswith("circulusd-native-celld-build-") or metadata.st_uid != os.geteuid() or metadata.st_mode & 0o777 != 0o700:
            raise SystemExit("build root must be an owned private native build cache")
    logs = Path.home() / "logs"
    logs.mkdir(mode=0o700, exist_ok=True)
    logs.chmod(0o700)
    fd, log = tempfile.mkstemp(prefix="circulusd-native-celld-build-", suffix=".log", dir=logs)
    os.fchmod(fd, 0o600)
    status = log + ".status.json"
    process = subprocess.Popen([
        sys.executable, str(Path(__file__).resolve()), "--source", str(source),
        "--output", str(output), "--build-root", str(build_root), "--status", status,
    ], stdout=fd, stderr=subprocess.STDOUT, start_new_session=True)
    os.close(fd)
    print(json.dumps({"pid": process.pid, "log": log, "status": status,
                      "buildRoot": str(build_root), "output": str(output)}, sort_keys=True))


if __name__ == "__main__":
    main()
