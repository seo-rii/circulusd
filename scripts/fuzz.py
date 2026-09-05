#!/usr/bin/env python3
"""Discover and run bounded local fuzz suites, retaining logs and reproducers."""

import argparse
import json
import os
from pathlib import Path
import re
import signal
import subprocess
import sys
import tempfile
import time


ROOT = Path(__file__).resolve().parents[1]
FUZZ_FUNCTION = re.compile(r"^func\s+(Fuzz\w+)\s*\(\s*\w+\s+\*testing\.F\s*\)", re.M)
SKIP_DIRECTORIES = {"node_modules", "testdata", "dist", "bin", "data", "var", "coverage"}


def discover():
    targets = []
    for directory, subdirectories, filenames in os.walk(ROOT):
        subdirectories[:] = sorted(
            name for name in subdirectories
            if not name.startswith(".") and name not in SKIP_DIRECTORIES
        )
        for filename in sorted(filenames):
            source = Path(directory) / filename
            relative = source.relative_to(ROOT)
            if filename.endswith("_test.go"):
                for name in FUZZ_FUNCTION.findall(source.read_text()):
                    package = "./" + relative.parent.as_posix()
                    targets.append({"suite": "go", "name": f"{package}#{name}",
                                    "package": package, "function": name,
                                    "source": relative.as_posix()})
            elif filename.endswith(".fuzz.test.ts") and relative.parts[0] in {"packages", "workers"}:
                package = source.parent
                while package != ROOT and not (package / "package.json").is_file():
                    package = package.parent
                if package == ROOT:
                    raise ValueError(f"no workspace package for {relative}")
                targets.append({"suite": "typescript", "name": relative.as_posix(),
                                "package": package.relative_to(ROOT).as_posix(),
                                "source": source.relative_to(package).as_posix()})
    for case in ("value", "bytes"):
        targets.append({"suite": "differential", "name": f"differential:{case}", "case": case})
    return sorted(targets, key=lambda target: (target["suite"], target["name"]))


def integer_between(minimum, maximum):
    def parse(value):
        try:
            parsed = int(value)
        except ValueError as error:
            raise argparse.ArgumentTypeError("must be an integer") from error
        if not minimum <= parsed <= maximum:
            raise argparse.ArgumentTypeError(f"must be between {minimum} and {maximum}")
        return parsed
    return parse


def duration(value):
    match = re.fullmatch(r"([1-9][0-9]*)(ms|s|m)", value)
    if match is None:
        raise argparse.ArgumentTypeError("use a positive duration such as 500ms, 30s, or 2m")
    seconds = int(match[1]) * {"ms": 0.001, "s": 1, "m": 60}[match[2]]
    if seconds > 3600:
        raise argparse.ArgumentTypeError("maximum duration is 60m per Go target")
    return seconds


def write_json(path, value):
    temporary = path.with_suffix(path.suffix + ".tmp")
    with temporary.open("w") as output:
        os.chmod(temporary, 0o600)
        json.dump(value, output, indent=2)
        output.write("\n")
    temporary.replace(path)


def jobs_for(config, directory):
    settings = config["settings"]
    jobs = []
    for target in config["targets"]:
        if target["suite"] == "go":
            seconds = duration(settings["duration"])
            jobs.append({"name": target["name"], "cwd": str(ROOT),
                         "timeout": seconds + 120,
                         "command": ["go", "test", target["package"], "-run=^$",
                                     f"-fuzz=^{target['function']}$",
                                     f"-fuzztime={settings['duration']}",
                                     f"-parallel={settings['workers']}",
                                     f"-timeout={int(seconds + 60)}s"]})
        elif target["suite"] == "typescript":
            command = ["pnpm", "exec", "vitest", "run", target["source"],
                       f"--maxWorkers={settings['workers']}", "--no-file-parallelism"]
            if settings["test_name"]:
                command += ["--testNamePattern", settings["test_name"]]
            jobs.append({"name": target["name"], "cwd": str(ROOT / target["package"]),
                         "timeout": settings["job_timeout"], "command": command})
    differential = [target for target in config["targets"] if target["suite"] == "differential"]
    if differential:
        binary = directory / "cbor-probe"
        jobs.append({"name": "build:cbor-probe", "cwd": str(ROOT), "timeout": 120,
                     "command": ["go", "build", "-o", str(binary), "./testdata/cbor-differential"]})
        for target in differential:
            command = ["node", "testdata/cbor-differential/fuzz.mjs", "--go-probe", str(binary),
                       "--case", target["case"], "--seed", str(settings["seed"]),
                       "--num-runs", str(settings["num_runs"]),
                       "--time-limit-ms", str((settings["job_timeout"] - 10) * 1000),
                       "--artifacts", str(directory / f"differential-{target['case']}")]
            if settings["path"]:
                command += ["--path", settings["path"]]
            jobs.append({"name": target["name"], "cwd": str(ROOT),
                         "timeout": settings["job_timeout"], "command": command})
    return jobs


def stop_process(process):
    if process.poll() is not None:
        return
    try:
        os.killpg(process.pid, signal.SIGTERM)
    except ProcessLookupError:
        process.wait()
        return
    try:
        process.wait(timeout=2)
    except subprocess.TimeoutExpired:
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        process.wait()


def worker(directory):
    config = json.loads((directory / "run.json").read_text())
    status = {"pid": os.getpid(), "state": "running", "exit_code": None, "results": []}
    environment = os.environ.copy()
    environment.update({"CIRCULUSD_FUZZ_SEED": str(config["settings"]["seed"]),
                        "CIRCULUSD_FUZZ_RUNS": str(config["settings"]["num_runs"]),
                        "CIRCULUSD_FUZZ_PATH": config["settings"]["path"]})
    write_json(directory / "status.json", status)

    def interrupted(_signal, _frame):
        raise KeyboardInterrupt

    signal.signal(signal.SIGTERM, interrupted)
    result_code = 0
    process = None
    try:
        for index, job in enumerate(jobs_for(config, directory)):
            log = directory / f"{index:02d}.log"
            started = time.monotonic()
            result = {**job, "log": str(log)}
            with log.open("wb") as output:
                os.chmod(log, 0o600)
                output.write((json.dumps({"command": job["command"], "cwd": job["cwd"]}) + "\n").encode())
                output.flush()
                process = subprocess.Popen(job["command"], cwd=job["cwd"], env=environment,
                                           stdin=subprocess.DEVNULL, stdout=output, stderr=subprocess.STDOUT,
                                           start_new_session=True, umask=0o077)
                result["pid"] = process.pid
                status["active"] = result
                write_json(directory / "status.json", status)
                try:
                    code = process.wait(timeout=job["timeout"])
                except subprocess.TimeoutExpired:
                    stop_process(process)
                    code = 124
            result.update({"exit_code": code, "seconds": round(time.monotonic() - started, 3)})
            status["results"].append(result)
            status.pop("active", None)
            write_json(directory / "status.json", status)
            if code != 0:
                result_code = code if code > 0 else 1
                break
    except KeyboardInterrupt:
        result_code = 130
    except Exception as error:
        result_code = 1
        status["error"] = f"{type(error).__name__}: {error}"
    finally:
        if process is not None:
            stop_process(process)
        if "active" in status:
            result = status.pop("active")
            result["exit_code"] = process.returncode if process is not None else result_code
            status["results"].append(result)
        status.update({"state": "finished", "exit_code": result_code})
        write_json(directory / "status.json", status)
    return result_code


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--suite", choices=("all", "go", "typescript", "differential"), default="all")
    parser.add_argument("--list", action="store_true", help="list source-discovered targets without executing them")
    parser.add_argument("--target", default="", help="regular expression matching listed target names")
    parser.add_argument("--duration", default="30s", help="time per Go target, for example 30s or 2m (maximum 60m)")
    parser.add_argument("--workers", type=integer_between(1, 64), default=2)
    parser.add_argument("--seed", type=integer_between(-(2**31), 2**31 - 1), default=20260905,
                        help="fast-check seed; Go reproduces failures from its saved corpus")
    parser.add_argument("--num-runs", type=integer_between(1, 1_000_000), default=1000)
    parser.add_argument("--path", default="", help="fast-check counterexample path (select exactly one property)")
    parser.add_argument("--test-name", default="", help="Vitest test name pattern for one property")
    parser.add_argument("--job-timeout", type=integer_between(11, 3600), default=300,
                        help="seconds per TypeScript or differential job; Go gets duration + 120 seconds")
    parser.add_argument("--worker", help=argparse.SUPPRESS)
    arguments = parser.parse_args()
    if arguments.worker:
        return worker(Path(arguments.worker))
    try:
        duration(arguments.duration)
        pattern = re.compile(arguments.target)
    except (argparse.ArgumentTypeError, re.error) as error:
        parser.error(str(error))
    targets = [target for target in discover()
               if arguments.suite in ("all", target["suite"]) and pattern.search(target["name"])]
    if not targets:
        parser.error("no fuzz targets match this selection")
    if arguments.list:
        for target in targets:
            print(f"{target['suite']:12} {target['name']}")
        return 0
    if arguments.path and (len(targets) != 1 or targets[0]["suite"] == "go" or
                           (targets[0]["suite"] == "typescript" and not arguments.test_name)):
        parser.error("--path requires one differential target, or one TypeScript file with --test-name")
    logs = Path.home() / "logs"
    logs.mkdir(mode=0o700, exist_ok=True)
    os.chmod(logs, 0o700)
    directory = Path(tempfile.mkdtemp(prefix="circulusd-fuzz-", dir=logs))
    settings = vars(arguments).copy()
    settings.pop("worker")
    write_json(directory / "run.json", {"root": str(ROOT), "settings": settings, "targets": targets})
    with (directory / "supervisor.log").open("wb") as output:
        os.chmod(directory / "supervisor.log", 0o600)
        process = subprocess.Popen([sys.executable, str(Path(__file__).resolve()), "--worker", str(directory)],
                                   cwd=ROOT, stdin=subprocess.DEVNULL, stdout=output, stderr=subprocess.STDOUT,
                                   start_new_session=True, umask=0o077)
    print(json.dumps({"pid": process.pid, "artifacts": str(directory),
                      "status": str(directory / "status.json"), "targets": len(targets)}, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
