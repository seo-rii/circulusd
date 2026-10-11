#!/usr/bin/env python3
"""Run a private, subscription-authenticated Codex smoke test in Bubblewrap.

Use --launch to start a detached, bounded test. The command prints the private
run directory, worker PID, log and status paths; report.json records completion.
Use --offline with --launch to check isolation without a model request.
The host configuration, instructions, plugins and MCP connections are not mounted.
"""

import argparse
import hashlib
import json
import os
from pathlib import Path
import resource
import selectors
import shlex
import shutil
import signal
import stat
import subprocess
import sys
import tempfile
import time
import uuid


REPOSITORY = Path(__file__).resolve().parent.parent
RUN_PARENT = REPOSITORY / ".codex" / "codex-isolated-test"
VIRTUAL_HOME = "/home/test"
VIRTUAL_CODEX_HOME = VIRTUAL_HOME + "/.codex"
VIRTUAL_WORKSPACE = "/workspace"
CONFIG = [
    "project_doc_max_bytes=0",
    "project_doc_fallback_filenames=[]",
    'developer_instructions=""',
    "include_apps_instructions=false",
    "include_environment_context=false",
    "include_collaboration_mode_instructions=false",
    "skills.bundled.enabled=false",
    "skills.include_instructions=false",
    "features.apps=false",
    "features.plugins=false",
    "features.hooks=false",
    "features.skill_mcp_dependency_install=false",
    "features.shell_snapshot=false",
    "features.multi_agent=false",
    "features.multi_agent_v2=false",
    "features.memory_tool=false",
    "features.code_mode_host=true",
    "features.code_mode.enabled=false",
    'web_search="disabled"',
    'model_reasoning_effort="low"',
    'history.persistence="none"',
    'shell_environment_policy.inherit="none"',
    "shell_environment_policy.experimental_use_profile=false",
    'shell_environment_policy.set={PATH="/usr/bin:/bin", HOME="/home/test", LANG="C.UTF-8"}',
    'forced_login_method="chatgpt"',
    "feedback.enabled=false",
]


def private_json(path, value):
    temporary = path.with_name(path.name + ".tmp")
    with open(temporary, "w", opener=lambda p, f: os.open(p, f, 0o600)) as handle:
        json.dump(value, handle, ensure_ascii=False, sort_keys=True, indent=2)
        handle.write("\n")
    os.chmod(temporary, 0o600)
    os.replace(temporary, path)


def private_text(path, value):
    with open(path, "w", opener=lambda p, f: os.open(p, f, 0o600)) as handle:
        handle.write(value)
    os.chmod(path, 0o600)


def config_arguments():
    return [argument for value in CONFIG for argument in ("-c", value)]


def sandbox_arguments(run, command, online=False):
    """Construct a new mount root; never bind the host home or repository."""
    specification = json.loads((run / "run.json").read_text())
    arguments = [
        "/usr/bin/bwrap", "--unshare-all", "--die-with-parent", "--new-session",
        "--cap-drop", "ALL",
    ]
    if online:
        # Only the trusted CLI needs the host network to reach its official
        # subscription endpoint. This is filesystem/process isolation, not a VM
        # or network-egress qualification. Apps/MCP/web search remain disabled.
        arguments += ["--share-net"]
    arguments += [
        "--ro-bind", "/usr", "/usr",
        "--symlink", "usr/bin", "/bin",
        "--symlink", "usr/lib", "/lib",
        "--symlink", "usr/lib64", "/lib64",
        "--ro-bind", specification["codexBinary"], "/opt/codex",
        "--ro-bind", specification["codeModeHostBinary"], "/opt/codex-code-mode-host",
        "--proc", "/proc", "--dev", "/dev", "--tmpfs", "/tmp",
        "--bind", str(run / "home"), VIRTUAL_HOME,
        "--bind", str(run / "workspace"), VIRTUAL_WORKSPACE,
        "--ro-bind", str(run / "etc" / "passwd"), "/etc/passwd",
        "--ro-bind", str(run / "etc" / "group"), "/etc/group",
    ]
    for source, target in [
        ("/etc/resolv.conf", "/etc/resolv.conf"),
        ("/etc/nsswitch.conf", "/etc/nsswitch.conf"),
        ("/etc/ssl/certs", "/etc/ssl/certs"),
    ]:
        if Path(source).exists():
            arguments += ["--ro-bind", source, target]
    for key, value in {
        "HOME": VIRTUAL_HOME,
        "CODEX_HOME": VIRTUAL_CODEX_HOME,
        "PATH": "/usr/bin:/bin",
        "LANG": "C.UTF-8",
        "TERM": "dumb",
        "XDG_CONFIG_HOME": VIRTUAL_HOME + "/.config",
        "XDG_CACHE_HOME": VIRTUAL_HOME + "/.cache",
        "XDG_DATA_HOME": VIRTUAL_HOME + "/.local/share",
    }.items():
        if key == "HOME":
            arguments += ["--clearenv"]
        arguments += ["--setenv", key, value]
    return arguments + ["--chdir", VIRTUAL_WORKSPACE, "--"] + command


def child_limits():
    os.umask(0o077)
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    resource.setrlimit(resource.RLIMIT_CPU, (45, 50))
    resource.setrlimit(resource.RLIMIT_NOFILE, (256, 256))
    resource.setrlimit(resource.RLIMIT_FSIZE, (16 * 1024**2, 16 * 1024**2))


def authentication_secrets(auth_file):
    if not auth_file.exists():
        return []
    try:
        encoded = auth_file.read_text()
        if len(encoded) > 256 * 1024:
            raise ValueError()
        auth = json.loads(encoded)
        tokens = auth.get("tokens") if isinstance(auth, dict) else None
        if not isinstance(tokens, dict) or not isinstance(tokens.get("access_token"), str):
            raise ValueError()
        return [value for value in tokens.values() if isinstance(value, str) and len(value) >= 12]
    except Exception:
        raise RuntimeError("cannot safely inspect isolated authentication metadata") from None


def invoke(run, command, online=False, timeout=25):
    started = time.monotonic()
    auth_file = run / "home" / ".codex" / "auth.json"
    secrets = authentication_secrets(auth_file)
    process = subprocess.Popen(
        sandbox_arguments(run, command, online), cwd=run,
        env={"PATH": "/usr/bin:/bin", "CIRCULUSD_ISOLATION_CANARY": "must-not-inherit"},
        stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        start_new_session=True, preexec_fn=child_limits,
    )
    captured = [bytearray(), bytearray()]
    deadline = started + timeout
    try:
        with process.stdout, process.stderr, selectors.DefaultSelector() as streams:
            for index, (pipe, limit) in enumerate([(process.stdout, 4 * 1024**2), (process.stderr, 1024**2)]):
                os.set_blocking(pipe.fileno(), False)
                streams.register(pipe, selectors.EVENT_READ, (index, limit))
            while streams.get_map():
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise subprocess.TimeoutExpired(command, timeout)
                for key, _ in streams.select(remaining):
                    index, limit = key.data
                    # Read at most one byte beyond the allowance to detect an
                    # overflow without buffering the rest of a noisy child.
                    chunk = os.read(key.fd, min(64 * 1024, limit - len(captured[index]) + 1))
                    if not chunk:
                        streams.unregister(key.fileobj)
                    elif len(captured[index]) + len(chunk) > limit:
                        raise RuntimeError("isolated child exceeded its output limit")
                    else:
                        captured[index].extend(chunk)
            # EOF can precede process exit; closing both pipes must not evade
            # the original wall-clock deadline.
            process.wait(timeout=max(0, deadline - time.monotonic()))
    except BaseException as failure:
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        process.wait()
        if isinstance(failure, subprocess.TimeoutExpired):
            raise RuntimeError("isolated child exceeded its time limit") from None
        raise
    output, error = [value.decode("utf-8").replace("\r\n", "\n").replace("\r", "\n") for value in captured]
    if secrets and not auth_file.exists():
        raise RuntimeError("isolated authentication disappeared before output inspection")
    secrets += authentication_secrets(auth_file)
    if any(secret in output or secret in error for secret in secrets):
        raise RuntimeError("isolated child attempted to print authentication data")
    # All runs use only our fixed fixture/prompt. Authentication contents are
    # never requested from the model, printed, or included in reports.
    private_text(run / ("last-child.stderr"), error)
    if process.returncode:
        raise RuntimeError("isolated child exited with code " + str(process.returncode))
    return output, round(time.monotonic() - started, 3)


def prepare(offline):
    if not shutil.which("bwrap") or not shutil.which("codex"):
        raise RuntimeError("bwrap and codex must be installed")
    RUN_PARENT.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(RUN_PARENT, 0o700)
    run = Path(tempfile.mkdtemp(prefix="run-", dir=RUN_PARENT))
    for directory in [run / "home" / ".codex", run / "workspace", run / "etc"]:
        directory.mkdir(parents=True, mode=0o700)
    os.chmod(run / "home", 0o700)
    codex = Path(shutil.which("codex")).resolve()
    code_mode_host = codex.with_name("codex-code-mode-host")
    if not code_mode_host.is_file():
        raise RuntimeError("installed Codex package is missing its execution helper")
    version = subprocess.run([str(codex), "--version"], capture_output=True, text=True, check=True).stdout.strip()
    specification = {
        "schemaVersion": 1, "kind": "circulusd.isolated-codex-test.v1",
        "createdAtUnixMs": int(time.time() * 1000), "offlineOnly": offline,
        "codexBinary": str(codex), "codexVersion": version,
        "codexBinarySHA256": hashlib.sha256(codex.read_bytes()).hexdigest(),
        "codeModeHostBinary": str(code_mode_host),
        "codeModeHostBinarySHA256": hashlib.sha256(code_mode_host.read_bytes()).hexdigest(),
        "runnerSHA256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        "configOverrides": CONFIG,
        "nonce": uuid.uuid4().hex,
        "hostNamespaceIDs": {name: os.readlink("/proc/self/ns/" + name) for name in ["user", "mnt", "pid", "ipc", "uts", "net"]},
    }
    private_json(run / "run.json", specification)
    private_text(run / "etc" / "passwd", "test:x:%d:%d::/home/test:/bin/sh\n" % (os.getuid(), os.getgid()))
    private_text(run / "etc" / "group", "test:x:%d:\n" % os.getgid())
    private_json(run / "workspace" / "fixture.json", {"nonce": specification["nonce"], "numbers": [17, 23, 41, -5, 11]})
    # A conflicting file stays OUTSIDE every mount. This supplements the checks
    # against the real workspace instruction paths without reading their text.
    private_text(run / "AGENTS.md", "CIRCULUSD_HOST_INSTRUCTIONS_MUST_NOT_APPEAR\n")
    if not offline:
        source_home = Path(os.environ.get("CODEX_HOME", str(Path.home() / ".codex")))
        source = source_home / "auth.json"
        # Do not copy the user's config, skills, hooks, plugins or API keys.
        try:
            fd = os.open(source, os.O_RDONLY | os.O_NOFOLLOW)
            with os.fdopen(fd) as handle:
                if not stat.S_ISREG(os.fstat(handle.fileno()).st_mode):
                    raise RuntimeError("subscription auth must be a regular file")
                encoded_auth = handle.read(256 * 1024 + 1)
                if len(encoded_auth) > 256 * 1024:
                    raise RuntimeError("subscription auth file exceeds its size limit")
                auth = json.loads(encoded_auth)
            tokens = auth.get("tokens") if isinstance(auth, dict) else None
            access_token = tokens.get("access_token") if isinstance(tokens, dict) else None
            if not isinstance(auth, dict) or auth.get("auth_mode") != "chatgpt" or not isinstance(access_token, str) or not access_token.strip() or access_token != access_token.strip():
                raise RuntimeError("an existing ChatGPT subscription login is required")
            subscription_auth = {key: auth[key] for key in ["auth_mode", "last_refresh"] if key in auth}
            subscription_auth["tokens"] = {key: tokens[key] for key in ["access_token", "refresh_token", "id_token", "account_id"] if key in tokens}
            private_json(run / "home" / ".codex" / "auth.json", subscription_auth)
        except Exception:
            shutil.rmtree(run)
            raise
    return run


def worker(run):
    report = {"schemaVersion": 1, "kind": "circulusd.isolated-codex-test-report.v1", "checks": {}, "fullPlatformQualified": False}
    status = json.loads((run / "status.json").read_text())
    status["pid"] = os.getpid()
    private_json(run / "status.json", status)
    specification = json.loads((run / "run.json").read_text())
    failure = None
    exit_code = 1
    try:
        if hashlib.sha256(Path(__file__).read_bytes()).hexdigest() != specification["runnerSHA256"]:
            raise RuntimeError("runner changed after launch")
        if hashlib.sha256(Path(specification["codexBinary"]).read_bytes()).hexdigest() != specification["codexBinarySHA256"]:
            raise RuntimeError("Codex binary changed after launch")
        if hashlib.sha256(Path(specification["codeModeHostBinary"]).read_bytes()).hexdigest() != specification["codeModeHostBinarySHA256"]:
            raise RuntimeError("Codex execution helper changed after launch")
        inspector = '''import os,json
paths=["/home/seorii","/home/seorii/dev/hancomac","/home/seorii/dev/hancomac/AGENTS.md","/root/.codex","/etc/codex","/home/test/.agents","/workspace/.codex","/workspace/AGENTS.md","/home/test/.codex/AGENTS.md","/AGENTS.md","/proc/1/root/home/seorii","/run/docker.sock"]
status=open("/proc/self/status").read().splitlines()
print(json.dumps({"cwd":os.getcwd(),"environmentKeys":sorted(os.environ),"visiblePaths":{p:os.path.exists(p) for p in paths},"namespaces":{n:os.readlink("/proc/self/ns/"+n) for n in ["user","mnt","pid","ipc","uts","net"]},"capabilities":next(l.split()[1] for l in status if l.startswith("CapEff:")),"noNewPrivileges":next(l.split()[1] for l in status if l.startswith("NoNewPrivs:"))}))'''
        raw, _ = invoke(run, ["/usr/bin/python3", "-c", inspector])
        inspection = json.loads(raw)
        allowed_env = {"HOME", "CODEX_HOME", "PATH", "LANG", "TERM", "XDG_CONFIG_HOME", "XDG_CACHE_HOME", "XDG_DATA_HOME", "PWD"}
        if inspection["cwd"] != VIRTUAL_WORKSPACE or any(inspection["visiblePaths"].values()) or set(inspection["environmentKeys"]) != allowed_env:
            raise RuntimeError("host files or environment leaked into sandbox")
        if inspection["capabilities"] != "0000000000000000" or inspection["noNewPrivileges"] != "1":
            raise RuntimeError("sandbox retained privileges")
        if any(inspection["namespaces"][name] == specification["hostNamespaceIDs"][name] for name in inspection["namespaces"]):
            raise RuntimeError("offline sandbox retained a host namespace")
        report["checks"]["isolation"] = inspection
        common = ["/opt/codex", "--no-daemon"] + config_arguments()
        raw, _ = invoke(run, common + ["mcp", "list", "--json"])
        if json.loads(raw) != []:
            raise RuntimeError("sandbox loaded MCP servers")
        report["checks"]["mcpServers"] = []
        raw, _ = invoke(run, common + ["features", "list"])
        feature_lines = {line.split()[0]: line.split()[-1] for line in raw.splitlines() if line.split()}
        required_disabled = ["apps", "plugins", "hooks", "multi_agent", "multi_agent_v2"]
        if any(feature_lines.get(name) != "false" for name in required_disabled):
            raise RuntimeError("sandbox retained an inherited integration feature")
        report["checks"]["disabledFeatures"] = {name: False for name in required_disabled}
        raw, _ = invoke(run, common + ["debug", "prompt-input", "circulusd isolation diagnostic"])
        prompt = json.loads(raw)
        private_json(run / "prompt-input.json", prompt)
        forbidden = ["CIRCULUSD_HOST_INSTRUCTIONS_MUST_NOT_APPEAR", "/home/seorii", "# Workspace Scope", "dev_bypass_waf", "<skills_instructions>", "## Skills", "AGENTS.md instructions for", "## Available skills"]
        if any(marker in raw for marker in forbidden):
            raise RuntimeError("sandbox prompt inherited instructions or skills")
        report["checks"]["prompt"] = {"inheritedInstructions": False, "skillCatalogPresent": False, "sha256": hashlib.sha256(raw.encode()).hexdigest()}
        if specification["offlineOnly"]:
            report["modelTest"] = {"status": "NOT_RUN_OFFLINE"}
        else:
            raw, _ = invoke(run, common + ["login", "status"])
            # Some releases print the login mode on stderr instead.
            login_text = raw + (run / "last-child.stderr").read_text()
            if "chatgpt" not in login_text.lower() or "api key" in login_text.lower():
                raise RuntimeError("sandbox did not use subscription authentication")
            report["checks"]["authentication"] = "chatgpt-subscription"
            expected = {"test": "circulusd-isolated", "nonce": specification["nonce"], "sum": 87, "cwd": VIRTUAL_WORKSPACE, "host_visible": False, "agents_visible": False, "inherited_env_visible": False}
            schema = {"type": "object", "additionalProperties": False, "required": list(expected), "properties": {key: {"type": "boolean" if isinstance(value, bool) else "integer" if isinstance(value, int) else "string"} for key, value in expected.items()}}
            private_json(run / "workspace" / "response-schema.json", schema)
            probe = '''import json,os,pathlib
f=json.loads(pathlib.Path("/workspace/fixture.json").read_text())
print(json.dumps({"test":"circulusd-isolated","nonce":f["nonce"],"sum":sum(f["numbers"]),"cwd":os.getcwd(),"host_visible":pathlib.Path("/home/seorii/dev/hancomac").exists(),"agents_visible":any(pathlib.Path(p).exists() for p in ["/AGENTS.md","/workspace/AGENTS.md","/home/test/.codex/AGENTS.md"]),"inherited_env_visible":"CIRCULUSD_ISOLATION_CANARY" in os.environ}))'''
            private_text(run / "workspace" / "probe.py", probe)
            request = "This is a personal circulusd execution smoke test. Run exactly one shell command, without extra arguments:\n```sh\npython3 /workspace/probe.py\n```\nIt reads only our fixture and checks path existence. Do not read authentication, make network calls, use MCP, or edit files. Return the command's JSON object unchanged as your final response."
            command = common + ["-a", "never", "exec", "--strict-config", "--ignore-user-config", "--ignore-rules", "--ephemeral", "--skip-git-repo-check", "--sandbox", "read-only", "--json", "--color", "never", "--output-schema", "/workspace/response-schema.json", "--output-last-message", "/workspace/response.json", request]
            raw, elapsed = invoke(run, command, online=True, timeout=180)
            events = [json.loads(line) for line in raw.splitlines() if line.strip()]
            completed = [event for event in events if event.get("type") == "turn.completed"]
            commands = [event["item"] for event in events if event.get("type") == "item.completed" and event.get("item", {}).get("type") == "command_execution"]
            diagnostics = {"eventTypes": sorted({event.get("type", "") for event in events}), "commandCount": len(commands), "commands": []}
            for item in commands:
                parts = shlex.split(item.get("command", ""))
                if len(parts) == 3 and parts[0] in ["/bin/sh", "/bin/bash", "/usr/bin/bash"] and parts[1] in ["-c", "-lc"]:
                    parts = shlex.split(parts[2])
                allowed_diagnostic_words = {"python3", "/usr/bin/python3", "/workspace/probe.py", "."}
                diagnostics["commands"].append({"argumentCount": len(parts), "parts": parts if all(part in allowed_diagnostic_words for part in parts) else ["withheld"], "exitCode": item.get("exit_code"), "status": item.get("status")})
            private_json(run / "model-diagnostics.json", diagnostics)
            # Do not retain arbitrary model command output. This test accepts
            # only its one fixed fixture command and exact computed result.
            for item in commands:
                if item.get("status") != "completed" or type(item.get("exit_code")) is not int or item["exit_code"] != 0:
                    raise RuntimeError("model probe command did not exit successfully")
                parts = shlex.split(item.get("command", ""))
                if len(parts) == 3 and parts[0] in ["/bin/sh", "/bin/bash", "/usr/bin/bash"] and parts[1] in ["-c", "-lc"]:
                    parts = shlex.split(parts[2])
                if parts not in [["python3", "/workspace/probe.py"], ["/usr/bin/python3", "/workspace/probe.py"]]:
                    raise RuntimeError("model attempted a command outside the fixed fixture")
            response = json.loads((run / "workspace" / "response.json").read_text())
            outputs = []
            for command_result in commands:
                output = command_result.get("aggregated_output", command_result.get("output", ""))
                try:
                    outputs.append(json.loads(output))
                except (ValueError, TypeError):
                    pass
            if len(completed) != 1 or len(commands) != 1 or outputs != [expected] or response != expected:
                raise RuntimeError("model turn did not execute and return the exact fixture result")
            if any(event.get("type") in ["error", "turn.failed"] for event in events):
                raise RuntimeError("model turn reported an error")
            private_text(run / "events.jsonl", raw)
            report["modelTest"] = {"status": "PASS", "elapsedSeconds": elapsed, "response": response, "commandCount": len(commands), "usage": completed[0].get("usage"), "eventTypes": sorted({event.get("type") for event in events}), "sandboxPolicy": "read-only", "networkNamespace": "host-network-for-cli"}
        report["status"] = "PASS"
        exit_code = 0
    except Exception as error:
        # Error messages in this runner are fixed and never contain auth values.
        failure = str(error) if isinstance(error, RuntimeError) else type(error).__name__
        report["status"] = "FAIL"
        report["failure"] = failure
    finally:
        shutil.rmtree(run / "home")
        (run / "home").mkdir(mode=0o700)
        report["temporaryAuthenticationRemoved"] = not any((run / "home").iterdir())
        report["codexVersion"] = specification["codexVersion"]
        report["finishedAtUnixMs"] = int(time.time() * 1000)
        private_json(run / "report.json", report)
        status.update(state="completed", exitCode=exit_code, finishedAtUnixMs=report["finishedAtUnixMs"], failure=failure)
        private_json(run / "status.json", status)
        print(json.dumps({"state": status["state"], "exitCode": exit_code, "report": str(run / "report.json")}), flush=True)
    return exit_code


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--launch", action="store_true")
    parser.add_argument("--offline", action="store_true")
    parser.add_argument("--worker", type=Path, help=argparse.SUPPRESS)
    arguments = parser.parse_args()
    if arguments.worker:
        return worker(arguments.worker.resolve())
    if not arguments.launch:
        parser.error("use --launch to create a detached private test")
    run = prepare(arguments.offline)
    try:
        logs = Path.home() / "logs"
        logs.mkdir(mode=0o700, exist_ok=True)
        os.chmod(logs, 0o700)
        log_fd, log_name = tempfile.mkstemp(prefix="circulusd-isolated-codex-", suffix=".log", dir=logs)
        os.fchmod(log_fd, 0o600)
        status = {"schemaVersion": 1, "state": "running", "pid": None, "log": log_name, "status": str(run / "status.json"), "report": str(run / "report.json"), "startedAtUnixMs": int(time.time() * 1000)}
        private_json(run / "status.json", status)
        with os.fdopen(log_fd, "w") as log:
            process = subprocess.Popen([sys.executable, str(Path(__file__).resolve()), "--worker", str(run)], cwd=run, stdin=subprocess.DEVNULL, stdout=log, stderr=log, start_new_session=True)
    except Exception:
        shutil.rmtree(run / "home")
        (run / "home").mkdir(mode=0o700)
        private_json(run / "status.json", {"state": "completed", "exitCode": 1, "failure": "worker launch failed", "temporaryAuthenticationRemoved": True})
        raise RuntimeError("could not launch private test worker") from None
    status["pid"] = process.pid
    print(json.dumps(status, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
