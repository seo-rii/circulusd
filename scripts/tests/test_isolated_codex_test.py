"""Focused isolation tests; subprocesses and credentials are synthetic."""

import contextlib
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import signal
import stat
import subprocess
import tempfile
import tomllib
import types
import unittest
from unittest.mock import Mock, patch


SCRIPT = Path(__file__).resolve().parents[1] / "test-isolated-codex.py"
SPEC = importlib.util.spec_from_file_location("isolated_codex_test_runner", SCRIPT)
runner = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(runner)


class IsolatedCodexTest(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.run = self.root / "run"
        for name in ["home/.codex", "workspace", "etc"]:
            (self.run / name).mkdir(parents=True, mode=0o700)
        self.binary = self.root / "bin" / "codex"
        self.binary.parent.mkdir()
        self.binary.write_bytes(b"synthetic executable, never executed")
        self.helper = self.binary.with_name("codex-code-mode-host")
        self.helper.write_bytes(b"synthetic execution helper, never executed")
        self.source_home = self.root / "source-home"
        self.source_home.mkdir()
        self.specification = {
            "schemaVersion": 1,
            "offlineOnly": True,
            "codexBinary": str(self.binary),
            "codexBinarySHA256": hashlib.sha256(self.binary.read_bytes()).hexdigest(),
            "codeModeHostBinary": str(self.helper),
            "codeModeHostBinarySHA256": hashlib.sha256(self.helper.read_bytes()).hexdigest(),
            "runnerSHA256": hashlib.sha256(SCRIPT.read_bytes()).hexdigest(),
            "codexVersion": "synthetic test version",
            "nonce": "synthetic-fixture-nonce",
            "hostNamespaceIDs": {name: "host-" + name for name in ["user", "mnt", "pid", "ipc", "uts", "net"]},
        }
        runner.private_json(self.run / "run.json", self.specification)
        runner.private_json(self.run / "status.json", {"state": "running", "pid": None})
        self.inspection = {
            "cwd": "/workspace",
            "environmentKeys": ["HOME", "CODEX_HOME", "PATH", "LANG", "TERM", "XDG_CONFIG_HOME", "XDG_CACHE_HOME", "XDG_DATA_HOME", "PWD"],
            "visiblePaths": {"/home/seorii": False, "/etc/codex": False, "/workspace/AGENTS.md": False},
            "capabilities": "0000000000000000",
            "noNewPrivileges": "1",
            "namespaces": {name: "child-" + name for name in self.specification["hostNamespaceIDs"]},
        }
        self.features = "\n".join(name + " stable false" for name in ["apps", "plugins", "hooks", "multi_agent", "multi_agent_v2", "code_mode_host"])
        self.expected = {
            "test": "circulusd-isolated", "nonce": self.specification["nonce"],
            "sum": 87, "cwd": "/workspace", "host_visible": False,
            "agents_visible": False, "inherited_env_visible": False,
        }

    def auth(self, **changes):
        value = {
            "auth_mode": "chatgpt",
            "tokens": {"access_token": "synthetic-access-token", "refresh_token": "synthetic-refresh-token", "id_token": "synthetic-id-token", "account_id": "synthetic-account-id"},
            "last_refresh": "2026-01-01T00:00:00Z",
            "OPENAI_API_KEY": "synthetic-api-key-must-not-copy",
            "unrelated": {"secret": "synthetic-unrelated-must-not-copy"},
        }
        value.update(changes)
        return value

    def prepare(self, offline=False, auth=None):
        if auth is not None:
            runner.private_json(self.source_home / "auth.json", auth)
        def which(name):
            return "/usr/bin/bwrap" if name == "bwrap" else str(self.binary) if name == "codex" else None
        with patch.object(runner, "RUN_PARENT", self.root / "prepared"), patch.object(runner.shutil, "which", side_effect=which), patch.object(runner.subprocess, "run", return_value=types.SimpleNamespace(stdout="synthetic test version\n")), patch.dict(os.environ, {"CODEX_HOME": str(self.source_home)}, clear=True):
            return runner.prepare(offline)

    def sandbox_prefix(self, online=False):
        arguments = runner.sandbox_arguments(self.run, ["/opt/codex", "exec", "synthetic"], online)
        return arguments[:arguments.index("--")]

    def worker(self, responses, online=False):
        self.specification["offlineOnly"] = not online
        runner.private_json(self.run / "run.json", self.specification)
        def invoke(*args, **kwargs):
            runner.private_text(self.run / "last-child.stderr", "")
            result = responses.pop(0)
            return result, 0.01
        with patch.object(runner, "invoke", side_effect=invoke) as mocked, contextlib.redirect_stdout(io.StringIO()):
            result = runner.worker(self.run)
        return result, mocked

    def offline_responses(self):
        return [json.dumps(self.inspection), "[]", self.features, "[]"]

    def online_responses(self, command="python3 /workspace/probe.py", exit_code=0):
        runner.private_json(self.run / "workspace" / "response.json", self.expected)
        events = [
            {"type": "item.completed", "item": {"type": "command_execution", "status": "completed", "command": command, "exit_code": exit_code, "aggregated_output": json.dumps(self.expected)}},
            {"type": "turn.completed", "usage": {"input_tokens": 1, "output_tokens": 1}},
        ]
        return self.offline_responses() + ["Logged in using ChatGPT\n", "\n".join(json.dumps(event) for event in events)]

    def assert_auth_removed(self):
        self.assertFalse((self.run / "home" / ".codex" / "auth.json").exists())
        self.assertEqual(list((self.run / "home").iterdir()), [])

    def test_mount_allowlist_excludes_host_home_repository_and_configuration(self):
        prefix = self.sandbox_prefix()
        mounts = [(prefix[i], prefix[i + 1], prefix[i + 2]) for i in range(len(prefix)) if prefix[i] in ["--bind", "--ro-bind", "--dev-bind"]]
        self.assertEqual({target for kind, _, target in mounts if kind == "--bind"}, {"/home/test", "/workspace"})
        allowed = {"/usr", "/opt/codex", "/opt/codex-code-mode-host", "/home/test", "/workspace", "/etc/passwd", "/etc/group", "/etc/resolv.conf", "/etc/nsswitch.conf", "/etc/ssl/certs"}
        self.assertEqual({target for _, _, target in mounts} - allowed, set())
        self.assertIn(("--ro-bind", str(self.helper), "/opt/codex-code-mode-host"), mounts)
        self.assertNotIn("/", {target for _, _, target in mounts})
        self.assertNotIn(str(runner.REPOSITORY), {source for _, source, _ in mounts})
        self.assertIn("--unshare-all", prefix)
        self.assertIn("--die-with-parent", prefix)
        self.assertEqual(prefix[prefix.index("--cap-drop") + 1], "ALL")

    def test_environment_is_cleared_and_only_explicit_virtual_paths_are_set(self):
        with patch.dict(os.environ, {"OPENAI_API_KEY": "synthetic-unrelated", "CODEX_HOME": "/host-secret", "CIRCULUSD_ISOLATION_CANARY": "synthetic-parent"}):
            prefix = self.sandbox_prefix()
        assignments = {prefix[i + 1]: prefix[i + 2] for i in range(len(prefix)) if prefix[i] == "--setenv"}
        self.assertLess(prefix.index("--clearenv"), prefix.index("--setenv"))
        self.assertEqual(set(assignments), {"HOME", "CODEX_HOME", "PATH", "LANG", "TERM", "XDG_CONFIG_HOME", "XDG_CACHE_HOME", "XDG_DATA_HOME"})
        self.assertEqual(assignments["HOME"], "/home/test")
        self.assertEqual(assignments["CODEX_HOME"], "/home/test/.codex")
        self.assertNotIn("synthetic-unrelated", prefix)

    def test_network_is_shared_only_for_explicit_online_invocation(self):
        self.assertNotIn("--share-net", self.sandbox_prefix())
        self.assertIn("--share-net", self.sandbox_prefix(online=True))

    def test_config_disables_instruction_integrations_and_shell_inheritance(self):
        config = tomllib.loads("\n".join(runner.CONFIG))
        self.assertEqual(config["project_doc_max_bytes"], 0)
        self.assertEqual(config["project_doc_fallback_filenames"], [])
        self.assertEqual(config["developer_instructions"], "")
        self.assertFalse(config["skills"]["bundled"]["enabled"])
        self.assertFalse(config["skills"]["include_instructions"])
        for name in ["apps", "plugins", "hooks", "multi_agent", "multi_agent_v2"]:
            self.assertIs(config["features"][name], False)
        self.assertEqual(config["shell_environment_policy"]["inherit"], "none")
        self.assertFalse(config["shell_environment_policy"]["experimental_use_profile"])
        self.assertEqual(config["forced_login_method"], "chatgpt")
        self.assertEqual(config["web_search"], "disabled")

    def test_offline_prepare_does_not_need_or_copy_authentication(self):
        run = self.prepare(offline=True)
        self.assertFalse((run / "home" / ".codex" / "auth.json").exists())
        self.assertFalse((run / "home" / ".codex" / "config.toml").exists())
        self.assertTrue(json.loads((run / "run.json").read_text())["offlineOnly"])

    def test_online_prepare_copies_only_subscription_fields_privately(self):
        source = self.auth()
        run = self.prepare(auth=source)
        copied_path = run / "home" / ".codex" / "auth.json"
        copied = json.loads(copied_path.read_text())
        self.assertEqual(set(copied), {"auth_mode", "tokens", "last_refresh"})
        self.assertEqual(copied["tokens"], source["tokens"])
        self.assertNotIn(source["OPENAI_API_KEY"], copied_path.read_text())
        self.assertEqual(json.loads((self.source_home / "auth.json").read_text()), source)
        self.assertEqual(stat.S_IMODE(copied_path.stat().st_mode), 0o600)
        self.assertEqual(stat.S_IMODE((run / "home").stat().st_mode), 0o700)

    def test_nested_authentication_metadata_uses_an_allowlist(self):
        source = self.auth()
        source["tokens"]["unrelated_key"] = "synthetic-key-must-not-copy"
        run = self.prepare(auth=source)
        copied = json.loads((run / "home" / ".codex" / "auth.json").read_text())
        self.assertEqual(set(copied["tokens"]), {"access_token", "refresh_token", "id_token", "account_id"})
        self.assertNotIn(source["tokens"]["unrelated_key"], json.dumps(copied))

    def test_oversized_authentication_fails_without_leaving_a_private_copy(self):
        source = self.auth()
        source["unrelated"] = "x" * (256 * 1024)
        with self.assertRaisesRegex(RuntimeError, "size limit"):
            self.prepare(auth=source)
        self.assertEqual(list((self.root / "prepared").glob("run-*")), [])

    def test_authentication_rejects_api_mode_and_invalid_bearer_shape(self):
        for auth in [self.auth(auth_mode="apikey"), self.auth(tokens=[]), self.auth(tokens={}), self.auth(tokens={"access_token": 123}), self.auth(tokens={"access_token": "   "})]:
            with self.subTest(auth_mode=auth.get("auth_mode"), tokens_type=type(auth.get("tokens")).__name__):
                with self.assertRaises(RuntimeError):
                    self.prepare(auth=auth)

    def test_prepare_rejects_symlinked_authentication(self):
        outside = self.root / "outside-auth.json"
        runner.private_json(outside, self.auth())
        (self.source_home / "auth.json").symlink_to(outside)
        with self.assertRaises((RuntimeError, OSError)):
            self.prepare()

    def test_prepare_requires_execution_helper_before_model_access(self):
        self.helper.unlink()
        with self.assertRaises(RuntimeError):
            self.prepare(offline=True)

    def test_offline_worker_finishes_and_removes_temporary_home(self):
        runner.private_json(self.run / "home" / ".codex" / "auth.json", self.auth())
        result, invoked = self.worker(self.offline_responses())
        self.assertEqual(result, 0)
        self.assertEqual(invoked.call_count, 4)
        self.assertTrue(all(not call.kwargs.get("online", False) for call in invoked.call_args_list))
        self.assert_auth_removed()
        report = json.loads((self.run / "report.json").read_text())
        self.assertEqual(report["modelTest"]["status"], "NOT_RUN_OFFLINE")
        self.assertFalse(report["fullPlatformQualified"])
        self.assertEqual(json.loads((self.run / "status.json").read_text())["state"], "completed")

    def test_environment_path_privilege_and_namespace_leaks_fail_closed(self):
        mutations = [
            ("environmentKeys", self.inspection["environmentKeys"] + ["OPENAI_API_KEY"]),
            ("visiblePaths", {"/home/seorii": True}),
            ("capabilities", "0000000000000001"),
            ("noNewPrivileges", "0"),
            ("namespaces", self.specification["hostNamespaceIDs"]),
        ]
        for key, value in mutations:
            with self.subTest(key=key):
                (self.run / "home" / ".codex").mkdir(parents=True, exist_ok=True)
                runner.private_json(self.run / "home" / ".codex" / "auth.json", self.auth())
                inspection = dict(self.inspection, **{key: value})
                result, invoked = self.worker([json.dumps(inspection)])
                self.assertEqual(result, 1)
                self.assertEqual(invoked.call_count, 1)
                self.assert_auth_removed()

    def test_mcp_or_enabled_integration_stops_before_model_access(self):
        for answers in [self.offline_responses()[:1] + ['[{"name":"host-mcp"}]'], self.offline_responses()[:2] + [self.features.replace("apps stable false", "apps stable true")]]:
            with self.subTest(stage=len(answers)):
                (self.run / "home" / ".codex").mkdir(parents=True, exist_ok=True)
                result, invoked = self.worker(answers, online=True)
                self.assertEqual(result, 1)
                self.assertTrue(all(not call.kwargs.get("online", False) for call in invoked.call_args_list))

    def test_inherited_prompt_marker_stops_before_model_access(self):
        answers = self.offline_responses()
        answers[-1] = json.dumps([{"role": "developer", "content": [{"type": "input_text", "text": "CIRCULUSD_HOST_INSTRUCTIONS_MUST_NOT_APPEAR"}]}])
        result, invoked = self.worker(answers, online=True)
        self.assertEqual(result, 1)
        self.assertEqual(invoked.call_count, 4)
        self.assertFalse((self.run / "events.jsonl").exists())

    def test_changed_execution_helper_fails_before_any_sandbox_call(self):
        self.helper.write_bytes(b"changed helper")
        with patch.object(runner, "invoke") as invoked, contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(runner.worker(self.run), 1)
        invoked.assert_not_called()
        self.assert_auth_removed()

    def test_live_success_requires_real_probe_command_and_exact_result(self):
        result, invoked = self.worker(self.online_responses(), online=True)
        self.assertEqual(result, 0)
        command = invoked.call_args_list[-1].args[1]
        for flag in ["--no-daemon", "exec", "--strict-config", "--ignore-user-config", "--ignore-rules", "--ephemeral", "--skip-git-repo-check"]:
            self.assertIn(flag, command)
        self.assertEqual(command[command.index("--sandbox") + 1], "read-only")
        self.assertEqual(invoked.call_args_list[-1].kwargs["online"], True)
        self.assert_auth_removed()

    def test_model_cannot_pass_by_running_other_command_with_forged_output(self):
        result, _ = self.worker(self.online_responses(command="cat /home/test/.codex/auth.json"), online=True)
        self.assertEqual(result, 1)
        self.assertFalse((self.run / "events.jsonl").exists())
        self.assert_auth_removed()

    def test_failed_probe_exit_cannot_be_reported_as_success(self):
        result, _ = self.worker(self.online_responses(exit_code=17), online=True)
        self.assertEqual(result, 1)
        self.assertFalse((self.run / "events.jsonl").exists())

    def test_authentication_output_is_rejected_before_log_write(self):
        auth = self.auth()
        runner.private_json(self.run / "home" / ".codex" / "auth.json", auth)
        process = Mock(pid=12345, returncode=0)
        process.communicate.return_value = ("output " + auth["tokens"]["access_token"], "")
        with patch.object(runner.subprocess, "Popen", return_value=process):
            with self.assertRaisesRegex(RuntimeError, "authentication"):
                runner.invoke(self.run, ["/opt/codex", "exec"])
        self.assertFalse((self.run / "last-child.stderr").exists())

    def test_refreshed_authentication_is_also_rejected_before_log_write(self):
        auth_path = self.run / "home" / ".codex" / "auth.json"
        runner.private_json(auth_path, self.auth())
        refreshed = self.auth(tokens={"access_token": "synthetic-refreshed-access-token"})
        process = Mock(pid=12345, returncode=0)
        def communicate(**kwargs):
            runner.private_json(auth_path, refreshed)
            return "", "unexpected " + refreshed["tokens"]["access_token"]
        process.communicate.side_effect = communicate
        with patch.object(runner.subprocess, "Popen", return_value=process):
            with self.assertRaisesRegex(RuntimeError, "authentication"):
                runner.invoke(self.run, ["/opt/codex", "exec"])
        self.assertFalse((self.run / "last-child.stderr").exists())

    def test_timeout_kills_and_reaps_isolated_process_group(self):
        process = Mock(pid=12345)
        process.communicate.side_effect = [subprocess.TimeoutExpired("synthetic", 1), ("", "")]
        with patch.object(runner.subprocess, "Popen", return_value=process), patch.object(runner.os, "killpg") as kill:
            with self.assertRaisesRegex(RuntimeError, "time limit"):
                runner.invoke(self.run, ["/opt/codex", "exec"], timeout=1)
        kill.assert_called_once_with(12345, signal.SIGKILL)
        self.assertEqual(process.communicate.call_count, 2)

    def test_fast_worker_completion_is_not_overwritten_by_launcher(self):
        def launch(*args, **kwargs):
            runner.private_json(self.run / "status.json", {"state": "completed", "pid": 4242, "exitCode": 0})
            return types.SimpleNamespace(pid=4242)
        with patch.object(runner, "prepare", return_value=self.run), patch.object(Path, "home", return_value=self.root), patch.object(runner.subprocess, "Popen", side_effect=launch), patch.object(runner.sys, "argv", [str(SCRIPT), "--launch", "--offline"]), contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(runner.main(), 0)
        self.assertEqual(json.loads((self.run / "status.json").read_text())["state"], "completed")

    def test_failed_worker_launch_removes_copied_authentication(self):
        runner.private_json(self.run / "home" / ".codex" / "auth.json", self.auth())
        with patch.object(runner, "prepare", return_value=self.run), patch.object(Path, "home", return_value=self.root), patch.object(runner.subprocess, "Popen", side_effect=OSError("synthetic launch failure")), patch.object(runner.sys, "argv", [str(SCRIPT), "--launch"]), contextlib.redirect_stdout(io.StringIO()):
            try:
                runner.main()
            except (OSError, RuntimeError):
                pass
        self.assertFalse((self.run / "home" / ".codex" / "auth.json").exists())
        self.assertNotEqual(json.loads((self.run / "status.json").read_text())["state"], "running")


if __name__ == "__main__":
    unittest.main()
