"""Exercise reviewed fork validation against real staged/unstaged Git edits."""
import importlib.util
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest


class ReviewedSourceTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory(prefix="circulusd-native-build-validation-")
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        self.source = self.root / "source"
        self.source.mkdir()
        self.package = self.root / "package"
        self.package.mkdir()
        spec = importlib.util.spec_from_file_location("native_build_fixture", Path(__file__).with_name("build.py"))
        self.module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.module)
        self.module.__file__ = str(self.package / "build.py")
        originals = {
            "crates/celld/Cargo.toml": "[package]\nname = 'celld'\n",
            "crates/celld/lib.rs": "pub fn original() {}\n",
            "crates/celld/fleet.rs": "pub fn fleet() {}\n",
            "crates/celld/main.rs": "fn main() {}\n",
            "crates/celld/control_plane.rs": "pub fn control() {}\n",
            "crates/celld/js/harness.js": "async function rpc() { return await invoke(); }\n",
            "crates/celld/js/other.js": "const untouched = true;\n",
            "Cargo.lock": "version = 4\n",
        }
        self.git("init", "--quiet")
        for filename, content in originals.items():
            target = self.source / filename
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(content)
        self.git("add", ".")
        self.git("-c", "user.name=Native validation fixture", "-c", "user.email=fixture@example.invalid", "commit", "--quiet", "-m", "fixture")
        self.module.COMMIT = self.git("rev-parse", "HEAD").decode().strip()
        harness = self.source / "crates/celld/js/harness.js"
        harness.write_text("async function rpc() { const reply = await invoke(); await gate(); return reply; }\n")
        for name, content in {
            "src/lib.rs": "pub fn reviewed_proof() {}\n",
            "Cargo.toml": "[package]\nname = 'fixture-proof'\n\n[workspace]\n",
            "fixtures/state-production-probe-v1alpha1.json": "{}\n",
        }.items():
            file = self.package / name
            file.parent.mkdir(parents=True, exist_ok=True)
            file.write_text(content)
        payload = self.source / "crates/circulusd-native-proof"
        shutil.copytree(self.package, payload)
        (payload / "Cargo.toml").write_text((self.package / "Cargo.toml").read_text().replace("\n[workspace]\n", "\n"))
        (self.package / "celld-native.patch").write_bytes(self.git("diff", self.module.COMMIT))

    def git(self, *arguments):
        return subprocess.check_output(["git", "-C", str(self.source), *arguments], stderr=subprocess.PIPE)

    def test_reviewed_harness_is_pinned_even_when_staged(self):
        expected = self.module.validate_source(self.source)
        self.assertEqual(expected["patchDigest"], self.module.digest(self.package / "celld-native.patch"))
        self.git("add", "crates/celld/js/harness.js")
        self.assertEqual(self.module.validate_source(self.source), expected)

    def test_changed_harness_cannot_use_the_previous_reviewed_patch(self):
        file = self.source / "crates/celld/js/harness.js"
        file.write_text(file.read_text() + "const injected = true;\n")
        with self.assertRaisesRegex(ValueError, "source patch differs"):
            self.module.validate_source(self.source)
        self.git("add", "crates/celld/js/harness.js")
        with self.assertRaisesRegex(ValueError, "source patch differs"):
            self.module.validate_source(self.source)

    def test_other_tracked_javascript_edits_are_rejected_even_when_staged(self):
        file = self.source / "crates/celld/js/other.js"
        file.write_text("const unauthorized = true;\n")
        with self.assertRaisesRegex(ValueError, "unexpected source edits"):
            self.module.validate_source(self.source)
        self.git("add", "crates/celld/js/other.js")
        with self.assertRaisesRegex(ValueError, "unexpected source edits"):
            self.module.validate_source(self.source)

    def test_proof_payload_and_exact_commit_remain_required(self):
        file = self.source / "crates/circulusd-native-proof/src/lib.rs"
        file.write_text("pub fn optimistic_proof() {}\n")
        with self.assertRaisesRegex(ValueError, "payload differs"):
            self.module.validate_source(self.source)
        file.write_text((self.package / "src/lib.rs").read_text())
        self.module.COMMIT = "0" * 40
        with self.assertRaisesRegex(ValueError, "not the pinned source commit"):
            self.module.validate_source(self.source)


if __name__ == "__main__":
    unittest.main()
