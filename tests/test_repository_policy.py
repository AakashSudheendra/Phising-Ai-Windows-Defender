import tempfile
import unittest
from pathlib import Path

from tools import repository_policy
from tools.generate_public_suffix_js import SOURCE, load_rules, render


class RepositoryPolicyTests(unittest.TestCase):
    def test_generated_public_suffix_bundles_are_identical(self):
        web_bundle = repository_policy.ROOT / "web/public-suffix.js"
        extension_bundle = (
            repository_policy.ROOT / "browser-extension/chromium/public-suffix.js"
        )

        self.assertEqual(web_bundle.read_bytes(), extension_bundle.read_bytes())
        self.assertEqual(web_bundle.read_text(encoding="utf-8"), render(load_rules(SOURCE)))

    def test_current_repository_passes(self):
        self.assertEqual(repository_policy.main(), 0)

    def test_rejects_binary_and_executable_files(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            executable = Path(temp_dir) / "payload.exe"
            executable.write_bytes(b"MZ")
            binary = Path(temp_dir) / "payload.dat"
            binary.write_bytes(b"text\0binary")

            errors = repository_policy.check_files(
                [("100644", executable), ("100644", binary)]
            )

        self.assertTrue(any("blocked executable" in error for error in errors))
        self.assertTrue(any("NUL byte" in error for error in errors))

    def test_allows_reviewed_extension_icon_assets(self):
        icon_path = repository_policy.ROOT / "browser-extension/chromium/icons/icon16.png"

        errors = repository_policy.check_files([("100644", icon_path)])

        self.assertEqual(errors, [])

    def test_rejects_symlinks_and_executable_modes(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "script"
            path.write_text("print('test')", encoding="utf-8")

            errors = repository_policy.check_files(
                [("120000", path), ("100755", path)]
            )

        self.assertTrue(any("symbolic links" in error for error in errors))
        self.assertTrue(any("executable file mode" in error for error in errors))
