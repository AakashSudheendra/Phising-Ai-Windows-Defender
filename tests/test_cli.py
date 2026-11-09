from contextlib import redirect_stdout
from io import StringIO
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import phishguard

PROJECT_ROOT = Path(__file__).resolve().parents[1]


class CliTests(unittest.TestCase):
    def run_cli(self, *args):
        return subprocess.run(
            [sys.executable, str(PROJECT_ROOT / "phishguard.py"), *args],
            cwd=PROJECT_ROOT,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            check=False,
        )

    def test_redirect_error_is_visible_when_no_hop_completed(self):
        chain = {
            "final_url": "https://example.com",
            "hops": 0,
            "chain": ["https://example.com"],
            "crossed_domain": False,
            "error": "mocked connection failure",
        }
        output = StringIO()

        with patch("phishguard.follow_redirects", return_value=chain):
            with redirect_stdout(output):
                phishguard.analyze_url(
                    "https://example.com",
                    plain=True,
                    follow_redirects_hops=3,
                )

        self.assertIn(
            "redirect trace stopped early - mocked connection failure",
            output.getvalue(),
        )

    def test_check_domain_age_prints_unknown_when_lookup_fails(self):
        output = StringIO()

        with patch("phishguard.domain_age_features", return_value={}):
            with redirect_stdout(output):
                phishguard.analyze_url(
                    "https://example.com",
                    plain=True,
                    check_domain_age=True,
                )

        self.assertIn("registration age unknown", output.getvalue())

    def test_check_domain_age_prints_recency_when_known(self):
        output = StringIO()

        with patch(
            "phishguard.domain_age_features",
            return_value={"domain_newer_than_30d": 1, "domain_newer_than_90d": 1},
        ):
            with redirect_stdout(output):
                result = phishguard.analyze_url(
                    "https://example.com",
                    plain=True,
                    check_domain_age=True,
                )

        self.assertIn("registered under 30 days ago", output.getvalue())
        self.assertEqual(result["features"]["domain_newer_than_30d"], 1)

    def test_check_domain_age_is_off_by_default(self):
        with patch("phishguard.domain_age_features") as mocked:
            with redirect_stdout(StringIO()):
                result = phishguard.analyze_url("https://example.com", plain=True)

        mocked.assert_not_called()
        self.assertNotIn("domain_newer_than_30d", result["features"])

    def assert_plain_output(self, output):
        self.assertTrue(output.isascii(), output)
        self.assertNotIn("\033[", output)
        self.assertIn("-" * 60, output)

    def assert_help_contains(self, args, expected_terms):
        result = self.run_cli(*args)

        self.assertEqual(result.returncode, 0, result.stderr)
        for term in expected_terms:
            self.assertIn(term, result.stdout)

    def test_root_help_lists_available_commands(self):
        self.assert_help_contains(
            ["--help"],
            [
                "usage:",
                "url",
                "email",
                "batch",
            ],
        )

    def test_url_help_lists_input_and_output_options(self):
        self.assert_help_contains(
            ["url", "--help"],
            [
                "target",
                "--verbose",
                "--output",
                "--format",
                "--plain",
            ],
        )

    def test_email_help_lists_authentication_and_output_options(self):
        self.assert_help_contains(
            ["email", "--help"],
            [
                "--subject",
                "--body",
                "--authentication-results",
                "--verbose",
                "--output",
                "--format",
                "--plain",
            ],
        )

    def test_eml_help_lists_trusted_authserv_id(self):
        self.assert_help_contains(
            ["eml", "--help"],
            [
                "file",
                "--trusted-authserv-id",
                "--verbose",
                "--output",
                "--format",
                "--plain",
            ],
        )

    def test_eml_rejects_unsafe_trusted_authserv_id(self):
        result = self.run_cli(
            "eml",
            "message.eml",
            "--trusted-authserv-id",
            "mx.example; spf=pass",
        )

        self.assertEqual(result.returncode, 2)
        self.assertIn("trusted authserv-id must contain only", result.stderr)

    def test_batch_help_lists_file_and_output_options(self):
        self.assert_help_contains(
            ["batch", "--help"],
            [
                "file",
                "--verbose",
                "--output",
                "--format",
                "--plain",
            ],
        )

    def test_url_command_handles_limited_console_encoding(self):
        environment = os.environ.copy()
        environment["PYTHONIOENCODING"] = "cp1252"

        result = subprocess.run(
            [
                sys.executable,
                "phishguard.py",
                "url",
                "https://www.google.com",
            ],
            capture_output=True,
            text=True,
            encoding="cp1252",
            env=environment,
            check=False,
        )

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("SAFE", result.stdout)

    def test_plain_url_command_uses_ascii_output(self):
        result = subprocess.run(
            [
                sys.executable,
                "phishguard.py",
                "url",
                "https://www.google.com",
                "--verbose",
                "--plain",
            ],
            capture_output=True,
            text=True,
            encoding="utf-8",
            check=False,
        )

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assert_plain_output(result.stdout)
        self.assertIn("Feature breakdown:", result.stdout)
        self.assertIn("#", result.stdout)

    def test_verbose_marker_reflects_weight_sign_not_just_value(self):
        # domain_length has a negative weight (a longer domain is
        # slightly *safer*), so it must never get the risk marker even
        # though its value is > 0 for any real hostname -- previously
        # marked via `value > 0`, which mismarked it. has_ip_address has
        # a strong positive weight and should still be marked.
        result = subprocess.run(
            [
                sys.executable,
                "phishguard.py",
                "url",
                "http://192.0.2.10/secure-login/verify",
                "--verbose",
                "--plain",
            ],
            capture_output=True,
            text=True,
            encoding="utf-8",
            check=False,
        )

        self.assertEqual(result.returncode, 0, result.stderr)
        lines = {
            line.split(":", 1)[0].strip(): line
            for line in result.stdout.splitlines()
            if ":" in line
        }
        self.assertIn("domain_length", lines["domain_length"])
        self.assertNotIn("*", lines["domain_length"])
        self.assertIn("*", lines["has_ip_address"])

    def test_plain_email_command_uses_ascii_output(self):
        result = subprocess.run(
            [
                sys.executable,
                "phishguard.py",
                "email",
                "--subject",
                "Meeting reminder",
                "--body",
                "Our meeting is scheduled for tomorrow.",
                "--plain",
            ],
            capture_output=True,
            text=True,
            encoding="utf-8",
            check=False,
        )

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assert_plain_output(result.stdout)
        self.assertIn("Subject : Meeting reminder", result.stdout)

    def test_email_command_accepts_authentication_results(self):
        result = subprocess.run(
            [
                sys.executable,
                "phishguard.py",
                "email",
                "--subject",
                "Security alert",
                "--body",
                "Click here to verify your account.",
                "--authentication-results",
                "mx.example; spf=fail; dkim=fail; dmarc=fail",
                "--verbose",
                "--plain",
            ],
            capture_output=True,
            text=True,
            encoding="utf-8",
            check=False,
        )

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("dmarc_result              : fail", result.stdout)

    def test_no_unicode_batch_command_uses_ascii_output(self):
        result = subprocess.run(
            [
                sys.executable,
                "phishguard.py",
                "batch",
                "data/urls.txt",
                "--no-unicode",
            ],
            capture_output=True,
            text=True,
            encoding="utf-8",
            check=False,
        )

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assert_plain_output(result.stdout)
        self.assertIn("Scanning", result.stdout)
        self.assertIn("Summary:", result.stdout)

    def test_plain_mode_keeps_json_report_unchanged(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            output_path = Path(temp_dir) / "result.json"
            result = subprocess.run(
                [
                    sys.executable,
                    "phishguard.py",
                    "url",
                    "https://www.google.com",
                    "--plain",
                    "--output",
                    str(output_path),
                ],
                capture_output=True,
                text=True,
                encoding="utf-8",
                check=False,
            )

            self.assertEqual(result.returncode, 0, result.stderr)
            payload = json.loads(output_path.read_text(encoding="utf-8"))
            self.assertEqual(payload["url"], "https://www.google.com")
            self.assertEqual(payload["verdict"], "SAFE")
            self.assertIsInstance(payload["probability"], float)
            self.assertIsInstance(payload["features"], dict)

    def test_plain_mode_does_not_persist_between_in_process_calls(self):
        plain_output = StringIO()
        with redirect_stdout(plain_output):
            phishguard.analyze_url("https://www.google.com", plain=True)

        decorated_output = StringIO()
        with redirect_stdout(decorated_output):
            phishguard.analyze_url("https://www.google.com")

        plain_text = plain_output.getvalue()
        decorated_text = decorated_output.getvalue()

        self.assert_plain_output(plain_text)
        self.assertIn("\033[", decorated_text)
        self.assertIn(phishguard.separator(), decorated_text)

    def test_batch_command_writes_sarif_findings(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            output_path = Path(temp_dir) / "results.sarif"
            result = subprocess.run(
                [
                    sys.executable,
                    "phishguard.py",
                    "batch",
                    "data/urls.txt",
                    "--format",
                    "sarif",
                    "--output",
                    str(output_path),
                ],
                capture_output=True,
                text=True,
                check=False,
            )

            self.assertEqual(result.returncode, 0, result.stderr)
            payload = json.loads(output_path.read_text(encoding="utf-8"))
            self.assertEqual(payload["version"], "2.1.0")
            self.assertTrue(payload["runs"][0]["results"])
            self.assertTrue(
                all(
                    finding["level"] in {"warning", "error"}
                    for finding in payload["runs"][0]["results"]
                )
            )

    def test_sarif_format_requires_output_path(self):
        result = subprocess.run(
            [
                sys.executable,
                "phishguard.py",
                "url",
                "https://example.com",
                "--format",
                "sarif",
            ],
            capture_output=True,
            text=True,
            check=False,
        )

        self.assertEqual(result.returncode, 2)
        self.assertIn("--format sarif requires --output", result.stderr)


if __name__ == "__main__":
    unittest.main()
