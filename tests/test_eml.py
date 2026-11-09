"""Tests for the .eml file parsing command."""

import json
import subprocess
import sys
import tempfile
import textwrap
import unittest
from pathlib import Path


SAFE_EML = textwrap.dedent("""\
    From: colleague@company.com
    To: you@company.com
    Subject: Project update
    Authentication-Results: mx.company.com; spf=pass; dkim=pass; dmarc=pass
    MIME-Version: 1.0
    Content-Type: text/plain; charset=utf-8

    Hi,

    Here is the project update from yesterday's working session.
    Everything is on track. See you at the meeting tomorrow.

    Best,
    Colleague
""")

PHISHING_EML = textwrap.dedent("""\
    From: security@paypa1-secure.xyz
    To: victim@example.com
    Subject: URGENT: Your account has been suspended
    Authentication-Results: mx.example.com; spf=fail; dkim=fail; dmarc=fail
    MIME-Version: 1.0
    Content-Type: text/plain; charset=utf-8

    URGENT ACTION REQUIRED

    Your account has been suspended due to unusual activity.
    Click here immediately to verify your account:
    http://paypa1-secure-login.xyz/account/verify?id=99999

    Failure to act will result in permanent account termination.
""")


def _write_eml(content: str, directory: str) -> str:
    path = Path(directory) / "test.eml"
    path.write_text(content, encoding="utf-8")
    return str(path)


def _run_eml(eml_path: str, *extra_args: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, "phishguard.py", "eml", eml_path, "--plain", *extra_args],
        capture_output=True,
        text=True,
        encoding="utf-8",
        check=False,
    )


class EmlCommandTests(unittest.TestCase):
    def test_embedded_authentication_results_are_ignored_by_default(self):
        with tempfile.TemporaryDirectory() as td:
            eml_path = _write_eml(SAFE_EML, td)
            out_path = Path(td) / "result.json"
            result = _run_eml(eml_path, "--output", str(out_path))
            payload = json.loads(out_path.read_text(encoding="utf-8"))

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(payload["features"]["spf_result"], "unknown")
        self.assertEqual(payload["features"]["dkim_result"], "unknown")
        self.assertEqual(payload["features"]["dmarc_result"], "unknown")
        self.assertFalse(payload["authentication_evidence"]["matched"])
        self.assertIn("embedded Authentication-Results ignored", result.stdout)

    def test_exact_trusted_authserv_id_enables_authentication_evidence(self):
        with tempfile.TemporaryDirectory() as td:
            eml_path = _write_eml(SAFE_EML, td)
            out_path = Path(td) / "result.json"
            result = _run_eml(
                eml_path,
                "--trusted-authserv-id",
                "mx.company.com",
                "--output",
                str(out_path),
            )
            payload = json.loads(out_path.read_text(encoding="utf-8"))

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(payload["features"]["spf_result"], "pass")
        self.assertEqual(payload["features"]["dkim_result"], "pass")
        self.assertEqual(payload["features"]["dmarc_result"], "pass")
        self.assertTrue(payload["authentication_evidence"]["matched"])
        self.assertIn("using trusted Authentication-Results evidence", result.stdout)
        self.assertNotIn("mx.company.com", result.stdout)

    def test_lookalike_authserv_id_is_not_trusted(self):
        lookalike_eml = SAFE_EML.replace(
            "mx.company.com;",
            "mx.company.com.attacker;",
        )
        with tempfile.TemporaryDirectory() as td:
            eml_path = _write_eml(lookalike_eml, td)
            out_path = Path(td) / "result.json"
            result = _run_eml(
                eml_path,
                "--trusted-authserv-id",
                "mx.company.com",
                "--output",
                str(out_path),
            )
            payload = json.loads(out_path.read_text(encoding="utf-8"))

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(payload["features"]["dmarc_result"], "unknown")
        self.assertFalse(payload["authentication_evidence"]["matched"])
        self.assertIn("no exact trusted authserv-id match", result.stdout)
        self.assertNotIn("mx.company.com", result.stdout)

    def test_safe_eml_returns_exit_zero(self):
        with tempfile.TemporaryDirectory() as td:
            path = _write_eml(SAFE_EML, td)
            result = _run_eml(path)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_safe_eml_shows_subject(self):
        with tempfile.TemporaryDirectory() as td:
            path = _write_eml(SAFE_EML, td)
            result = _run_eml(path)
        self.assertIn("Project update", result.stdout)

    def test_safe_eml_shows_safe_verdict(self):
        with tempfile.TemporaryDirectory() as td:
            path = _write_eml(SAFE_EML, td)
            result = _run_eml(path)
        self.assertIn("SAFE", result.stdout)

    def test_phishing_eml_shows_phishing_verdict(self):
        with tempfile.TemporaryDirectory() as td:
            path = _write_eml(PHISHING_EML, td)
            result = _run_eml(path)
        self.assertIn("PHISHING", result.stdout)

    def test_phishing_eml_reports_embedded_url(self):
        with tempfile.TemporaryDirectory() as td:
            path = _write_eml(PHISHING_EML, td)
            result = _run_eml(path)
        self.assertIn("Embedded URLs", result.stdout)

    def test_phishing_eml_shows_source_path(self):
        with tempfile.TemporaryDirectory() as td:
            path = _write_eml(PHISHING_EML, td)
            result = _run_eml(path)
        self.assertIn("Source", result.stdout)

    def test_missing_eml_file_exits_nonzero(self):
        result = _run_eml("/nonexistent/path/file.eml")
        self.assertNotEqual(result.returncode, 0)

    def test_verbose_flag_shows_feature_breakdown(self):
        with tempfile.TemporaryDirectory() as td:
            path = _write_eml(PHISHING_EML, td)
            result = _run_eml(path, "--verbose")
        self.assertIn("Feature breakdown:", result.stdout)

    def test_eml_output_saved_to_json(self):
        with tempfile.TemporaryDirectory() as td:
            eml_path = _write_eml(SAFE_EML, td)
            out_path = Path(td) / "result.json"
            result = _run_eml(eml_path, "--output", str(out_path))
            self.assertEqual(result.returncode, 0, result.stderr)
            payload = json.loads(out_path.read_text(encoding="utf-8"))
            self.assertIn("verdict", payload)
            self.assertIn("probability", payload)


if __name__ == "__main__":
    unittest.main()
