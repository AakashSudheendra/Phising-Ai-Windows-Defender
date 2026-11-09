import json
import sys
import tempfile
import unittest
from pathlib import Path

TOOLS_DIR = Path(__file__).resolve().parents[1] / "tools"
sys.path.insert(0, str(TOOLS_DIR))

from action_result import sarif_exit_status


class ActionResultTests(unittest.TestCase):
    def write_sarif(self, levels):
        temp_dir = tempfile.TemporaryDirectory()
        self.addCleanup(temp_dir.cleanup)
        path = Path(temp_dir.name) / "results.sarif"
        path.write_text(
            json.dumps(
                {
                    "version": "2.1.0",
                    "runs": [
                        {
                            "results": [
                                {"level": level}
                                for level in levels
                            ]
                        }
                    ],
                }
            ),
            encoding="utf-8",
        )
        return path

    def test_error_finding_fails_action(self):
        self.assertEqual(sarif_exit_status(self.write_sarif(["warning", "error"])), 1)

    def test_non_error_findings_pass_action(self):
        self.assertEqual(sarif_exit_status(self.write_sarif(["note", "warning"])), 0)

    def test_missing_output_reports_invalid_status(self):
        self.assertEqual(sarif_exit_status(Path("missing-results.sarif")), 2)


if __name__ == "__main__":
    unittest.main()
