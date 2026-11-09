"""Translate PhishGuard SARIF findings into a GitHub Action exit status."""

import json
import sys
from pathlib import Path


def sarif_exit_status(path: Path) -> int:
    """Return 1 for phishing findings, 0 for none, and 2 for invalid output."""
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        print(f"::error::Failed to read SARIF output: {exc}")
        return 2

    phishing_found = any(
        result.get("level") == "error"
        for run in data.get("runs", [])
        for result in run.get("results", [])
    )
    return 1 if phishing_found else 0


def main() -> int:
    """Read the SARIF path from argv and return its action exit status."""
    if len(sys.argv) != 2:
        print("::error::Expected one SARIF output path.")
        return 2
    return sarif_exit_status(Path(sys.argv[1]))


if __name__ == "__main__":
    raise SystemExit(main())
