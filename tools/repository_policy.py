"""Reject repository changes that need explicit security review."""

from __future__ import annotations

import ast
import re
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
MAX_FILE_BYTES = 1_000_000
BLOCKED_SUFFIXES = {
    ".app",
    ".bat",
    ".bin",
    ".cmd",
    ".com",
    ".dll",
    ".dmg",
    ".exe",
    ".jar",
    ".msi",
    ".ps1",
    ".scr",
    ".so",
}
ALLOWED_BINARY_PATHS = {
    "browser-extension/chromium/icons/icon16.png",
    "browser-extension/chromium/icons/icon32.png",
    "browser-extension/chromium/icons/icon48.png",
    "browser-extension/chromium/icons/icon128.png",
}
PINNED_ACTION = re.compile(r"^[^@\s]+@[0-9a-fA-F]{40}(?:\s+#.*)?$")
RISKY_WORKFLOW_PATTERNS = {
    "pull_request_target": re.compile(r"^\s*pull_request_target\s*:", re.MULTILINE),
    "download piped to shell": re.compile(
        r"(?:curl|wget)\b[^\n|]*\|\s*(?:ba)?sh\b", re.IGNORECASE
    ),
    "PowerShell expression execution": re.compile(
        r"\b(?:Invoke-Expression|iex)\b", re.IGNORECASE
    ),
}


def tracked_files() -> list[tuple[str, Path]]:
    output = subprocess.check_output(
        ["git", "ls-files", "-s", "-z"], cwd=ROOT
    ).decode("utf-8")
    entries = []
    for record in output.split("\0"):
        if not record:
            continue
        metadata, name = record.split("\t", 1)
        mode = metadata.split(" ", 1)[0]
        entries.append((mode, ROOT / name))
    return entries


def check_files(entries: list[tuple[str, Path]]) -> list[str]:
    errors = []
    for mode, path in entries:
        try:
            relative = path.relative_to(ROOT).as_posix()
        except ValueError:
            relative = path.name
        if mode == "120000":
            errors.append(f"{relative}: symbolic links are not allowed")
        if mode.endswith("755"):
            errors.append(f"{relative}: executable file mode requires manual approval")
        if path.suffix.lower() in BLOCKED_SUFFIXES:
            errors.append(f"{relative}: blocked executable or binary file type")
        if not path.is_file():
            continue
        data = path.read_bytes()
        if len(data) > MAX_FILE_BYTES:
            errors.append(f"{relative}: file exceeds {MAX_FILE_BYTES} bytes")
        if b"\0" in data and relative not in ALLOWED_BINARY_PATHS:
            errors.append(f"{relative}: NUL byte indicates binary content")
    return errors


def check_dependencies() -> list[str]:
    errors = []
    metadata = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
    project_section = metadata.split("[project]", 1)[1].split("\n[", 1)[0]
    match = re.search(r"(?ms)^dependencies\s*=\s*(\[.*?\])", project_section)
    dependencies = ast.literal_eval(match.group(1)) if match else None
    if dependencies is None:
        errors.append("pyproject.toml: project dependencies declaration is required")
    if dependencies:
        errors.append("pyproject.toml: runtime dependencies require maintainer review")

    requirements = ROOT / "requirements.txt"
    if requirements.exists():
        active = [
            line
            for line in requirements.read_text(encoding="utf-8").splitlines()
            if line.strip() and not line.lstrip().startswith("#")
        ]
        if active:
            errors.append("requirements.txt: active dependencies require maintainer review")
    return errors


def check_workflows() -> list[str]:
    errors = []
    workflow_dir = ROOT / ".github" / "workflows"
    for path in sorted(workflow_dir.glob("*.y*ml")):
        relative = path.relative_to(ROOT).as_posix()
        text = path.read_text(encoding="utf-8")
        for label, pattern in RISKY_WORKFLOW_PATTERNS.items():
            if pattern.search(text):
                errors.append(f"{relative}: blocked workflow pattern ({label})")
        for line_number, line in enumerate(text.splitlines(), 1):
            stripped = line.strip()
            if not stripped.startswith("uses:"):
                continue
            reference = stripped.removeprefix("uses:").strip()
            if reference.startswith("./"):
                continue
            if not PINNED_ACTION.fullmatch(reference):
                errors.append(
                    f"{relative}:{line_number}: action must use a full commit SHA"
                )
    return errors


def main() -> int:
    errors = check_files(tracked_files())
    errors.extend(check_dependencies())
    errors.extend(check_workflows())
    if errors:
        print("Repository security policy failed:", file=sys.stderr)
        for error in errors:
            print(f"- {error}", file=sys.stderr)
        return 1
    print("Repository security policy passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
