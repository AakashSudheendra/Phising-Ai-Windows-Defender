"""Build a public-safe benchmark slice from the licensed URL-Phish dataset."""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
from pathlib import Path
from urllib.parse import urlsplit, urlunsplit

DATASET_SHA256 = (
    "d68b3cd0648dcf9c775347416ad1a8995e8a025921fbe3871ca6158d4db3c3a1"
)
EXPECTED_LABEL_COUNTS = {"0": 100_000, "1": 16_600}
SELECTED_ROWS = {
    2: ("public-legitimate-001", "legitimate"),
    3: ("public-legitimate-002", "legitimate"),
    4: ("public-legitimate-003", "legitimate"),
    5: ("public-legitimate-004", "legitimate"),
    6: ("public-legitimate-005", "legitimate"),
    100_002: ("public-phishing-001", "phishing"),
    100_003: ("public-phishing-002", "phishing"),
    100_004: ("public-phishing-003", "phishing"),
    100_005: ("public-phishing-004", "phishing"),
    100_006: ("public-phishing-005", "phishing"),
}
SOURCE = {
    "source_dataset": "URL-Phish",
    "source_doi": "10.17632/65z9twcx3r.1",
    "source_version": "1",
    "source_license": "CC BY 4.0",
    "source_authors": "Linh Dam Minh and Hung Tran Cong",
    "source_dataset_sha256": DATASET_SHA256,
    "retrieved_on": "2026-06-12",
}


class BuildError(ValueError):
    """Raised when the source dataset does not match the documented input."""


def file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def sanitize_phishing_url(url: str) -> str:
    """Replace the source hostname suffix with the reserved .example TLD."""
    parsed = urlsplit(url)
    if not parsed.hostname:
        raise BuildError("selected phishing URL has no hostname")

    labels = parsed.hostname.split(".")
    safe_host = ".".join([*labels[:-1], "example"])
    if parsed.port:
        safe_host = f"{safe_host}:{parsed.port}"
    return urlunsplit(
        (parsed.scheme, safe_host, parsed.path, parsed.query, "")
    )


def build_records(source_path: Path) -> list[dict[str, str | int]]:
    if file_sha256(source_path) != DATASET_SHA256:
        raise BuildError("source SHA-256 does not match URL-Phish v1")

    selected = {}
    label_counts = {"0": 0, "1": 0}
    with source_path.open("r", encoding="utf-8-sig", newline="") as source:
        reader = csv.DictReader(source)
        if (
            not reader.fieldnames
            or "url" not in reader.fieldnames
            or "label" not in reader.fieldnames
        ):
            raise BuildError("source CSV must contain url and label columns")
        for physical_row, row in enumerate(reader, start=2):
            label = row["label"]
            if label not in label_counts:
                raise BuildError(
                    f"unexpected label at source row {physical_row}"
                )
            label_counts[label] += 1
            if physical_row in SELECTED_ROWS:
                selected[physical_row] = row["url"]

    if label_counts != EXPECTED_LABEL_COUNTS:
        raise BuildError(f"unexpected label counts: {label_counts}")
    if set(selected) != set(SELECTED_ROWS):
        raise BuildError("one or more selected source rows are missing")

    records = []
    for physical_row, (sample_id, label) in SELECTED_ROWS.items():
        source_url = selected[physical_row]
        safe_url = (
            source_url
            if label == "legitimate"
            else sanitize_phishing_url(source_url)
        )
        rationale = (
            "Public institutional URL retained for "
            "legitimate-regression coverage."
            if label == "legitimate"
            else "Dataset phishing sample with its hostname "
            "rewritten to .example."
        )
        records.append(
            {
                "id": sample_id,
                "label": label,
                "url": safe_url,
                "rationale": rationale,
                "provenance": "URL-Phish v1 public-safe deterministic slice",
                **SOURCE,
                "source_row": physical_row,
                "source_url_sha256": hashlib.sha256(
                    source_url.encode("utf-8")
                ).hexdigest(),
                "sanitization": (
                    "none"
                    if label == "legitimate"
                    else "hostname final label replaced with reserved "
                    ".example; fragment removed"
                ),
            }
        )
    return records


def write_records(
    records: list[dict[str, str | int]], output_path: Path
) -> None:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    content = "".join(
        json.dumps(record, ensure_ascii=True, separators=(",", ":")) + "\n"
        for record in records
    )
    output_path.write_text(content, encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Build the public-safe URL-Phish benchmark slice."
    )
    parser.add_argument(
        "source", type=Path, help="Downloaded URL-Phish v1 CSV"
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("data/public_benchmark_urls.jsonl"),
    )
    args = parser.parse_args()

    try:
        write_records(build_records(args.source), args.output)
    except (BuildError, OSError) as exc:
        parser.error(str(exc))
    print(f"Wrote {len(SELECTED_ROWS)} sanitized samples to {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
