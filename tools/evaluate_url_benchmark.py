"""Evaluate the URL detector against a small, public-safe regression fixture."""

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from model import THRESHOLD, classify, score_url


VALID_LABELS = {"legitimate", "phishing"}
REQUIRED_FIELDS = {"id", "label", "url", "rationale", "provenance"}


class BenchmarkError(ValueError):
    """Raised when a benchmark fixture is malformed."""


@dataclass(frozen=True)
class BenchmarkSample:
    id: str
    label: str
    url: str
    rationale: str
    provenance: str


@dataclass(frozen=True)
class Prediction:
    sample: BenchmarkSample
    probability: float
    verdict: str

    @property
    def predicted_label(self) -> str:
        return "phishing" if self.probability >= THRESHOLD else "legitimate"


def load_samples(path: str | Path) -> list[BenchmarkSample]:
    """Load and validate an ordered JSON Lines benchmark fixture."""
    fixture_path = Path(path)
    samples = []
    seen_ids = set()

    try:
        lines = fixture_path.read_text(encoding="utf-8").splitlines()
    except OSError as exc:
        raise BenchmarkError(f"cannot read fixture: {fixture_path}") from exc

    for line_number, line in enumerate(lines, 1):
        if not line.strip():
            continue
        try:
            record = json.loads(line)
        except json.JSONDecodeError as exc:
            raise BenchmarkError(f"line {line_number}: invalid JSON: {exc.msg}") from exc

        if not isinstance(record, dict):
            raise BenchmarkError(f"line {line_number}: sample must be a JSON object")

        missing = sorted(REQUIRED_FIELDS - set(record))
        if missing:
            raise BenchmarkError(
                f"line {line_number}: missing required fields: {', '.join(missing)}"
            )

        for field in REQUIRED_FIELDS:
            if not isinstance(record[field], str) or not record[field].strip():
                raise BenchmarkError(
                    f"line {line_number}: {field} must be a non-empty string"
                )

        if record["label"] not in VALID_LABELS:
            raise BenchmarkError(
                f"line {line_number}: unknown label: {record['label']}"
            )
        if record["id"] in seen_ids:
            raise BenchmarkError(f"line {line_number}: duplicate id: {record['id']}")

        seen_ids.add(record["id"])
        samples.append(BenchmarkSample(**{field: record[field] for field in REQUIRED_FIELDS}))

    if not samples:
        raise BenchmarkError("fixture contains no samples")
    return samples


def evaluate(samples: Iterable[BenchmarkSample]) -> list[Prediction]:
    """Score benchmark samples in their fixture order."""
    predictions = []
    for sample in samples:
        probability, _ = score_url(sample.url)
        predictions.append(
            Prediction(
                sample=sample,
                probability=probability,
                verdict=classify(probability),
            )
        )
    return predictions


def confusion_matrix(predictions: Iterable[Prediction]) -> dict[str, int]:
    """Return binary confusion-matrix counts for phishing detection."""
    counts = {"true_positive": 0, "true_negative": 0, "false_positive": 0, "false_negative": 0}
    for prediction in predictions:
        actual_positive = prediction.sample.label == "phishing"
        predicted_positive = prediction.predicted_label == "phishing"
        if actual_positive and predicted_positive:
            counts["true_positive"] += 1
        elif not actual_positive and not predicted_positive:
            counts["true_negative"] += 1
        elif not actual_positive and predicted_positive:
            counts["false_positive"] += 1
        else:
            counts["false_negative"] += 1
    return counts


def calculate_metrics(counts: dict[str, int]) -> dict[str, float]:
    """Calculate deterministic metrics with explicit zero-division behavior."""
    true_positive = counts["true_positive"]
    true_negative = counts["true_negative"]
    false_positive = counts["false_positive"]
    false_negative = counts["false_negative"]

    precision_denominator = true_positive + false_positive
    recall_denominator = true_positive + false_negative
    false_positive_denominator = false_positive + true_negative

    return {
        "precision": true_positive / precision_denominator if precision_denominator else 0.0,
        "recall": true_positive / recall_denominator if recall_denominator else 0.0,
        "false_positive_rate": (
            false_positive / false_positive_denominator
            if false_positive_denominator
            else 0.0
        ),
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Report reproducible fixture metrics for PhishGuard URL detection."
    )
    parser.add_argument(
        "fixture",
        nargs="?",
        default="data/benchmark_urls.jsonl",
        help="JSON Lines benchmark fixture (default: data/benchmark_urls.jsonl)",
    )
    args = parser.parse_args(argv)

    try:
        samples = load_samples(args.fixture)
    except BenchmarkError as exc:
        print(f"benchmark error: {exc}", file=sys.stderr)
        return 1

    predictions = evaluate(samples)
    counts = confusion_matrix(predictions)
    metrics = calculate_metrics(counts)

    for prediction in predictions:
        print(
            f"{prediction.sample.id}: expected={prediction.sample.label} "
            f"predicted={prediction.predicted_label} verdict={prediction.verdict} "
            f"score={prediction.probability:.4f}"
        )
    print(
        "confusion_matrix: "
        f"tp={counts['true_positive']} tn={counts['true_negative']} "
        f"fp={counts['false_positive']} fn={counts['false_negative']}"
    )
    print(
        "fixture_metrics: "
        f"precision={metrics['precision']:.3f} "
        f"recall={metrics['recall']:.3f} "
        f"false_positive_rate={metrics['false_positive_rate']:.3f}"
    )
    print(
        "note: these are regression-fixture metrics, not population-level "
        "accuracy or calibration estimates"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
