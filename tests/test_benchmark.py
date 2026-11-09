import json
import tempfile
import unittest
from pathlib import Path

from tools.build_public_benchmark_slice import sanitize_phishing_url
from tools.evaluate_url_benchmark import (
    BenchmarkError,
    BenchmarkSample,
    Prediction,
    calculate_metrics,
    confusion_matrix,
    evaluate,
    load_samples,
    main,
)


def sample(sample_id: str, label: str) -> BenchmarkSample:
    return BenchmarkSample(
        id=sample_id,
        label=label,
        url="https://example.com",
        rationale="Test sample",
        provenance="synthetic",
    )


class BenchmarkFixtureTests(unittest.TestCase):
    def test_checked_in_fixture_loads_in_order(self):
        samples = load_samples("data/benchmark_urls.jsonl")

        self.assertEqual(len(samples), 14)
        self.assertEqual(samples[0].id, "legitimate-001")
        self.assertEqual(samples[-1].id, "phishing-007")

    def test_public_fixture_has_attribution_and_sanitized_phishing_hosts(self):
        fixture = Path("data/public_benchmark_urls.jsonl")
        records = [
            json.loads(line)
            for line in fixture.read_text(encoding="utf-8").splitlines()
        ]

        self.assertEqual(len(records), 10)
        self.assertEqual(records[0]["id"], "public-legitimate-001")
        self.assertEqual(records[-1]["id"], "public-phishing-005")
        for record in records:
            self.assertEqual(record["source_license"], "CC BY 4.0")
            self.assertEqual(record["source_doi"], "10.17632/65z9twcx3r.1")
            self.assertEqual(record["retrieved_on"], "2026-06-12")
            self.assertEqual(len(record["source_url_sha256"]), 64)
        for record in records[5:]:
            self.assertIn(".example", record["url"])
            self.assertNotIn("source_url", record)

        self.assertEqual(len(load_samples(fixture)), 10)

    def test_phishing_url_sanitization_preserves_path_and_query(self):
        sanitized = sanitize_phishing_url(
            "https://login.bad.invalid/account?continue=1#section"
        )

        self.assertEqual(
            sanitized,
            "https://login.bad.example/account?continue=1",
        )

    def test_unknown_label_is_rejected(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            fixture = Path(temp_dir) / "benchmark.jsonl"
            fixture.write_text(
                json.dumps(
                    {
                        "id": "unknown-001",
                        "label": "suspicious",
                        "url": "https://example.com",
                        "rationale": "Unknown binary label",
                        "provenance": "synthetic",
                    }
                ),
                encoding="utf-8",
            )

            with self.assertRaisesRegex(BenchmarkError, "unknown label"):
                load_samples(fixture)

    def test_malformed_json_returns_nonzero(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            fixture = Path(temp_dir) / "benchmark.jsonl"
            fixture.write_text("{not-json}\n", encoding="utf-8")

            self.assertEqual(main([str(fixture)]), 1)

    def test_public_fixture_recall_regression_target(self):
        predictions = evaluate(load_samples("data/public_benchmark_urls.jsonl"))
        counts = confusion_matrix(predictions)
        metrics = calculate_metrics(counts)

        self.assertEqual(counts["false_positive"], 0)
        self.assertGreaterEqual(metrics["recall"], 0.80)


class BenchmarkMetricTests(unittest.TestCase):
    def test_wrong_predictions_enter_expected_confusion_buckets(self):
        predictions = [
            Prediction(sample("tp", "phishing"), 0.90, "PHISHING"),
            Prediction(sample("tn", "legitimate"), 0.10, "SAFE"),
            Prediction(sample("fp", "legitimate"), 0.60, "SUSPICIOUS"),
            Prediction(sample("fn", "phishing"), 0.20, "SAFE"),
        ]

        self.assertEqual(
            confusion_matrix(predictions),
            {
                "true_positive": 1,
                "true_negative": 1,
                "false_positive": 1,
                "false_negative": 1,
            },
        )

    def test_metrics_define_zero_division_as_zero(self):
        metrics = calculate_metrics(
            {
                "true_positive": 0,
                "true_negative": 0,
                "false_positive": 0,
                "false_negative": 0,
            }
        )

        self.assertEqual(
            metrics,
            {"precision": 0.0, "recall": 0.0, "false_positive_rate": 0.0},
        )


if __name__ == "__main__":
    unittest.main()
