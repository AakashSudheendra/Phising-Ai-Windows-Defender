"""Output serializers for PhishGuard scan results."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any


SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"
SARIF_VERSION = "2.1.0"

SARIF_RULES = {
    "SUSPICIOUS": {
        "id": "PHISHGUARD_SUSPICIOUS",
        "name": "SuspiciousPhishingIndicator",
        "shortDescription": {
            "text": "PhishGuard identified suspicious phishing indicators."
        },
        "defaultConfiguration": {"level": "warning"},
    },
    "PHISHING": {
        "id": "PHISHGUARD_PHISHING",
        "name": "LikelyPhishing",
        "shortDescription": {
            "text": "PhishGuard classified the input as likely phishing."
        },
        "defaultConfiguration": {"level": "error"},
    },
}


def build_sarif(results: dict[str, Any] | list[dict[str, Any]]) -> dict[str, Any]:
    """Convert one or more PhishGuard results to a SARIF 2.1.0 log."""
    normalized_results = results if isinstance(results, list) else [results]
    findings = [
        finding
        for result in normalized_results
        if (finding := _build_sarif_result(result)) is not None
    ]

    return {
        "$schema": SARIF_SCHEMA,
        "version": SARIF_VERSION,
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "PhishGuard AI",
                        "informationUri": (
                            "https://github.com/omobolajiadeyan/phishguard-ai"
                        ),
                        "rules": list(SARIF_RULES.values()),
                    }
                },
                "results": findings,
            }
        ],
    }


def write_report(
    results: dict[str, Any] | list[dict[str, Any]],
    output_path: str,
    output_format: str = "json",
) -> None:
    """Write scan results as native JSON or SARIF."""
    payload = build_sarif(results) if output_format == "sarif" else results
    Path(output_path).write_text(
        json.dumps(payload, indent=2) + "\n",
        encoding="utf-8",
    )


def _build_sarif_result(result: dict[str, Any]) -> dict[str, Any] | None:
    verdict = result["verdict"]
    if verdict == "SAFE":
        return None

    rule = SARIF_RULES[verdict]
    target_type = "url" if "url" in result else "email"
    target = result.get("url") or result.get("subject") or "Email message"
    probability = float(result["probability"])
    fingerprint_source = f"{target_type}:{target}".encode("utf-8")

    location_entry = {
        "logicalLocations": [
            {
                "fullyQualifiedName": target,
                "kind": target_type,
            }
        ]
    }

    source_path = result.get("source_path")
    line_number = result.get("line_number")

    if source_path and line_number:
        location_entry["physicalLocation"] = {
            "artifactLocation": {
                "uri": Path(source_path).as_posix()
            },
            "region": {
                "startLine": line_number
            }
        }

    return {
        "ruleId": rule["id"],
        "level": rule["defaultConfiguration"]["level"],
        "message": {
            "text": (
                f"{target_type.title()} classified as {verdict} "
                f"with {probability:.1%} phishing risk."
            )
        },
        "locations": [location_entry],
        "partialFingerprints": {
            "phishguard/v1": hashlib.sha256(fingerprint_source).hexdigest()
        },
        "properties": {
            "probability": probability,
            "targetType": target_type,
            "features": result.get("features", {}),
        },
    }
