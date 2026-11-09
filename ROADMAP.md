# PhishGuard AI Roadmap

This roadmap separates shipped capability from future work. Priorities are
driven by measured detection gaps, reproducible evidence, and safe integration
boundaries—not feature count alone.

Implementation work should begin with a scoped GitHub issue so behavior,
fixtures, and evaluation criteria can be reviewed before code changes.

## Current Priorities

| Priority | Intended outcome | Evidence required |
| --- | --- | --- |
| Offline domain reputation | Reduce false positives on legitimate branded subdomains and security-heavy paths without weakening phishing recall | Licensed or redistributable data source, stress-test improvement, and recall comparison |
| Unicode confusable matching | Detect hostname impersonation beyond the current punycode and Unicode-presence signals | Named brand-confusable fixtures plus legitimate internationalized-domain negatives |
| Benchmark expansion | Improve coverage beyond small regression fixtures while keeping provenance and sanitization reviewable | Dated source, license record, confusion matrix, and documented sampling limits |
| Release consolidation | Publish the current REST server, browser demo, extension prototype, domain-age signals, and scoring fixes as a versioned release | Full Python matrix, JS parity, package inspection, checksums, provenance, and release notes |

## Recently Shipped on `main`

- Query-string-aware URL scoring and a realistic false-positive stress test.
- Opt-in RDAP domain-age signals, including conservative risk reduction for
  established domains.
- A static browser demo with Python/JavaScript scoring-parity tests.
- A Chromium extension prototype using the same local scoring model.
- A standard-library REST server with health, URL, and email endpoints,
  redirect resolution, rate limiting, and a Render blueprint.
- Trusted-receiver handling for saved-email authentication evidence.
- Stable Python API documentation for URL and email scoring.
- Public-safe benchmark provenance and dated live-traffic evaluation notes.

## Stable Release Line (`v0.5.1`)

- URL, email, and `.eml` analysis.
- Redirect-chain tracing with SSRF protections.
- Explainable typosquatting and structural URL features.
- JSON and SARIF 2.1.0 output.
- Reusable GitHub Marketplace Action.
- Windows-safe and plain-text CLI output.
- Python 3.10–3.13 continuous integration.
- Wheel and source artifacts with checksums and build provenance.

## Later

- Optional page-content and TLS-certificate signals with explicit network and
  privacy controls.
- Optional trained-model support while preserving the explainable heuristic
  path and stable output contracts.
- Threat-intelligence adapters that remain opt-in and do not weaken offline
  operation.
- Broader browser-extension distribution after detection evaluation and store
  privacy requirements are mature.

## Change Standard

Detection changes should include:

- a named, explainable signal rather than an opaque weight adjustment;
- positive fixtures using synthetic, reserved, or properly licensed data;
- legitimate negative cases that guard against false positives;
- before-and-after scores, verdicts, and benchmark results;
- a documented privacy and network boundary;
- a passing full suite on every supported Python version and JS parity checks
  when shared scoring behavior changes.

Roadmap items are not promises or deadlines. Priorities may change when
testing, security review, licensing constraints, or contributor feedback
reveals a better direction.
