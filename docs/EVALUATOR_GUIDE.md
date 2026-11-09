# External Evaluator Guide

This guide is for security engineers, maintainers, recruiters, and technical
reviewers who want to judge PhishGuard AI quickly without reading the entire
repository first.

## Five-Minute Review Path

1. Read the project promise: offline, explainable phishing analysis for URLs and
   email.
2. Run one safe URL and one synthetic suspicious URL.
3. Inspect the feature explanation.
4. Export SARIF or JSON.
5. Review the documented limits before treating the output as evidence.

```bash
python3 phishguard.py url "https://www.example.com/account" --plain
python3 phishguard.py url "http://192.0.2.10/secure-login/verify" --verbose --plain
python3 phishguard.py url "http://192.0.2.10/secure-login/verify" \
  --format sarif \
  --output phishguard-results.sarif
```

`192.0.2.10` is part of the documentation address range, so the suspicious
example is safe to run and does not touch live phishing infrastructure.

## What A Good Result Looks Like

The tool should show:

- a verdict: `SAFE`, `SUSPICIOUS`, or `PHISHING`
- a risk score
- the features that influenced the verdict
- exportable JSON or SARIF for automation

For email authentication examples, the output should make clear that SPF, DKIM,
and DMARC are supporting signals from a trusted receiver, not automatic proof
that a message is safe or malicious.

## What To Review

| Area | Where To Look |
|---|---|
| Quick demo | [QUICK_DEMO.md](QUICK_DEMO.md) |
| Detection model | [DETECTION_MODEL.md](DETECTION_MODEL.md) |
| Benchmark evidence | [BENCHMARK.md](BENCHMARK.md) |
| GitHub Code Scanning | [GITHUB_CODE_SCANNING.md](GITHUB_CODE_SCANNING.md) |
| Python API | [PYTHON_API.md](PYTHON_API.md) |
| Adoption guide | [ADOPTION.md](ADOPTION.md) |
| Public evidence | [PUBLIC_EVIDENCE.md](PUBLIC_EVIDENCE.md) |

## Trust Boundaries

PhishGuard AI is useful for lightweight triage, education, CI checks, and
repeatable examples. It is not a replacement for:

- enterprise email security gateways
- commercial threat-intelligence feeds
- sandbox detonation
- statistically trained production ML models
- human investigation of business context

Use the output as explainable supporting evidence, not as a final incident
verdict.

## Strongest Product Signals

- GitHub Marketplace Action packaging
- zero runtime dependencies
- JSON and SARIF output
- documented detection model and benchmark limits
- tests covering CLI, model behavior, reporting, email parsing, SARIF, and API
- local browser demo and stdlib REST server mode
