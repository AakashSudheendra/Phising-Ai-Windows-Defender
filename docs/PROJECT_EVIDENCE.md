# Project Evidence

This page records reproducible technical and community evidence for
PhishGuard AI. Counts are a dated snapshot, not claims of production adoption.

## Technical Evidence

Snapshot re-verified three times on August 24, 2026 (previous snapshot: July
28, 2026): once against `main` after #99–#103 (the false-positive
rearchitecture — see "False-Positive Rearchitecture Evidence" below), again
after #104 (a browser-demo UI redesign), and once more after #107 corrected
CLI explainability markers and refreshed the demo evidence. The latest run
covered the complete 199-test suite:

- URL regression fixture: 14 public-safe samples
- Confusion matrix: 7 true positives, 7 true negatives, 0 false positives,
  and 0 false negatives
- Fixture precision: 1.000
- Fixture recall: 1.000
- Fixture false-positive rate: 0.000
- A second regression fixture (`data/branded_path_benchmark_urls.jsonl`, 8
  branded-path samples) guards the false-positive fix specifically: 5/8
  clean, 3/8 a known, named, still-open gap (see below) — not hidden by a
  weakened test.
- Full test suite: 199/199 passing (2 skipped, 1 deliberately tracked
  `expectedFailure` for the named open gap), run locally via
  `python -m unittest discover -s tests`
- Supported Python versions in CI: 3.10, 3.11, 3.12, and 3.13
- Security automation: CodeQL, repository policy checks, and dependency audit
- Release engineering: five tagged releases, with installable artifacts,
  checksums, and build provenance on recent releases; wheel contents
  independently rebuilt and inspected twice on 2026-08-24 (immediately
  after the rearchitecture, and again after the UI redesign) to confirm
  packaging stayed correct across both changes (`python -m build --wheel`)
- Integration surfaces: CLI, stable Python API, GitHub Marketplace Action,
  SARIF 2.1.0 output, browser demo, browser extension prototype, and stdlib
  REST API server mode (`/healthz`, `POST /v1/url`, `POST /v1/email` — all
  smoke-tested live on 2026-08-24, including 400 rejection of a malformed
  request body)
- Trust-boundary coverage: saved-email authentication parsing, SARIF
  validation, parser regression tests, public-safe demonstration inputs, and
  an opt-in RDAP domain-age lookup (`--check-domain-age`) that is the one
  place the offline scanner makes a network call — always to the fixed,
  trusted `rdap.org` bootstrap, never to the domain being scored

Run the benchmark yourself:

```bash
python tools/evaluate_url_benchmark.py
```

These results measure the checked-in regression fixture. They are not
population-level accuracy, calibration, or production-effectiveness claims.
See [BENCHMARK.md](BENCHMARK.md) for the fixture limitations.

## Live-Traffic Validation Evidence

Re-verified twice on August 24, 2026: once immediately after the
false-positive rearchitecture (#99–#103) landed, and again independently
after the UI redesign (#104), each time against a freshly re-downloaded
OpenPhish feed and Tranco list (never the same sample twice):

| Metric | Offline only | + opt-in domain age |
| --- | --- | --- |
| Recall (flag = PHISHING or SUSPICIOUS) | 55.7% (167/300) | 59.0% (177/300) |
| Recall (strict PHISHING only) | 34.0% (102/300) | 34.7% (104/300) |
| False positives on real legitimate sites | 0/1,000 | 0/300 |

Recall moves within normal sample-to-sample variance between runs on
different dates against a rotating public feed — that's expected, and is
itself part of the evidence: two independent pulls, days or hours apart,
land in the same range rather than drifting, which is what "not a one-off
lucky measurement" looks like in practice. See
[BENCHMARK.md](BENCHMARK.md)'s "Domain-Age Validation" and "Live-Traffic
Validation" sections for full methodology, sample-size caveats, and the
named categories of phishing this still misses (bare-root URLs and
old-but-compromised domains, both page-content problems no URL-only or
registration-date feature can reach).

The domain-age feature was independently smoke-tested end to end for this
snapshot: CLI lookup against a real, long-registered domain correctly
returned "registered 90+ days ago," and the same check surfaced
`domain_newer_than_30d`/`domain_newer_than_90d` in the REST server's
`POST /v1/url` response when `check_domain_age` was set. (Reviewer note: a
Homebrew-Python local CA bundle gap — unrelated to this project's code —
caused an initial `CERTIFICATE_VERIFY_FAILED`; setting `SSL_CERT_FILE` to
`certifi`'s bundle resolved it. Anyone hitting the same error locally is
looking at a Python install issue, not a PhishGuard bug.)

## False-Positive Rearchitecture Evidence

A 2026-08-24 audit found that every prior false-positive claim in this
project's evidence — including the table above — was measured against bare
root URLs (`https://{domain}/`), the easiest possible case. A new tool,
`tools/evaluate_fp_stress_test.py`, tests 10 realistic security-relevant
URL shapes (login, signin, password-reset-with-token, identity
verification, branded subdomains) against real domains instead, and found
a severe gap: on 3,000 real Tranco top-3,000 domains, **40.0% overall false
positives, 27.4% strict PHISHING**, with token-bearing links at 70-100%
regardless of which real, popular domain they were attached to.

This was root-caused (an uncapped, whole-URL `url_length` weight structurally
unable to distinguish a legitimate reset token from obfuscation) and fixed
across four PRs (#99–#101, #103), each independently reviewable, each
validated against the full test suite, both regression fixtures, and real
recall on a fresh feed before merging — not merged blind:

| Metric | Before | After (2026-08-24, run 1) | After (2026-08-24, run 2, independent) |
| --- | --- | --- | --- |
| Overall false-positive rate | 40.0% | 21.4% offline, 15.7% w/ domain-age | 21.4% offline, 16.9% w/ domain-age |
| Strict PHISHING false-positive rate | 27.4% | 10.3% offline, 6.1% w/ domain-age | 10.3% offline, 6.5% w/ domain-age |
| `password_reset_link` strict (worst offender) | 100% | 0.3% | 0.0% |
| Real recall (fresh feed, independent sample) | — | held steady | held steady (55.7%→59.0% flagged with domain age) |

Run 2 used a completely fresh Tranco/OpenPhish pull, hours after run 1 and
after the unrelated UI redesign (#104) landed — the offline number is
identical to the decimal (21.4%) and the domain-age numbers move only within
the sampling noise expected from a 150-domain subsample, not a regression.

Two false-positive shapes remain open on purpose, named rather than hidden:
branded subdomains and a keyword-dense path with no query string, both
needing a domain-reputation signal beyond what was fixed here (see
[DETECTION_MODEL.md](DETECTION_MODEL.md)'s Known Limitations). The regression
tests for both are in the suite now — one passing after the fix, one tracked
as an explicit `expectedFailure` so the gap can't silently regress or
silently get hidden.

Full methodology, per-template tables, and rerun commands:
[BENCHMARK.md](BENCHMARK.md)'s "False-Positive Stress Test", "Query-String
Scoping Fix", and "Domain-Age False-Positive Suppression" sections.

## Product Readiness Evidence

Recent reviewer-facing improvements:

| Area | Evidence |
| --- | --- |
| Benchmark transparency | [BENCHMARK.md](BENCHMARK.md) records the public-safe baseline, recall improvement, and limits. |
| Realistic false-positive testing | `tools/evaluate_fp_stress_test.py` tests real domains against realistic security-URL shapes, not just bare roots — the gap that let earlier false-positive claims look cleaner than reality; see the False-Positive Rearchitecture Evidence above. |
| Detection model | [DETECTION_MODEL.md](DETECTION_MODEL.md)'s "Domain Age (RDAP)", "Query-string scoping", and "Domain-age false-positive suppression" sections document every opt-in and default-path weight, with rationale and explicit blind spots. |
| Python embedding | [PYTHON_API.md](PYTHON_API.md) documents direct `score_url` and `score_email` usage without shelling out. |
| CI and code scanning | [GITHUB_CODE_SCANNING.md](GITHUB_CODE_SCANNING.md) provides SARIF generation and upload guidance. |
| Browser use | [BROWSER_EXTENSION.md](BROWSER_EXTENSION.md) documents the unpacked Chrome/Edge extension for current-tab and pasted-URL checks. |
| Browser demo | Redesigned 2026-08-24 (#104) with a distinct visual identity and a threshold-labeled risk meter. Verified end-to-end with Playwright screenshots (dark/light themes, both tabs, SAFE/PHISHING verdicts) — zero console errors. Fixed a real explainability bug in the process: the feature-breakdown "triggered" indicator now checks the actual model weight sign (`scoring.js` exports `URL_WEIGHTS`/`EMAIL_WEIGHTS`) instead of the CLI's cruder value-only heuristic, which mismarked `domain_length` (a risk-*reducing* feature) as a risk contributor. Live at [omobolajiadeyan.github.io/phishguard-ai](https://omobolajiadeyan.github.io/phishguard-ai/), confirmed serving the current build on 2026-08-24. |
| REST integration | The README documents `phishguard serve` with local default binding and endpoint examples. |
| Safe adoption | [ADOPTION.md](ADOPTION.md) and [FIRST_CONTRIBUTION.md](FIRST_CONTRIBUTION.md) give external users low-friction paths to try, report, and contribute. |
| Evaluator experience | [EVALUATOR_GUIDE.md](EVALUATOR_GUIDE.md) gives a five-minute path to run safe examples and inspect trust boundaries. |

## Community Evidence

GitHub snapshot verified on June 9, 2026 and retained as a historical
baseline:

- 3 repository forks
- 1 merged pull request from an external human contributor
- 1 automated dependency-update pull request merged
- 7 open issues offering scoped contribution opportunities
- 3 tagged releases
- 1 recorded download of a v0.4.0 release asset

The external contribution added plain-text CLI output and is preserved in
[pull request #7](https://github.com/omobolajiadeyan/phishguard-ai/pull/7).
Repository counts change over time; use the live badges and GitHub pages for
current values.

## Demonstration

![PhishGuard safe-input and phishing-input terminal comparison](assets/phishguard-demo.svg?v=20260824-2)

The screenshot was prepared from the real output of:

```bash
python phishguard.py url "https://www.example.com/account" --plain
python phishguard.py url \
  "http://192.0.2.10/secure-login/verify" \
  --verbose \
  --plain
```

Both inputs are public-safe. `example.com` is reserved for documentation, and
`192.0.2.0/24` is the TEST-NET-1 documentation range.

The
[18-second safe demo video](https://github.com/omobolajiadeyan/phishguard-ai/releases/download/v0.4.0/phishguard-demo.mp4)
attached to the
[v0.4.0 release](https://github.com/omobolajiadeyan/phishguard-ai/releases/tag/v0.4.0)
shows the same offline workflow. The commands remain in
[QUICK_DEMO.md](QUICK_DEMO.md) so reviewers can reproduce the result rather
than relying on a recording.

## Evidence Boundaries

PhishGuard is an early-stage open-source project. Stars, traffic, deployments,
and organizational adoption are not claimed unless they can be independently
verified. Future evidence should include dated sources, commands, and
limitations.
