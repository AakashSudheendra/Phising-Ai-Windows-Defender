# Public Evidence and Adoption

PhishGuard AI is maintained as a practical security tool, not a black-box
claim. This page records what the project can currently prove, how to reproduce
that evidence, and what would strengthen future adoption.

## Current Public Evidence

| Evidence | Location | Notes |
| --- | --- | --- |
| GitHub Marketplace Action | https://github.com/marketplace/actions/phishguard-ai-phishing-detector | Reusable action for CI-based URL and email scanning. |
| Latest release | https://github.com/omobolajiadeyan/phishguard-ai/releases/tag/v0.5.1 | Published release with installable package artifacts. |
| Project benchmark | [BENCHMARK.md](BENCHMARK.md) | Regression fixture metrics, live-traffic recall validation, and a realistic false-positive stress test that found and fixed a severe gap (see below) — reconfirmed on an independent fresh data pull hours later, not measured once and assumed stable. |
| Detection model | [DETECTION_MODEL.md](DETECTION_MODEL.md) | Feature semantics, limitations, scoring-change requirements, the opt-in RDAP domain-age lookup, and the query-string scoping fix. |
| Browser demo | [omobolajiadeyan.github.io/phishguard-ai](https://omobolajiadeyan.github.io/phishguard-ai/) | Redesigned 2026-08-24 with a distinct visual identity; verified live and rendering correctly (Playwright, dark/light, both tabs, zero console errors). |
| Code scanning workflow | [GITHUB_CODE_SCANNING.md](GITHUB_CODE_SCANNING.md) | SARIF integration path for GitHub Code Scanning. |
| Adoption guide | [ADOPTION.md](ADOPTION.md) | Safe path for third-party workflow examples and showcase reports. |
| First contribution guide | [FIRST_CONTRIBUTION.md](FIRST_CONTRIBUTION.md) | Scoped path for new contributors. |

## What the Metrics Mean

The checked-in benchmark is a 14-sample regression fixture. It is useful for
detecting behavior changes across releases, but it is not a population-level
accuracy claim and should not be presented as independent model validation.

Separately, [BENCHMARK.md](BENCHMARK.md) also records live-traffic
validation runs against real, rotating public feeds (OpenPhish phishing
URLs, Tranco top-domain legitimate URLs) — most recently on 2026-08-24,
showing the opt-in domain-age check raising flagged recall from 55.7%
(167/300) to 59.0% (177/300). The corresponding legitimate-site checks found
0 false positives among 1,000 offline samples and 0 among the 300-domain
RDAP-enabled sample. This is closer to real-world signal than the fixture,
but it is still a bounded sample against two specific public feeds, not a
comprehensive accuracy claim — treat it the same way: reproducible, dated,
and bounded, not definitive.

**A 2026-08-24 self-audit found that every false-positive number above,
including the "zero new false positives" claim, was measured against bare
root URLs** (`https://{domain}/`) — the easiest possible case, not the
login/reset/verification URL shapes a real security workflow actually
produces. A new stress test against realistic shapes on 3,000 real domains
found 40.0% overall false positives, with password-reset links at 100%
regardless of which real domain they were attached to. This was fixed
(overall down to 21.4% offline, 15.7-16.9% with domain-age enabled across
two independent reruns; the worst shape down from 100% to 0.0-0.3%) across
four reviewable PRs, each validated against real recall before merging.
Reconfirmed hours later on a second, completely independent data pull
(different domains, different phishing feed) after an unrelated UI change
— the offline number matched to the decimal, the domain-age numbers moved
only within normal sampling noise. Two narrower false-positive shapes
remain open on purpose, named rather than hidden — see
[DETECTION_MODEL.md](DETECTION_MODEL.md)'s Known Limitations. Full tables:
[BENCHMARK.md](BENCHMARK.md)'s "False-Positive Stress Test" section
onward.

PhishGuard AI is strongest when used as an explainable supporting signal in a
security workflow:

- flag suspicious URLs or email evidence in CI;
- produce JSON or SARIF for downstream tools;
- explain which features contributed to a score;
- keep data local by avoiding external API calls.

## Adoption Signals to Build Next

The next useful public signals are:

- third-party workflow examples using the Marketplace Action;
- independent issue reports or pull requests from users;
- release notes tied to reproducible benchmark changes;
- short technical posts explaining trust boundaries and model limitations;
- a domain-reputation signal for the offline default path, closing the two
  false-positive shapes (branded subdomains, keyword-dense paths) the
  2026-08-24 fix deliberately left open — see
  [DETECTION_MODEL.md](DETECTION_MODEL.md)'s Known Limitations.

Documented false-positive and false-negative cases are no longer a gap:
see [BENCHMARK.md](BENCHMARK.md)'s "False-Positive Stress Test" section
onward for the fullest self-audit this project has published.

## Maintainer Position

PhishGuard AI should stay conservative. Pass results for SPF, DKIM, or DMARC do
not lower risk on their own because authenticated infrastructure can still send
malicious content. Authentication failures are supporting evidence, not proof of
phishing.

Contributions that improve tests, documentation, parser safety, SARIF output,
or benchmark transparency are preferred over broad model changes.
