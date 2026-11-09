# Changelog

All notable changes to PhishGuard AI are documented here.

## [Unreleased]

### Added

- **Redesigned browser demo UI** (`web/index.html`, `web/style.css`,
  `web/app.js`) — a distinct visual identity (brand mark, refined dark/light
  color system, monospace technical fields) replacing the generic form
  layout. The risk meter now shows the actual `SAFE`/`SUSPICIOUS`/`PHISHING`
  threshold positions (55%/75%) instead of a plain bar. The feature
  breakdown now marks which features actually contributed to the verdict —
  previously only the CLI did this (`phishguard.py`'s `*` marker), and even
  that marker mismarks `domain_length` (a negative-weight, risk-*reducing*
  feature) as triggered whenever its value is positive. The web version is
  more correct than the CLI it mirrors: `scoring.js` now exports
  `URL_WEIGHTS`/`EMAIL_WEIGHTS` (purely additive, no scoring behavior
  changed — mirrors `model.py`, which already exposes these as importable
  constants) so `app.js` can check the actual weight sign instead of
  guessing from the value alone. No changes to `scoring.js`'s scoring
  logic; `tests/test_js_parity.py` still passes unchanged.
- **`domain_older_than_2y` feature** (`domain_age.py`, opt-in via
  `--check-domain-age`) — a domain registered 730+ days ago now lowers
  risk (weight `-0.60`), the mirror image of the existing
  `domain_newer_than_30d`/`90d` features that raise it. Added to partially
  mitigate two false-positive shapes the query-string scoping fix below
  doesn't touch (branded subdomains like `accounts.{domain}`, and a
  keyword-dense path with no query string): real long-established domains
  like `accounts.google.com/signin` and `secure.github.com/login` flip from
  `SUSPICIOUS` to `SAFE` with this enabled. The weight was kept
  deliberately conservative rather than maximal — old domains are also
  exactly the category `docs/BENCHMARK.md`'s "Domain-Age Validation"
  already names as a real, unaddressed phishing vector (compromised or
  abused-as-a-service infrastructure), so a strong negative weight here
  would work directly against that. **Opt-in only — the default offline
  path is unaffected**, and one of the two false-positive shapes
  (keyword-dense path) still isn't fully fixed even with this enabled. See
  `docs/DETECTION_MODEL.md`'s "Domain-age false-positive suppression" and
  `docs/BENCHMARK.md`'s "Domain-Age False-Positive Suppression" for full
  methodology and the real-recall check this was validated against.

### Fixed

- **CLI verbose output's `*` risk marker now checks the actual feature
  weight sign** (`URL_WEIGHTS`), not just whether the value is positive.
  Found while verifying `docs/assets/phishguard-demo.svg` was still
  accurate: `domain_length` carries a negative weight (a longer domain is
  slightly *safer*), so it was mismarked as a risk contributor for every
  real hostname, with a hardcoded `has_https` exception papering over the
  one case anyone had noticed. The same bug this session's web UI redesign
  (#104) already fixed in `app.js` — the CLI had never gotten the matching
  fix. New test: `test_verbose_marker_reflects_weight_sign_not_just_value`.
- **Regenerated the stale demo evidence** (`docs/assets/phishguard-demo.svg`):
  the SAFE example's risk score (34.7%) predated this session's
  query-string-scoping fix and no longer matched real CLI output (now
  25.3%, still `SAFE`). The PHISHING example's 98.8% was unaffected and
  unchanged. Also updated the "Generated" date.
- **`domain_age.py`'s RDAP request re-validates the domain at the network
  call itself** (`_fetch_registration_age_days`), not just in its caller.
  CodeQL alert #16 (`py/partial-ssrf`) stayed open even after #102's
  `quote()`-encoding fix, because the format validation
  (`_is_valid_registrable_domain`) happened in `lookup_domain_age_days`,
  a different function than the actual `urlopen` sink — a cross-function
  taint flow CodeQL's static analysis (correctly) didn't trust as safe.
  The request target was never attacker-controlled (`_RDAP_BASE` is a
  hardcoded constant; only the path segment after it varies), so full
  SSRF was never possible, but the sink now validates on its own,
  defense-in-depth, regardless of what future caller reaches it. New
  test: `test_fetch_rejects_malformed_domain_without_a_network_call`
  asserts path-manipulation-shaped input never reaches `urlopen`.
- **`url_length`, `special_char_count`, and `digit_ratio` now score
  `scheme://host/path` only, excluding the query string** (`url_length`
  additionally capped at 80 characters). Previously scored against the
  whole URL, which made a realistic token-bearing security link (a
  password-reset or verification link) structurally indistinguishable from
  obfuscation — found by the 2026-08-24 false-positive stress test. Two new
  features, `query_length` and `query_param_count`, restore a small,
  deliberately weak amount of query-string signal back — validating this
  fix caught a real regression (a licensed phishing sample whose only
  suspicious structure was five chained tracking parameters, which the
  first version of this fix would have missed; `query_param_count` fixes
  it). Measured on the 3,000-domain × 10-template stress test: overall
  false-positive rate 40.0%→**21.4%**, strict PHISHING 27.4%→**10.3%**,
  `password_reset_link` (previously 100%/100%) down to 4.3%/0.3%. Real
  recall re-validated on a fresh feed: unchanged within normal sample
  variance, both regression fixtures stayed at precision/recall 1.000. Two
  false-positive shapes are **not** fixed by this change and remain a
  named, tracked gap — see `docs/DETECTION_MODEL.md`'s Known Limitations.
  See `docs/DETECTION_MODEL.md`'s "Query-string scoping" and
  `docs/BENCHMARK.md`'s "Query-String Scoping Fix" for full methodology.
- **Typosquat weight lowered from `0.85` to `0.65`** (`typosquatting_score`
  in `model.py`'s `URL_WEIGHTS`). A lone edit-distance-1 collision against
  the 47-entry brand reference list (e.g. `hicloud.com` vs. `icloud.com` —
  a real, coincidental collision, not a constructed example) now lands in
  `SUSPICIOUS` rather than `PHISHING` when nothing else about the URL is
  suspicious. Does not fully solve the collision (softened, not
  eliminated); a genuine typosquat (`paypa1.com/login`) is unaffected,
  still `SUSPICIOUS` at this weight as it was before.

### Added

- **`data/branded_path_benchmark_urls.jsonl` + `RealisticSecurityUrlFalsePositiveTests`**
  — a permanent regression guard for the false-positive gap found by
  `tools/evaluate_fp_stress_test.py`: 8 `.example`-suffixed synthetic cases
  covering the exact realistic login/verify/reset/subdomain URL shapes that
  stress test found false-positiving at scale on real domains, plus a
  `tests/test_model.py` test asserting they don't classify as PHISHING.
  Added deliberately failing (3/8 currently fail) per this project's
  test-before-fix convention — a following PR fixes the underlying scoring
  to turn them green. No scoring behavior changed in this commit.
- **`tools/evaluate_fp_stress_test.py`** — every existing false-positive
  number in this project's evidence docs is measured against bare root URLs
  (`https://{domain}/`), which is the easiest possible case. This tool
  generates ten realistic security-relevant URL shapes per real domain
  (login, signin, account/verify with a token, password-reset with a token
  and redirect, branded subdomains, a nested identity-verification path)
  against an externally-supplied domain ranking (nothing bundled, same
  no-committed-third-party-data design as `evaluate_live_traffic_benchmark.py`)
  and reports the false-positive rate per template. Found a severe gap:
  3,000 real Tranco top-3,000 domains × 10 templates (30,000 URLs), offline
  scoring only — 40.0% overall false-positive rate, 27.4% strict PHISHING,
  with three templates (`verify_token_link`, `password_reset_link`,
  `support_verify_identity`) at 70-100% false positives regardless of which
  real domain they're attached to. Root and simple-login shapes stay near
  zero, which is exactly why this was invisible until now. See
  `docs/BENCHMARK.md`'s new "False-Positive Stress Test" section for the
  full table and `docs/DETECTION_MODEL.md`'s Known Limitations for the root
  cause. This is instrumentation only — no scoring behavior changed; fixes
  are tracked as a phased rearchitecture.
- **`--check-domain-age` / `domain_age.py`** — an opt-in RDAP lookup that
  weights recently-registered domains as more suspicious
  (`domain_newer_than_30d` weight `0.65`, `domain_newer_than_90d` weight
  `0.30`). Added after auditing the model's remaining false negatives on a
  fresh live-traffic run and finding, case by case, that several missed
  phishing URLs (e.g. a 46-day-old `.com.br` domain with no other
  suspicious feature) had no signal any existing feature could reach —
  registration recency is a domain-level property that exists whether or
  not the URL has a path, unlike every other current feature. This is the
  first feature that calls a third party (the free `rdap.org` RDAP
  bootstrap) instead of scoring the URL string alone, so it's opt-in, off
  by default, and deliberately unavailable on `batch` — that public
  service rate-limits aggressively (429s observed after ~10 rapid
  lookups). Available on `url`, `eml`, and `POST /v1/url`
  (`check_domain_age`). Live-traffic validation (2026-08-24 OpenPhish feed,
  300 phishing URLs / top 300 Tranco domains): 55.0%→**65.7%** recall
  (strict PHISHING-only: 29.7%→**32.7%**), 0→**0** false positives. See
  `docs/DETECTION_MODEL.md`'s
  "Domain Age (RDAP)" section and `docs/BENCHMARK.md`'s "Domain-Age
  Validation" for full methodology, and `tests/test_domain_age.py` for
  coverage.
- **`on_free_hosting_platform` feature** — detects subdomains of commonly
  abused free-hosting platforms (pages.dev, netlify.app, blogspot.com,
  github.io, etc.). Added after a live-traffic validation against 300 real
  OpenPhish URLs and 1,000 real Tranco top-1000 domains found this was a
  major quantified gap (32% of missed real phishing was on these
  platforms, second only to bare-root URLs at 76% — see docs/BENCHMARK.md
  for why that larger gap isn't fixed by this change). Recall improved
  46.7%→63.3% (strict PHISHING-only:
  24.0%→51.0%) with 0 new false positives. See `docs/BENCHMARK.md`'s
  "Live-Traffic Validation" section and `tools/evaluate_live_traffic_benchmark.py`.
- **`phishguard serve` REST API mode** for SIEM and proxy integrations that
  want a long-running scoring endpoint instead of shelling out to the CLI per
  lookup. Built on the standard-library `http.server`, so it adds no runtime
  dependencies. Exposes `GET /healthz`, `POST /v1/url` (with optional
  `follow_redirects`), and `POST /v1/email`. Binds to `127.0.0.1` by default;
  see the README's REST API Server section for the security note on `--host`.
- **Browser demo UI** (`web/`, vanilla JS, no build step, no new
  dependencies) — paste a URL or email and get a verdict with a feature
  breakdown. Scoring runs entirely client-side via `web/scoring.js`, a
  JavaScript port of the Python model verified against the original by
  `tests/test_js_parity.py`, so the demo works as a static page with no
  backend to run: open `web/index.html` directly, or host it anywhere
  static files are served (e.g. GitHub Pages via
  `.github/workflows/pages.yml`). `phishguard serve` also serves the same
  UI at `/`, where it additionally gets redirect-chain resolution, which
  needs a real server-side request the static version can't make.
  `render.yaml` provides a one-click Render blueprint for self-hosting the
  full server.
- **Per-IP rate limiting on `POST /v1/*`** (`--rate-limit` / `--rate-limit-window`,
  default 30 requests/60s, `0` disables it), a basic safeguard for anyone
  running `serve` somewhere publicly reachable.

### Fixed

- **`FREE_HOSTING_SUFFIXES` now includes `replit.app` and `replit.dev`**.
  Found while auditing the model's current false negatives: two live
  OpenPhish URLs on `*.replit.app` in a fresh 2026-08-24 feed scored `SAFE`
  because only the older `repl.co` suffix was listed. Offline live-traffic
  recall (2026-08-24 feed, 300 phishing / 1,000 legitimate):
  54.3%→**55.0%** (strict PHISHING-only: 29.0%→**29.7%**), 0 new false
  positives.
- **`subdomain_count` now uses the Public Suffix List boundary** (issue #82)
  instead of assuming every registrable domain has two labels. Domains such as
  `www.example.co.uk` no longer count `example` as a subdomain, and private
  suffixes such as `github.io` retain their independently registrable boundary.
  The same generated offline PSL implementation is used by the web demo and
  Chromium extension, with Python/JavaScript parity coverage.
- **Saved-email analysis no longer trusts embedded authentication results by
  default.** The `eml` command ignores `Authentication-Results` unless
  `--trusted-authserv-id` is configured, and then accepts only an exact
  authserv-id match. Reports record the number of embedded headers and whether
  trusted evidence matched.
- **Redirect cross-domain comparison now uses the registrable domain
  (eTLD+1), not the raw hostname** (issue #29). Same-organization subdomain
  redirects (e.g. `www.example.com` -> `login.example.com`) no longer set
  `redirect_crossed_domain`. Added `psl.py`, a minimal parser for a bundled
  copy of the Mozilla Public Suffix List (`data/public_suffix_list.dat`),
  keeping the zero-runtime-dependency promise instead of adding `tldextract`.
  See `docs/DETECTION_MODEL.md` for the before/after regression example.

## [0.5.1] - 2026-06-12

### Added

- Optional SPF, DKIM, and DMARC `Authentication-Results` parsing with
  conservative, explainable email risk signals.
- A one-minute demo, first-contribution guide, support policy, and structured
  documentation issue template.
- A CI smoke test that executes the root `action.yml` and validates its SARIF
  output before release.

### Changed

- Renamed the Marketplace action to `PhishGuard AI Phishing Detector` using
  Marketplace-compatible characters.
- Made the composite action install PhishGuard from its checked-out action
  directory, so consumers receive the implementation pinned by their selected
  tag instead of code from a moving branch.
- Pinned the action's Python setup dependency to a reviewed commit.
- Refreshed the roadmap with scoped Python API, email-authentication, and
  benchmark tasks.

## [0.5.0] - 2026-06-11

### Added

- **URL redirect chain tracing** (`--follow-redirects N`): follow up to N HTTP
  hops using only the Python standard library and score the final destination
  URL. Flags when a redirect chain crosses domain boundaries. Degrades
  gracefully when the network is unavailable — the tool remains fully offline
  without the flag.
- **Typosquatting / lookalike detection**: a pure-Python Levenshtein comparison
  against 50 well-known brand domains. Edit-distance-1 matches score 1.0,
  distance-2 matches score 0.6. Exact legitimate domain matches are excluded
  from scoring.
- **`.eml` file analysis** (`phishguard eml <file>`): parse RFC 5322 email
  files using the Python standard library `email` module. Extracts subject and
  body, then runs both email scoring and a URL scan of every link found in the
  body. Authentication evidence requires an explicitly trusted receiver.
- **Reusable GitHub Action** (`action.yml`): any repository can use
  `omobolajiadeyan/phishguard-ai@main` in a workflow to scan URLs and upload
  SARIF findings to GitHub Code Scanning.
- **Self-scan CI workflow** (`.github/workflows/phishguard-self-scan.yml`):
  PhishGuard scans its own test URLs on every push and pull request, uploading
  results to GitHub Code Scanning.
- `redirect_crossed_domain` and `redirect_hops` optional model features,
  active only when redirect tracing is used.

### Changed

- `score_url` now accepts an optional `extra_features` dict for injecting
  redirect chain signals without modifying the feature extractor.
- `phishguard eml` verbose output includes a per-feature breakdown for both
  the email body analysis and each embedded URL.
- `pyproject.toml` version bumped from `0.5.0.dev0` to `0.5.0`.
- `redirect` module added to `py-modules` in `pyproject.toml`.

## [0.4.0] - 2026-06-09

### Added

- Conservative punycode and Unicode hostname indicators for URL analysis
- Public-safe URL regression fixture and deterministic benchmark metrics
- Standards-based Python packaging with an installed `phishguard` command
- Isolated distribution build, metadata, wheel-installation, and CLI checks
- CodeQL analysis using pinned GitHub Actions
- Tag-gated release automation with checksums and signed build provenance
- Detection-model documentation and evidence requirements for scoring changes
- Reproducible contributor setup, verification, safe-data, and review guidance
- Structured issue routing for design discussions and private security reports
- Branch protection and confidential GitHub vulnerability reporting

### Changed

- Clarified that current scores are explainable heuristics rather than
  statistically calibrated probabilities
- Expanded contributor coordination and evaluation benchmark requirements

## [0.3.0] - 2026-06-08

### Added

- Dependency-free SARIF 2.1.0 export for URL, email, and batch results
- GitHub Code Scanning workflow template and integration guide
- Stable finding fingerprints, severity mapping, and explainable SARIF properties
- CLI and serializer regression tests for JSON and SARIF output

### Changed

- Added `--format json|sarif` to every CLI scan command
- Standardized report files as UTF-8 with a trailing newline

## [0.2.0] - 2026-06-08

### Added

- Regression tests for URL scoring, email scoring, and limited console encodings
- Continuous integration across Python 3.10 through 3.13
- Contributor guide, security policy, governance, roadmap, and issue templates
- Project citation metadata and an MIT open-source license

### Changed

- Calibrated URL and email scoring to reduce false positives on legitimate input
- Made CLI output resilient on Windows consoles with limited encodings
- Established Omobolaji Adeyan as creator and lead maintainer

## [0.1.0] - 2025-04-20

- Initial explainable URL and email phishing detector
- Single-target and batch CLI workflows
- JSON output for downstream analysis
