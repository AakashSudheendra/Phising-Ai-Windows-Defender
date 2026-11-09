# Detection Model

PhishGuard uses an explainable heuristic model. It does not currently ship a
trained machine-learning model, call a remote reputation service, or claim
that a score is a calibrated real-world probability.

## Processing

1. `features.py` extracts structural URL or email indicators.
2. `model.py` multiplies each indicator by a reviewable weight.
3. A bias and sigmoid transform produce a stable score from 0 to 1.
4. `classify()` maps the score to `SAFE`, `SUSPICIOUS`, or `PHISHING`.

The score is useful for ranking and decision support. It should not be treated
as the measured probability that a target is malicious.

## Current URL Indicators

- URL, hostname, path, and subdomain length or depth (`url_length` is
  scored on `scheme://host/path` only, excluding the query string, and
  capped at 80 characters — see "Query-string scoping" below)
- IP-address hosts and explicit ports
- HTTPS presence
- Suspicious top-level domains
- Phishing-related words
- Digit and special-character density (also scored on `scheme://host/path`
  only, for the same reason as `url_length`)
- Query-string length and parameter count (`query_length`,
  `query_param_count`), each weighted deliberately small — see
  "Query-string scoping" below
- Hostname entropy
- Reserved opaque hostname labels: long, compact, alphanumeric labels with
  moderate entropy and no separators in `.example` public-safe fixtures
- Punycode labels and Unicode hostname presence

Reserved opaque hostname labels are treated as a regression-fixture signal
because some public-data phishing samples use brandless generated-looking
hostnames after live infrastructure has been neutralized to `.example` for safe
testing. The feature excludes short labels, non-`.example` hosts, multi-label
hosts, hyphenated labels, Unicode labels, and punycode labels so it does not
penalize ordinary long production domains.

Two more indicators are available only when a caller opts in and network
access is available (`--check-domain-age` / `check_domain_age`), and are
never part of the default offline scan: `domain_newer_than_30d` and
`domain_newer_than_90d`, from `domain_age.py`'s RDAP lookup. See "Domain
Age (RDAP)" below.

IDN indicators are contextual signals with deliberately modest weights.
Internationalized domains are legitimate and are not classified as phishing
from either indicator alone. Confusable-character and brand-impersonation
matching are not currently implemented.

### Public-suffix-aware subdomain depth

`subdomain_count` measures labels above the registrable domain rather than
assuming the final two hostname labels always form that domain. The boundary
comes from the bundled Mozilla Public Suffix List already used for redirect
comparison. For example, `www.example.co.uk` has no meaningful subdomain after
the presentation label `www` is removed, while `login.example.co.uk` has one.
Private-section rules are honored, so `alice.github.io` is independently
registrable and `foo.alice.github.io` has one subdomain.

The web demo and Chromium extension load generated, offline JavaScript bundles
from the same canonical `data/public_suffix_list.dat`; no DNS or remote lookup
is performed. `tools/generate_public_suffix_js.py` regenerates both copies, and
repository tests require them to remain identical and current.

Live string-only validation on 2026-08-01 used 300 current OpenPhish URLs and
the Tranco top 1,000 domains. The corrected boundary changed the feature for
195 phishing samples and 29 legitimate samples. Legitimate false positives
remained `0/1000`. Flagged phishing samples changed from `186/300` with the
old, inflated count to `170/300`; strict `PHISHING` verdicts changed from
`133/300` to `107/300`. This is a deliberate removal of invalid signal, not an
accuracy improvement claim. Testing the existing free-hosting weight from
`0.7` through `1.2` recovered at most three flagged samples with no false
positives, so the weight was not changed merely to chase the prior number.
Page-content or reputation signals are needed to recover that structural gap
without miscounting suffix labels.

### Query-string scoping

Found via a 2026-08-24 stress test (docs/BENCHMARK.md's "False-Positive
Stress Test") against 3,000 real domains: `url_length`, `special_char_count`,
and `digit_ratio`, when scored against the whole URL, made a realistic
token-bearing security link (a password-reset or verification link) close
to indistinguishable from obfuscation, because both are long, digit-heavy,
and punctuation-heavy for the same structural reason — a query string is
doing what query strings are for. All three are now scored on
`scheme://host/path` only (`features.py`'s `_url_without_query`), and
`url_length` is capped at 80 characters as a secondary safety net against
pathologically deep paths.

This isn't a blanket "ignore the query string" fix: validating it against
the existing licensed regression slice caught a real phishing sample
(`public-phishing-001`, five chained `utm_*` tracking parameters and no
other suspicious structure) whose only signal was query-string clutter,
and the initial version of this fix would have missed it. Two features
restore a small amount of query-string signal deliberately: `query_length`
(near-zero weight — length alone doesn't distinguish a legitimate token
from padding) and `query_param_count` (a small weight per `=`-separated
parameter — a single token is cheap, several chained parameters still
counts for something). Re-validated: `data/public_benchmark_urls.jsonl`
recall stayed at 1.000 with this restored, and the branded-path fixture's
token-link cases stayed non-PHISHING.

Measured impact (3,000-domain × 10-template stress test, before → after):
overall false-positive rate 40.0%→21.4%, strict PHISHING 27.4%→10.3%,
`verify_token_link` 71.5%→0.5% strict, `password_reset_link` 100%→0.3%
strict. Two shapes are unaffected by this fix and remain a known gap —
see Known Limitations below.

## Current Email Indicators

- URLs and link-like language
- Urgency phrases
- Exclamation marks and uppercase words
- HTML tags
- Attachment language
- Message length
- Optional categorical SPF, DKIM, and DMARC results parsed from a trusted
  receiver's `Authentication-Results` header

Authentication failures are supporting signals, not proof of phishing. SPF
failure has a weight of `0.08`, DKIM failure `0.10`, and DMARC failure `0.18`.
SPF softfail contributes half of the SPF failure value. Pass, neutral, none,
missing, malformed, and unsupported results add no risk and never lower the
score. This keeps a legitimate forwarded message with an SPF failure from
being classified as malicious solely because of authentication.

The parser is deliberately limited rather than RFC-complete. It normalizes
SPF, DKIM, and DMARC values to `pass`, `fail`, `softfail`, `neutral`, `none`,
or `unknown`. Callers must provide the final trusted receiver's header:
attacker-supplied `Authentication-Results` values are not independently
trustworthy, and PhishGuard does not validate cryptographic signatures or DNS
policy itself.

For saved messages, `phishguard eml` ignores every embedded
`Authentication-Results` header by default. Set `--trusted-authserv-id` to use
the first header whose leading authserv-id is an exact, case-insensitive match.
Prefix lookalikes are rejected. This selection is not cryptographic proof: the
trusted receiving system must prevent untrusted messages from preserving or
prepending a forged header with its own authserv-id.

For the checked-in regression examples:

| Example | Content only | With authentication results |
| --- | --- | --- |
| Forwarded legitimate message (`spf=fail`, `dkim=pass`, `dmarc=pass`) | `0.3149 SAFE` | `0.3595 SAFE` |
| Synthetic lure (`spf=fail`, `dkim=fail`, `dmarc=fail`) | `0.6525 SUSPICIOUS` | `0.8220 PHISHING` |
| Authenticated malicious sender (`spf=pass`, `dkim=pass`, `dmarc=pass`) | `0.9583 PHISHING` | `0.9583 PHISHING` (unchanged) |
| Malformed `Authentication-Results` value | `0.9583 PHISHING` | `0.9583 PHISHING` (parses to `unknown`, same as omitting the header) |
| Mild message with a lone DMARC failure (`spf=pass`, `dkim=pass`, `dmarc=fail`) | `0.3143 SAFE` | `0.4182 SAFE` (raised but not decisive) |

These examples demonstrate expected model behavior, not population-level
accuracy. Forwarding and mailing lists can legitimately break SPF or DKIM, so
authentication failures remain modest supporting signals. The authenticated-sender
and malformed-header rows are the flip side of that same design: passing,
missing, or malformed authentication never *lowers* a score either — a
properly authenticated phishing email (e.g. from a compromised mailbox or an
attacker's own correctly configured domain) is scored purely on its content.
Authentication-Results is supporting evidence in one direction only.

## Redirect Cross-Domain Comparison (eTLD+1)

`--follow-redirects` flags a chain as `redirect_crossed_domain` when a hop
leaves the origin's registrable domain. Comparing raw hostnames instead of
the registrable domain (eTLD+1) caused false positives on ordinary
same-organization subdomain redirects, since `www.example.com` and
`login.example.com` are different hostnames but the same registrable domain
(tracked as [issue #29](https://github.com/omobolajiadeyan/phishguard-ai/issues/29)).

The fix bundles the Mozilla Public Suffix List
(`data/public_suffix_list.dat`, refreshed via
`tools/update_public_suffix_list.py`) and parses it in `psl.py`, rather than
adding `tldextract` as a dependency. `redirect.py` now compares
`psl.registrable_domain(hostname)` instead of the raw hostname. This also
keeps private-section entries correct: `alice.github.io` and
`bob.github.io` are still treated as different registrable domains, since
GitHub Pages subdomains are independently registrable.

Before/after, using `model.score_url` on a same-organization redirect from
`https://www.example.com/` to `https://login.example.com/verify`
(reserved documentation domain, `redirect_hops=1`):

| | `redirect_crossed_domain` | Score | Verdict |
| --- | --- | --- | --- |
| Before fix (hostname compare) | `1` (incorrect) | `0.8670` | `PHISHING` |
| After fix (eTLD+1 compare) | `0` (correct) | `0.5621` | `SUSPICIOUS` |

The remaining `SUSPICIOUS` verdict after the fix comes from unrelated
features on this URL (phishing-keyword density from `login`/`verify`), not
from the redirect signal — confirming the fix removed exactly the intended
false-positive contribution rather than masking other signals. Regression
coverage: `tests/test_psl.py`.

## Domain Age (RDAP)

`--check-domain-age` (CLI: `url`, `eml`; REST: `POST /v1/url`'s
`check_domain_age`) looks up the registrable domain's registration date via
RDAP (`domain_age.py`) and adds three features: `domain_newer_than_30d`
(weight `0.65`) and `domain_newer_than_90d` (weight `0.30`, additive with
the first for a domain under 30 days old) raise risk; `domain_older_than_2y`
(weight `-0.60`, domains registered 730+ days ago) lowers it. All three are
absent — not zero — when the age can't be determined, so an unknown age
contributes no risk either way, the same convention `redirect_hops` already
uses.

This closes a gap the project's own live-traffic validation quantified
directly: of the phishing URLs the string-only model still misses, most are
bare-root URLs with no path, where every existing feature (keywords, TLD,
entropy, free-hosting) has nothing to match against. Registration recency
is a domain-level signal that exists whether or not the URL has a path, so
it reaches exactly the cases the other features structurally can't.

**Deliberately not part of the default scan or `batch`.** Domain age is the
only feature in PhishGuard that makes a network call to a *third party*
(the free `rdap.org` bootstrap) rather than to the URL being scored. Two
consequences follow directly, not as bugs:

- It's opt-in, so PhishGuard's offline promise stays true by default.
- It's excluded from `batch`, because `rdap.org` rate-limits aggressively
  (429s were observed after roughly ten rapid lookups during development)
  and scanning a URL list would hammer a shared public service. Bulk
  research use should go through
  `tools/evaluate_live_traffic_benchmark.py --check-domain-age
  --domain-age-delay`, which paces its own requests.

Every RDAP failure mode — timeout, 404 (no participating registry for that
TLD), 429, malformed JSON, no `registration` event in the response —
degrades to "unknown" rather than raising, and results are cached per
registrable domain for the life of the process so a single `.eml` scan or
benchmark run never looks the same domain up twice.

**Weight rationale.** `0.65`/`0.30` sit in the same range as the model's
other strong single-signal features (`suspicious_tld` `0.70`,
`on_free_hosting_platform` `0.70`, `has_ip_address` `0.90`) rather than
being decisive on their own — a newly-registered domain with no other
suspicious characteristic lands in `SUSPICIOUS`, not an automatic
`PHISHING`, consistent with the model's existing "supporting evidence, not
proof" posture toward every other single feature (see the email
authentication section above for the same philosophy applied to SPF/DKIM/DMARC).

**Live-traffic validation (2026-08-24):** re-running
`tools/evaluate_live_traffic_benchmark.py` against a fresh OpenPhish feed
and the top 300 Tranco domains, with domain-age enabled:

| Metric | Offline only | + domain age |
|---|---|---|
| Recall (flag = PHISHING or SUSPICIOUS) | 55.0% (165/300) | **65.7%** (197/300) |
| Recall (strict PHISHING only) | 29.7% (89/300) | **32.7%** (98/300) |
| False positives on real legitimate sites | 0/1,000 | **0/300** |

See `docs/BENCHMARK.md`'s "Domain-Age Validation" section for the full
methodology, the sample-size caveat on the false-positive row, and what
this still doesn't fix.

### Domain-age false-positive suppression

`domain_older_than_2y` is the mirror-image feature: registration age also
lowers risk for domains old enough that a fresh-registration-based attack
is implausible. It exists to partially mitigate two false-positive shapes
named in Known Limitations — branded subdomains (`accounts.{domain}`,
`secure.{domain}`) and keyword-dense paths — that the query-string scoping
fix above deliberately didn't touch, since neither is a query-string
problem.

**Weight rationale.** `-0.60` was chosen conservatively, not maximally: a
stronger negative weight flips more false positives, but this feature can
only fire when a caller opts in and has network access, and — more
importantly — old domains are also exactly the category
`docs/BENCHMARK.md`'s "Domain-Age Validation" already names as unaddressed
(compromised or abused-as-a-service infrastructure, e.g. the `s4w.in`
example there). A strong negative weight for "old domain" would directly
work against detecting that category. `-0.60` was picked as the point that
meaningfully helps the false-positive shapes above without being aggressive
enough to erase that signal — see the validation below for the real-recall
check this reasoning was verified against, not just assumed.

**Validation (2026-08-24):** individual real-domain spot checks —
`accounts.google.com/signin` and `secure.github.com/login` (offline:
`SUSPICIOUS`) both move to `SAFE`; `github.com/support/account/security/
verify-identity` (offline: `PHISHING`, 0.9291) drops to 0.7745 — real
improvement, but not enough alone to clear the `SUSPICIOUS` threshold at
this weight (a stronger weight, empirically `-0.90`, would flip it, but was
rejected — see the weight rationale above).

At scale (150 real domains x the same 10 templates as the stress test
above, `--check-domain-age`): overall false-positive rate 21.4%->**15.7%**,
strict PHISHING 10.3%->**6.1%**; `accounts_subdomain` flagged 69.0%->**26.7%**,
`secure_subdomain_login` flagged 24.2%->**12.0%**; `support_verify_identity`
strict PHISHING 100%->**56.0%** -- confirms the single-case result above
generalizes: roughly half of the previously-guaranteed false positives on
this shape now land in `SUSPICIOUS` instead, real softening, not a full fix.

Real recall was re-checked on the same live-traffic + domain-age
methodology as the table above, on a fresh feed, to confirm this weight
doesn't cost detection of old-but-compromised phishing domains: 62.0%
flagged / 37.3% strict PHISHING, 0 false positives on 300 real legitimate
domains -- held steady, not below the offline baseline. See
`docs/BENCHMARK.md`'s "Domain-Age False-Positive Suppression" for the full
tables.

This does not fix the default offline path — both false-positive shapes
above are still present without `--check-domain-age` (or when RDAP is
unreachable). Closing that gap needs the deferred domain-reputation signal
discussed in Known Limitations.

## Change Standard

A detection change should include:

- A named and explainable feature rather than an opaque score adjustment.
- Synthetic or reserved-domain positive cases.
- Legitimate negative cases that guard against false positives.
- Before-and-after scores and verdicts.
- A rationale for the weight and its interaction with existing features.
- A passing full test suite on every supported Python version.

Threshold or weight changes should be deferred when the available examples
cannot distinguish an improvement from overfitting.

## Known Limitations

- The model does not fetch page content or inspect TLS certificates. It can
  optionally follow redirects (`--follow-redirects`) and look up domain
  registration age via RDAP (`--check-domain-age`), but both are opt-in and
  off by default; the offline default scans the URL string alone.
- It does not query DNS, blocklists, or threat intelligence, and domain age
  is best-effort against one free, rate-limited third-party bootstrap —
  many lookups legitimately resolve to "unknown" rather than an age.
- It parses supplied authentication results but does not independently
  validate SPF, DKIM, DMARC, DNS policy, or cryptographic signatures.
- Unicode confusable-character and brand-impersonation matching are not implemented.
- The current regression set is small and is not a population-level accuracy
  benchmark. The live-traffic validations (free-hosting, domain age) are
  larger and use real, dated samples, but are still snapshots, not a
  permanent accuracy claim — see docs/BENCHMARK.md.
- Even with domain age enabled, roughly a third of missed live phishing
  samples are on domains many months or years old (compromised or
  abused-as-a-service infrastructure, not freshly registered) — no feature
  in this model addresses that category. See docs/BENCHMARK.md's
  "Domain-Age Validation" for the specific example found during this audit.
- **Realistic security-relevant URL shapes** (login pages, password-reset
  links with tokens, verification paths, branded subdomains) previously had
  a severe false-positive rate — up to 100% on some shapes — because
  `url_length`, `special_char_count`, and `digit_ratio` were scored against
  the *whole* URL, so a realistic token-bearing security link was
  structurally indistinguishable from obfuscation. This is now
  substantially fixed: those three features are scored on
  `scheme://host/path` only (query-string tokens carry almost no signal —
  see `query_length`/`query_param_count`), `url_length` is capped at 80
  characters, and the typosquat weight was lowered so a lone edit-distance
  collision (e.g. `hicloud.com` vs. `icloud.com`) lands in `SUSPICIOUS`, not
  `PHISHING`. Measured on the same 3,000-domain × 10-template stress test:
  overall false-positive rate 40.0%→**21.4%**, strict PHISHING 27.4%→**10.3%**,
  with `password_reset_link` (previously 100%/100%) down to 4.3%/0.3%. See
  docs/BENCHMARK.md's "False-Positive Stress Test" for the full before/after
  table and methodology.
- **Two categories in that same stress test are not fixed by the query-string
  change above**, named rather than hidden: (1) `subdomain_count` still
  penalizes branded subdomains like `accounts.{domain}` (69.0% flagged) and
  `secure.{domain}` (24.2% flagged) offline — this is a domain-reputation
  problem, not a length/query problem; (2) a URL with several generic
  security keywords packed into a deep path but no query string
  (`/support/account/security/verify-identity`, 100% flagged, 100% strict
  PHISHING offline) is driven by `phishing_keywords` density plus base path
  length, neither of which the query-string fix touches — tuning either
  weight down to fix this one shape was rejected as likely overfitting (see
  the Change Standard above) without domain-reputation context to tell a
  real branded path from an imitation of one.
- **Partially mitigated, opt-in only:** `domain_older_than_2y` (see "Domain
  Age (RDAP)" above) fixes both branded-subdomain cases (`SUSPICIOUS`→`SAFE`
  for real, long-established domains) and meaningfully reduces the
  keyword-dense case (0.9291→0.7745, though not enough to clear the
  threshold at the chosen, deliberately conservative weight). This only
  applies when a caller opts into `--check-domain-age` and has network
  access — **the default offline path still has both gaps, unchanged.**
- **A full offline fix remains deferred**: the existing 47-entry brand
  reference list is far too small to help as a general reputation signal
  (fires on ~1.4% of real domains), and a larger bundled popularity list
  raises an unresolved third-party redistribution-licensing question that
  hasn't been resolved. This is the one remaining piece of the tracked
  rearchitecture plan without a shipped fix.

Issue #3 tracks a labeled evaluation benchmark for reproducible regression
metrics. Population-level accuracy or calibration claims require a larger,
representative dataset with documented provenance.
