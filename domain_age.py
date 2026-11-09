"""Domain-age lookup via RDAP -- an optional, network-dependent signal.

Newly-registered domains are one of the strongest real-world phishing
indicators: most phishing domains are registered within days of a campaign,
but a URL string alone cannot reveal registration date. This module is the
one place PhishGuard makes a network call to a *fixed, trusted* third party
(the RDAP bootstrap at rdap.org) to look up a domain's registration date --
never to the domain being scored itself, so this carries none of the SSRF
exposure that redirect.py guards against (the connection target is always
rdap.org; the scored domain is only ever sent as a URL path segment).

Registration age cuts both ways: a domain young enough raises risk
(`domain_newer_than_30d`/`90d`), and a domain old enough lowers it
(`domain_older_than_2y`) -- a real, if partial, mitigation for the
false-positive gap the offline default has on branded subdomains and
keyword-dense paths (see docs/DETECTION_MODEL.md's Known Limitations).
It's a partial fix, not a full one: it only applies when a caller opts in
and has network access, so the default offline path is unaffected.

Every failure -- timeout, no RDAP record, rate limiting, a TLD with no
participating registry, malformed JSON -- is caught and turned into
"unknown" rather than raised, so a caller can never have a scan break just
because it opted into this. Opt-in only: the default, offline scan never
calls this module. See docs/BENCHMARK.md's "Domain-Age Validation" section
for the measured recall/false-positive impact and docs/DETECTION_MODEL.md
for the feature weights.

rdap.org's free bootstrap rate-limits aggressively (observed 429s after
roughly ten rapid requests during development). This module does not retry
or back off on 429 -- a rate-limited lookup degrades to "unknown" exactly
like any other failure, which is the honest behavior for a shared public
service. Callers that need to check many domains (see
tools/evaluate_live_traffic_benchmark.py's --check-domain-age) should add
their own delay between lookups; the CLI and REST server intentionally
offer this feature only for single-URL lookups (`url`, `eml`, `POST
/v1/url`), not `batch`, so routine use can't hammer the shared service.
"""

from __future__ import annotations

import ipaddress
import json
import re
import urllib.error
import urllib.request
from datetime import datetime, timezone
from urllib.parse import quote, urlparse

from psl import registrable_domain

_RDAP_BASE = "https://rdap.org/domain/"
_USER_AGENT = (
    "PhishGuard-AI/0.5 domain-age-lookup "
    "(+https://github.com/omobolajiadeyan/phishguard-ai)"
)

# Newly-registered-domain thresholds. Both may be 1 at once (a 10-day-old
# domain is also "newer than 90d"); see model.py for the weight rationale.
_NEW_DOMAIN_DAYS = 30
_RECENT_DOMAIN_DAYS = 90

# Established-domain threshold, for the opposite direction: reducing risk
# for domains old enough that a fresh-registration-based attack is
# implausible. Deliberately conservative (2 years) so a legitimate but
# fairly new business gets no bonus rather than a wrong one -- this key is
# additive risk *reduction* only, so under-firing is the safe failure mode,
# unlike domain_newer_than_30d/90d where under-firing would miss real
# signal. See model.py for the weight rationale and docs/BENCHMARK.md's
# "Domain-Age False-Positive Suppression" for the measured effect.
_ESTABLISHED_DOMAIN_DAYS = 730

# Per-process cache keyed by registrable domain, so a single .eml or batch
# run never looks the same domain up twice -- both to spare the shared
# rdap.org service and because repeated lookups add nothing.
_cache: dict[str, int | None] = {}
_DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$"
)


def _is_ip_literal(hostname: str) -> bool:
    try:
        ipaddress.ip_address(hostname)
        return True
    except ValueError:
        return False


def _is_valid_registrable_domain(domain: str) -> bool:
    return bool(_DOMAIN_RE.fullmatch(domain))


def _parse_registration_date(payload: dict) -> datetime | None:
    for event in payload.get("events", []) or []:
        if event.get("eventAction") != "registration":
            continue
        raw_date = event.get("eventDate")
        if not raw_date:
            return None
        try:
            return datetime.fromisoformat(raw_date.replace("Z", "+00:00"))
        except ValueError:
            return None
    return None


def _fetch_registration_age_days(domain: str, timeout: float) -> int | None:
    # Re-validated here, at the network call itself, rather than trusting
    # the caller's already-done check (lookup_domain_age_days() validates
    # too, before registrable_domain()'s output ever reaches this
    # function) -- this is the actual SSRF-relevant boundary, so it should
    # be safe on its own regardless of what future caller reaches it. The
    # regex only allows DNS-label characters, so this also makes the
    # quote() below belt-and-suspenders rather than the only guard: no
    # "/", "?", "#", "@", or control character can reach the request URL.
    if not _is_valid_registrable_domain(domain):
        return None
    encoded_domain = quote(domain, safe="")
    request = urllib.request.Request(
        _RDAP_BASE + encoded_domain,
        headers={"User-Agent": _USER_AGENT, "Accept": "application/rdap+json"},
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            payload = json.loads(response.read().decode("utf-8"))
    except Exception:
        # Deliberately broad: DNS failure, timeout, HTTP 4xx/5xx (including
        # the 429s this free bootstrap issues under load), TLS errors, and
        # malformed JSON all mean the same thing to a caller -- "unknown".
        return None

    registered = _parse_registration_date(payload)
    if registered is None:
        return None
    return max((datetime.now(timezone.utc) - registered).days, 0)


def lookup_domain_age_days(url: str, timeout: float = 5.0) -> int | None:
    """Return the registrable domain's age in days, or None when unknown."""
    try:
        hostname = (urlparse(url).hostname or "").lower()
    except ValueError:
        return None
    if not hostname or _is_ip_literal(hostname):
        return None

    domain = registrable_domain(hostname)
    if not _is_valid_registrable_domain(domain):
        return None
    if domain in _cache:
        return _cache[domain]

    age_days = _fetch_registration_age_days(domain, timeout)
    _cache[domain] = age_days
    return age_days


def domain_age_features(url: str, timeout: float = 5.0) -> dict:
    """Build the extra_features dict `score_url` expects.

    Returns an empty dict when the age is unknown, so the caller's merged
    feature dict behaves exactly like an offline scan -- the weighted sum in
    model.py skips any key that's simply absent, contributing zero risk
    rather than guessing.
    """
    age_days = lookup_domain_age_days(url, timeout=timeout)
    if age_days is None:
        return {}
    return {
        "domain_newer_than_30d": int(age_days < _NEW_DOMAIN_DAYS),
        "domain_newer_than_90d": int(age_days < _RECENT_DOMAIN_DAYS),
        "domain_older_than_2y": int(age_days >= _ESTABLISHED_DOMAIN_DAYS),
    }
