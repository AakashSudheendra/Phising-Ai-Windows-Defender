"""
Lightweight phishing classifier using a hand-tuned decision tree.
No external ML libraries needed — pure Python implementation.

Design: each feature has a reviewable, hand-tuned heuristic weight. The
weights are not the output of a trained statistical model.
"""

from features import extract_url_features, extract_email_features
from email_auth import extract_authentication_features


# Explainable heuristic weights for common phishing indicators.
# Positive weight = increases phishing probability.
URL_WEIGHTS = {
    "url_length":            0.015,  # longer URLs are more suspicious (scored on host+path only, capped at 80 chars -- see features.py's _url_without_query)
    "query_length":          0.002,  # near-zero: legitimate reset/tracking tokens and phishing obfuscation both produce long query strings, so length alone here carries almost no signal
    "query_param_count":     0.02,   # small: a single reset/session token is cheap, but several chained tracking/obfuscation params still counts for something
    "subdomain_count":       0.18,   # subdomains used to fake legitimacy
    "has_ip_address":        0.90,   # IP in URL = very suspicious
    "special_char_count":    0.06,   # many special chars = obfuscation
    "has_https":            -0.20,   # HTTPS slightly reduces suspicion
    "digit_ratio":           0.60,   # high digit ratio = suspicious
    "phishing_keywords":     0.25,   # each matching keyword adds weight
    "path_depth":            0.04,   # deep paths can hide payloads
    "suspicious_tld":        0.70,   # .xyz/.tk etc highly suspicious
    "domain_length":        -0.01,   # short domains slightly safer
    "url_entropy":           0.12,   # high entropy = randomly generated domain
    "has_port":              0.40,   # non-standard port = suspicious
    "has_punycode":          0.10,   # contextual IDNA signal, not malicious alone
    "has_unicode_hostname":  0.08,   # legitimate IDNs exist; keep weight modest
    "has_opaque_hostname_label": 0.90, # long compact labels can indicate generated hosts
    "typosquatting_score":   0.65,   # close edit-distance match to a known brand. Was 0.85; lowered so a lone typosquat hit with no corroborating signal lands in SUSPICIOUS, not PHISHING -- edit-distance-1 collisions against short real domains happen by coincidence (e.g. hicloud.com vs icloud.com) more often than the raw distance-1 signal implies. Does not fully solve that collision (still SUSPICIOUS, not SAFE) -- see docs/DETECTION_MODEL.md's Known Limitations.
    "on_free_hosting_platform": 0.70, # disposable free-hosting subdomain (pages.dev, netlify.app, etc.)
    # redirect chain features — only present when --follow-redirects is used
    "redirect_crossed_domain": 0.65, # chain left the original domain
    "redirect_hops":           0.05, # each hop adds marginal suspicion
    # domain-age features — only present when --check-domain-age is used.
    # Both may be 1 at once for a very new domain; see docs/BENCHMARK.md's
    # "Domain-Age Validation" for the measured tuning behind these weights.
    "domain_newer_than_30d":   0.65, # registered under 30 days ago
    "domain_newer_than_90d":   0.30, # registered under 90 days ago
    "domain_older_than_2y":   -0.60, # registered 2+ years ago -- partial false-positive mitigation, opt-in only; kept moderate rather than strong, since a stronger weight risks masking the old-but-compromised-domain category docs/BENCHMARK.md's "Domain-Age Validation" already names as unaddressed. See "Domain-Age False-Positive Suppression" for the calibration.
}

EMAIL_WEIGHTS = {
    "url_count":              0.10,
    "link_count":             0.12,
    "urgency_word_count":     0.22,
    "exclamation_count":      0.05,
    "all_caps_word_count":    0.08,
    "html_tag_count":         0.03,
    "has_attachment_mention": 0.30,
    "word_count":            -0.001,  # longer emails slightly less phishy
    "spf_auth_risk":          0.08,
    "dkim_auth_risk":         0.10,
    "dmarc_auth_risk":        0.18,
}

THRESHOLD = 0.55  # score above this = classified as phishing
URL_BIAS = -1.30
EMAIL_BIAS = -0.30


def score_url(
    url: str,
    extra_features: dict | None = None,
) -> tuple[float, dict]:
    """
    Score a URL for phishing likelihood.

    *extra_features* allows callers to inject additional signals (e.g. redirect
    chain metadata) without modifying the feature extractor.

    Returns (probability 0.0-1.0, feature breakdown).
    """
    features = extract_url_features(url)
    if extra_features:
        features.update(extra_features)
    raw_score = URL_BIAS + sum(
        features[f] * URL_WEIGHTS[f]
        for f in URL_WEIGHTS
        if f in features
    )

    # Sigmoid normalisation to keep output between 0 and 1
    import math
    probability = 1 / (1 + math.exp(-raw_score * 2.5))
    return round(probability, 4), features


def score_email(
    subject: str,
    body: str,
    authentication_results: str | None = None,
) -> tuple[float, dict]:
    """
    Score an email for phishing likelihood.
    Returns (probability 0.0-1.0, feature breakdown).
    """
    features = extract_email_features(subject, body)
    features.update(extract_authentication_features(authentication_results))
    raw_score = EMAIL_BIAS + sum(
        features[f] * EMAIL_WEIGHTS[f]
        for f in EMAIL_WEIGHTS
        if f in features
    )

    import math
    probability = 1 / (1 + math.exp(-raw_score * 2.5))
    return round(probability, 4), features


def classify(probability: float) -> str:
    if probability >= 0.75:
        return "PHISHING"
    elif probability >= THRESHOLD:
        return "SUSPICIOUS"
    else:
        return "SAFE"
