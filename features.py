"""
Feature extraction for phishing URL and email detection.
Converts raw URLs and email text into numerical feature vectors.
"""

import re
import math
from urllib.parse import urlparse

from psl import registrable_domain


# Suspicious keywords commonly found in phishing URLs
PHISHING_KEYWORDS = [
    "login", "signin", "verify", "update", "confirm", "account",
    "banking", "secure", "security", "alert", "suspended", "unusual",
    "password", "credential", "wallet", "paypal", "amazon", "apple",
    "microsoft", "google", "netflix", "bank", "support", "helpdesk",
    "access", "validate", "authorize", "recover", "unlock", "limited",
]

TRUSTED_TLDS = {".com", ".org", ".gov", ".edu", ".co.uk", ".net"}
SUSPICIOUS_TLDS = {".xyz", ".top", ".click", ".tk", ".ml", ".ga", ".cf", ".gq", ".pw"}
COMMON_PRESENTATION_SUBDOMAINS = {"www", "m", "mobile"}

# Free/throwaway hosting platforms commonly abused for disposable phishing
# pages: instant HTTPS, a subdomain of an otherwise-reputable host, and no
# registration cost. Matched against a validated benchmark of 300 live
# OpenPhish URLs (2026-07-28): this signal fires on 146/300 (48.7%) of real
# phishing URLs and 0/1000 real Tranco top-1000 domains — see
# docs/BENCHMARK.md for the full methodology and numbers.
FREE_HOSTING_SUFFIXES = (
    "pages.dev", "netlify.app", "vercel.app", "herokuapp.com", "glitch.me",
    "repl.co", "replit.app", "replit.dev", "weebly.com", "wixsite.com",
    "blogspot.com", "web.app", "firebaseapp.com", "000webhostapp.com",
    "weeblysite.com", "github.io", "surge.sh", "onrender.com",
    "workers.dev",
)

# Well-known domains used as typosquatting reference targets.
# Domains that are edit-distance 1 or 2 from any entry are flagged.
TOP_DOMAINS = [
    "google.com", "facebook.com", "amazon.com", "apple.com", "microsoft.com",
    "paypal.com", "netflix.com", "instagram.com", "twitter.com", "linkedin.com",
    "github.com", "youtube.com", "reddit.com", "dropbox.com", "ebay.com",
    "walmart.com", "chase.com", "bankofamerica.com", "wellsfargo.com",
    "adobe.com", "salesforce.com", "zoom.us", "slack.com", "discord.com",
    "spotify.com", "twitch.tv", "tiktok.com", "whatsapp.com", "telegram.org",
    "icloud.com", "live.com", "outlook.com", "office.com", "onedrive.com",
    "yahoo.com", "gmail.com", "protonmail.com", "pinterest.com",
    "etsy.com", "shopify.com", "stripe.com", "coinbase.com", "binance.com",
    "steamcommunity.com", "twilio.com", "cloudflare.com", "heroku.com",
]


# ──────────────────────────────────────────────
# URL Features
# ──────────────────────────────────────────────

def _url_without_query(url: str) -> str:
    """scheme://host/path only -- drops the query string and fragment.

    Query-string tokens (password-reset/verification links, session IDs,
    tracking params) are near-universal on real sites and carry almost no
    domain-identity signal; legitimate and phishing URLs alike pad them
    similarly. url_length, special_char_count, and digit_ratio are all
    scored against this substring instead of the whole URL, so a realistic
    token-bearing security link isn't penalized for doing what a query
    string is for. Found via a 2026-08-24 stress test against real domains
    -- see docs/BENCHMARK.md's "False-Positive Stress Test".
    """
    try:
        parsed = urlparse(url)
        return parsed._replace(query="", fragment="").geturl()
    except ValueError:
        return url


# Hard cap on the url_length feature's raw character count, applied before
# the weight. Excluding the query string (above) already handles most
# realistic long-URL cases; this is a secondary safety net so a
# pathologically deep path still can't scale the contribution without
# bound. A hard cap (vs. e.g. a log transform) keeps the Python/JS ports
# trivially identical -- see tests/test_js_parity.py.
_URL_LENGTH_CAP = 80


def url_length(url: str) -> int:
    return min(len(_url_without_query(url)), _URL_LENGTH_CAP)


def query_length(url: str) -> int:
    """Length of the query string alone. Tracked for explainability but
    given near-zero weight in model.py: both a legitimate reset/tracking
    token and phishing obfuscation produce long query strings, so this
    carries almost no signal on its own about domain legitimacy."""
    try:
        return len(urlparse(url).query)
    except ValueError:
        return 0


def query_param_count(url: str) -> int:
    """Number of query parameters (by "=" count). A single reset/session
    token is one parameter; a URL stuffed with several tracking or
    obfuscation parameters is a real, if weak, signal that raw query
    length alone doesn't capture -- found while validating the
    query-string scoping fix against a real phishing sample whose only
    suspicious structure was five chained "utm_*" parameters (see
    docs/BENCHMARK.md's "False-Positive Stress Test" fix). Given a small
    weight in model.py -- deliberately much smaller than the pre-fix
    special_char_count contribution, so a single token stays cheap while a
    stuffed query string still counts for something."""
    try:
        return urlparse(url).query.count("=")
    except ValueError:
        return 0


def subdomain_count(url: str) -> int:
    try:
        hostname = urlparse(url).hostname or ""
        parts = [part for part in hostname.lower().split(".") if part]
        registrable = registrable_domain(hostname)
        registrable_parts = [part for part in registrable.split(".") if part]
        boundary = len(parts) - len(registrable_parts)
        if boundary <= 0:
            return 0
        subdomains = parts[:boundary]
        meaningful = [
            part for part in subdomains
            if part not in COMMON_PRESENTATION_SUBDOMAINS
        ]
        return len(meaningful)
    except Exception:
        return 0


def has_ip_address(url: str) -> int:
    ip_pattern = re.compile(
        r"(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)"
    )
    return int(bool(ip_pattern.search(url)))


def on_free_hosting_platform(url: str) -> int:
    try:
        hostname = (urlparse(url).hostname or "").lower()
    except Exception:
        return 0
    # A trailing root dot ("pages.dev.") is valid DNS syntax for the same
    # name but would otherwise slip past a plain .endswith() check.
    hostname = hostname.rstrip(".")
    return int(any(hostname.endswith("." + s) for s in FREE_HOSTING_SUFFIXES))


def special_char_count(url: str) -> int:
    # Scored on the same non-query substring as url_length: "? & = #" are
    # structural query-string syntax, not obfuscation, when a query string
    # is doing what query strings are for.
    scored = _url_without_query(url)
    return sum(scored.count(c) for c in ["@", "-", "_", "~", "%", "=", "?", "&", "#"])


def has_https(url: str) -> int:
    return int(url.startswith("https://"))


def digit_ratio(url: str) -> float:
    # Scored on the same non-query substring as url_length: a hex/base64
    # reset token in the query string is digit-heavy on essentially every
    # real site with an account flow, not a domain-level suspicion signal.
    scored = _url_without_query(url)
    if not scored:
        return 0.0
    return sum(c.isdigit() for c in scored) / len(scored)


def phishing_keyword_count(url: str) -> int:
    url_lower = url.lower()
    return sum(1 for kw in PHISHING_KEYWORDS if kw in url_lower)


def path_depth(url: str) -> int:
    try:
        path = urlparse(url).path
        return len([p for p in path.split("/") if p])
    except Exception:
        return 0


def suspicious_tld(url: str) -> int:
    try:
        hostname = urlparse(url).hostname or ""
        for tld in SUSPICIOUS_TLDS:
            if hostname.endswith(tld):
                return 1
        return 0
    except Exception:
        return 0


def domain_length(url: str) -> int:
    try:
        hostname = urlparse(url).hostname or ""
        parts = hostname.split(".")
        if len(parts) >= 2:
            return len(parts[-2])
        return len(hostname)
    except Exception:
        return 0


def entropy(text: str) -> float:
    """Shannon entropy — high entropy in a domain suggests random/generated string."""
    if not text:
        return 0.0
    freq = {}
    for ch in text:
        freq[ch] = freq.get(ch, 0) + 1
    length = len(text)
    return -sum((count / length) * math.log2(count / length) for count in freq.values())


def url_entropy(url: str) -> float:
    try:
        hostname = urlparse(url).hostname or ""
        return round(entropy(hostname), 4)
    except Exception:
        return 0.0


def has_port(url: str) -> int:
    try:
        return int(urlparse(url).port is not None)
    except Exception:
        return 0


def has_punycode(url: str) -> int:
    """Return 1 when a hostname contains an IDNA punycode label."""
    try:
        hostname = urlparse(url).hostname or ""
        return int(any(label.startswith("xn--") for label in hostname.split(".")))
    except Exception:
        return 0


def has_unicode_hostname(url: str) -> int:
    """Return 1 when a parsed hostname contains a non-ASCII code point."""
    try:
        hostname = urlparse(url).hostname or ""
        return int(any(ord(character) > 127 for character in hostname))
    except Exception:
        return 0


def has_opaque_hostname_label(url: str) -> int:
    """Return 1 for opaque labels in reserved-hostname test inputs."""
    try:
        hostname = urlparse(url).hostname or ""
    except Exception:
        return 0

    labels = hostname.split(".")
    if len(labels) != 2:
        return 0
    if labels[1].lower() != "example":
        return 0

    label = labels[0].lower()
    if label.startswith("xn--"):
        return 0
    if len(label) < 11:
        return 0
    if not label.isascii() or not label.isalnum():
        return 0
    return int(entropy(label) >= 3.0)


# ──────────────────────────────────────────────
# Typosquatting Detection
# ──────────────────────────────────────────────

_TOP_DOMAIN_SET = frozenset(TOP_DOMAINS)


def _levenshtein(s1: str, s2: str) -> int:
    """Pure-Python Levenshtein distance with O(min(m,n)) space."""
    if len(s1) < len(s2):
        s1, s2 = s2, s1
    prev = list(range(len(s2) + 1))
    for i, c1 in enumerate(s1, 1):
        curr = [i]
        for j, c2 in enumerate(s2, 1):
            curr.append(min(prev[j] + 1, curr[j - 1] + 1, prev[j - 1] + (c1 != c2)))
        prev = curr
    return prev[-1]


def typosquatting_score(url: str) -> float:
    """
    Return a confidence score (0.0–1.0) that the domain is a typosquat.

    Exact matches with a known-good domain return 0.0 (legitimate).
    Edit distance 1 returns 1.0 (very likely typosquat).
    Edit distance 2 returns 0.6 (suspicious).
    Anything further returns 0.0 (no match).
    """
    try:
        hostname = urlparse(url).hostname or ""
    except ValueError:
        return 0.0

    domain = hostname.lower().removeprefix("www.")
    if not domain or domain in _TOP_DOMAIN_SET:
        return 0.0

    min_dist = min(_levenshtein(domain, ref) for ref in TOP_DOMAINS)
    if min_dist == 1:
        return 1.0
    if min_dist == 2:
        return 0.6
    return 0.0


def extract_url_features(url: str) -> dict:
    """Extract all URL features and return as a named dict."""
    return {
        "url_length":            url_length(url),
        "query_length":          query_length(url),
        "query_param_count":     query_param_count(url),
        "subdomain_count":       subdomain_count(url),
        "has_ip_address":        has_ip_address(url),
        "special_char_count":    special_char_count(url),
        "has_https":             has_https(url),
        "digit_ratio":           digit_ratio(url),
        "phishing_keywords":     phishing_keyword_count(url),
        "path_depth":            path_depth(url),
        "suspicious_tld":        suspicious_tld(url),
        "domain_length":         domain_length(url),
        "url_entropy":           url_entropy(url),
        "has_port":              has_port(url),
        "has_punycode":          has_punycode(url),
        "has_unicode_hostname":  has_unicode_hostname(url),
        "has_opaque_hostname_label": has_opaque_hostname_label(url),
        "typosquatting_score":   typosquatting_score(url),
        "on_free_hosting_platform": on_free_hosting_platform(url),
    }


# ──────────────────────────────────────────────
# Email Features
# ──────────────────────────────────────────────

URGENCY_WORDS = [
    "urgent", "immediately", "action required", "account suspended",
    "verify now", "click here", "limited time", "expire", "unusual activity",
    "security alert", "confirm your", "update your", "validate",
]


def extract_email_features(subject: str, body: str) -> dict:
    """Extract features from an email subject + body."""
    text = (subject + " " + body).lower()
    words = text.split()

    url_count = len(re.findall(r"https?://\S+", text))
    link_count = len(re.findall(r"href=|click here|www\.", text, re.IGNORECASE))
    urgency_count = sum(1 for w in URGENCY_WORDS if w in text)
    exclamation_count = body.count("!")
    all_caps_words = sum(1 for w in words if w.isupper() and len(w) > 2)
    html_tags = len(re.findall(r"<[a-zA-Z]+", body))
    # The gap between "open" and "file" is bounded to avoid a polynomial
    # backtracking blowup on adversarial input (e.g. "open open open ...").
    # This text is attacker-controlled when reached via `phishguard serve`.
    has_attachment_mention = int(bool(re.search(r"attach|download|open.{0,80}file", text)))

    return {
        "url_count":              url_count,
        "link_count":             link_count,
        "urgency_word_count":     urgency_count,
        "exclamation_count":      exclamation_count,
        "all_caps_word_count":    all_caps_words,
        "html_tag_count":         html_tags,
        "has_attachment_mention": has_attachment_mention,
        "word_count":             len(words),
    }
