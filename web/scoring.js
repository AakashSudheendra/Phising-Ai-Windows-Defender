"use strict";

// Client-side port of the Python scoring model (features.py, model.py,
// email_auth.py), so the demo works fully offline as a static page (e.g.
// GitHub Pages) with no backend to run or keep alive. This is a second,
// independent implementation of the same heuristics -- see
// tests/test_js_parity.py, which runs both implementations on shared cases
// and fails the suite if they ever disagree, so this file can't silently
// drift from the Python original it mirrors.
//
// Faithfully mirrors the Python source function-by-function; if you change
// features.py, model.py, or email_auth.py, mirror the change here too.

const PhishGuardPsl =
  typeof module !== "undefined" && module.exports
    ? require("./public-suffix.js")
    : PhishGuardPublicSuffix;

const PhishGuardScoring = (() => {
  const PHISHING_KEYWORDS = [
    "login", "signin", "verify", "update", "confirm", "account",
    "banking", "secure", "security", "alert", "suspended", "unusual",
    "password", "credential", "wallet", "paypal", "amazon", "apple",
    "microsoft", "google", "netflix", "bank", "support", "helpdesk",
    "access", "validate", "authorize", "recover", "unlock", "limited",
  ];

  const SUSPICIOUS_TLDS = [".xyz", ".top", ".click", ".tk", ".ml", ".ga", ".cf", ".gq", ".pw"];
  const COMMON_PRESENTATION_SUBDOMAINS = new Set(["www", "m", "mobile"]);

  // Free/throwaway hosting platforms commonly abused for disposable
  // phishing pages. Validated against a real 300-URL OpenPhish sample
  // (2026-07-28): fires on 146/300 real phishing URLs, 0/1000 real
  // Tranco top-1000 domains. See docs/BENCHMARK.md.
  const FREE_HOSTING_SUFFIXES = [
    "pages.dev", "netlify.app", "vercel.app", "herokuapp.com", "glitch.me",
    "repl.co", "weebly.com", "wixsite.com", "blogspot.com", "web.app",
    "firebaseapp.com", "000webhostapp.com", "weeblysite.com",
    "github.io", "surge.sh", "onrender.com", "workers.dev",
  ];

  const TOP_DOMAINS = [
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
  ];
  const TOP_DOMAIN_SET = new Set(TOP_DOMAINS);

  // --- URL features -------------------------------------------------

  // Python len(str) counts Unicode code points; JavaScript String.length
  // counts UTF-16 code units. Array.from keeps browser scoring in parity
  // for emoji and other non-BMP characters.
  function pythonLength(value) {
    return Array.from(value).length;
  }

  // Python's urlparse() never throws and validates almost nothing: it
  // accepts out-of-range IPv4 octets ("256.1.1.1"), doesn't canonicalize
  // octal-looking hosts ("0177.0.0.1" stays literal, unlike the WHATWG URL
  // parser which silently normalizes it to "127.0.0.1"), and only strips
  // *leading* whitespace/control characters. The native URL class enforces
  // real navigation-grade validation, which is stricter than that in ways
  // that would make this port disagree with the Python original on
  // malformed input -- so this mirrors urlparse's algorithm directly
  // instead of delegating to URL(). See tests/test_js_parity.py.
  // Query string after a "?" up to the next "#" (fragment), matching
  // urlparse's split -- factored out since both the netloc and no-netloc
  // branches below need it.
  function extractQueryFromSegment(segment) {
    const qIdx = segment.indexOf("?");
    if (qIdx === -1) return "";
    const afterQ = segment.slice(qIdx + 1);
    const hIdx = afterQ.indexOf("#");
    return hIdx === -1 ? afterQ : afterQ.slice(0, hIdx);
  }

  function pythonLikeUrlParse(rawUrl) {
    const url = String(rawUrl).replace(/^[ \t\r\n\f\v]+/, "");

    const schemeMatch = url.match(/^([a-zA-Z][a-zA-Z0-9+.-]*):/);
    const scheme = schemeMatch ? schemeMatch[1].toLowerCase() : "";
    let rest = url;
    if (schemeMatch) {
      rest = url.slice(schemeMatch[0].length);
    }

    let netloc = "";
    let path;
    let query;
    const hasNetloc = rest.startsWith("//");
    if (hasNetloc) {
      const afterSlashes = rest.slice(2);
      const end = afterSlashes.search(/[/?#]/);
      netloc = end === -1 ? afterSlashes : afterSlashes.slice(0, end);
      const remainder = end === -1 ? "" : afterSlashes.slice(end);
      path = remainder.split(/[?#]/)[0];
      query = extractQueryFromSegment(remainder);
    } else {
      path = rest.split(/[?#]/)[0];
      query = extractQueryFromSegment(rest);
    }

    let hostPart = netloc;
    const atIndex = hostPart.lastIndexOf("@");
    if (atIndex !== -1) hostPart = hostPart.slice(atIndex + 1);

    let hostname = "";
    let port = "";
    if (hostPart.startsWith("[")) {
      const closeIdx = hostPart.indexOf("]");
      if (closeIdx !== -1) {
        hostname = hostPart.slice(1, closeIdx).toLowerCase();
        const portPart = hostPart.slice(closeIdx + 1);
        if (portPart.startsWith(":")) port = portPart.slice(1);
      } else {
        hostname = hostPart.toLowerCase();
      }
    } else {
      const colonIdx = hostPart.lastIndexOf(":");
      if (colonIdx !== -1 && /^\d*$/.test(hostPart.slice(colonIdx + 1))) {
        hostname = hostPart.slice(0, colonIdx).toLowerCase();
        port = hostPart.slice(colonIdx + 1);
      } else {
        hostname = hostPart.toLowerCase();
      }
    }

    return { hostname, port, path, scheme, netloc, hasNetloc, query };
  }

  // scheme://host/path only -- drops the query string and fragment, the
  // same substring features.py's _url_without_query() scores url_length,
  // special_char_count, and digit_ratio against. Query-string tokens
  // (password-reset/verification links, session IDs, tracking params) are
  // near-universal on real sites and carry almost no domain-identity
  // signal. Mirrors Python's urlparse(url)._replace(query="",
  // fragment="").geturl() reconstruction rule exactly (verified against
  // every case in tests/test_js_parity.py's URL_CASES, including
  // no-scheme, no-netloc, and malformed input).
  function urlWithoutQuery(rawUrl) {
    const parsed = pythonLikeUrlParse(rawUrl);
    if (parsed.scheme && parsed.hasNetloc) {
      return parsed.scheme + "://" + parsed.netloc + parsed.path;
    }
    if (parsed.scheme) {
      return parsed.scheme + ":" + parsed.path;
    }
    return parsed.path;
  }

  function safeHostname(url) {
    return pythonLikeUrlParse(url).hostname;
  }

  function safePath(url) {
    return pythonLikeUrlParse(url).path;
  }

  function safePort(url) {
    return pythonLikeUrlParse(url).port;
  }

  // Hard cap on the raw character count before the weight is applied.
  // Excluding the query string (via urlWithoutQuery) already handles most
  // realistic long-URL cases; this is a secondary safety net so a
  // pathologically deep path still can't scale the contribution without
  // bound. Must match features.py's _URL_LENGTH_CAP exactly.
  const URL_LENGTH_CAP = 80;

  function urlLength(url) {
    return Math.min(pythonLength(urlWithoutQuery(url)), URL_LENGTH_CAP);
  }

  function queryLength(url) {
    return pythonLength(pythonLikeUrlParse(url).query);
  }

  function queryParamCount(url) {
    const query = pythonLikeUrlParse(url).query;
    return query.split("=").length - 1;
  }

  function subdomainCount(url) {
    const hostname = safeHostname(url);
    const parts = hostname ? hostname.toLowerCase().split(".").filter((p) => p.length > 0) : [];
    const registrable = PhishGuardPsl.registrableDomain(hostname);
    const registrableParts = registrable ? registrable.split(".").filter((p) => p.length > 0) : [];
    const boundary = parts.length - registrableParts.length;
    if (boundary <= 0) return 0;
    const subdomains = parts.slice(0, boundary);
    return subdomains.filter((part) => !COMMON_PRESENTATION_SUBDOMAINS.has(part)).length;
  }

  const IP_PATTERN = /(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)/;

  function onFreeHostingPlatform(url) {
    // A trailing root dot ("pages.dev.") is valid DNS syntax for the same
    // name but would otherwise slip past a plain endsWith() check.
    const hostname = safeHostname(url).replace(/\.+$/, "");
    return FREE_HOSTING_SUFFIXES.some((s) => hostname.endsWith("." + s)) ? 1 : 0;
  }

  function hasIpAddress(url) {
    return IP_PATTERN.test(url) ? 1 : 0;
  }

  function specialCharCount(url) {
    // Scored on the same non-query substring as urlLength: "? & = #" are
    // structural query-string syntax, not obfuscation, when a query
    // string is doing what query strings are for.
    const scored = urlWithoutQuery(url);
    const chars = ["@", "-", "_", "~", "%", "=", "?", "&", "#"];
    let count = 0;
    for (const c of chars) {
      count += scored.split(c).length - 1;
    }
    return count;
  }

  function hasHttps(url) {
    return url.startsWith("https://") ? 1 : 0;
  }

  function digitRatio(url) {
    // Scored on the same non-query substring as urlLength: a hex/base64
    // reset token in the query string is digit-heavy on essentially every
    // real site with an account flow, not a domain-level suspicion signal.
    const scored = urlWithoutQuery(url);
    if (!scored) return 0.0;
    let digits = 0;
    for (const ch of scored) {
      if (ch >= "0" && ch <= "9") digits += 1;
    }
    return digits / pythonLength(scored);
  }

  function phishingKeywordCount(url) {
    const lower = url.toLowerCase();
    let count = 0;
    for (const kw of PHISHING_KEYWORDS) {
      if (lower.includes(kw)) count += 1;
    }
    return count;
  }

  function pathDepth(url) {
    const path = safePath(url);
    return path.split("/").filter((p) => p.length > 0).length;
  }

  function suspiciousTld(url) {
    const hostname = safeHostname(url);
    for (const tld of SUSPICIOUS_TLDS) {
      if (hostname.endsWith(tld)) return 1;
    }
    return 0;
  }

  function domainLength(url) {
    const hostname = safeHostname(url);
    const parts = hostname ? hostname.split(".") : [];
    if (parts.length >= 2) return parts[parts.length - 2].length;
    return pythonLength(hostname);
  }

  function entropy(text) {
    if (!text) return 0.0;
    const freq = {};
    for (const ch of text) {
      freq[ch] = (freq[ch] || 0) + 1;
    }
    const length = pythonLength(text);
    let sum = 0;
    for (const ch of Object.keys(freq)) {
      const p = freq[ch] / length;
      sum += p * Math.log2(p);
    }
    return -sum;
  }

  function urlEntropy(url) {
    const hostname = safeHostname(url);
    return Math.round(entropy(hostname) * 10000) / 10000;
  }

  function hasPort(url) {
    return safePort(url) !== "" ? 1 : 0;
  }

  function hasPunycode(url) {
    const hostname = safeHostname(url);
    const labels = hostname ? hostname.split(".") : [];
    return labels.some((label) => label.startsWith("xn--")) ? 1 : 0;
  }

  function hasUnicodeHostname(url) {
    const hostname = safeHostname(url);
    for (const ch of hostname) {
      if (ch.codePointAt(0) > 127) return 1;
    }
    return 0;
  }

  function isAsciiAlnum(s) {
    return /^[A-Za-z0-9]+$/.test(s);
  }

  function hasOpaqueHostnameLabel(url) {
    const hostname = safeHostname(url);
    const labels = hostname ? hostname.split(".") : [];
    if (labels.length !== 2) return 0;
    if (labels[1] !== "example") return 0;

    const label = labels[0];
    if (label.startsWith("xn--")) return 0;
    if (pythonLength(label) < 11) return 0;
    if (!isAsciiAlnum(label)) return 0;
    return entropy(label) >= 3.0 ? 1 : 0;
  }

  // --- Typosquatting ---------------------------------------------------

  function levenshtein(a, b) {
    let aChars = Array.from(a);
    let bChars = Array.from(b);
    if (aChars.length < bChars.length) {
      const tmp = aChars; aChars = bChars; bChars = tmp;
    }
    let prev = [];
    for (let j = 0; j <= bChars.length; j++) prev.push(j);
    for (let i = 1; i <= aChars.length; i++) {
      const curr = [i];
      for (let j = 1; j <= bChars.length; j++) {
        const cost = aChars[i - 1] === bChars[j - 1] ? 0 : 1;
        curr.push(Math.min(prev[j] + 1, curr[j - 1] + 1, prev[j - 1] + cost));
      }
      prev = curr;
    }
    return prev[prev.length - 1];
  }

  function typosquattingScore(url) {
    let hostname = safeHostname(url);
    let domain = hostname.startsWith("www.") ? hostname.slice(4) : hostname;
    if (!domain || TOP_DOMAIN_SET.has(domain)) return 0.0;

    let minDist = Infinity;
    for (const ref of TOP_DOMAINS) {
      const d = levenshtein(domain, ref);
      if (d < minDist) minDist = d;
    }
    if (minDist === 1) return 1.0;
    if (minDist === 2) return 0.6;
    return 0.0;
  }

  function extractUrlFeatures(url) {
    return {
      url_length: urlLength(url),
      query_length: queryLength(url),
      query_param_count: queryParamCount(url),
      subdomain_count: subdomainCount(url),
      has_ip_address: hasIpAddress(url),
      special_char_count: specialCharCount(url),
      has_https: hasHttps(url),
      digit_ratio: digitRatio(url),
      phishing_keywords: phishingKeywordCount(url),
      path_depth: pathDepth(url),
      suspicious_tld: suspiciousTld(url),
      domain_length: domainLength(url),
      url_entropy: urlEntropy(url),
      has_port: hasPort(url),
      has_punycode: hasPunycode(url),
      has_unicode_hostname: hasUnicodeHostname(url),
      has_opaque_hostname_label: hasOpaqueHostnameLabel(url),
      typosquatting_score: typosquattingScore(url),
      on_free_hosting_platform: onFreeHostingPlatform(url),
    };
  }

  // --- Email features ----------------------------------------------

  const URGENCY_WORDS = [
    "urgent", "immediately", "action required", "account suspended",
    "verify now", "click here", "limited time", "expire", "unusual activity",
    "security alert", "confirm your", "update your", "validate",
  ];

  function countMatches(regex, text) {
    const matches = text.match(regex);
    return matches ? matches.length : 0;
  }

  function extractEmailFeatures(subject, body) {
    const text = `${subject} ${body}`.toLowerCase();
    const words = text.split(/\s+/).filter((w) => w.length > 0);

    const urlCount = countMatches(/https?:\/\/\S+/g, text);
    const linkCount = countMatches(/href=|click here|www\./gi, text);
    let urgencyCount = 0;
    for (const w of URGENCY_WORDS) {
      if (text.includes(w)) urgencyCount += 1;
    }
    const exclamationCount = (body.match(/!/g) || []).length;
    const allCapsWords = words.filter(
      (w) => w === w.toUpperCase() && w !== w.toLowerCase() && pythonLength(w) > 2
    ).length;
    const htmlTags = countMatches(/<[a-zA-Z]+/g, body);
    const hasAttachmentMention = /attach|download|open.{0,80}file/.test(text) ? 1 : 0;

    return {
      url_count: urlCount,
      link_count: linkCount,
      urgency_word_count: urgencyCount,
      exclamation_count: exclamationCount,
      all_caps_word_count: allCapsWords,
      html_tag_count: htmlTags,
      has_attachment_mention: hasAttachmentMention,
      word_count: words.length,
    };
  }

  // --- Authentication-Results parsing --------------------------------

  const AUTH_METHODS = ["spf", "dkim", "dmarc"];
  const AUTH_RESULTS = new Set(["pass", "fail", "softfail", "neutral", "none"]);
  const RESULT_PATTERN = /(?:^|[;\s])(spf|dkim|dmarc)\s*=\s*([a-z][a-z0-9_-]*)/gi;

  function parseAuthenticationResults(value) {
    const results = {};
    for (const m of AUTH_METHODS) results[m] = "unknown";
    if (!value) return results;

    let match;
    RESULT_PATTERN.lastIndex = 0;
    while ((match = RESULT_PATTERN.exec(value)) !== null) {
      const method = match[1].toLowerCase();
      const result = match[2].toLowerCase();
      if (results[method] === "unknown" && AUTH_RESULTS.has(result)) {
        results[method] = result;
      }
    }
    return results;
  }

  function extractAuthenticationFeatures(value) {
    const results = parseAuthenticationResults(value);
    const spfRisk = results.spf === "fail" ? 1.0 : results.spf === "softfail" ? 0.5 : 0.0;
    return {
      spf_result: results.spf,
      dkim_result: results.dkim,
      dmarc_result: results.dmarc,
      spf_auth_risk: spfRisk,
      dkim_auth_risk: results.dkim === "fail" ? 1.0 : 0.0,
      dmarc_auth_risk: results.dmarc === "fail" ? 1.0 : 0.0,
    };
  }

  // --- Model: weights, scoring, classification -----------------------

  const URL_WEIGHTS = {
    url_length: 0.015,
    query_length: 0.002,
    query_param_count: 0.02,
    subdomain_count: 0.18,
    has_ip_address: 0.90,
    special_char_count: 0.06,
    has_https: -0.20,
    digit_ratio: 0.60,
    phishing_keywords: 0.25,
    path_depth: 0.04,
    suspicious_tld: 0.70,
    domain_length: -0.01,
    url_entropy: 0.12,
    has_port: 0.40,
    has_punycode: 0.10,
    has_unicode_hostname: 0.08,
    has_opaque_hostname_label: 0.90,
    typosquatting_score: 0.65, // was 0.85; lowered so a lone typosquat hit lands in SUSPICIOUS, not PHISHING -- see model.py
    on_free_hosting_platform: 0.70,
    redirect_crossed_domain: 0.65,
    redirect_hops: 0.05,
  };

  const EMAIL_WEIGHTS = {
    url_count: 0.10,
    link_count: 0.12,
    urgency_word_count: 0.22,
    exclamation_count: 0.05,
    all_caps_word_count: 0.08,
    html_tag_count: 0.03,
    has_attachment_mention: 0.30,
    word_count: -0.001,
    spf_auth_risk: 0.08,
    dkim_auth_risk: 0.10,
    dmarc_auth_risk: 0.18,
  };

  const THRESHOLD = 0.55;
  const URL_BIAS = -1.30;
  const EMAIL_BIAS = -0.30;

  function sigmoid(rawScore) {
    return 1 / (1 + Math.exp(-rawScore * 2.5));
  }

  function round4(x) {
    return Math.round(x * 10000) / 10000;
  }

  function scoreUrl(url) {
    const features = extractUrlFeatures(url);
    let raw = URL_BIAS;
    for (const key of Object.keys(URL_WEIGHTS)) {
      if (key in features) raw += features[key] * URL_WEIGHTS[key];
    }
    return { probability: round4(sigmoid(raw)), features };
  }

  function scoreEmail(subject, body, authenticationResults) {
    const features = extractEmailFeatures(subject, body);
    Object.assign(features, extractAuthenticationFeatures(authenticationResults));
    let raw = EMAIL_BIAS;
    for (const key of Object.keys(EMAIL_WEIGHTS)) {
      if (key in features) raw += features[key] * EMAIL_WEIGHTS[key];
    }
    return { probability: round4(sigmoid(raw)), features };
  }

  function classify(probability) {
    if (probability >= 0.75) return "PHISHING";
    if (probability >= THRESHOLD) return "SUSPICIOUS";
    return "SAFE";
  }

  // URL_WEIGHTS/EMAIL_WEIGHTS are exposed read-only so callers (the web
  // demo's app.js) can tell whether a feature's current value is actually
  // pushing the score toward PHISHING or away from it, rather than
  // guessing from the value alone -- domain_length and has_https both
  // have negative weights, so a truthy/positive value there *lowers*
  // risk. This is purely additive (no scoring behavior changes) and
  // mirrors model.py, which already exposes these as importable
  // module-level constants in Python.
  return { scoreUrl, scoreEmail, classify, URL_WEIGHTS, EMAIL_WEIGHTS };
})();

if (typeof module !== "undefined" && module.exports) {
  module.exports = PhishGuardScoring;
}
