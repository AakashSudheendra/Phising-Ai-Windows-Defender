"use strict";

// Vanilla JS, no build step, no dependencies — matches the CLI's
// zero-dependency ethos. Scoring runs entirely in the browser via
// scoring.js (a verified port of the Python model — see
// tests/test_js_parity.py), so this page works as a static file with no
// backend at all: the same web/ directory can be served by
// `phishguard serve` or hosted standalone (e.g. GitHub Pages).
//
// Only textContent/DOM APIs are used to insert values that came from user
// input, never innerHTML, so nothing typed into the form can run as markup.

const VERDICT_CLASS = {
  PHISHING: "verdict-phishing",
  SUSPICIOUS: "verdict-suspicious",
  SAFE: "verdict-safe",
};

// Human-readable labels for the raw model feature keys, so the "feature
// breakdown" table reads as an explanation rather than a variable dump.
const FEATURE_LABELS = {
  url_length: "URL length",
  subdomain_count: "Subdomain count",
  has_ip_address: "Uses a raw IP address",
  special_char_count: "Special character count",
  has_https: "Uses HTTPS",
  digit_ratio: "Digit ratio",
  phishing_keywords: "Phishing keyword matches",
  path_depth: "Path depth",
  suspicious_tld: "Suspicious top-level domain",
  domain_length: "Domain name length",
  url_entropy: "Hostname randomness (entropy)",
  has_port: "Uses a non-default port",
  has_punycode: "Uses punycode encoding",
  has_unicode_hostname: "Uses non-ASCII hostname characters",
  has_opaque_hostname_label: "Opaque/high-entropy hostname label",
  typosquatting_score: "Typosquatting similarity score",
  redirect_crossed_domain: "Redirect crossed to a new domain",
  redirect_hops: "Redirect hop count",
  url_count: "Links in message",
  link_count: "Link-like phrases",
  urgency_word_count: "Urgency word matches",
  exclamation_count: "Exclamation marks",
  all_caps_word_count: "ALL-CAPS words",
  html_tag_count: "HTML tags in body",
  has_attachment_mention: "Mentions an attachment/download",
  word_count: "Word count",
  spf_result: "SPF result",
  dkim_result: "DKIM result",
  dmarc_result: "DMARC result",
  spf_auth_risk: "SPF failure risk",
  dkim_auth_risk: "DKIM failure risk",
  dmarc_auth_risk: "DMARC failure risk",
};

const BOOLEAN_FEATURES = new Set([
  "has_ip_address", "has_https", "suspicious_tld", "has_port",
  "has_punycode", "has_unicode_hostname", "has_opaque_hostname_label",
  "has_attachment_mention", "redirect_crossed_domain",
]);

function formatFeatureName(name) {
  return FEATURE_LABELS[name] || name;
}

const PREFERS_REDUCED_MOTION = window.matchMedia
  ? window.matchMedia("(prefers-reduced-motion: reduce)").matches
  : false;

function scrollIntoViewRespectingMotion(el) {
  el.scrollIntoView({ behavior: PREFERS_REDUCED_MOTION ? "auto" : "smooth", block: "nearest" });
}

function formatFeatureValue(name, value) {
  if (BOOLEAN_FEATURES.has(name)) return value ? "Yes" : "No";
  if (typeof value === "number" && !Number.isInteger(value)) {
    return (Math.round(value * 1000) / 1000).toString();
  }
  return String(value);
}

// A feature "triggered" the score if it's actually pushing the result
// toward PHISHING, not just because its value happens to be truthy.
// phishguard.py's CLI marks any value > 0 (except has_https, hardcoded
// as a special case) -- but domain_length also carries a negative weight,
// so that heuristic mismarks it too. Checking the real weight sign from
// scoring.js's exported URL_WEIGHTS/EMAIL_WEIGHTS is both simpler and
// correct for every feature, no special-casing needed. Categorical
// email-auth fields (spf/dkim/dmarc_result) aren't in either weights
// table -- the numeric *_auth_risk features are -- so those fall back to
// a plain fail/softfail check for a still-useful visual.
function isTriggered(name, value) {
  const weights = PhishGuardScoring.URL_WEIGHTS || {};
  const emailWeights = PhishGuardScoring.EMAIL_WEIGHTS || {};
  const weight = name in weights ? weights[name] : emailWeights[name];
  if (typeof weight === "number") {
    const numericValue = typeof value === "boolean" ? Number(value) : value;
    return typeof numericValue === "number" && weight * numericValue > 0;
  }
  if (typeof value === "string") return value === "fail" || value === "softfail";
  return false;
}

const tabs = document.querySelectorAll(".tab");
const panels = {
  url: document.getElementById("panel-url"),
  email: document.getElementById("panel-email"),
};

function activateTab(tab) {
  tabs.forEach((t) => {
    const selected = t === tab;
    t.classList.toggle("active", selected);
    t.setAttribute("aria-selected", selected ? "true" : "false");
    t.tabIndex = selected ? 0 : -1;
  });
  Object.entries(panels).forEach(([name, panel]) => {
    panel.classList.toggle("hidden", name !== tab.dataset.tab);
  });
  clearResult();
}

tabs.forEach((tab, index) => {
  tab.addEventListener("click", () => activateTab(tab));
  tab.addEventListener("keydown", (event) => {
    if (event.key !== "ArrowRight" && event.key !== "ArrowLeft") return;
    event.preventDefault();
    const next = event.key === "ArrowRight"
      ? tabs[(index + 1) % tabs.length]
      : tabs[(index - 1 + tabs.length) % tabs.length];
    next.focus();
    activateTab(next);
  });
});

const resultEl = document.getElementById("result");
const errorEl = document.getElementById("error");
const verdictBadge = document.getElementById("verdict-badge");
const probabilityText = document.getElementById("probability-text");
const probabilityFill = document.getElementById("probability-fill");
const featuresTableBody = document.querySelector("#features-table tbody");
const featuresDetails = document.getElementById("features-details");

function clearResult() {
  resultEl.classList.add("hidden");
  errorEl.classList.add("hidden");
  errorEl.textContent = "";
}

function showError(message) {
  clearResult();
  errorEl.textContent = message;
  errorEl.classList.remove("hidden");
  scrollIntoViewRespectingMotion(errorEl);
}

function renderFeatures(features) {
  featuresTableBody.textContent = "";
  for (const [name, value] of Object.entries(features)) {
    const row = document.createElement("tr");
    if (isTriggered(name, value)) row.classList.add("triggered");

    const nameCell = document.createElement("td");
    const dot = document.createElement("span");
    dot.className = "feature-dot";
    dot.setAttribute("aria-hidden", "true");
    const label = document.createElement("span");
    label.textContent = formatFeatureName(name);
    nameCell.append(dot, label);

    const valueCell = document.createElement("td");
    valueCell.textContent = formatFeatureValue(name, value);

    row.append(nameCell, valueCell);
    featuresTableBody.appendChild(row);
  }
  featuresDetails.open = false;
}

function renderResult({ probability, features }) {
  errorEl.classList.add("hidden");

  const verdict = PhishGuardScoring.classify(probability);
  const verdictClass = VERDICT_CLASS[verdict] || "";
  verdictBadge.textContent = verdict;
  verdictBadge.className = `badge ${verdictClass}`;

  const pct = Math.round(probability * 1000) / 10;
  probabilityText.textContent = `${pct}% phishing probability`;
  probabilityFill.style.width = `${Math.min(100, Math.max(0, pct))}%`;
  probabilityFill.className = `meter-fill ${verdictClass}`;

  renderFeatures(features || {});
  resultEl.classList.remove("hidden");
  scrollIntoViewRespectingMotion(resultEl);
}

document.getElementById("url-form").addEventListener("submit", (event) => {
  event.preventDefault();
  const url = event.currentTarget.url.value.trim();
  if (!url) return;
  try {
    renderResult(PhishGuardScoring.scoreUrl(url));
  } catch (err) {
    showError("Could not analyze that input. Try a different URL.");
  }
});

document.getElementById("email-form").addEventListener("submit", (event) => {
  event.preventDefault();
  const form = event.currentTarget;
  const subject = form.subject.value;
  const body = form.body.value;
  const authenticationResults = form.authentication_results.value.trim() || null;
  try {
    renderResult(PhishGuardScoring.scoreEmail(subject, body, authenticationResults));
  } catch (err) {
    showError("Could not analyze that input. Try a different subject/body.");
  }
});
