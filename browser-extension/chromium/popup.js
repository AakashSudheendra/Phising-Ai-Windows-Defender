"use strict";

const CLASS_BY_VERDICT = {
  SAFE: "safe",
  SUSPICIOUS: "suspicious",
  PHISHING: "phishing",
};

const GUIDANCE_BY_VERDICT = {
  SAFE: "No strong phishing indicators were found. This is not a guarantee, but the URL looks low risk under the current heuristic model.",
  SUSPICIOUS: "PhishGuard found warning signs. Verify the sender, domain, and destination before entering credentials or payment details.",
  PHISHING: "High-risk indicators were found. Avoid signing in, downloading files, or sharing sensitive information on this page.",
};

const currentUrlEl = document.getElementById("current-url");
const scanCurrentButton = document.getElementById("scan-current");
const manualForm = document.getElementById("manual-form");
const manualUrlInput = document.getElementById("manual-url");
const sampleButtons = document.querySelectorAll(".sample-button");
const resultEl = document.getElementById("result");
const errorEl = document.getElementById("error");
const verdictEl = document.getElementById("verdict");
const riskLabelEl = document.getElementById("risk-label");
const scoreEl = document.getElementById("score");
const guidanceEl = document.getElementById("guidance");
const barFillEl = document.getElementById("bar-fill");
const featuresEl = document.getElementById("features");
const modeLabelEl = document.getElementById("mode-label");

let activeTabUrl = "";

function clearError() {
  errorEl.classList.add("hidden");
  errorEl.textContent = "";
}

function showError(message) {
  resultEl.classList.add("hidden");
  errorEl.textContent = message;
  errorEl.classList.remove("hidden");
}

function normalizeUrlInput(value) {
  const candidate = String(value || "").trim();
  if (!candidate) return "";
  if (/^https?:\/\//i.test(candidate)) return candidate;
  if (/^[a-z0-9.-]+\.[a-z]{2,}(?::\d+)?(?:[/?#].*)?$/i.test(candidate)) {
    return `https://${candidate}`;
  }
  return candidate;
}

function normalizeForDisplay(url) {
  if (!url) return "";
  if (url.length <= 150) return url;
  return `${url.slice(0, 147)}...`;
}

function renderFeatures(features) {
  featuresEl.textContent = "";

  const important = Object.entries(features)
    .filter(([, value]) => value !== 0 && value !== 0.0 && value !== "")
    .sort(([nameA], [nameB]) => nameA.localeCompare(nameB));

  const rows = important.length ? important : Object.entries(features).slice(0, 8);

  for (const [name, value] of rows) {
    const dt = document.createElement("dt");
    const dd = document.createElement("dd");
    dt.textContent = name;
    dd.textContent = String(value);
    featuresEl.append(dt, dd);
  }
}

function renderResult(url) {
  clearError();

  const result = PhishGuardScoring.scoreUrl(url);
  const verdict = PhishGuardScoring.classify(result.probability);
  const className = CLASS_BY_VERDICT[verdict] || "suspicious";
  const pct = Math.round(result.probability * 1000) / 10;

  verdictEl.textContent = verdict;
  verdictEl.className = `verdict ${className}`;
  riskLabelEl.textContent = verdict === "SAFE" ? "Low phishing risk" : "Phishing-risk warning";
  scoreEl.textContent = `${pct}% phishing risk`;
  barFillEl.style.width = `${Math.min(100, Math.max(0, pct))}%`;
  barFillEl.className = `bar-fill ${className}`;
  guidanceEl.textContent = GUIDANCE_BY_VERDICT[verdict] || GUIDANCE_BY_VERDICT.SUSPICIOUS;
  renderFeatures(result.features || {});

  resultEl.classList.remove("hidden");
}

function scanUrl(url) {
  const candidate = normalizeUrlInput(url);
  if (!candidate) {
    showError("Paste a URL or open a normal web page first.");
    return;
  }
  if (!/^https?:\/\//i.test(candidate)) {
    showError("Enter a web URL, for example www.yahoo.com or https://example.com.");
    return;
  }
  try {
    renderResult(candidate);
  } catch (err) {
    showError("Could not analyze that input. Try a different URL.");
  }
}

async function loadCurrentTab() {
  if (typeof chrome === "undefined" || !chrome.tabs || !chrome.tabs.query) {
    currentUrlEl.textContent = "Install as an extension to check the active tab. Paste a URL below to test the scanner here.";
    modeLabelEl.textContent = "Preview mode";
    scanCurrentButton.disabled = true;
    return;
  }

  const tabs = await chrome.tabs.query({ active: true, currentWindow: true });
  const tab = tabs && tabs[0];
  activeTabUrl = tab && tab.url ? tab.url : "";

  if (!activeTabUrl || !/^https?:\/\//i.test(activeTabUrl)) {
    currentUrlEl.textContent = "Open an http:// or https:// page to scan the current tab.";
    modeLabelEl.textContent = "Extension mode";
    scanCurrentButton.disabled = true;
    return;
  }

  currentUrlEl.textContent = normalizeForDisplay(activeTabUrl);
  modeLabelEl.textContent = "Extension mode";
  scanCurrentButton.disabled = false;
}

scanCurrentButton.addEventListener("click", () => {
  scanUrl(activeTabUrl);
});

manualForm.addEventListener("submit", (event) => {
  event.preventDefault();
  scanUrl(manualUrlInput.value);
});

sampleButtons.forEach((button) => {
  button.addEventListener("click", () => {
    manualUrlInput.value = button.dataset.url || "";
    scanUrl(manualUrlInput.value);
  });
});

loadCurrentTab().catch(() => {
  currentUrlEl.textContent = "Could not read the current tab URL.";
  modeLabelEl.textContent = "Preview mode";
  scanCurrentButton.disabled = true;
});
