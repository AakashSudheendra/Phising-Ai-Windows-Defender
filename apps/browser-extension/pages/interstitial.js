/**
 * Interstitial Warning Page Logic.
 * Controls the pre-navigation blocking screen, renders detection results,
 * and handles user actions (Return to Safety, Proceed Anyway with bypass confirmation).
 */

const LOCAL_SERVICE_URL = 'http://127.0.0.1:8766';

// Elements
const targetUrlEl = document.getElementById('target-url-text');
const threatBadgeEl = document.getElementById('threat-badge');
const alertHeadingEl = document.getElementById('alert-heading');
const riskClassificationEl = document.getElementById('risk-classification');
const riskScoreValueEl = document.getElementById('risk-score-value');
const riskFillEl = document.getElementById('risk-fill');
const reasonsListEl = document.getElementById('reasons-list');
const featuresTbodyEl = document.getElementById('features-tbody');
const shieldIconWrapper = document.getElementById('shield-icon-wrapper');

const btnReturnSafety = document.getElementById('btn-return-safety');
const btnWhitelist = document.getElementById('btn-whitelist');
const chkBypassConfirm = document.getElementById('chk-bypass-confirm');
const btnProceedAnyway = document.getElementById('btn-proceed-anyway');

// Parse query params
const params = new URLSearchParams(window.location.search);
const targetUrl = params.get('url') || '';
const tabId = parseInt(params.get('tabId') || '0', 10);

targetUrlEl.textContent = targetUrl || 'Unknown Destination';

/**
 * Renders threat data onto the page.
 */
function renderThreatDetails(data) {
  if (!data) return;

  const isPhishing = (data.verdict || '').toUpperCase() === 'PHISHING';
  const riskScore = data.riskScore || 0;

  threatBadgeEl.textContent = isPhishing ? 'PHISHING BLOCKED' : 'SUSPICIOUS WARNING';
  riskClassificationEl.textContent = data.verdict || 'SUSPICIOUS';
  riskScoreValueEl.textContent = `${riskScore}%`;
  riskFillEl.style.width = `${Math.min(100, Math.max(10, riskScore))}%`;

  if (isPhishing) {
    threatBadgeEl.style.background = '#fef2f2';
    threatBadgeEl.style.color = '#991b1b';
    threatBadgeEl.style.borderColor = '#fca5a5';
    riskFillEl.style.background = '#dc2626';
    shieldIconWrapper.style.color = '#dc2626';
    shieldIconWrapper.style.background = '#fef2f2';
    shieldIconWrapper.style.borderColor = '#fca5a5';
  } else {
    threatBadgeEl.style.background = '#fffbeb';
    threatBadgeEl.style.color = '#92400e';
    threatBadgeEl.style.borderColor = '#fde68a';
    riskFillEl.style.background = '#d97706';
    shieldIconWrapper.style.color = '#d97706';
    shieldIconWrapper.style.background = '#fffbeb';
    shieldIconWrapper.style.borderColor = '#fde68a';
    alertHeadingEl.textContent = 'Security Warning: Suspicious Website Detected';
  }

  // Populate reasons
  reasonsListEl.innerHTML = '';
  const reasons = data.reasons || ['Multiple structural risk signals flagged this destination'];
  for (const r of reasons) {
    const li = document.createElement('li');
    li.textContent = r;
    reasonsListEl.appendChild(li);
  }

  // Populate technical features table
  if (data.features && typeof data.features === 'object') {
    featuresTbodyEl.innerHTML = '';
    for (const [key, val] of Object.entries(data.features)) {
      const row = document.createElement('tr');
      const tdKey = document.createElement('td');
      tdKey.textContent = key;

      const tdVal = document.createElement('td');
      tdVal.textContent = typeof val === 'number' ? (Number.isInteger(val) ? val : val.toFixed(3)) : String(val);

      const tdRisk = document.createElement('td');
      if (val > 0 && ['phishing_keywords', 'suspicious_tld', 'has_ip_address', 'typosquatting_score', 'on_free_hosting_platform'].includes(key)) {
        tdRisk.innerHTML = '<span style="color:#ef4444;font-weight:600">Elevated</span>';
      } else {
        tdRisk.innerHTML = '<span style="color:#94a3b8">Normal</span>';
      }

      row.appendChild(tdKey);
      row.appendChild(tdVal);
      row.appendChild(tdRisk);
      featuresTbodyEl.appendChild(row);
    }
  }
}

/**
 * Load threat details from background script.
 */
function loadThreatData() {
  if (!targetUrl) return;

  chrome.runtime.sendMessage(
    { type: 'GET_THREAT_DATA', targetUrl },
    (response) => {
      if (chrome.runtime.lastError) {
        return;
      }
      if (response && response.ok && response.data) {
        renderThreatDetails(response.data);
      }
    }
  );
}

// Listen for push updates from background script
chrome.runtime.onMessage.addListener((message) => {
  if (message && message.type === 'PHISHGUARD_THREAT_DETECTED' && message.targetUrl === targetUrl) {
    renderThreatDetails(message.data);
  }
});

// Event Listeners
btnReturnSafety.addEventListener('click', () => {
  // Instruct background script to close this tab and cancel navigation
  chrome.runtime.sendMessage({ type: 'CLOSE_TAB', tabId, url: targetUrl }, () => {
    if (chrome.runtime.lastError) {
      // ignore
    }
    window.close();
  });
});

btnWhitelist.addEventListener('click', async () => {
  try {
    const parsed = new URL(targetUrl);
    const domain = parsed.hostname;
    const tokenRes = await chrome.storage.local.get(['authToken']);
    const token = tokenRes.authToken || '';

    await fetch(`${LOCAL_SERVICE_URL}/api/trusted`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-PhishGuard-Auth': token,
      },
      body: JSON.stringify({ domain }),
    });

    // Whitelisted: proceed to destination
    chrome.runtime.sendMessage(
      { type: 'PROCEED_ANYWAY', targetUrl, tabId },
      () => {
        window.location.href = targetUrl;
      }
    );
  } catch (err) {
    alert('Failed to whitelist domain: ' + err.message);
  }
});

chkBypassConfirm.addEventListener('change', (e) => {
  btnProceedAnyway.disabled = !e.target.checked;
});

btnProceedAnyway.addEventListener('click', () => {
  if (!chkBypassConfirm.checked) return;

  btnProceedAnyway.disabled = true;
  btnProceedAnyway.textContent = 'Redirecting to unsafe destination...';

  chrome.runtime.sendMessage(
    { type: 'PROCEED_ANYWAY', targetUrl, tabId },
    () => {
      if (chrome.runtime.lastError) {
        // ignore
      }
      window.location.href = targetUrl;
    }
  );
});

// Initialize on page load
loadThreatData();
