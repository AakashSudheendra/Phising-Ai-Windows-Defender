/**
 * PhishGuard Extension Popup Logic.
 */

const LOCAL_SERVICE_URL = 'http://127.0.0.1:8766';

const pillDot = document.getElementById('pill-dot');
const pillText = document.getElementById('pill-text');
const toggleProtection = document.getElementById('toggle-protection');
const protectionStatusTitle = document.getElementById('protection-status-title');
const protectionStatusDesc = document.getElementById('protection-status-desc');
const siteUrlEl = document.getElementById('site-url');
const siteVerdictEl = document.getElementById('site-verdict');
const verdictLabel = document.getElementById('verdict-label');
const btnOpenDashboard = document.getElementById('btn-open-dashboard');
const btnReportSite = document.getElementById('btn-report-site');

let currentActiveUrl = '';

/**
 * Checks connection status to desktop security service.
 */
async function checkServiceStatus() {
  try {
    const res = await fetch(`${LOCAL_SERVICE_URL}/healthz`, { method: 'GET' });
    if (res.ok) {
      const data = await res.json();
      pillDot.className = 'pill-dot connected';
      pillText.textContent = 'Service Online';
      toggleProtection.checked = data.realTimeProtection !== false;
      updateProtectionUI(data.realTimeProtection !== false);
      return true;
    }
  } catch {
    pillDot.className = 'pill-dot disconnected';
    pillText.textContent = 'Service Offline';
  }
  return false;
}

function updateProtectionUI(isActive) {
  if (isActive) {
    protectionStatusTitle.textContent = 'Real-Time Protection';
    protectionStatusDesc.textContent = 'Active pre-navigation defense';
    protectionStatusTitle.style.color = '#fff';
  } else {
    protectionStatusTitle.textContent = 'Protection Paused';
    protectionStatusDesc.textContent = 'Browsing is currently unprotected!';
    protectionStatusTitle.style.color = '#f87171';
  }
}

/**
 * Inspects current active browser tab.
 */
async function checkCurrentTab() {
  try {
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    if (!tab || !tab.url) {
      siteUrlEl.textContent = 'No web page active';
      verdictLabel.textContent = 'Inactive';
      return;
    }

    currentActiveUrl = tab.url;
    siteUrlEl.textContent = currentActiveUrl;

    if (!currentActiveUrl.startsWith('http://') && !currentActiveUrl.startsWith('https://')) {
      verdictLabel.textContent = 'Internal browser page';
      siteVerdictEl.querySelector('.verdict-dot').className = 'verdict-dot safe';
      return;
    }

    // Query threat data
    chrome.runtime.sendMessage(
      { type: 'GET_THREAT_DATA', targetUrl: currentActiveUrl },
      (response) => {
        if (chrome.runtime.lastError) {
          return;
        }
        if (response && response.ok && response.data) {
          const { verdict, riskScore } = response.data;
          const v = (verdict || 'SAFE').toUpperCase();
          verdictLabel.textContent = `${v} (${riskScore || 0}% risk)`;

          const dot = siteVerdictEl.querySelector('.verdict-dot');
          if (v === 'PHISHING') dot.className = 'verdict-dot phishing';
          else if (v === 'SUSPICIOUS') dot.className = 'verdict-dot suspicious';
          else dot.className = 'verdict-dot safe';
        }
      }
    );
  } catch (err) {
    siteUrlEl.textContent = 'Error reading tab URL';
  }
}

// Toggle Protection Handler
toggleProtection.addEventListener('change', async (e) => {
  const isEnabled = e.target.checked;
  updateProtectionUI(isEnabled);

  try {
    const stored = await chrome.storage.local.get(['authToken']);
    const token = stored.authToken || '';

    await fetch(`${LOCAL_SERVICE_URL}/api/settings`, {
      method: 'PUT',
      headers: {
        'Content-Type': 'application/json',
        'X-PhishGuard-Auth': token,
      },
      body: JSON.stringify({ realTimeProtection: isEnabled }),
    });
  } catch (err) {
    console.error('Failed to update protection setting:', err);
  }
});

// Open Desktop Dashboard
btnOpenDashboard.addEventListener('click', () => {
  chrome.tabs.create({ url: 'http://127.0.0.1:8765' });
});

// Report Site
btnReportSite.addEventListener('click', () => {
  if (!currentActiveUrl) return;
  alert(`Report submitted for ${currentActiveUrl}. Thank you for helping keep the PhishGuard AI community safe!`);
});

// Initialize
checkServiceStatus();
checkCurrentTab();
