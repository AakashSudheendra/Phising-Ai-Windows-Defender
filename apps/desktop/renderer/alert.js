/**
 * Logic for Windows Security Alert Popup Window.
 */

const alertUrl = document.getElementById('alert-url');
const alertRiskLevel = document.getElementById('alert-risk-level');
const alertConfidence = document.getElementById('alert-confidence');
const alertReasonsList = document.getElementById('alert-reasons-list');
const alertTechBody = document.getElementById('alert-tech-body');
const btnAlertSafety = document.getElementById('btn-alert-safety');
const chkAlertConfirm = document.getElementById('chk-alert-confirm');
const btnAlertProceed = document.getElementById('btn-alert-proceed');
const tabOverview = document.getElementById('tab-overview');
const tabTechnical = document.getElementById('tab-technical');
const panelReasons = document.getElementById('panel-reasons');
const panelTechnical = document.getElementById('panel-technical');
const alertTag = document.getElementById('alert-tag');
const alertIconWrapper = document.getElementById('alert-icon-wrapper');

// Tab toggling
tabOverview.addEventListener('click', () => {
  tabOverview.classList.add('active');
  tabTechnical.classList.remove('active');
  panelReasons.classList.add('active');
  panelTechnical.classList.remove('active');
});

tabTechnical.addEventListener('click', () => {
  tabTechnical.classList.add('active');
  tabOverview.classList.remove('active');
  panelTechnical.classList.add('active');
  panelReasons.classList.remove('active');
});

// Parse threat data from query string
let threatData = null;
try {
  const params = new URLSearchParams(window.location.search);
  const raw = params.get('data');
  if (raw) {
    threatData = JSON.parse(decodeURIComponent(raw));
  }
} catch (err) {
  console.error('Failed to parse threat data:', err);
}

if (threatData) {
  alertUrl.textContent = threatData.url || 'Unknown Destination URL';
  const isPhish = (threatData.classification || '').toUpperCase() === 'PHISHING';

  if (isPhish) {
    alertTag.textContent = 'PHISHING BLOCKED';
    alertRiskLevel.textContent = 'CRITICAL PHISHING';
    alertRiskLevel.className = 'chip-val high';
    alertConfidence.className = 'chip-val high';
  } else {
    alertTag.textContent = 'SUSPICIOUS LINK';
    alertTag.classList.add('warning');
    alertRiskLevel.textContent = 'MEDIUM RISK (SUSPICIOUS)';
    alertRiskLevel.className = 'chip-val medium';
    alertIconWrapper.classList.add('warning');
  }

  alertConfidence.textContent = `${threatData.riskScore || 0}%`;

  // Populate reasons
  alertReasonsList.innerHTML = '';
  const reasons = threatData.reasons || ['Multiple structural heuristics exceeded security threshold'];
  for (const r of reasons) {
    const li = document.createElement('li');
    li.textContent = r;
    alertReasonsList.appendChild(li);
  }

  // Populate technical features grid
  if (threatData.features && typeof threatData.features === 'object') {
    alertTechBody.innerHTML = Object.entries(threatData.features)
      .map(([k, v]) => `
        <div class="tech-item">
          <span class="tech-key">${escapeHtml(k)}</span>
          <span class="tech-val ${v > 0 && ['phishing_keywords', 'suspicious_tld', 'has_ip_address', 'typosquatting_score', 'on_free_hosting_platform'].includes(k) ? 'elevated' : ''}">${escapeHtml(typeof v === 'number' && !Number.isInteger(v) ? v.toFixed(3) : String(v))}</span>
        </div>
      `)
      .join('');
  } else {
    alertTechBody.innerHTML = '<div class="tech-item">No extended feature payload attached.</div>';
  }
}

// Action: Close and cancel navigation (DO NOT GO TO WEBSITE)
btnAlertSafety.addEventListener('click', async () => {
  if (window.phishguardAPI && window.phishguardAPI.cancelNavigation) {
    await window.phishguardAPI.cancelNavigation({
      url: threatData ? threatData.url : '',
      tabId: threatData ? threatData.tabId : null,
    });
  } else {
    try {
      await fetch('http://127.0.0.1:8766/api/cancel-navigation', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          url: threatData ? threatData.url : '',
          tabId: threatData ? threatData.tabId : null,
        }),
      });
    } catch {
      // ignore
    }
  }

  window.close();
});

chkAlertConfirm.addEventListener('change', (e) => {
  btnAlertProceed.disabled = !e.target.checked;
});

btnAlertProceed.addEventListener('click', async () => {
  if (!chkAlertConfirm.checked) return;

  if (threatData && threatData.url) {
    try {
      await fetch('http://127.0.0.1:8766/api/bypass', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url: threatData.url }),
      });
    } catch {
      // ignore
    }
  }

  window.close();
});

function escapeHtml(str) {
  if (!str) return '';
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}
