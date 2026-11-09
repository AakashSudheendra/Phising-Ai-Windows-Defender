/**
 * PhishGuard AI Windows Desktop App — Renderer Logic.
 */

// Navigation
const navItems = document.querySelectorAll('.nav-item');
const viewPanels = document.querySelectorAll('.view-panel');
const pageTitle = document.getElementById('page-title');
const pageSubtitle = document.getElementById('page-subtitle');

// Status banner & controls
const statusBanner = document.getElementById('status-banner');
const bannerTitle = document.getElementById('banner-title');
const bannerDesc = document.getElementById('banner-desc');
const dashProtectionToggle = document.getElementById('dash-protection-toggle');
const btnSimulateThreat = document.getElementById('btn-simulate-threat');

// Stat cards
const statTotal = document.getElementById('stat-total');
const statBlocked = document.getElementById('stat-blocked');
const statSuspicious = document.getElementById('stat-suspicious');
const statSafe = document.getElementById('stat-safe');
const badgeLastScan = document.getElementById('badge-last-scan');
const recentThreatsTbody = document.getElementById('recent-threats-tbody');
const linkViewAllHistory = document.getElementById('link-view-all-history');

// History view
const historySearchInput = document.getElementById('history-search-input');
const historyFilterSelect = document.getElementById('history-filter-select');
const btnClearHistory = document.getElementById('btn-clear-history');
const fullHistoryTbody = document.getElementById('full-history-tbody');

// Trusted domains
const inputTrustedDomain = document.getElementById('input-trusted-domain');
const btnAddTrusted = document.getElementById('btn-add-trusted');
const trustedList = document.getElementById('trusted-list');

// Settings controls
const settingRealtime = document.getElementById('setting-realtime');
const settingNotifications = document.getElementById('setting-notifications');
const settingPopup = document.getElementById('setting-popup');
const settingPolicyMode = document.getElementById('setting-policy-mode');
const settingFailMode = document.getElementById('setting-fail-mode');
const settingAutostart = document.getElementById('setting-autostart');
const btnSaveSettings = document.getElementById('btn-save-settings');
const saveStatus = document.getElementById('save-status');

/**
 * Switch Active View.
 */
function switchView(viewName) {
  navItems.forEach((item) => {
    item.classList.toggle('active', item.dataset.view === viewName);
  });

  viewPanels.forEach((panel) => {
    panel.classList.toggle('active', panel.id === `view-${viewName}`);
  });

  if (viewName === 'dashboard') {
    pageTitle.textContent = 'Security Dashboard';
    pageSubtitle.textContent = 'Real-time Windows anti-phishing overview and threat metrics';
    loadDashboardStats();
  } else if (viewName === 'history') {
    pageTitle.textContent = 'Security Detection History';
    pageSubtitle.textContent = 'Comprehensive log of intercepted URLs and security decisions';
    loadFullHistory();
  } else if (viewName === 'trusted') {
    pageTitle.textContent = 'Trusted Websites';
    pageSubtitle.textContent = 'Websites whitelisted from heuristic phishing analysis';
    loadTrustedDomains();
  } else if (viewName === 'settings') {
    pageTitle.textContent = 'Protection Controls';
    pageSubtitle.textContent = 'Configure real-time engine behavior and Windows integration';
    loadSettings();
  }
}

navItems.forEach((item) => {
  item.addEventListener('click', () => switchView(item.dataset.view));
});

linkViewAllHistory.addEventListener('click', () => switchView('history'));

/**
 * Updates the Banner and UI based on protection status.
 */
function updateProtectionBanner(isActive) {
  dashProtectionToggle.checked = isActive;
  settingRealtime.checked = isActive;

  if (isActive) {
    statusBanner.className = 'status-banner banner-active';
    bannerTitle.textContent = 'Real-Time Protection is Active';
    bannerDesc.textContent = 'PhishGuard is intercepting dangerous links in your browser before they load.';
  } else {
    statusBanner.className = 'status-banner banner-inactive';
    bannerTitle.textContent = 'Real-Time Protection is Disabled!';
    bannerDesc.textContent = 'WARNING: Browsers are not currently protected against malicious phishing links.';
  }
}

/**
 * Loads Stats & Recent Events for Dashboard.
 */
async function loadDashboardStats() {
  if (!window.phishguardAPI) return;

  try {
    const stats = await window.phishguardAPI.getStats();
    statTotal.textContent = stats.totalScanned || 0;
    statBlocked.textContent = stats.blockedPhishing || 0;
    statSuspicious.textContent = stats.detectedSuspicious || 0;
    statSafe.textContent = stats.safeVerified || 0;

    if (stats.lastScanTimestamp) {
      const dt = new Date(stats.lastScanTimestamp);
      badgeLastScan.textContent = dt.toLocaleTimeString();
    } else {
      badgeLastScan.textContent = 'Never';
    }

    // Load recent events
    const historyData = await window.phishguardAPI.getHistory({ limit: 5 });
    renderRecentThreats(historyData.events || []);
  } catch (err) {
    console.error('Failed to load stats:', err);
  }
}

/**
 * Render recent threats table.
 */
function renderRecentThreats(events) {
  if (!events || events.length === 0) {
    recentThreatsTbody.innerHTML = `
      <tr>
        <td colspan="6" class="empty-state">No detections recorded yet. Active protection will log events here.</td>
      </tr>
    `;
    return;
  }

  recentThreatsTbody.innerHTML = events
    .map((e) => {
      const isPhish = e.classification === 'PHISHING';
      const isSusp = e.classification === 'SUSPICIOUS';
      const badgeClass = isPhish ? 'badge-phishing' : isSusp ? 'badge-suspicious' : 'badge-safe';
      const keyReason = (e.reasons && e.reasons[0]) || 'Baseline safe';
      const timeStr = new Date(e.timestamp).toLocaleTimeString();

      return `
      <tr>
        <td>${timeStr}</td>
        <td style="font-family:ui-monospace, monospace;color:#0f172a;font-weight:600;">${escapeHtml(e.url)}</td>
        <td><span class="badge-tag ${badgeClass}">${e.classification}</span></td>
        <td><strong>${e.riskScore}%</strong></td>
        <td>${escapeHtml(e.action.toUpperCase())}</td>
        <td style="color:#64748b;">${escapeHtml(keyReason)}</td>
      </tr>
    `;
    })
    .join('');
}

/**
 * Loads full history list with search & filter.
 */
async function loadFullHistory() {
  if (!window.phishguardAPI) return;

  const filter = historyFilterSelect.value;
  const search = historySearchInput.value;

  try {
    const res = await window.phishguardAPI.getHistory({ limit: 100, filter, search });
    const events = res.events || [];

    if (events.length === 0) {
      fullHistoryTbody.innerHTML = `
        <tr><td colspan="6" class="empty-state">No matching security events found.</td></tr>
      `;
      return;
    }

    fullHistoryTbody.innerHTML = events
      .map((e) => {
        const isPhish = e.classification === 'PHISHING';
        const isSusp = e.classification === 'SUSPICIOUS';
        const badgeClass = isPhish ? 'badge-phishing' : isSusp ? 'badge-suspicious' : 'badge-safe';
        const reasonsStr = (e.reasons || []).join('; ');
        const dateStr = new Date(e.timestamp).toLocaleString();

        return `
        <tr>
          <td>${dateStr}</td>
          <td style="font-family:ui-monospace, monospace;color:#0f172a;font-weight:600;">${escapeHtml(e.url)}</td>
          <td><span class="badge-tag ${badgeClass}">${e.classification}</span></td>
          <td><strong>${e.riskScore}%</strong></td>
          <td>${escapeHtml(e.action.toUpperCase())}</td>
          <td style="color:#64748b;font-size:12px;">${escapeHtml(reasonsStr)}</td>
        </tr>
      `;
      })
      .join('');
  } catch (err) {
    console.error('Failed to load history:', err);
  }
}

historySearchInput.addEventListener('input', () => loadFullHistory());
historyFilterSelect.addEventListener('change', () => loadFullHistory());

btnClearHistory.addEventListener('click', async () => {
  if (confirm('Are you sure you want to clear your local security history?')) {
    await window.phishguardAPI.clearHistory();
    loadFullHistory();
    loadDashboardStats();
  }
});

/**
 * Loads Trusted Domains.
 */
async function loadTrustedDomains() {
  if (!window.phishguardAPI) return;

  try {
    const domains = await window.phishguardAPI.getTrustedDomains();
    trustedList.innerHTML = (domains || [])
      .map(
        (d) => `
      <li class="trusted-item">
        <span class="trusted-domain-name">${escapeHtml(d)}</span>
        <button class="btn-remove" data-domain="${escapeHtml(d)}">Remove</button>
      </li>
    `
      )
      .join('');

    trustedList.querySelectorAll('.btn-remove').forEach((btn) => {
      btn.addEventListener('click', async () => {
        const d = btn.dataset.domain;
        await window.phishguardAPI.removeTrustedDomain(d);
        loadTrustedDomains();
      });
    });
  } catch (err) {
    console.error('Failed to load trusted domains:', err);
  }
}

btnAddTrusted.addEventListener('click', async () => {
  const domain = inputTrustedDomain.value.trim().toLowerCase();
  if (!domain) return;

  await window.phishguardAPI.addTrustedDomain(domain);
  inputTrustedDomain.value = '';
  loadTrustedDomains();
});

/**
 * Loads Settings into controls.
 */
async function loadSettings() {
  if (!window.phishguardAPI) return;

  try {
    const settings = await window.phishguardAPI.getSettings();
    settingRealtime.checked = settings.realTimeProtection !== false;
    settingNotifications.checked = settings.desktopNotifications !== false;
    settingPopup.checked = settings.warningPopup !== false;
    settingPolicyMode.value = settings.policyMode || 'standard';
    settingFailMode.value = settings.failMode || 'fail_open';
    settingAutostart.checked = settings.autoStart === true;
    updateProtectionBanner(settingRealtime.checked);
  } catch (err) {
    console.error('Failed to load settings:', err);
  }
}

btnSaveSettings.addEventListener('click', async () => {
  if (!window.phishguardAPI) return;

  const updates = {
    realTimeProtection: settingRealtime.checked,
    desktopNotifications: settingNotifications.checked,
    warningPopup: settingPopup.checked,
    policyMode: settingPolicyMode.value,
    failMode: settingFailMode.value,
    autoStart: settingAutostart.checked,
  };

  await window.phishguardAPI.updateSettings(updates);
  updateProtectionBanner(updates.realTimeProtection);

  saveStatus.textContent = 'Settings saved successfully.';
  setTimeout(() => {
    saveStatus.textContent = '';
  }, 3000);
});

dashProtectionToggle.addEventListener('change', async (e) => {
  const isEnabled = e.target.checked;
  updateProtectionBanner(isEnabled);
  if (window.phishguardAPI) {
    await window.phishguardAPI.updateSettings({ realTimeProtection: isEnabled });
  }
});

// Simulate Threat Trigger
btnSimulateThreat.addEventListener('click', async () => {
  if (!window.phishguardAPI) return;
  btnSimulateThreat.disabled = true;
  btnSimulateThreat.textContent = 'Testing...';

  try {
    const res = await window.phishguardAPI.simulateThreat('http://paypa1-secure-login.xyz/verify?token=test_simulation');
    loadDashboardStats();
  } catch (err) {
    alert('Simulation error: ' + err.message);
  } finally {
    btnSimulateThreat.disabled = false;
    btnSimulateThreat.innerHTML = `
      <svg viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="currentColor" stroke-width="2">
        <polygon points="5 3 19 12 5 21 5 3"/>
      </svg>
      Simulate Threat
    `;
  }
});

// Real-time threat alert listener from main process
if (window.phishguardAPI) {
  window.phishguardAPI.onThreatAlert(() => {
    loadDashboardStats();
  });
}

function escapeHtml(str) {
  if (!str) return '';
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}

// Initial boot
loadSettings();
loadDashboardStats();
