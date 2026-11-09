/**
 * PhishGuard AI Content Script.
 * Synchronously intercepts link clicks on messaging platforms (WhatsApp Web, Telegram, Discord, etc.)
 * and web pages to change the navigation path to our application BEFORE the destination loads.
 */

(function () {
  const SENSITIVE_DOMAINS = [
    'web.whatsapp.com',
    'discord.com',
    'web.telegram.org',
    'mail.google.com',
    'outlook.live.com',
    'outlook.office.com',
  ];

  // Capture link clicks at the earliest capture phase
  document.addEventListener(
    'click',
    (e) => {
      // Find nearest <a> anchor
      const link = e.target.closest('a');
      if (!link || !link.href) return;

      const targetUrl = link.href.trim();
      if (!targetUrl.startsWith('http://') && !targetUrl.startsWith('https://')) return;

      // Ignore links to the exact same host/origin
      try {
        const parsedTarget = new URL(targetUrl);
        if (parsedTarget.origin === window.location.origin) {
          return; // internal navigation
        }
      } catch {
        return;
      }

      // CRITICAL: SYNCHRONOUSLY prevent default navigation so Chrome does NOT open the destination!
      e.preventDefault();
      e.stopImmediatePropagation();

      // Show temporary loading indicator on cursor / overlay
      document.body.style.cursor = 'wait';

      // Send to PhishGuard background service to evaluate threat
      chrome.runtime.sendMessage({ type: 'CHECK_LINK_CLICK', url: targetUrl }, (response) => {
        document.body.style.cursor = 'default';

        if (chrome.runtime.lastError) {
          window.open(targetUrl, link.target || '_blank', 'noopener,noreferrer');
          return;
        }

        if (!response || !response.ok || !response.decision) {
          // Fallback: open safely in new tab
          window.open(targetUrl, link.target || '_blank', 'noopener,noreferrer');
          return;
        }

        const decision = response.decision;
        if (decision.action === 'block' || decision.action === 'warn') {
          // THREAT DETECTED: Show in-page security popup modal and notify Desktop Application!
          showInPageAlertModal(targetUrl, decision, link.target);
        } else {
          // Safe destination: allow navigation
          window.open(targetUrl, link.target || '_blank', 'noopener,noreferrer');
        }
      });
    },
    true
  );

  /**
   * Shows the in-page security warning popup modal.
   */
  function showInPageAlertModal(targetUrl, decision, originalTarget) {
    // Remove existing if any
    const existing = document.getElementById('phishguard-active-overlay');
    if (existing) existing.remove();

    const overlay = document.createElement('div');
    overlay.id = 'phishguard-active-overlay';
    overlay.className = 'phishguard-overlay';

    const isPhishing = (decision.verdict || '').toUpperCase() === 'PHISHING';
    const riskScore = decision.riskScore || 95;
    const reasons = decision.reasons || ['Multiple structural risk signals flagged this destination'];

    overlay.innerHTML = `
      <div class="phishguard-modal">
        <div class="phishguard-header">
          <div class="phishguard-icon-box">
            <svg viewBox="0 0 24 24" width="28" height="28" fill="none" stroke="currentColor" stroke-width="2.2">
              <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
              <path d="M12 8v4M12 16h.01"/>
            </svg>
          </div>
          <div class="phishguard-title-box">
            <span class="phishguard-threat-badge">${isPhishing ? 'PHISHING THREAT BLOCKED' : 'SUSPICIOUS LINK DETECTED'}</span>
            <h3>Pre-Navigation Security Alert</h3>
            <p>PhishGuard intercepted this link before opening the destination.</p>
          </div>
        </div>

        <div class="phishguard-url-box">
          <div class="phishguard-url-label">Attempted Destination URL:</div>
          <div class="phishguard-url-text">${escapeHtml(targetUrl)}</div>
        </div>

        <div style="margin-bottom:12px;display:flex;justify-content:space-between;font-size:12px;color:#64748b;">
          <span>Threat Confidence: <strong style="color:${isPhishing ? '#dc2626' : '#d97706'}">${riskScore}%</strong></span>
          <span>Classification: <strong style="color:${isPhishing ? '#dc2626' : '#d97706'}">${escapeHtml(decision.verdict || 'PHISHING')}</strong></span>
        </div>

        <ul class="phishguard-reasons-list">
          ${reasons.map((r) => `<li>${escapeHtml(r)}</li>`).join('')}
        </ul>

        <div class="phishguard-actions">
          <button class="phishguard-btn-close" id="pg-btn-cancel-link">
            <svg viewBox="0 0 24 24" width="18" height="18" fill="none" stroke="currentColor" stroke-width="2.2">
              <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
              <path d="M9 12l2 2 4-4"/>
            </svg>
            Close (Do Not Open Website)
          </button>

          <div class="phishguard-bypass-row">
            <label>
              <input type="checkbox" id="pg-chk-bypass">
              <span>I understand the risk and want to proceed</span>
            </label>
            <button class="phishguard-btn-proceed" id="pg-btn-proceed" disabled>
              Proceed Anyway
            </button>
          </div>
        </div>
      </div>
    `;

    document.body.appendChild(overlay);

    // Close button: cancels navigation completely and removes modal
    overlay.querySelector('#pg-btn-cancel-link').addEventListener('click', () => {
      overlay.remove();
    });

    // Checkbox toggle
    const chk = overlay.querySelector('#pg-chk-bypass');
    const btnProceed = overlay.querySelector('#pg-btn-proceed');
    chk.addEventListener('change', () => {
      btnProceed.disabled = !chk.checked;
    });

    // Proceed button
    btnProceed.addEventListener('click', () => {
      overlay.remove();
      chrome.runtime.sendMessage({ type: 'PROCEED_ANYWAY', targetUrl }, () => {
        if (chrome.runtime.lastError) {
          // ignore
        }
        window.open(targetUrl, originalTarget || '_blank', 'noopener,noreferrer');
      });
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
})();
