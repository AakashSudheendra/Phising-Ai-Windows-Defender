/**
 * PhishGuard AI Background Service Worker (Manifest V3).
 * Intercepts attempted navigations before remote pages load, queries the Local Security Service,
 * and enforces pre-navigation security interstitials for suspicious and phishing URLs.
 * Includes embedded offline heuristic engine so phishing sites are blocked even if local service is offline.
 */

// Import bundled offline heuristics for instant pre-navigation protection
try {
  importScripts('public-suffix.js', 'scoring.js');
} catch (err) {
  console.warn('[PhishGuard Background] Could not import offline scoring scripts:', err);
}

const LOCAL_SERVICE_URL = 'http://127.0.0.1:8766';
const CACHE_TTL_MS = 300 * 1000; // 5 minutes

// In-memory session caches
const urlCache = new Map(); // url -> { action, verdict, riskScore, reasons, features, expiresAt }
const pendingChecks = new Map(); // url -> Promise<Decision>
const bypassedUrls = new Set(); // set of URLs/domains user explicitly confirmed to proceed
const interceptedTabs = new Map(); // targetUrl -> Set<tabId>

let authToken = null;
let isConnectedToService = false;
let isStreamConnecting = false;
let streamAbortController = null;

function getScoringEngine() {
  if (typeof PhishGuardScoring !== 'undefined') return PhishGuardScoring;
  if (typeof self !== 'undefined' && self.PhishGuardScoring) return self.PhishGuardScoring;
  if (typeof globalThis !== 'undefined' && globalThis.PhishGuardScoring) return globalThis.PhishGuardScoring;
  return null;
}

/**
 * Generate human-readable reasons from offline features.
 */
function generateLocalReasons(features, verdict) {
  const reasons = [];
  if (!features) return ['Multiple structural risk signals flagged this destination'];

  if (features.typosquatting_score > 0) {
    reasons.push('Possible brand impersonation / typosquatting of a popular domain');
  }
  if (features.has_ip_address > 0) {
    reasons.push('Uses raw numerical IP address instead of a recognized domain');
  }
  if (features.suspicious_tld > 0) {
    reasons.push('Uses a high-risk suspicious top-level domain (.xyz, .tk, .top, etc.)');
  }
  if (features.phishing_keywords > 0) {
    reasons.push(`Contains ${features.phishing_keywords} sensitive account/credential keyword(s)`);
  }
  if (features.on_free_hosting_platform > 0) {
    reasons.push('Hosted on a disposable free hosting platform commonly abused for phishing');
  }
  if (features.url_entropy > 3.8) {
    reasons.push('Unusually high character entropy (randomly generated URL pattern)');
  }
  if (features.has_https === 0) {
    reasons.push('Insecure connection (no HTTPS encryption)');
  }

  if (reasons.length === 0) {
    reasons.push(
      verdict === 'PHISHING'
        ? 'High-confidence structural phishing indicators detected'
        : 'Suspicious structural characteristics detected'
    );
  }
  return reasons;
}

/**
 * Evaluates URL offline using embedded PhishGuard heuristic engine.
 */
function evaluateOfflineScoring(targetUrl) {
  try {
    const engine = getScoringEngine();
    if (engine) {
      const score = engine.scoreUrl(targetUrl);
      const verdict = engine.classify(score.probability);
      const riskScore = Math.round(score.probability * 100);

      if (verdict === 'PHISHING' || verdict === 'SUSPICIOUS') {
        return {
          action: 'block',
          verdict,
          riskScore,
          features: score.features || {},
          reasons: generateLocalReasons(score.features, verdict),
          offlineScored: true,
        };
      }
    }
  } catch (err) {
    console.warn('[PhishGuard Background] Offline scoring error:', err);
  }
  return null;
}

/**
 * Initializes and retrieves authentication token for the local security service.
 */
async function initializeAuth() {
  try {
    const stored = await chrome.storage.local.get(['authToken']);
    if (stored.authToken) {
      authToken = stored.authToken;
    }

    const res = await fetch(`${LOCAL_SERVICE_URL}/api/token`, { method: 'GET' });
    if (res.ok) {
      const data = await res.json();
      if (data && data.token) {
        authToken = data.token;
        await chrome.storage.local.set({ authToken: data.token });
        isConnectedToService = true;
        updateBadge('ON', '#10b981');
        connectEventStream();
        return true;
      }
    }
  } catch {
    isConnectedToService = false;
    updateBadge('!', '#f59e0b');
  }
  return false;
}

/**
 * Connects to Local Security Service SSE stream to receive cancel-navigation commands.
 */
function connectEventStream() {
  if (!authToken || isStreamConnecting) return;
  isStreamConnecting = true;

  if (streamAbortController) {
    try {
      streamAbortController.abort();
    } catch {}
  }
  streamAbortController = new AbortController();

  fetch(`${LOCAL_SERVICE_URL}/api/events?auth=${encodeURIComponent(authToken)}`, {
    headers: { 'X-PhishGuard-Auth': authToken },
    signal: streamAbortController.signal,
  })
    .then(async (response) => {
      isStreamConnecting = false;
      if (!response.ok || !response.body) {
        return;
      }

      const reader = response.body.getReader();
      const decoder = new TextDecoder();
      let buffer = '';

      while (true) {
        const { done, value } = await reader.read();
        if (done) break;
        buffer += decoder.decode(value, { stream: true });
        const lines = buffer.split('\n');
        buffer = lines.pop();

        for (const line of lines) {
          if (line.startsWith('data: ')) {
            try {
              const payload = JSON.parse(line.slice(6));
              if (payload.type === 'CANCEL_NAVIGATION') {
                handleCancelNavigation(payload);
              }
            } catch {
              // ignore malformed SSE line
            }
          }
        }
      }
    })
    .catch(() => {
      isStreamConnecting = false;
      // Retry after delay
      setTimeout(connectEventStream, 15000);
    });
}

/**
 * Handles cancel navigation triggered from Desktop Warning Popup or Interstitial.
 */
function handleCancelNavigation(data) {
  if (!data) return;
  const { url, tabId } = data;

  if (tabId && tabId > 0) {
    chrome.tabs.remove(tabId).catch(() => {});
    return;
  }

  if (url && interceptedTabs.has(url)) {
    const tabs = interceptedTabs.get(url);
    for (const tid of tabs) {
      if (tid > 0) {
        chrome.tabs.remove(tid).catch(() => {});
      }
    }
    interceptedTabs.delete(url);
  }
}

function updateBadge(text, color) {
  try {
    chrome.action.setBadgeText({ text }).catch(() => {});
    chrome.action.setBadgeBackgroundColor({ color }).catch(() => {});
  } catch {
    // ignore
  }
}

/**
 * Checks URL against Local Security Service with immediate offline heuristic fallback.
 */
async function checkUrlWithService(targetUrl) {
  const cached = urlCache.get(targetUrl);
  if (cached && cached.expiresAt > Date.now()) {
    return cached;
  }

  if (pendingChecks.has(targetUrl)) {
    return pendingChecks.get(targetUrl);
  }

  const checkPromise = (async () => {
    // 1. Try local desktop service
    if (!authToken) {
      await initializeAuth().catch(() => {});
    }

    try {
      const res = await fetch(`${LOCAL_SERVICE_URL}/api/check-url`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'X-PhishGuard-Auth': authToken || '',
        },
        body: JSON.stringify({
          url: targetUrl,
          browser: 'Chrome / Chromium (MV3)',
          isNavigation: true,
        }),
      });

      if (res.ok) {
        const decision = await res.json();
        decision.expiresAt = Date.now() + CACHE_TTL_MS;
        urlCache.set(targetUrl, decision);
        isConnectedToService = true;
        return decision;
      }
    } catch {
      isConnectedToService = false;
    }

    // 2. Local service offline -> USE OFFLINE HEURISTIC SCORING ENGINE!
    const offlineDecision = evaluateOfflineScoring(targetUrl);
    if (offlineDecision) {
      offlineDecision.expiresAt = Date.now() + CACHE_TTL_MS;
      urlCache.set(targetUrl, offlineDecision);
      return offlineDecision;
    }

    // Baseline safe
    return {
      action: 'allow',
      verdict: 'SAFE',
      riskScore: 10,
      reasons: ['Destination passed baseline security checks'],
      serviceOffline: true,
    };
  })();

  pendingChecks.set(targetUrl, checkPromise);
  try {
    return await checkPromise;
  } finally {
    pendingChecks.delete(targetUrl);
  }
}

function shouldCheckUrl(urlStr) {
  if (!urlStr || typeof urlStr !== 'string') return false;
  return urlStr.startsWith('http://') || urlStr.startsWith('https://');
}

/**
 * Redirects tab to the local PhishGuard Interstitial page.
 */
function redirectToInterstitial(tabId, targetUrl, decision) {
  if (!tabId || tabId <= 0) return;

  if (!interceptedTabs.has(targetUrl)) {
    interceptedTabs.set(targetUrl, new Set());
  }
  interceptedTabs.get(targetUrl).add(tabId);

  const interstitialUrl = chrome.runtime.getURL(
    `pages/interstitial.html?url=${encodeURIComponent(targetUrl)}&tabId=${tabId}`
  );

  chrome.tabs.update(tabId, { url: interstitialUrl })
    .then(() => {
      // Send decision details to the interstitial once it loads
      setTimeout(() => {
        chrome.tabs.sendMessage(tabId, {
          type: 'PHISHGUARD_THREAT_DETECTED',
          data: decision,
          targetUrl,
        }).catch(() => {});
      }, 250);
    })
    .catch(() => {});
}

/**
 * Pre-Navigation Interception via webNavigation.onBeforeNavigate.
 * Intercepts top-level navigation before remote network content renders.
 */
chrome.webNavigation.onBeforeNavigate.addListener((details) => {
  if (details.frameId !== 0) return;
  if (!details.tabId || details.tabId <= 0) return;

  const targetUrl = details.url;
  if (!shouldCheckUrl(targetUrl)) return;
  if (bypassedUrls.has(targetUrl)) return;

  // Don't intercept internal extension pages
  if (targetUrl.startsWith(chrome.runtime.getURL(''))) return;

  // Check cache first
  const cached = urlCache.get(targetUrl);
  if (cached && cached.expiresAt > Date.now()) {
    if (cached.action === 'allow') return;
    redirectToInterstitial(details.tabId, targetUrl, cached);
    return;
  }

  // Pre-check offline heuristics immediately
  const offlineCheck = evaluateOfflineScoring(targetUrl);
  if (offlineCheck && (offlineCheck.action === 'block' || offlineCheck.action === 'warn')) {
    urlCache.set(targetUrl, offlineCheck);
    redirectToInterstitial(details.tabId, targetUrl, offlineCheck);
    // Notify local security service in background to trigger desktop popup
    checkUrlWithService(targetUrl).catch(() => {});
    return;
  }

  // For URLs not immediately flagged offline, query local service in background
  checkUrlWithService(targetUrl)
    .then((decision) => {
      if (decision && (decision.action === 'block' || decision.action === 'warn')) {
        redirectToInterstitial(details.tabId, targetUrl, decision);
      }
    })
    .catch(() => {});
});

/**
 * Message handler for Interstitial page, Content script, and Popup.
 */
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (!message || !message.type) {
    sendResponse({ ok: false });
    return false;
  }

  if (message.type === 'GET_THREAT_DATA') {
    const targetUrl = message.targetUrl;
    const cached = urlCache.get(targetUrl);
    if (cached) {
      sendResponse({ ok: true, data: cached });
      return false;
    }
    checkUrlWithService(targetUrl)
      .then((decision) => {
        sendResponse({ ok: true, data: decision });
      })
      .catch((err) => {
        sendResponse({ ok: false, error: err.message });
      });
    return true; // asynchronous response
  }

  if (message.type === 'CHECK_LINK_CLICK') {
    const targetUrl = message.url;
    checkUrlWithService(targetUrl)
      .then((decision) => {
        sendResponse({ ok: true, decision });
      })
      .catch((err) => {
        sendResponse({ ok: false, error: err.message });
      });
    return true; // asynchronous response
  }

  if (message.type === 'CLOSE_TAB') {
    const tabIdToClose = message.tabId || (sender.tab && sender.tab.id);
    if (tabIdToClose && tabIdToClose > 0) {
      chrome.tabs.remove(tabIdToClose).catch(() => {});
    }
    if (message.url) {
      fetch(`${LOCAL_SERVICE_URL}/api/cancel-navigation`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'X-PhishGuard-Auth': authToken || '',
        },
        body: JSON.stringify({ url: message.url, tabId: tabIdToClose }),
      }).catch(() => {});
    }
    sendResponse({ ok: true });
    return false;
  }

  if (message.type === 'PROCEED_ANYWAY') {
    const { targetUrl, tabId } = message;
    if (targetUrl) {
      bypassedUrls.add(targetUrl);
      fetch(`${LOCAL_SERVICE_URL}/api/bypass`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'X-PhishGuard-Auth': authToken || '',
        },
        body: JSON.stringify({ url: targetUrl }),
      }).catch(() => {});
    }

    if (tabId && tabId > 0 && targetUrl) {
      chrome.tabs.update(tabId, { url: targetUrl }).catch(() => {});
    }
    sendResponse({ ok: true });
    return false;
  }

  if (message.type === 'GET_SERVICE_STATUS') {
    sendResponse({
      isConnected: isConnectedToService,
      authToken: !!authToken,
    });
    return false;
  }

  if (message.type === 'REPORT_SITE') {
    sendResponse({ ok: true });
    return false;
  }

  sendResponse({ ok: false });
  return false;
});

chrome.tabs.onRemoved.addListener((tabId) => {
  for (const [url, tabs] of interceptedTabs.entries()) {
    if (tabs.has(tabId)) {
      tabs.delete(tabId);
      if (tabs.size === 0) {
        interceptedTabs.delete(url);
      }
    }
  }
});

initializeAuth().catch(() => {});
setInterval(() => {
  initializeAuth().catch(() => {});
}, 30000);
