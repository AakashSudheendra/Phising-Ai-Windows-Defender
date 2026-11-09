/**
 * PhishGuard Security Policy & Decision Engine.
 * Implements URL normalization, in-memory caching with TTL, trusted domain checks,
 * policy evaluation (block/warn/allow), and event broadcasting.
 */

const { db, extractDomain, redactUrl } = require('./database');
const { classifyUrl, checkEngineHealth } = require('./engine-client');

class PolicyEngine {
  constructor() {
    this.cache = new Map(); // url -> { result, expiresAt }
    this.bypassTokens = new Map(); // domain/url -> expiresAt
    this.alertListeners = new Set(); // SSE callback functions
    this.cancelListeners = new Set(); // Cancellation callback functions
  }

  /**
   * Registers a callback for real-time security alerts (for SSE and Electron IPC).
   */
  onAlert(listener) {
    this.alertListeners.add(listener);
    return () => this.alertListeners.delete(listener);
  }

  /**
   * Broadcasts an alert event to all connected listeners.
   */
  broadcastAlert(event) {
    for (const listener of this.alertListeners) {
      try {
        listener(event);
      } catch (err) {
        console.error('[Policy] Error notifying alert listener:', err.message);
      }
    }
  }

  /**
   * Registers a callback for navigation cancellations.
   */
  onCancelNavigation(listener) {
    this.cancelListeners.add(listener);
    return () => this.cancelListeners.delete(listener);
  }

  /**
   * Broadcasts a cancel navigation event.
   */
  broadcastCancelNavigation(data) {
    for (const listener of this.cancelListeners) {
      try {
        listener(data);
      } catch (err) {
        console.error('[Policy] Error notifying cancel listener:', err.message);
      }
    }
  }

  /**
   * Cleans up expired cache items.
   */
  pruneCache() {
    const now = Date.now();
    for (const [key, item] of this.cache.entries()) {
      if (item.expiresAt <= now) {
        this.cache.delete(key);
      }
    }

    for (const [key, expiresAt] of this.bypassTokens.entries()) {
      if (expiresAt <= now) {
        this.bypassTokens.delete(key);
      }
    }
  }

  /**
   * Grants a temporary user-confirmed bypass for a specific URL/domain.
   */
  grantBypass(targetUrl, durationSeconds = 600) {
    const domain = extractDomain(targetUrl);
    const expiresAt = Date.now() + durationSeconds * 1000;
    this.bypassTokens.set(targetUrl, expiresAt);
    this.bypassTokens.set(domain, expiresAt);
    return { ok: true, domain, expiresAt: new Date(expiresAt).toISOString() };
  }

  /**
   * Checks if a URL or domain has an active user-confirmed bypass.
   */
  hasBypass(targetUrl) {
    const now = Date.now();
    if (this.bypassTokens.has(targetUrl)) {
      if (this.bypassTokens.get(targetUrl) > now) return true;
      this.bypassTokens.delete(targetUrl);
    }

    const domain = extractDomain(targetUrl);
    if (this.bypassTokens.has(domain)) {
      if (this.bypassTokens.get(domain) > now) return true;
      this.bypassTokens.delete(domain);
    }

    return false;
  }

  /**
   * Main entry point to evaluate a navigation URL.
   */
  async evaluateUrl(rawUrl, { browser = 'Browser Extension', isNavigation = true } = {}) {
    this.pruneCache();

    if (!rawUrl || typeof rawUrl !== 'string') {
      return {
        action: 'allow',
        verdict: 'SAFE',
        riskScore: 0,
        reasons: ['Invalid or empty URL format'],
      };
    }

    const trimmed = rawUrl.trim();

    // Check scheme: only check http and https
    if (!trimmed.startsWith('http://') && !trimmed.startsWith('https://')) {
      return {
        action: 'allow',
        verdict: 'SAFE',
        riskScore: 0,
        reasons: ['Internal or non-web protocol'],
      };
    }

    const domain = extractDomain(trimmed);
    const settings = db.getSettings();

    // 1. Check if Real-Time Protection is disabled
    if (!settings.realTimeProtection) {
      return {
        action: 'allow',
        verdict: 'SAFE',
        riskScore: 0,
        reasons: ['Real-time protection is currently disabled by user'],
        protectionDisabled: true,
      };
    }

    // 2. Check Whitelist / Trusted Domains
    if (db.isDomainTrusted(domain)) {
      return {
        action: 'allow',
        verdict: 'SAFE',
        riskScore: 0,
        reasons: ['Domain is in user trusted list'],
        trusted: true,
      };
    }

    // 3. Check User-Confirmed Bypass Token
    if (this.hasBypass(trimmed)) {
      return {
        action: 'allow',
        verdict: 'SUSPICIOUS',
        riskScore: 50,
        reasons: ['User explicitly confirmed proceeding past security warning'],
        bypassed: true,
      };
    }

    // 4. Check In-Memory Cache
    const cached = this.cache.get(trimmed);
    if (cached && cached.expiresAt > Date.now()) {
      return cached.result;
    }

    // 5. Query PhishGuard AI Detection Engine
    let classificationResult;
    try {
      classificationResult = await classifyUrl(trimmed);
    } catch (err) {
      console.error(`[Policy] Engine failure for ${trimmed}:`, err.message);

      // Handle Fail Mode
      if (settings.failMode === 'fail_closed') {
        const fallback = {
          action: 'block',
          verdict: 'SUSPICIOUS',
          riskScore: 70,
          reasons: ['PhishGuard service could not verify URL and fail-closed security policy is active'],
          engineUnavailable: true,
        };
        db.recordEvent({
          url: trimmed,
          classification: 'SUSPICIOUS',
          riskScore: 0.70,
          reasons: fallback.reasons,
          action: 'block',
          browser,
        });
        return fallback;
      }

      // Default: Fail Open
      return {
        action: 'allow',
        verdict: 'UNKNOWN',
        riskScore: 0,
        reasons: ['PhishGuard detection engine unavailable (fail-open mode active)'],
        engineUnavailable: true,
      };
    }

    // 6. Apply Decision Rules
    const { verdict, probability, features, reasons } = classificationResult;
    let action = 'allow';

    if (verdict === 'PHISHING') {
      action = 'block';
    } else if (verdict === 'SUSPICIOUS') {
      action = settings.policyMode === 'strict' ? 'block' : 'warn';
    } else {
      action = 'allow';
    }

    const finalResult = {
      action, // 'block' | 'warn' | 'allow'
      verdict, // 'PHISHING' | 'SUSPICIOUS' | 'SAFE'
      riskScore: Math.round(probability * 100),
      reasons,
      features,
      url: trimmed,
      domain,
    };

    // 7. Cache result with TTL
    const ttlMs = (settings.cacheTtlSeconds || 300) * 1000;
    this.cache.set(trimmed, {
      result: finalResult,
      expiresAt: Date.now() + ttlMs,
    });

    // 8. Record event in history
    const recordedEvent = db.recordEvent({
      url: trimmed,
      classification: verdict,
      riskScore: probability,
      reasons,
      action,
      browser,
      features,
    });

    // 9. If threat detected, broadcast alert for Windows notifications & popup
    if (action === 'block' || action === 'warn') {
      this.broadcastAlert(recordedEvent);
    }

    return finalResult;
  }
}

const policy = new PolicyEngine();

module.exports = {
  policy,
};
