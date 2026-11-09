/**
 * Local Persistent Storage for PhishGuard Security History & Settings.
 * Implements atomic writes, query-string privacy redaction, and querying capabilities.
 */

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const DATA_DIR = path.resolve(__dirname, '..', '..', 'data');
const HISTORY_FILE = path.join(DATA_DIR, 'security_history.json');
const SETTINGS_FILE = path.join(DATA_DIR, 'protection_settings.json');
const TRUSTED_DOMAINS_FILE = path.join(DATA_DIR, 'trusted_domains.json');

const SENSITIVE_PARAM_NAMES = new Set([
  'token', 'access_token', 'id_token', 'refresh_token', 'auth', 'authorization',
  'password', 'pass', 'pwd', 'secret', 'key', 'api_key', 'apikey', 'code',
  'session', 'session_id', 'sessionid', 'jwt', 'ticket', 'sig', 'signature'
]);

const DEFAULT_SETTINGS = {
  realTimeProtection: true,
  desktopNotifications: true,
  warningPopup: true,
  policyMode: 'standard', // 'standard' (block phishing, warn suspicious) | 'strict' (block both)
  failMode: 'fail_open',  // 'fail_open' | 'fail_closed'
  cacheTtlSeconds: 300,
  autoStart: false,
};

const DEFAULT_TRUSTED = [
  'google.com',
  'github.com',
  'microsoft.com',
  'apple.com',
  'amazon.com'
];

/**
 * Redacts sensitive query parameters from a URL for privacy.
 */
function redactUrl(rawUrl) {
  try {
    const parsed = new URL(rawUrl);
    let modified = false;

    for (const [key, val] of Array.from(parsed.searchParams.entries())) {
      const lower = key.toLowerCase();
      if (SENSITIVE_PARAM_NAMES.has(lower) || val.length > 40) {
        parsed.searchParams.set(key, '[REDACTED]');
        modified = true;
      }
    }

    if (modified) {
      return parsed.toString().replace(/%5BREDACTED%5D/g, '[REDACTED]');
    }
    return rawUrl;
  } catch {
    return rawUrl;
  }
}

/**
 * Extracts the host or domain name safely.
 */
function extractDomain(rawUrl) {
  try {
    const parsed = new URL(rawUrl);
    return parsed.hostname.toLowerCase();
  } catch {
    return 'unknown';
  }
}

/**
 * Safely writes JSON atomically to a file using a temp file.
 */
function writeJsonAtomic(filePath, data) {
  if (!fs.existsSync(DATA_DIR)) {
    fs.mkdirSync(DATA_DIR, { recursive: true });
  }

  const tempPath = `${filePath}.${crypto.randomBytes(6).toString('hex')}.tmp`;
  fs.writeFileSync(tempPath, JSON.stringify(data, null, 2), 'utf8');
  fs.renameSync(tempPath, filePath);
}

/**
 * Reads JSON file with fallback.
 */
function readJsonSafe(filePath, fallback) {
  try {
    if (fs.existsSync(filePath)) {
      const content = fs.readFileSync(filePath, 'utf8');
      return JSON.parse(content);
    }
  } catch (err) {
    console.error(`[DB] Error reading ${filePath}:`, err.message);
  }
  return fallback;
}

class SecurityDatabase {
  constructor() {
    this._init();
  }

  _init() {
    if (!fs.existsSync(DATA_DIR)) {
      fs.mkdirSync(DATA_DIR, { recursive: true });
    }

    if (!fs.existsSync(SETTINGS_FILE)) {
      writeJsonAtomic(SETTINGS_FILE, DEFAULT_SETTINGS);
    }

    if (!fs.existsSync(TRUSTED_DOMAINS_FILE)) {
      writeJsonAtomic(TRUSTED_DOMAINS_FILE, DEFAULT_TRUSTED);
    }

    if (!fs.existsSync(HISTORY_FILE)) {
      writeJsonAtomic(HISTORY_FILE, []);
    }
  }

  // Settings
  getSettings() {
    const current = readJsonSafe(SETTINGS_FILE, DEFAULT_SETTINGS);
    return { ...DEFAULT_SETTINGS, ...current };
  }

  updateSettings(updates) {
    const current = this.getSettings();
    const updated = { ...current, ...updates };
    writeJsonAtomic(SETTINGS_FILE, updated);
    return updated;
  }

  // Trusted Domains
  getTrustedDomains() {
    return readJsonSafe(TRUSTED_DOMAINS_FILE, DEFAULT_TRUSTED);
  }

  isDomainTrusted(domain) {
    const list = this.getTrustedDomains();
    const norm = (domain || '').toLowerCase().trim();
    return list.some(td => norm === td || norm.endsWith(`.${td}`));
  }

  addTrustedDomain(domain) {
    const norm = (domain || '').toLowerCase().trim();
    if (!norm) return false;

    const list = this.getTrustedDomains();
    if (!list.includes(norm)) {
      list.push(norm);
      writeJsonAtomic(TRUSTED_DOMAINS_FILE, list);
      return true;
    }
    return false;
  }

  removeTrustedDomain(domain) {
    const norm = (domain || '').toLowerCase().trim();
    const list = this.getTrustedDomains();
    const next = list.filter(d => d !== norm);
    writeJsonAtomic(TRUSTED_DOMAINS_FILE, next);
    return true;
  }

  // Security History
  recordEvent({ url, classification, riskScore, reasons, action, browser, features }) {
    const history = readJsonSafe(HISTORY_FILE, []);
    const redacted = redactUrl(url);
    const domain = extractDomain(url);

    const event = {
      id: crypto.randomUUID(),
      timestamp: new Date().toISOString(),
      url: redacted,
      originalUrl: url,
      domain,
      classification: classification.toUpperCase(), // 'PHISHING' | 'SUSPICIOUS' | 'SAFE'
      riskScore: Math.round(riskScore * 100),       // 0 - 100
      reasons: reasons || [],
      action: action.toLowerCase(),                 // 'block' | 'warn' | 'allow'
      browser: browser || 'Browser Extension',
      features: features || {}
    };

    // Store up to 1000 events
    history.unshift(event);
    if (history.length > 1000) {
      history.length = 1000;
    }

    writeJsonAtomic(HISTORY_FILE, history);
    return event;
  }

  getEvents({ limit = 50, offset = 0, filter = null, search = null } = {}) {
    let history = readJsonSafe(HISTORY_FILE, []);

    if (filter && filter !== 'ALL') {
      const f = filter.toUpperCase();
      history = history.filter(e => e.classification === f || e.action === f.toLowerCase());
    }

    if (search && search.trim()) {
      const q = search.trim().toLowerCase();
      history = history.filter(e => 
        (e.domain && e.domain.toLowerCase().includes(q)) ||
        (e.url && e.url.toLowerCase().includes(q)) ||
        (e.classification && e.classification.toLowerCase().includes(q))
      );
    }

    const total = history.length;
    const paginated = history.slice(offset, offset + limit);

    return {
      total,
      limit,
      offset,
      events: paginated
    };
  }

  clearEvents() {
    writeJsonAtomic(HISTORY_FILE, []);
    return true;
  }

  getStats() {
    const history = readJsonSafe(HISTORY_FILE, []);
    let blockedCount = 0;
    let suspiciousCount = 0;
    let safeCount = 0;

    for (const item of history) {
      if (item.classification === 'PHISHING' || item.action === 'block') {
        blockedCount++;
      } else if (item.classification === 'SUSPICIOUS' || item.action === 'warn') {
        suspiciousCount++;
      } else {
        safeCount++;
      }
    }

    return {
      totalScanned: history.length,
      blockedPhishing: blockedCount,
      detectedSuspicious: suspiciousCount,
      safeVerified: safeCount,
      lastScanTimestamp: history.length > 0 ? history[0].timestamp : null
    };
  }
}

const db = new SecurityDatabase();

module.exports = {
  db,
  redactUrl,
  extractDomain,
};
