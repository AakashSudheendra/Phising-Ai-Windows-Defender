/**
 * Authentication and Origin Protection for PhishGuard Local Security Service.
 * Ensures only authorized local clients (Desktop app, browser extension) can interact with the service.
 */

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const DATA_DIR = path.resolve(__dirname, '..', '..', 'data');
const TOKEN_FILE = path.join(DATA_DIR, 'service_auth.token');

let cachedToken = null;

/**
 * Returns or generates a persistent authentication token.
 */
function getOrCreateAuthToken() {
  if (cachedToken) {
    return cachedToken;
  }

  try {
    if (!fs.existsSync(DATA_DIR)) {
      fs.mkdirSync(DATA_DIR, { recursive: true });
    }

    if (fs.existsSync(TOKEN_FILE)) {
      const existing = fs.readFileSync(TOKEN_FILE, 'utf8').trim();
      if (existing.length >= 32) {
        cachedToken = existing;
        return cachedToken;
      }
    }

    // Generate new cryptographically secure token
    const newToken = crypto.randomBytes(32).toString('hex');
    fs.writeFileSync(TOKEN_FILE, newToken, { encoding: 'utf8', mode: 0o600 });
    cachedToken = newToken;
    return cachedToken;
  } catch (err) {
    console.error('[Auth] Failed to load/store auth token:', err.message);
    if (!cachedToken) {
      cachedToken = crypto.randomBytes(32).toString('hex');
    }
    return cachedToken;
  }
}

/**
 * Validates whether the request comes from an authorized origin and provides a valid token.
 */
function validateRequestAuth(req) {
  const token = getOrCreateAuthToken();

  // Allow health check without token
  if (req.url === '/healthz' && req.method === 'GET') {
    return { ok: true };
  }

  // Check header
  const authHeader = req.headers['x-phishguard-auth'] || req.headers['authorization'];
  let providedToken = null;

  if (authHeader) {
    if (authHeader.startsWith('Bearer ')) {
      providedToken = authHeader.slice(7).trim();
    } else {
      providedToken = authHeader.trim();
    }
  }

  // Also support query param for EventSource / SSE connection: ?auth=...
  if (!providedToken && req.url.includes('?')) {
    try {
      const u = new URL(req.url, 'http://127.0.0.1:8766');
      providedToken = u.searchParams.get('auth');
    } catch {
      // ignore
    }
  }

  if (!providedToken || providedToken !== token) {
    return { ok: false, status: 401, error: 'Unauthorized: Missing or invalid authentication token' };
  }

  // Check origin if present
  const origin = req.headers['origin'];
  if (origin) {
    const isExtension = origin.startsWith('chrome-extension://') || origin.startsWith('moz-extension://');
    const isLocalhost = origin.startsWith('http://127.0.0.1:') || origin.startsWith('http://localhost:');

    if (!isExtension && !isLocalhost) {
      return { ok: false, status: 403, error: 'Forbidden: Request origin not permitted' };
    }
  }

  return { ok: true };
}

/**
 * Set CORS headers safe for browser extensions and localhost.
 */
function setCorsHeaders(req, res) {
  const origin = req.headers['origin'] || '*';
  const isExtension = origin.startsWith('chrome-extension://') || origin.startsWith('moz-extension://');
  const isLocalhost = origin.startsWith('http://127.0.0.1:') || origin.startsWith('http://localhost:');

  if (isExtension || isLocalhost) {
    res.setHeader('Access-Control-Allow-Origin', origin);
  } else {
    res.setHeader('Access-Control-Allow-Origin', 'null');
  }

  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, X-PhishGuard-Auth, Authorization');
  res.setHeader('Access-Control-Max-Age', '86400');
}

module.exports = {
  getOrCreateAuthToken,
  validateRequestAuth,
  setCorsHeaders,
};
