/**
 * PhishGuard Local Security Service HTTP Server.
 * Binds to 127.0.0.1:8766.
 * Bridges Browser Extension, Electron Desktop App, and Python PhishGuard AI engine.
 */

const http = require('http');
const { URL } = require('url');
const { getOrCreateAuthToken, validateRequestAuth, setCorsHeaders } = require('./auth');
const { db } = require('./database');
const { policy } = require('./policy');
const { checkEngineHealth, stopManagedServer } = require('./engine-client');

const PORT = 8766;
const HOST = '127.0.0.1';

/**
 * Parses JSON request body.
 */
function readJsonBody(req) {
  return new Promise((resolve, reject) => {
    let raw = '';
    req.on('data', (chunk) => {
      raw += chunk;
      if (raw.length > 1048576) {
        // 1MB limit
        reject(new Error('Request entity too large'));
      }
    });
    req.on('end', () => {
      if (!raw) return resolve({});
      try {
        resolve(JSON.parse(raw));
      } catch (err) {
        reject(new Error('Invalid JSON format'));
      }
    });
    req.on('error', reject);
  });
}

/**
 * Sends JSON HTTP response.
 */
function sendJson(res, statusCode, data) {
  const json = JSON.stringify(data);
  res.writeHead(statusCode, {
    'Content-Type': 'application/json; charset=utf-8',
    'Content-Length': Buffer.byteLength(json),
  });
  res.end(json);
}

const server = http.createServer(async (req, res) => {
  setCorsHeaders(req, res);

  if (req.method === 'OPTIONS') {
    res.writeHead(204);
    res.end();
    return;
  }

  const parsedUrl = new URL(req.url, `http://${HOST}:${PORT}`);
  const pathname = parsedUrl.pathname;

  // 1. Health check (unauthenticated for discovery)
  if (pathname === '/healthz' && req.method === 'GET') {
    const isEngineUp = await checkEngineHealth();
    const settings = db.getSettings();
    return sendJson(res, 200, {
      status: 'ok',
      service: 'phishguard-local-security-service',
      version: '1.0.0',
      engineOnline: isEngineUp,
      realTimeProtection: settings.realTimeProtection,
      policyMode: settings.policyMode,
    });
  }

  // 2. Token retrieval for localhost loopback callers (e.g. desktop app initializing)
  if (pathname === '/api/token' && req.method === 'GET') {
    const clientIp = req.socket.remoteAddress;
    if (clientIp === '127.0.0.1' || clientIp === '::1' || clientIp === '::ffff:127.0.0.1') {
      return sendJson(res, 200, { token: getOrCreateAuthToken() });
    }
    return sendJson(res, 403, { error: 'Forbidden' });
  }

  // 3. Authenticate all other endpoints
  const auth = validateRequestAuth(req);
  if (!auth.ok) {
    return sendJson(res, auth.status || 401, { error: auth.error });
  }

  try {
    // 4. Real-time Threat Alert Stream (SSE for Electron Desktop App and Browser Extension)
    if (pathname === '/api/events' && req.method === 'GET') {
      res.writeHead(200, {
        'Content-Type': 'text/event-stream',
        'Cache-Control': 'no-cache',
        Connection: 'keep-alive',
      });
      res.write(': connected\n\n');

      const unsubscribeAlert = policy.onAlert((alertEvent) => {
        res.write(`data: ${JSON.stringify({ type: 'THREAT_ALERT', event: alertEvent })}\n\n`);
      });

      const unsubscribeCancel = policy.onCancelNavigation((cancelEvent) => {
        res.write(`data: ${JSON.stringify({ type: 'CANCEL_NAVIGATION', ...cancelEvent })}\n\n`);
      });

      req.on('close', () => {
        unsubscribeAlert();
        unsubscribeCancel();
      });
      return;
    }

    // 4b. Cancel Navigation Endpoint (Triggered when user clicks 'Close' on popup)
    if (pathname === '/api/cancel-navigation' && req.method === 'POST') {
      const body = await readJsonBody(req);
      policy.broadcastCancelNavigation({
        url: body.url || '',
        tabId: body.tabId || null,
        timestamp: new Date().toISOString(),
      });
      return sendJson(res, 200, { ok: true, message: 'Navigation cancelled and tab closed' });
    }

    // 5. Check URL Endpoint (Called by browser extension on navigation)
    if (pathname === '/api/check-url' && req.method === 'POST') {
      const body = await readJsonBody(req);
      if (!body.url) {
        return sendJson(res, 400, { error: 'Missing required "url" parameter' });
      }

      const decision = await policy.evaluateUrl(body.url, {
        browser: body.browser || req.headers['user-agent'] || 'Browser Extension',
        isNavigation: body.isNavigation !== false,
      });

      return sendJson(res, 200, decision);
    }

    // 6. Security Statistics
    if (pathname === '/api/stats' && req.method === 'GET') {
      const stats = db.getStats();
      const isEngineUp = await checkEngineHealth();
      return sendJson(res, 200, {
        ...stats,
        engineOnline: isEngineUp,
        timestamp: new Date().toISOString(),
      });
    }

    // 7. Security History
    if (pathname === '/api/history') {
      if (req.method === 'GET') {
        const limit = parseInt(parsedUrl.searchParams.get('limit') || '50', 10);
        const offset = parseInt(parsedUrl.searchParams.get('offset') || '0', 10);
        const filter = parsedUrl.searchParams.get('filter');
        const search = parsedUrl.searchParams.get('search');

        const history = db.getEvents({ limit, offset, filter, search });
        return sendJson(res, 200, history);
      }

      if (req.method === 'DELETE') {
        db.clearEvents();
        return sendJson(res, 200, { ok: true, message: 'Security history cleared' });
      }
    }

    // 8. Protection Settings
    if (pathname === '/api/settings') {
      if (req.method === 'GET') {
        return sendJson(res, 200, db.getSettings());
      }

      if (req.method === 'PUT') {
        const updates = await readJsonBody(req);
        const updated = db.updateSettings(updates);
        return sendJson(res, 200, updated);
      }
    }

    // 9. Trusted Domains (Whitelist)
    if (pathname === '/api/trusted') {
      if (req.method === 'GET') {
        return sendJson(res, 200, { trustedDomains: db.getTrustedDomains() });
      }

      if (req.method === 'POST') {
        const body = await readJsonBody(req);
        if (!body.domain) {
          return sendJson(res, 400, { error: 'Missing domain parameter' });
        }
        const added = db.addTrustedDomain(body.domain);
        return sendJson(res, 200, { ok: added, trustedDomains: db.getTrustedDomains() });
      }
    }

    if (pathname.startsWith('/api/trusted/') && req.method === 'DELETE') {
      const domain = decodeURIComponent(pathname.replace('/api/trusted/', ''));
      db.removeTrustedDomain(domain);
      return sendJson(res, 200, { ok: true, trustedDomains: db.getTrustedDomains() });
    }

    // 10. Temporary Bypass Token (User clicked "Proceed Anyway" on Interstitial)
    if (pathname === '/api/bypass' && req.method === 'POST') {
      const body = await readJsonBody(req);
      if (!body.url) {
        return sendJson(res, 400, { error: 'Missing url parameter' });
      }
      const bypass = policy.grantBypass(body.url, body.durationSeconds || 600);
      return sendJson(res, 200, bypass);
    }

    // Route not found
    return sendJson(res, 404, { error: 'Endpoint not found' });
  } catch (err) {
    console.error(`[Server] Error processing ${req.method} ${pathname}:`, err);
    return sendJson(res, 500, { error: 'Internal server error', message: err.message });
  }
});

function startServer(port = PORT, host = HOST) {
  return new Promise((resolve, reject) => {
    server.listen(port, host, () => {
      console.log(`[LocalSecurityService] Online at http://${host}:${port}`);
      console.log(`[LocalSecurityService] Auth Token configured.`);
      resolve(server);
    });
    server.on('error', reject);
  });
}

function stopServer() {
  return new Promise((resolve) => {
    stopManagedServer();
    server.close(() => {
      console.log('[LocalSecurityService] Stopped.');
      resolve();
    });
  });
}

if (require.main === module) {
  startServer().catch((err) => {
    console.error('Failed to start local security service:', err);
    process.exit(1);
  });

  process.on('SIGINT', async () => {
    await stopServer();
    process.exit(0);
  });

  process.on('SIGTERM', async () => {
    await stopServer();
    process.exit(0);
  });
}

module.exports = {
  server,
  startServer,
  stopServer,
};
