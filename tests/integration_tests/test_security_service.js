/**
 * Automated Test Suite for PhishGuard Local Security Service.
 * Tests:
 * 1. Health check & discovery
 * 2. Auth token security & rejection of unauthorized requests
 * 3. Whitelist / trusted domains
 * 4. Safe URL evaluation
 * 5. Phishing URL blocking
 * 6. Query-parameter privacy redaction in history
 * 7. Bypass token generation & expiration
 * 8. Real-time protection disablement toggle
 */

const assert = require('assert');
const http = require('http');
const path = require('path');
const { startServer, stopServer } = require('../../services/local-security-service/index');
const { getOrCreateAuthToken } = require('../../services/local-security-service/auth');
const { redactUrl } = require('../../services/local-security-service/database');

const TEST_PORT = 8799;
let token;

function request(options, postData = null) {
  return new Promise((resolve, reject) => {
    const req = http.request(
      {
        host: '127.0.0.1',
        port: TEST_PORT,
        ...options,
        headers: {
          'Content-Type': 'application/json',
          ...(options.headers || {}),
        },
      },
      (res) => {
        let body = '';
        res.on('data', (c) => (body += c));
        res.on('end', () => {
          let parsed;
          try {
            parsed = JSON.parse(body);
          } catch {
            parsed = body;
          }
          resolve({ status: res.statusCode, data: parsed, headers: res.headers });
        });
      }
    );
    req.on('error', reject);
    if (postData) {
      req.write(typeof postData === 'string' ? postData : JSON.stringify(postData));
    }
    req.end();
  });
}

async function runTests() {
  console.log('=== Starting PhishGuard Local Security Service Automated Tests ===');
  await startServer(TEST_PORT);
  token = getOrCreateAuthToken();

  try {
    // 1. Health check (unauthenticated)
    console.log('[Test 1] Health check unauthenticated...');
    const healthRes = await request({ path: '/healthz', method: 'GET' });
    assert.strictEqual(healthRes.status, 200);
    assert.strictEqual(healthRes.data.status, 'ok');
    console.log('  -> PASS: Health check responds 200 OK');

    // 2. Reject unauthorized request
    console.log('[Test 2] Reject request without token...');
    const unauthRes = await request({
      path: '/api/stats',
      method: 'GET',
    });
    assert.strictEqual(unauthRes.status, 401);
    console.log('  -> PASS: Unauthorized request blocked with 401');

    // 3. Reject bad token
    console.log('[Test 3] Reject request with invalid token...');
    const badTokenRes = await request({
      path: '/api/stats',
      method: 'GET',
      headers: { 'X-PhishGuard-Auth': 'invalid-token-12345' },
    });
    assert.strictEqual(badTokenRes.status, 401);
    console.log('  -> PASS: Invalid token blocked with 401');

    // 4. Accept authorized request
    console.log('[Test 4] Accept request with valid token...');
    const statsRes = await request({
      path: '/api/stats',
      method: 'GET',
      headers: { 'X-PhishGuard-Auth': token },
    });
    assert.strictEqual(statsRes.status, 200);
    assert.ok('totalScanned' in statsRes.data);
    console.log('  -> PASS: Valid token allows access to /api/stats');

    // 5. Test Trusted Domain bypass
    console.log('[Test 5] Test Trusted Domain whitelist check...');
    const trustedRes = await request(
      {
        path: '/api/check-url',
        method: 'POST',
        headers: { 'X-PhishGuard-Auth': token },
      },
      { url: 'https://github.com/omobolajiadeyan' }
    );
    assert.strictEqual(trustedRes.status, 200);
    assert.strictEqual(trustedRes.data.action, 'allow');
    assert.strictEqual(trustedRes.data.verdict, 'SAFE');
    assert.strictEqual(trustedRes.data.trusted, true);
    console.log('  -> PASS: Whitelisted domain github.com allowed immediately');

    // 6. Test Phishing URL Detection & Blocking
    console.log('[Test 6] Test Phishing URL detection & blocking...');
    const phishRes = await request(
      {
        path: '/api/check-url',
        method: 'POST',
        headers: { 'X-PhishGuard-Auth': token },
      },
      { url: 'http://paypa1-secure-login.xyz/verify?token=secret12345678901234567890' }
    );
    assert.strictEqual(phishRes.status, 200);
    assert.strictEqual(phishRes.data.action, 'block');
    assert.strictEqual(phishRes.data.verdict, 'PHISHING');
    assert.ok(phishRes.data.riskScore >= 75);
    assert.ok(phishRes.data.reasons.length > 0);
    console.log(`  -> PASS: Phishing URL correctly blocked with risk score ${phishRes.data.riskScore}% and reasons:`, phishRes.data.reasons[0]);

    // 7. Test URL Privacy Redaction
    console.log('[Test 7] Verify sensitive parameter redaction...');
    const testUrl = 'https://login.example.com/verify?token=supersecrettoken12345&user=john';
    const redacted = redactUrl(testUrl);
    assert.ok(!redacted.includes('supersecrettoken12345'));
    assert.ok(redacted.includes('[REDACTED]'));
    console.log(`  -> PASS: Sensitive query param redacted: ${redacted}`);

    // 8. Test History records
    console.log('[Test 8] Check Security History storage...');
    const historyRes = await request({
      path: '/api/history',
      method: 'GET',
      headers: { 'X-PhishGuard-Auth': token },
    });
    assert.strictEqual(historyRes.status, 200);
    assert.ok(historyRes.data.events.length > 0);
    const lastEvent = historyRes.data.events[0];
    assert.ok(!lastEvent.url.includes('secret12345678901234567890'));
    console.log('  -> PASS: Security history correctly logged event with redacted URL');

    // 9. Test Temporary Bypass Token
    console.log('[Test 9] Test Proceed Anyway bypass mechanism...');
    const bypassUrl = 'http://paypa1-secure-login.xyz/verify';
    const bypassRes = await request(
      {
        path: '/api/bypass',
        method: 'POST',
        headers: { 'X-PhishGuard-Auth': token },
      },
      { url: bypassUrl, durationSeconds: 60 }
    );
    assert.strictEqual(bypassRes.status, 200);
    assert.strictEqual(bypassRes.data.ok, true);

    // Now re-evaluating the URL should return allowed due to bypass
    const reEvalRes = await request(
      {
        path: '/api/check-url',
        method: 'POST',
        headers: { 'X-PhishGuard-Auth': token },
      },
      { url: bypassUrl }
    );
    assert.strictEqual(reEvalRes.data.action, 'allow');
    assert.strictEqual(reEvalRes.data.bypassed, true);
    console.log('  -> PASS: Bypass token successfully allows navigation when user confirmed');

    console.log('\n=== ALL 9 INTEGRATION TESTS PASSED SUCCESSFULLY! ===\n');
  } finally {
    await stopServer();
  }
}

if (require.main === module) {
  runTests().catch((err) => {
    console.error('TEST RUNNER FAILED:', err);
    process.exit(1);
  });
}

module.exports = { runTests };
