/**
 * PhishGuard AI Python Engine Client.
 * Interfaces with the existing Python PhishGuard detection system (server.py or phishguard.py).
 * Reuses the existing model, weights, and feature extractors without rewriting them.
 */

const http = require('http');
const { spawn, execFile } = require('child_process');
const path = require('path');

const REPO_ROOT = path.resolve(__dirname, '..', '..');
const PYTHON_SCRIPT = path.join(REPO_ROOT, 'phishguard.py');
const ENGINE_HOST = '127.0.0.1';
const ENGINE_PORT = 8765;

let pythonServerProcess = null;
let isStartingServer = false;

/**
 * Checks if the PhishGuard Python server is reachable.
 */
function checkEngineHealth() {
  return new Promise((resolve) => {
    const req = http.request(
      {
        host: ENGINE_HOST,
        port: ENGINE_PORT,
        path: '/healthz',
        method: 'GET',
        timeout: 1000,
      },
      (res) => {
        if (res.statusCode === 200) {
          resolve(true);
        } else {
          resolve(false);
        }
      }
    );

    req.on('error', () => resolve(false));
    req.on('timeout', () => {
      req.destroy();
      resolve(false);
    });
    req.end();
  });
}

/**
 * Ensures the Python server is running, starting it as a background process if necessary.
 */
async function ensureEngineRunning() {
  const healthy = await checkEngineHealth();
  if (healthy) {
    return true;
  }

  if (isStartingServer) {
    // Wait briefly if already starting
    await new Promise((r) => setTimeout(r, 1000));
    return await checkEngineHealth();
  }

  isStartingServer = true;
  console.log('[EngineClient] Starting PhishGuard Python server...');

  try {
    // The engine's default public rate limit (30 POST/min per client IP) would
    // throttle this service, which is its only loopback client, and push every
    // check beyond the 30th per minute onto the ~200 ms CLI fallback. Callers are
    // already authenticated by this service, so disable the limit here.
    pythonServerProcess = spawn('python', ['phishguard.py', 'serve', '--port', String(ENGINE_PORT), '--rate-limit', '0'], {
      cwd: REPO_ROOT,
      stdio: ['ignore', 'pipe', 'pipe'],
      detached: false,
    });

    pythonServerProcess.on('error', (err) => {
      console.error('[EngineClient] Failed to start Python server process:', err.message);
    });

    // Wait for server to bind
    for (let i = 0; i < 8; i++) {
      await new Promise((r) => setTimeout(r, 400));
      if (await checkEngineHealth()) {
        console.log('[EngineClient] PhishGuard Python server is online.');
        isStartingServer = false;
        return true;
      }
    }
  } catch (err) {
    console.error('[EngineClient] Error spawning Python server:', err.message);
  } finally {
    isStartingServer = false;
  }

  return await checkEngineHealth();
}

/**
 * Maps PhishGuard AI's raw extracted features into clear, human-readable reasons.
 */
function generateFeatureReasons(features, verdict) {
  const reasons = [];
  if (!features) return reasons;

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

  if (features.has_opaque_hostname_label > 0) {
    reasons.push('Contains opaque hostname label (potential machine-generated host)');
  }

  if (features.has_https === 0) {
    reasons.push('Insecure connection (no HTTPS encryption)');
  }

  if (features.digit_ratio > 0.25) {
    reasons.push('Suspiciously high ratio of numerical digits in domain name');
  }

  if (features.subdomain_count > 2) {
    reasons.push(`Multiple nested subdomains (${features.subdomain_count}) attempting to disguise identity`);
  }

  if (reasons.length === 0) {
    if (verdict === 'PHISHING') {
      reasons.push('Multiple combined structural risk signals triggered phishing threshold');
    } else if (verdict === 'SUSPICIOUS') {
      reasons.push('Structural indicators exceed safe baseline; manual verification recommended');
    } else {
      reasons.push('Domain structure, reputation, and credentials match safe baseline patterns');
    }
  }

  return reasons;
}

/**
 * Scores a URL via HTTP request to Python server.
 */
function scoreUrlHttp(targetUrl) {
  return new Promise((resolve, reject) => {
    const postData = JSON.stringify({
      url: targetUrl,
      follow_redirects: 0,
      check_domain_age: false,
    });

    const req = http.request(
      {
        host: ENGINE_HOST,
        port: ENGINE_PORT,
        path: '/v1/url',
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Content-Length': Buffer.byteLength(postData),
        },
        timeout: 2500,
      },
      (res) => {
        let body = '';
        res.on('data', (chunk) => (body += chunk));
        res.on('end', () => {
          if (res.statusCode >= 200 && res.statusCode < 300) {
            try {
              const data = JSON.parse(body);
              resolve({
                url: data.url,
                verdict: data.verdict, // 'PHISHING' | 'SUSPICIOUS' | 'SAFE'
                probability: data.probability,
                features: data.features || {},
                reasons: generateFeatureReasons(data.features, data.verdict),
              });
            } catch (err) {
              reject(new Error(`Invalid JSON response from engine: ${err.message}`));
            }
          } else {
            reject(new Error(`Engine responded with HTTP ${res.statusCode}: ${body}`));
          }
        });
      }
    );

    req.on('error', reject);
    req.on('timeout', () => {
      req.destroy();
      reject(new Error('Engine request timed out'));
    });

    req.write(postData);
    req.end();
  });
}

/**
 * Fallback: Runs the CLI directly if the HTTP server is unreachable.
 */
function scoreUrlCliFallback(targetUrl) {
  return new Promise((resolve, reject) => {
    execFile(
      'python',
      [PYTHON_SCRIPT, 'url', targetUrl, '--plain', '--verbose'],
      { cwd: REPO_ROOT, timeout: 5000 },
      (error, stdout, stderr) => {
        if (error) {
          return reject(new Error(`CLI fallback failed: ${error.message}`));
        }

        try {
          // Parse output:
          // Verdict : PHISHING
          // Risk    : ... 95.0%
          const verdictMatch = stdout.match(/Verdict\s*:\s*(PHISHING|SUSPICIOUS|SAFE)/i);
          const riskMatch = stdout.match(/Risk\s*:.*?(\d+\.\d+)%/);

          const verdict = verdictMatch ? verdictMatch[1].toUpperCase() : 'SAFE';
          const probability = riskMatch ? parseFloat(riskMatch[1]) / 100 : 0.2;

          const features = {};
          // Parse lines like "url_length : 37 *"
          const lines = stdout.split('\n');
          for (const line of lines) {
            const m = line.match(/^\s*([a-z_]+)\s*:\s*([0-9.]+)/i);
            if (m) {
              features[m[1]] = parseFloat(m[2]);
            }
          }

          resolve({
            url: targetUrl,
            verdict,
            probability,
            features,
            reasons: generateFeatureReasons(features, verdict),
          });
        } catch (err) {
          reject(err);
        }
      }
    );
  });
}

/**
 * High-level detection call for a given URL.
 */
async function classifyUrl(targetUrl) {
  try {
    const isUp = await ensureEngineRunning();
    if (isUp) {
      return await scoreUrlHttp(targetUrl);
    }
  } catch (err) {
    console.warn('[EngineClient] HTTP query failed, trying CLI fallback:', err.message);
  }

  // Fallback to CLI execution
  return await scoreUrlCliFallback(targetUrl);
}

function stopManagedServer() {
  if (pythonServerProcess) {
    try {
      pythonServerProcess.kill();
    } catch {
      // ignore
    }
    pythonServerProcess = null;
  }
}

module.exports = {
  checkEngineHealth,
  ensureEngineRunning,
  classifyUrl,
  generateFeatureReasons,
  stopManagedServer,
};
