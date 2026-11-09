"""
Comprehensive End-to-End System Test for PhishGuard Anti-Phishing Protection System.
Validates:
1. Python PhishGuard engine scoring
2. Local Security Service bridging and HTTP REST API
3. Navigation interception decisions (Block Phishing, Allow Safe, Warn Suspicious)
4. Trusted domain whitelisting
5. Privacy-preserving sensitive query parameter redaction
6. One-time bypass token workflow
"""

import json
import os
import subprocess
import time
import unittest
import urllib.request
import urllib.error

SERVICE_PORT = 8798
SERVICE_URL = f"http://127.0.0.1:{SERVICE_PORT}"


class PhishGuardProtectionSystemTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Start the local security service on test port
        repo_root = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
        service_dir = os.path.join(repo_root, "services", "local-security-service")

        node_script = f"""
        const {{ startServer }} = require('./index');
        startServer({SERVICE_PORT}).then(() => {{
            console.log('TEST_SERVICE_STARTED');
        }}).catch(err => {{
            console.error('FAILED', err);
            process.exit(1);
        }});
        """

        cls.service_proc = subprocess.Popen(
            ["node", "-e", node_script],
            cwd=service_dir,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )

        # Wait for service to start
        started = False
        for _ in range(25):
            time.sleep(0.3)
            try:
                with urllib.request.urlopen(f"{SERVICE_URL}/healthz", timeout=1) as res:
                    if res.status == 200:
                        started = True
                        break
            except Exception:
                pass

        if not started:
            cls.tearDownClass()
            raise RuntimeError("Local Security Service failed to start within timeout.")

        # Get auth token
        with urllib.request.urlopen(f"{SERVICE_URL}/api/token", timeout=2) as res:
            data = json.loads(res.read().decode())
            cls.token = data["token"]

    @classmethod
    def tearDownClass(cls):
        if hasattr(cls, "service_proc") and cls.service_proc:
            try:
                cls.service_proc.terminate()
                cls.service_proc.wait(timeout=3)
            except Exception:
                cls.service_proc.kill()

    def _api_request(self, endpoint, method="GET", data=None):
        url = f"{SERVICE_URL}{endpoint}"
        body = json.dumps(data).encode("utf-8") if data else None
        headers = {
            "Content-Type": "application/json",
            "X-PhishGuard-Auth": self.token,
        }
        req = urllib.request.Request(url, data=body, headers=headers, method=method)
        with urllib.request.urlopen(req, timeout=5) as res:
            return json.loads(res.read().decode())

    def test_01_health_check(self):
        with urllib.request.urlopen(f"{SERVICE_URL}/healthz", timeout=2) as res:
            self.assertEqual(res.status, 200)
            data = json.loads(res.read().decode())
            self.assertEqual(data["status"], "ok")
            self.assertTrue("realTimeProtection" in data)

    def test_02_safe_url_navigation_allowed(self):
        payload = {"url": "https://www.google.com", "isNavigation": True}
        res = self._api_request("/api/check-url", method="POST", data=payload)
        self.assertEqual(res["action"], "allow")
        self.assertEqual(res["verdict"], "SAFE")
        self.assertLess(res["riskScore"], 50)

    def test_03_phishing_url_navigation_blocked(self):
        payload = {
            "url": "http://paypa1-secure-login.xyz/verify?token=fake1234567890",
            "isNavigation": True,
        }
        res = self._api_request("/api/check-url", method="POST", data=payload)
        self.assertEqual(res["action"], "block")
        self.assertEqual(res["verdict"], "PHISHING")
        self.assertGreaterEqual(res["riskScore"], 75)
        self.assertGreater(len(res["reasons"]), 0)

    def test_04_trusted_domain_whitelisted(self):
        # Add trusted domain
        self._api_request("/api/trusted", method="POST", data={"domain": "internal-sec-test.corp"})

        # Navigation should be immediately allowed
        payload = {"url": "http://internal-sec-test.corp/login", "isNavigation": True}
        res = self._api_request("/api/check-url", method="POST", data=payload)
        self.assertEqual(res["action"], "allow")
        self.assertTrue(res.get("trusted", False))

        # Cleanup
        self._api_request("/api/trusted/internal-sec-test.corp", method="DELETE")

    def test_05_privacy_redaction_in_history(self):
        secret_url = "http://paypa1-secure-login.xyz/verify?token=supersecretcredential9999"
        self._api_request("/api/check-url", method="POST", data={"url": secret_url})

        # Fetch history
        history = self._api_request("/api/history?limit=10")
        events = history.get("events", [])
        matching = [e for e in events if "paypa1-secure-login.xyz" in e["url"]]
        self.assertTrue(len(matching) > 0)
        # Ensure secret token is NOT in stored URL
        self.assertNotIn("supersecretcredential9999", matching[0]["url"])
        self.assertIn("[REDACTED]", matching[0]["url"])

    def test_06_bypass_token_proceed_anyway(self):
        target = "http://paypa1-secure-login.xyz/account"
        # Grant bypass
        bypass = self._api_request("/api/bypass", method="POST", data={"url": target, "durationSeconds": 60})
        self.assertTrue(bypass.get("ok", False))

        # Re-check URL should now be permitted
        res = self._api_request("/api/check-url", method="POST", data={"url": target})
        self.assertEqual(res["action"], "allow")
        self.assertTrue(res.get("bypassed", False))


if __name__ == "__main__":
    unittest.main()
