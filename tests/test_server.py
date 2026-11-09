import json
import threading
import time
import unittest
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer
from unittest.mock import patch

from server import PhishGuardRequestHandler, _RateLimiter, _static_assets


class ServerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.httpd = ThreadingHTTPServer(("127.0.0.1", 0), PhishGuardRequestHandler)
        cls.port = cls.httpd.server_address[1]
        cls.thread = threading.Thread(target=cls.httpd.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.httpd.shutdown()
        cls.httpd.server_close()
        cls.thread.join(timeout=5)

    def _url(self, path):
        return f"http://127.0.0.1:{self.port}{path}"

    def _post(self, path, payload, expect_status=200):
        data = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(
            self._url(path),
            data=data,
            method="POST",
            headers={"Content-Type": "application/json"},
        )
        try:
            with urllib.request.urlopen(req, timeout=5) as resp:
                return resp.status, json.loads(resp.read())
        except urllib.error.HTTPError as exc:
            with exc:
                self.assertEqual(exc.code, expect_status)
                return exc.code, json.loads(exc.read())

    def test_healthz(self):
        with urllib.request.urlopen(self._url("/healthz"), timeout=5) as resp:
            self.assertEqual(resp.status, 200)
            self.assertEqual(json.loads(resp.read()), {"status": "ok"})

    def test_routes_ignore_query_strings(self):
        with urllib.request.urlopen(self._url("/healthz?probe=1"), timeout=5) as resp:
            self.assertEqual(resp.status, 200)
        with urllib.request.urlopen(self._url("/style.css?v=1"), timeout=5) as resp:
            self.assertIn("text/css", resp.headers.get("Content-Type", ""))
        status, _body = self._post(
            "/v1/url?source=test", {"url": "https://example.com"}
        )
        self.assertEqual(status, 200)

    def test_unknown_get_path_is_404(self):
        with self.assertRaises(urllib.error.HTTPError) as ctx:
            urllib.request.urlopen(self._url("/nope"), timeout=5)
        with ctx.exception:
            self.assertEqual(ctx.exception.code, 404)

    def test_url_scoring_offline(self):
        status, body = self._post(
            "/v1/url", {"url": "http://paypa1-secure-login.xyz/verify"}
        )
        self.assertEqual(status, 200)
        self.assertEqual(body["url"], "http://paypa1-secure-login.xyz/verify")
        self.assertIn(body["verdict"], {"PHISHING", "SUSPICIOUS", "SAFE"})
        self.assertIn("features", body)
        self.assertNotIn("redirect_chain", body)

    def test_url_missing_field_is_400(self):
        status, body = self._post("/v1/url", {}, expect_status=400)
        self.assertEqual(status, 400)
        self.assertIn("error", body)

    def test_url_invalid_follow_redirects_is_400(self):
        status, body = self._post(
            "/v1/url",
            {"url": "https://example.com", "follow_redirects": -1},
            expect_status=400,
        )
        self.assertEqual(status, 400)

    def test_url_follow_redirects_uses_final_destination(self):
        chain = {
            "final_url": "https://example.com/landing",
            "hops": 2,
            "chain": ["https://bit.ly/abc", "https://example.com/landing"],
            "crossed_domain": True,
            "error": None,
        }
        with patch("server.follow_redirects", return_value=chain):
            status, body = self._post(
                "/v1/url", {"url": "https://bit.ly/abc", "follow_redirects": 3}
            )
        self.assertEqual(status, 200)
        self.assertEqual(body["final_url"], "https://example.com/landing")
        self.assertEqual(body["redirect_chain"], {"hops": 2, "crossed_domain": True})

    def test_url_invalid_check_domain_age_is_400(self):
        status, body = self._post(
            "/v1/url",
            {"url": "https://example.com", "check_domain_age": "yes"},
            expect_status=400,
        )
        self.assertEqual(status, 400)

    def test_url_check_domain_age_feeds_the_model(self):
        with patch(
            "server.domain_age_features",
            return_value={"domain_newer_than_30d": 1, "domain_newer_than_90d": 1},
        ) as mocked:
            status, body = self._post(
                "/v1/url",
                {"url": "https://freshly-registered.example", "check_domain_age": True},
            )
        self.assertEqual(status, 200)
        mocked.assert_called_once()
        self.assertEqual(body["features"]["domain_newer_than_30d"], 1)

    def test_url_check_domain_age_defaults_off(self):
        with patch("server.domain_age_features") as mocked:
            status, body = self._post("/v1/url", {"url": "https://example.com"})
        self.assertEqual(status, 200)
        mocked.assert_not_called()
        self.assertNotIn("domain_newer_than_30d", body["features"])

    def test_email_scoring(self):
        status, body = self._post(
            "/v1/email",
            {
                "subject": "URGENT: verify your account now",
                "body": "Click here immediately!!!",
            },
        )
        self.assertEqual(status, 200)
        self.assertIn(body["verdict"], {"PHISHING", "SUSPICIOUS", "SAFE"})
        self.assertIn("features", body)

    def test_email_missing_fields_is_400(self):
        status, body = self._post("/v1/email", {"subject": "hi"}, expect_status=400)
        self.assertEqual(status, 400)

    def test_post_unknown_path_is_404(self):
        status, body = self._post("/v1/nope", {"a": 1}, expect_status=404)
        self.assertEqual(status, 404)

    def test_malformed_json_is_400(self):
        req = urllib.request.Request(
            self._url("/v1/url"),
            data=b"{not json",
            method="POST",
            headers={"Content-Type": "application/json"},
        )
        with self.assertRaises(urllib.error.HTTPError) as ctx:
            urllib.request.urlopen(req, timeout=5)
        with ctx.exception:
            self.assertEqual(ctx.exception.code, 400)

    def test_invalid_utf8_json_is_400(self):
        req = urllib.request.Request(
            self._url("/v1/url"),
            data=b'{"url":"\xff"}',
            method="POST",
            headers={"Content-Type": "application/json"},
        )
        with self.assertRaises(urllib.error.HTTPError) as ctx:
            urllib.request.urlopen(req, timeout=5)
        with ctx.exception:
            self.assertEqual(ctx.exception.code, 400)

    def test_index_serves_the_demo_page(self):
        with urllib.request.urlopen(self._url("/"), timeout=5) as resp:
            self.assertEqual(resp.status, 200)
            self.assertIn("text/html", resp.headers.get("Content-Type", ""))
            body = resp.read().decode("utf-8")
            self.assertIn("PhishGuard AI", body)

    def test_app_js_is_served_with_javascript_content_type(self):
        with urllib.request.urlopen(self._url("/app.js"), timeout=5) as resp:
            self.assertEqual(resp.status, 200)
            self.assertIn("javascript", resp.headers.get("Content-Type", ""))

    def test_scoring_js_is_served_with_javascript_content_type(self):
        with urllib.request.urlopen(self._url("/scoring.js"), timeout=5) as resp:
            self.assertEqual(resp.status, 200)
            self.assertIn("javascript", resp.headers.get("Content-Type", ""))

    def test_public_suffix_js_is_served_with_javascript_content_type(self):
        with urllib.request.urlopen(self._url("/public-suffix.js"), timeout=5) as resp:
            self.assertEqual(resp.status, 200)
            self.assertIn("javascript", resp.headers.get("Content-Type", ""))

    def test_style_css_is_served_with_css_content_type(self):
        with urllib.request.urlopen(self._url("/style.css"), timeout=5) as resp:
            self.assertEqual(resp.status, 200)
            self.assertIn("text/css", resp.headers.get("Content-Type", ""))


class StaticAssetLoadingTests(unittest.TestCase):
    def test_known_routes_resolve_to_real_files_on_disk(self):
        assets = _static_assets()
        self.assertIn("/", assets)
        self.assertIn("/app.js", assets)
        self.assertIn("/public-suffix.js", assets)
        self.assertIn("/scoring.js", assets)
        self.assertIn("/style.css", assets)
        for body, _content_type in assets.values():
            self.assertIsInstance(body, bytes)
            self.assertGreater(len(body), 0)


class RateLimiterTests(unittest.TestCase):
    def test_allows_up_to_the_limit_then_blocks(self):
        limiter = _RateLimiter(max_requests=2, window_seconds=60)
        self.assertTrue(limiter.allow("1.2.3.4"))
        self.assertTrue(limiter.allow("1.2.3.4"))
        self.assertFalse(limiter.allow("1.2.3.4"))

    def test_keys_are_independent(self):
        limiter = _RateLimiter(max_requests=1, window_seconds=60)
        self.assertTrue(limiter.allow("1.2.3.4"))
        self.assertTrue(limiter.allow("5.6.7.8"))
        self.assertFalse(limiter.allow("1.2.3.4"))

    def test_zero_disables_limiting(self):
        limiter = _RateLimiter(max_requests=0, window_seconds=60)
        for _ in range(50):
            self.assertTrue(limiter.allow("1.2.3.4"))

    def test_requests_outside_the_window_are_forgotten(self):
        limiter = _RateLimiter(max_requests=1, window_seconds=0.05)
        self.assertTrue(limiter.allow("1.2.3.4"))
        self.assertFalse(limiter.allow("1.2.3.4"))
        time.sleep(0.1)
        self.assertTrue(limiter.allow("1.2.3.4"))


class RateLimitedServerTests(unittest.TestCase):
    """End-to-end check that a configured rate_limiter is actually
    enforced over the wire, with the response shape a client depends on."""

    @classmethod
    def setUpClass(cls):
        cls.httpd = ThreadingHTTPServer(("127.0.0.1", 0), PhishGuardRequestHandler)
        cls.httpd.rate_limiter = _RateLimiter(max_requests=1, window_seconds=60)
        cls.port = cls.httpd.server_address[1]
        cls.thread = threading.Thread(target=cls.httpd.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.httpd.shutdown()
        cls.httpd.server_close()
        cls.thread.join(timeout=5)

    def test_second_request_from_same_ip_is_rate_limited(self):
        url = f"http://127.0.0.1:{self.port}/v1/url"
        payload = json.dumps({"url": "https://example.com"}).encode("utf-8")

        def post():
            req = urllib.request.Request(
                url, data=payload, method="POST",
                headers={"Content-Type": "application/json"},
            )
            return urllib.request.urlopen(req, timeout=5)

        with post() as resp:
            self.assertEqual(resp.status, 200)

        with self.assertRaises(urllib.error.HTTPError) as ctx:
            post()
        with ctx.exception:
            self.assertEqual(ctx.exception.code, 429)
            self.assertIn("Retry-After", ctx.exception.headers)
            body = json.loads(ctx.exception.read())
            self.assertIn("error", body)

    def test_get_requests_are_not_rate_limited(self):
        # Only POST /v1/* is metered; static assets and healthz stay free.
        url = f"http://127.0.0.1:{self.port}/healthz"
        for _ in range(5):
            with urllib.request.urlopen(url, timeout=5) as resp:
                self.assertEqual(resp.status, 200)


if __name__ == "__main__":
    unittest.main()
