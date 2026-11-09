"""
web/scoring.js and browser-extension/chromium/scoring.js are both
independent JavaScript ports of model.py + features.py + email_auth.py --
the former for the static (no-backend) browser demo, the latter for the
Chromium extension prototype. This test runs Python and BOTH JS ports on
the same inputs and fails the suite if any of them disagree, so neither JS
port can silently drift from the Python original (or from each other)
without the suite catching it.

Requires `node` on PATH; skipped (not failed) if it isn't available, since
the Python implementation is authoritative and CI environments without
Node.js can still run the rest of the suite.
"""

import json
import shutil
import subprocess
import unittest
from pathlib import Path

from model import classify, score_email, score_url

ROOT = Path(__file__).resolve().parents[1]
SCORING_JS_PATHS = {
    "web": ROOT / "web" / "scoring.js",
    "browser-extension": ROOT / "browser-extension" / "chromium" / "scoring.js",
}

URL_CASES = [
    "https://www.google.com/search?q=test",
    "https://www.yahoo.com",
    "http://paypa1-secure-login.xyz/verify",
    "https://bit.ly/abc123",
    "http://192.168.1.1/login",
    "http://192.0.2.10:8080/admin?token=abc123",
    "https://accounts.google.com.security-check.top/signin",
    "http://xn--e1aybc.xn--p1ai/",
    "http://paypal.com@evil.com/login",
    "https://github.com/omobolajiadeyan/phishguard-ai",
    "http://amaz0n-account-suspended.click/verify?user=1&token=" + "a" * 40,
    "https://sub.sub2.sub3.example.com/a/b/c/d",
    "https://www.example.co.uk/",
    "https://login.example.co.uk/",
    "https://foo.alice.github.io/",
    "http://EXAMPLE.COM/Path/To/Resource",
    "ftp://example.com/not-http",
    "not-a-url-at-all",
    "https://example.com",
    "http://xjr7f2k9qz.example/",
    "https://xn--pple-43d.com/signin",
    "http://" + "a" * 63 + ".example.com/",
    "https://example.com:65535/",
    "http://User:Pa%40ss@example.com/path?x=1#frag",
    "https://xn--e1aybc.xn--p1ai/login",
    "http://256.1.1.1/notanip",
    "http://0177.0.0.1/",
    "   https://example.com/   ",
    "http://[::1]:8080/path",
    "http://a@b@evil.com/",
    "https://exa mple.com/path",
    "\t\thttps://example.com/path",
    "https://example.com/verify/😀",
    "https://mybank-verify.pages.dev/",
    "https://vercel.app/",
]

EMAIL_CASES = [
    ("URGENT: Your account has been suspended", "Click here immediately to verify your account.", None),
    ("Meeting notes", "Let's catch up next week about the roadmap.", None),
    ("Re: Invoice #4521", "Please see the attached file for your records.", None),
    (
        "Security Alert",
        "We detected unusual activity!!! Please confirm your identity immediately.",
        "mx.example; spf=fail; dkim=fail; dmarc=fail",
    ),
    ("", "", None),
    ("Newsletter", "<html><body><h1>Big News</h1><p>Read more at www.example.com</p></body></html>", None),
    (
        "Password reset",
        "Someone requested a password reset. If this wasn't you, ignore this email.",
        "mx.example; spf=pass; dkim=pass; dmarc=pass",
    ),
    ("Hello 😀", "A Unicode parity fixture.", None),
]


def _run_js(payload: dict, script_path: Path) -> dict:
    script = """
      const PhishGuardScoring = require(process.argv[1]);
      const input = JSON.parse(require('fs').readFileSync(0, 'utf-8'));
      const out = { urls: [], emails: [] };
      for (const url of input.urls) {
        const { probability, features } = PhishGuardScoring.scoreUrl(url);
        out.urls.push({ probability, verdict: PhishGuardScoring.classify(probability), features });
      }
      for (const [subject, body, auth] of input.emails) {
        const { probability, features } = PhishGuardScoring.scoreEmail(subject, body, auth);
        out.emails.push({ probability, verdict: PhishGuardScoring.classify(probability), features });
      }
      process.stdout.write(JSON.stringify(out));
    """
    result = subprocess.run(
        ["node", "-e", script, str(script_path)],
        input=json.dumps(payload),
        capture_output=True,
        text=True,
        timeout=30,
        check=True,
    )
    return json.loads(result.stdout)


@unittest.skipUnless(shutil.which("node"), "node is not available on PATH")
class JsPortParityTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.js_results = {
            label: _run_js({"urls": URL_CASES, "emails": EMAIL_CASES}, path)
            for label, path in SCORING_JS_PATHS.items()
        }

    def test_url_scoring_matches_python(self):
        for label, js_results in self.js_results.items():
            self.assertEqual(len(js_results["urls"]), len(URL_CASES))
            for url, js_result in zip(URL_CASES, js_results["urls"], strict=True):
                with self.subTest(port=label, url=url):
                    py_probability, py_features = score_url(url)
                    py_verdict = classify(py_probability)

                    self.assertAlmostEqual(
                        js_result["probability"], py_probability, places=3,
                        msg=f"[{label}] probability mismatch for {url!r}",
                    )
                    self.assertEqual(
                        js_result["verdict"], py_verdict,
                        msg=f"[{label}] verdict mismatch for {url!r}",
                    )
                    self.assertEqual(
                        set(js_result["features"]),
                        set(py_features),
                        msg=f"[{label}] feature keys mismatch for {url!r}",
                    )
                    for key, py_value in py_features.items():
                        js_value = js_result["features"][key]
                        if isinstance(py_value, float):
                            self.assertAlmostEqual(
                                js_value, py_value, places=3,
                                msg=f"[{label}] feature {key!r} mismatch for {url!r}",
                            )
                        else:
                            self.assertEqual(
                                js_value, py_value,
                                msg=f"[{label}] feature {key!r} mismatch for {url!r}",
                            )

    def test_email_scoring_matches_python(self):
        for label, js_results in self.js_results.items():
            self.assertEqual(len(js_results["emails"]), len(EMAIL_CASES))
            for (subject, body, auth), js_result in zip(
                EMAIL_CASES, js_results["emails"], strict=True
            ):
                with self.subTest(port=label, subject=subject):
                    py_probability, py_features = score_email(subject, body, authentication_results=auth)
                    py_verdict = classify(py_probability)

                    self.assertAlmostEqual(
                        js_result["probability"], py_probability, places=3,
                        msg=f"[{label}] probability mismatch for {subject!r}",
                    )
                    self.assertEqual(
                        js_result["verdict"], py_verdict,
                        msg=f"[{label}] verdict mismatch for {subject!r}",
                    )
                    self.assertEqual(
                        set(js_result["features"]),
                        set(py_features),
                        msg=f"[{label}] feature keys mismatch for {subject!r}",
                    )
                    for key, py_value in py_features.items():
                        js_value = js_result["features"][key]
                        if isinstance(py_value, float):
                            self.assertAlmostEqual(
                                js_value, py_value, places=3,
                                msg=f"[{label}] feature {key!r} mismatch for {subject!r}",
                            )
                        else:
                            self.assertEqual(
                                js_value, py_value,
                                msg=f"[{label}] feature {key!r} mismatch for {subject!r}",
                            )


if __name__ == "__main__":
    unittest.main()
