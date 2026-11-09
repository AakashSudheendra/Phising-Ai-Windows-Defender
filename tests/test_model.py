import unittest

from model import classify, score_email, score_url


class UrlScoringTests(unittest.TestCase):
    def test_known_legitimate_urls_are_safe(self):
        urls = (
            "https://www.google.com",
            "https://www.yahoo.com",
            "https://github.com/omobolajiadeyan",
            "https://www.bbc.co.uk/news",
            "https://stackoverflow.com/questions",
        )

        for url in urls:
            with self.subTest(url=url):
                probability, _ = score_url(url)
                self.assertEqual(classify(probability), "SAFE")

    def test_common_presentation_subdomains_do_not_add_risk(self):
        root_probability, root_features = score_url("https://yahoo.com")
        www_probability, www_features = score_url("https://www.yahoo.com")

        self.assertEqual(www_features["subdomain_count"], 0)
        self.assertEqual(root_features["subdomain_count"], 0)
        self.assertLessEqual(www_probability, 0.12)
        # Adding "www." shouldn't meaningfully change the risk score (some
        # small drift is expected from the extra 4 characters feeding into
        # length/entropy-based features).
        self.assertAlmostEqual(www_probability, root_probability, delta=0.03)

    def test_obvious_phishing_urls_are_phishing(self):
        urls = (
            "http://paypa1-secure-login.xyz/account/verify?id=12345",
            "http://192.168.1.1/banking/login.php",
            "http://amazon-security-alert.tk/confirm-account",
        )

        for url in urls:
            with self.subTest(url=url):
                probability, _ = score_url(url)
                self.assertEqual(classify(probability), "PHISHING")

    def test_legitimate_idn_signals_are_safe(self):
        urls = (
            "https://xn--bcher-kva.example/catalog",
            "https://b\u00fccher.example/catalog",
        )

        for url in urls:
            with self.subTest(url=url):
                probability, features = score_url(url)
                self.assertEqual(classify(probability), "SAFE")
                self.assertEqual(
                    features["has_punycode"] + features["has_unicode_hostname"],
                    1,
                )

    def test_punycode_combines_with_credential_lure_signals(self):
        probability, features = score_url(
            "https://xn--pple-43d.example/login/verify"
        )

        self.assertEqual(classify(probability), "SUSPICIOUS")
        self.assertEqual(features["has_punycode"], 1)
        self.assertEqual(features["phishing_keywords"], 2)


class RealisticSecurityUrlFalsePositiveTests(unittest.TestCase):
    """Regression guard for the false-positive gap found by the 2026-08-24
    stress test (docs/BENCHMARK.md's "False-Positive Stress Test",
    tools/evaluate_fp_stress_test.py): every prior "known legitimate" test
    case above is a bare root domain or a trivial path, so none of them
    exercised the URL shapes a real login, verification, or password-reset
    flow actually produces -- which is also exactly the shape a phishing
    page is built to imitate. These cases are drawn directly from
    data/branded_path_benchmark_urls.jsonl.

    Fixed by the query-string scoping change (docs/DETECTION_MODEL.md's
    "Query-string scoping"): url_length, special_char_count, and
    digit_ratio are now scored on scheme://host/path only, so a realistic
    token-bearing security link isn't penalized for doing what a query
    string is for.
    """

    def test_realistic_security_urls_on_real_domains_are_not_phishing(self):
        urls = (
            "https://contoso.example/login",
            "https://www.fabrikam.example/signin",
            "https://northwind.example/account/login",
            "https://contoso.example/account/verify?token=a1b2c3d4e5f67890",
            "https://fabrikam.example/password/reset?token=b6c7d8e9f0a1b2c3&redirect=https://fabrikam.example/dashboard",
            "https://accounts.northwind.example/signin",
            "https://secure.contoso.example/login",
        )

        for url in urls:
            with self.subTest(url=url):
                probability, _ = score_url(url)
                self.assertNotEqual(
                    classify(probability),
                    "PHISHING",
                    f"{url} scored {probability} -- an ordinary security-relevant "
                    "path should not alone be enough to reach the highest verdict",
                )

    @unittest.expectedFailure
    def test_keyword_dense_path_without_query_string_is_a_known_gap(self):
        """NOT fixed by the query-string scoping change, and deliberately
        not chased with a weight tweak: this path has no query string at
        all, so the fix above doesn't touch it. The score is driven by
        phishing_keywords density (4 matches: support/account/security/
        verify) plus base path length -- tuning either down to pass this
        one case risked weakening real phishing detection without a
        domain-reputation signal to tell a real branded path from an
        imitation of one (see docs/DETECTION_MODEL.md's Known
        Limitations). Tracked here with @expectedFailure rather than
        deleted, so it stays visible in the suite and this decorator must
        be removed -- not silently left stale -- once a fix lands.
        """
        probability, _ = score_url(
            "https://fabrikam.example/support/account/security/verify-identity"
        )
        self.assertNotEqual(classify(probability), "PHISHING")


class EmailScoringTests(unittest.TestCase):
    def test_normal_email_is_safe(self):
        probability, _ = score_email(
            "Meeting reminder",
            "Our meeting is scheduled for tomorrow at 10 AM.",
        )

        self.assertEqual(classify(probability), "SAFE")

    def test_urgent_account_lure_is_phishing(self):
        probability, _ = score_email(
            "URGENT: Account suspended",
            "Click here immediately to verify your account or it will expire!",
        )

        self.assertEqual(classify(probability), "PHISHING")

    def test_forwarded_legitimate_email_stays_safe_with_spf_failure(self):
        probability, features = score_email(
            "Project update",
            "Here is the project update from yesterday's working session.",
            "forwarder.example; spf=fail; dkim=pass; dmarc=pass",
        )

        self.assertEqual(classify(probability), "SAFE")
        self.assertEqual(features["spf_result"], "fail")

    def test_combined_authentication_failures_raise_phishing_score(self):
        subject = "Security alert"
        body = "Click here to verify your account."
        baseline, _ = score_email(subject, body)
        authenticated, features = score_email(
            subject,
            body,
            "mx.example; spf=fail; dkim=fail; dmarc=fail",
        )

        self.assertGreater(authenticated, baseline)
        self.assertEqual(classify(authenticated), "PHISHING")
        self.assertEqual(features["dmarc_result"], "fail")

    def test_authenticated_sender_can_still_be_phishing(self):
        # A fully SPF/DKIM/DMARC-passing sender (e.g. a compromised mailbox
        # or an attacker's own properly configured domain) must not have
        # its phishing score reduced by passing authentication. Passing
        # auth proves message-transport authenticity, not sender intent.
        subject = "URGENT: Account suspended"
        body = (
            "Click here immediately to verify your account or it will "
            "expire! See attachment."
        )
        baseline, _ = score_email(subject, body)
        authenticated, features = score_email(
            subject, body, "mx.example; spf=pass; dkim=pass; dmarc=pass"
        )

        self.assertEqual(authenticated, baseline)
        self.assertEqual(classify(authenticated), "PHISHING")
        self.assertEqual(
            (features["spf_result"], features["dkim_result"], features["dmarc_result"]),
            ("pass", "pass", "pass"),
        )

    def test_missing_authentication_header_matches_explicit_none(self):
        subject = "Weekly newsletter"
        body = "Here are this week's top stories from our editorial team."

        omitted, _ = score_email(subject, body)
        explicit_none, features = score_email(subject, body, None)

        self.assertEqual(omitted, explicit_none)
        self.assertEqual(
            (features["spf_result"], features["dkim_result"], features["dmarc_result"]),
            ("unknown", "unknown", "unknown"),
        )

    def test_malformed_authentication_results_degrades_to_no_header(self):
        subject = "URGENT: Account suspended"
        body = (
            "Click here immediately to verify your account or it will "
            "expire! See attachment."
        )
        baseline, _ = score_email(subject, body)
        malformed, features = score_email(
            subject, body, "totally not a valid header ;;; ==="
        )

        self.assertEqual(malformed, baseline)
        self.assertEqual(
            (features["spf_result"], features["dkim_result"], features["dmarc_result"]),
            ("unknown", "unknown", "unknown"),
        )

    def test_single_authentication_failure_is_proportional_not_decisive(self):
        # A lone DMARC failure (the heaviest-weighted auth signal, 0.18) on
        # an otherwise mild email should nudge the score up without being
        # enough on its own to flip a SAFE email to PHISHING.
        subject = "Weekly newsletter"
        body = "Here are this week's top stories from our editorial team."

        baseline, _ = score_email(subject, body)
        dmarc_fail_only, features = score_email(
            subject, body, "mx.example; spf=pass; dkim=pass; dmarc=fail"
        )

        self.assertGreater(dmarc_fail_only, baseline)
        self.assertEqual(classify(baseline), "SAFE")
        self.assertEqual(classify(dmarc_fail_only), "SAFE")
        self.assertEqual(features["dmarc_result"], "fail")


if __name__ == "__main__":
    unittest.main()
