"""Tests for typosquatting / lookalike domain detection."""

import unittest

from features import typosquatting_score


class TyposquattingScoreTests(unittest.TestCase):
    def test_exact_known_domain_returns_zero(self):
        """Legitimate domains must not be flagged."""
        safe = [
            "https://paypal.com/login",
            "https://www.google.com/search",
            "https://github.com/omobolajiadeyan",
            "https://www.amazon.com/orders",
        ]
        for url in safe:
            with self.subTest(url=url):
                self.assertEqual(typosquatting_score(url), 0.0, url)

    def test_edit_distance_one_returns_high_score(self):
        """One-character mutations of known domains score 1.0."""
        typosquats = [
            "https://paypa1.com/login",   # '1' instead of 'l'
            "https://gogle.com/search",   # missing 'o'
            "https://githab.com/user",    # 'a' instead of 'u'
        ]
        for url in typosquats:
            with self.subTest(url=url):
                self.assertEqual(typosquatting_score(url), 1.0, url)

    def test_edit_distance_two_returns_medium_score(self):
        # g00gle vs google: two substitutions ('o'->'0' twice) = distance 2
        self.assertEqual(typosquatting_score("https://g00gle.com/search"), 0.6)

    def test_unrelated_domain_returns_zero(self):
        self.assertEqual(typosquatting_score("https://randomxyz9182.io/page"), 0.0)

    def test_empty_url_returns_zero(self):
        self.assertEqual(typosquatting_score(""), 0.0)

    def test_www_prefix_is_stripped_before_comparison(self):
        """www.paypal.com is the same as paypal.com — should be 0.0."""
        self.assertEqual(typosquatting_score("https://www.paypal.com"), 0.0)

    def test_score_is_float(self):
        self.assertIsInstance(typosquatting_score("https://example.com"), float)

    def test_score_within_range(self):
        urls = [
            "https://paypal.com",
            "https://paypa1.com",
            "https://randomsite.io",
        ]
        for url in urls:
            with self.subTest(url=url):
                score = typosquatting_score(url)
                self.assertGreaterEqual(score, 0.0)
                self.assertLessEqual(score, 1.0)


class TyposquattingModelIntegrationTests(unittest.TestCase):
    def test_typosquat_domain_scores_higher_than_random_domain(self):
        from model import score_url
        typosquat_prob, _ = score_url("https://paypa1.com/login")
        random_prob, _ = score_url("https://randomsitexyz.io/login")
        self.assertGreater(typosquat_prob, random_prob)

    def test_legitimate_domain_not_penalised(self):
        from model import score_url, classify
        prob, features = score_url("https://paypal.com/login")
        self.assertEqual(features["typosquatting_score"], 0.0)
        # Even with 'login' keyword, paypal.com itself should stay below phishing
        self.assertNotEqual(classify(prob), "PHISHING")


if __name__ == "__main__":
    unittest.main()
