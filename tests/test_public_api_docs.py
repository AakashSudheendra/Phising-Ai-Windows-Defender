import unittest

from model import classify, score_email, score_url


class PublicApiDocumentationExamples(unittest.TestCase):
    def test_url_scoring_example_shape(self):
        probability, features = score_url("https://www.example.com/account")

        self.assertGreaterEqual(probability, 0.0)
        self.assertLessEqual(probability, 1.0)
        self.assertEqual(classify(probability), "SAFE")
        self.assertIn("has_ip_address", features)

    def test_url_extra_features_example_shape(self):
        probability, features = score_url(
            "https://www.example.com/login",
            extra_features={
                "redirect_hops": 2,
                "redirect_crossed_domain": 1,
            },
        )

        self.assertEqual(features["redirect_hops"], 2)
        self.assertIn(classify(probability), {"SAFE", "SUSPICIOUS", "PHISHING"})

    def test_email_authentication_example_shape(self):
        probability, features = score_email(
            "Security alert",
            "Click here to verify your account.",
            "mx.example; spf=fail; dkim=fail; dmarc=fail",
        )

        self.assertEqual(classify(probability), "PHISHING")
        self.assertEqual(features["dmarc_result"], "fail")


if __name__ == "__main__":
    unittest.main()
