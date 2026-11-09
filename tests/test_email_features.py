import time
import unittest

from features import extract_email_features


class AttachmentMentionTests(unittest.TestCase):
    def test_detects_plain_attach_mention(self):
        features = extract_email_features("Invoice", "Please see the attached file.")
        self.assertEqual(features["has_attachment_mention"], 1)

    def test_detects_plain_download_mention(self):
        features = extract_email_features("Invoice", "Download the report here.")
        self.assertEqual(features["has_attachment_mention"], 1)

    def test_detects_open_file_within_bounded_gap(self):
        features = extract_email_features(
            "Invoice", "Please open the attached quarterly report file today."
        )
        self.assertEqual(features["has_attachment_mention"], 1)

    def test_ignores_unrelated_body(self):
        features = extract_email_features("Meeting", "Let's catch up next week.")
        self.assertEqual(features["has_attachment_mention"], 0)

    def test_adversarial_repetition_completes_quickly(self):
        """
        Regression test for a polynomial-regex denial-of-service: the body
        is attacker-controlled when reached via `phishguard serve`, so
        scoring must stay fast on adversarial input, not just typical mail.
        Before bounding the "open...file" gap, this input took multiple
        seconds; it should now complete in well under a second.
        """
        adversarial_body = "open " * 30000
        start = time.perf_counter()
        extract_email_features("Invoice", adversarial_body)
        elapsed = time.perf_counter() - start
        self.assertLess(elapsed, 2.0)


if __name__ == "__main__":
    unittest.main()
