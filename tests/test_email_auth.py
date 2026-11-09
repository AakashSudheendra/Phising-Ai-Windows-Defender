import unittest

from email_auth import (
    extract_authentication_features,
    parse_authentication_results,
    select_trusted_authentication_results,
    validate_authserv_id,
)


class AuthenticationResultsParserTests(unittest.TestCase):
    def test_selects_first_exact_trusted_authserv_id_match(self):
        headers = [
            "attacker.example; spf=fail; dkim=fail; dmarc=fail",
            "mx.example; spf=pass; dkim=pass; dmarc=pass",
            "mx.example; spf=fail; dkim=fail; dmarc=fail",
        ]

        selected = select_trusted_authentication_results(headers, "MX.EXAMPLE")

        self.assertEqual(selected, headers[1])

    def test_does_not_accept_authserv_id_prefix_match(self):
        headers = [
            "mx.example.attacker; spf=pass; dkim=pass; dmarc=pass",
        ]

        selected = select_trusted_authentication_results(headers, "mx.example")

        self.assertIsNone(selected)

    def test_does_not_select_header_without_explicit_trust(self):
        selected = select_trusted_authentication_results(
            ["mx.example; spf=pass; dkim=pass; dmarc=pass"],
            None,
        )

        self.assertIsNone(selected)

    def test_rejects_unsafe_authserv_id(self):
        for value in ("", "   ", "mx.example; spf=pass", "mx example"):
            with self.subTest(value=value):
                with self.assertRaises(ValueError):
                    validate_authserv_id(value)

    def test_parses_supported_result_matrix(self):
        cases = (
            (
                "none values",
                "mx.example; spf=none; dkim=none; dmarc=none",
                {"spf": "none", "dkim": "none", "dmarc": "none"},
            ),
            (
                "mixed spaces and tabs",
                "mx.example;\tspf\t=\tpass ; dkim = fail;\tdmarc = neutral",
                {"spf": "pass", "dkim": "fail", "dmarc": "neutral"},
            ),
            (
                "different method order",
                "mx.example; dmarc=fail; dkim=pass; spf=softfail",
                {"spf": "softfail", "dkim": "pass", "dmarc": "fail"},
            ),
            (
                "unrelated methods ignored",
                "mx.example; arc=pass; spf=pass; bimi=pass; dkim=pass; dmarc=pass",
                {"spf": "pass", "dkim": "pass", "dmarc": "pass"},
            ),
            (
                "unsupported values remain unknown",
                "mx.example; spf=temperror; dkim=permerror; dmarc=bestguesspass",
                {"spf": "unknown", "dkim": "unknown", "dmarc": "unknown"},
            ),
            (
                "unsupported value does not block other methods",
                "mx.example; spf=pass; dkim=policy; dmarc=fail; arc=pass",
                {"spf": "pass", "dkim": "unknown", "dmarc": "fail"},
            ),
        )

        for name, header, expected in cases:
            with self.subTest(name=name):
                self.assertEqual(parse_authentication_results(header), expected)

    def test_parses_case_insensitive_pass_results(self):
        results = parse_authentication_results(
            "mx.example; SPF=PASS smtp.mailfrom=example.com; "
            "DKIM=pass header.d=example.com; DMARC=Pass"
        )

        self.assertEqual(
            results,
            {"spf": "pass", "dkim": "pass", "dmarc": "pass"},
        )

    def test_parses_mixed_results(self):
        results = parse_authentication_results(
            "mx.example; spf=softfail; dkim=neutral; dmarc=fail"
        )

        self.assertEqual(
            results,
            {"spf": "softfail", "dkim": "neutral", "dmarc": "fail"},
        )

    def test_missing_and_malformed_values_are_unknown(self):
        expected = {"spf": "unknown", "dkim": "unknown", "dmarc": "unknown"}

        self.assertEqual(parse_authentication_results(None), expected)
        self.assertEqual(
            parse_authentication_results("mx.example; spf=; dkim=(broken)"),
            expected,
        )

    def test_unsupported_results_are_unknown(self):
        results = parse_authentication_results(
            "mx.example; spf=temperror; dkim=permerror; dmarc=bestguesspass"
        )

        self.assertEqual(
            results,
            {"spf": "unknown", "dkim": "unknown", "dmarc": "unknown"},
        )

    def test_first_supported_result_wins_for_duplicate_methods(self):
        results = parse_authentication_results(
            "mx.example; spf=pass; spf=fail; dkim=pass"
        )

        self.assertEqual(results["spf"], "pass")

    def test_extracts_conservative_numeric_risk(self):
        features = extract_authentication_features(
            "mx.example; spf=softfail; dkim=fail; dmarc=pass"
        )

        self.assertEqual(features["spf_auth_risk"], 0.5)
        self.assertEqual(features["dkim_auth_risk"], 1.0)
        self.assertEqual(features["dmarc_auth_risk"], 0.0)


if __name__ == "__main__":
    unittest.main()
