"""Tests for the RDAP-based domain-age lookup.

No real network calls are made here. urllib.request.urlopen is patched so
every case is deterministic and never depends on rdap.org being reachable
or unthrottled. Mirrors the mocking style in test_redirect.py.
"""

import json
import unittest
from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock, patch

import domain_age


def _mock_rdap_response(days_ago: int | None) -> MagicMock:
    """Build a urlopen()-shaped context manager for a mocked RDAP payload."""
    if days_ago is None:
        payload = {"objectClassName": "domain", "events": []}
    else:
        registered = datetime.now(timezone.utc) - timedelta(days=days_ago)
        payload = {
            "objectClassName": "domain",
            "events": [
                {"eventAction": "last changed", "eventDate": "2020-01-01T00:00:00Z"},
                {
                    "eventAction": "registration",
                    "eventDate": registered.strftime("%Y-%m-%dT%H:%M:%SZ"),
                },
            ],
        }
    response = MagicMock()
    response.read.return_value = json.dumps(payload).encode("utf-8")
    context_manager = MagicMock()
    context_manager.__enter__.return_value = response
    context_manager.__exit__.return_value = False
    return context_manager


def _mock_malformed_response() -> MagicMock:
    response = MagicMock()
    response.read.return_value = b"not json"
    context_manager = MagicMock()
    context_manager.__enter__.return_value = response
    context_manager.__exit__.return_value = False
    return context_manager


class DomainAgeLookupTests(unittest.TestCase):
    def setUp(self):
        domain_age._cache.clear()

    def test_returns_age_in_days_from_registration_event(self):
        with patch("urllib.request.urlopen", return_value=_mock_rdap_response(46)):
            age = domain_age.lookup_domain_age_days("https://rosakyiv.example.br/")
        self.assertEqual(age, 46)

    def test_returns_none_when_no_registration_event(self):
        with patch("urllib.request.urlopen", return_value=_mock_rdap_response(None)):
            age = domain_age.lookup_domain_age_days("https://example.com/")
        self.assertIsNone(age)

    def test_returns_none_on_any_network_error(self):
        with patch("urllib.request.urlopen", side_effect=OSError("mocked failure")):
            age = domain_age.lookup_domain_age_days("https://example.com/")
        self.assertIsNone(age)

    def test_returns_none_on_http_error(self):
        import urllib.error

        with patch(
            "urllib.request.urlopen",
            side_effect=urllib.error.HTTPError(
                "https://rdap.org/domain/example.com", 429, "rate limited", {}, None
            ),
        ):
            age = domain_age.lookup_domain_age_days("https://example.com/")
        self.assertIsNone(age)

    def test_returns_none_on_malformed_json(self):
        with patch("urllib.request.urlopen", return_value=_mock_malformed_response()):
            age = domain_age.lookup_domain_age_days("https://example.com/")
        self.assertIsNone(age)

    def test_returns_none_for_ip_literal_host(self):
        with patch("urllib.request.urlopen") as mocked:
            age = domain_age.lookup_domain_age_days("http://192.0.2.10/login")
        mocked.assert_not_called()
        self.assertIsNone(age)

    def test_returns_none_for_unparseable_url(self):
        age = domain_age.lookup_domain_age_days("http://[::1")
        self.assertIsNone(age)

    def test_second_lookup_for_same_registrable_domain_is_cached(self):
        with patch(
            "urllib.request.urlopen", return_value=_mock_rdap_response(10)
        ) as mocked:
            domain_age.lookup_domain_age_days("https://a.example.com/one")
            domain_age.lookup_domain_age_days("https://b.example.com/two")
        self.assertEqual(mocked.call_count, 1)

    def test_fetch_rejects_malformed_domain_without_a_network_call(self):
        # _fetch_registration_age_days() is the actual network sink -- it
        # must not trust its caller's validation (lookup_domain_age_days()
        # already checks this before registrable_domain()'s output reaches
        # here) since a future caller could reach it directly. Guards
        # against CodeQL alert #16 (py/partial-ssrf) regressing: a domain
        # string that could manipulate the request path must never reach
        # urlopen at all, encoded or not.
        malformed = [
            "evil.com/../../admin",
            "evil.com#@rdap.org",
            "evil.com?x=1",
            "",
        ]
        for domain in malformed:
            with self.subTest(domain=domain):
                with patch("urllib.request.urlopen") as mocked:
                    result = domain_age._fetch_registration_age_days(domain, 5.0)
                mocked.assert_not_called()
                self.assertIsNone(result)


class DomainAgeFeatureTests(unittest.TestCase):
    def setUp(self):
        domain_age._cache.clear()

    def _features_for_age(self, days_ago: int | None) -> dict:
        with patch("urllib.request.urlopen", return_value=_mock_rdap_response(days_ago)):
            return domain_age.domain_age_features("https://example.com/")

    def test_empty_dict_when_age_unknown(self):
        self.assertEqual(self._features_for_age(None), {})

    def test_both_flags_set_for_a_very_new_domain(self):
        features = self._features_for_age(5)
        self.assertEqual(
            features,
            {"domain_newer_than_30d": 1, "domain_newer_than_90d": 1, "domain_older_than_2y": 0},
        )

    def test_only_the_wider_flag_set_between_30_and_90_days(self):
        features = self._features_for_age(60)
        self.assertEqual(
            features,
            {"domain_newer_than_30d": 0, "domain_newer_than_90d": 1, "domain_older_than_2y": 0},
        )

    def test_neither_new_flag_set_for_a_moderately_established_domain(self):
        # Old enough to clear both "newer than" thresholds, but not yet
        # "older than 2y" (730 days) -- neutral on both axes.
        features = self._features_for_age(400)
        self.assertEqual(
            features,
            {"domain_newer_than_30d": 0, "domain_newer_than_90d": 0, "domain_older_than_2y": 0},
        )

    def test_boundary_at_exactly_30_days_is_not_newer_than_30d(self):
        features = self._features_for_age(30)
        self.assertEqual(features["domain_newer_than_30d"], 0)

    def test_older_than_2y_flag_set_for_a_long_established_domain(self):
        features = self._features_for_age(3650)  # ~10 years
        self.assertEqual(
            features,
            {"domain_newer_than_30d": 0, "domain_newer_than_90d": 0, "domain_older_than_2y": 1},
        )

    def test_boundary_at_exactly_730_days_is_older_than_2y(self):
        features = self._features_for_age(730)
        self.assertEqual(features["domain_older_than_2y"], 1)

    def test_boundary_at_729_days_is_not_yet_older_than_2y(self):
        features = self._features_for_age(729)
        self.assertEqual(features["domain_older_than_2y"], 0)


if __name__ == "__main__":
    unittest.main()
