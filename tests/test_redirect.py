"""Tests for the redirect chain tracer.

Network calls are not made in these tests. _head() is patched to raise
ConnectionRefusedError so the contract tests are deterministic and never
depend on a real port being free.
"""

import ssl
import unittest
from unittest.mock import patch

from redirect import (
    _domain,
    _head,
    _is_public_host,
    _registrable_domain,
    _resolve_public_addresses,
    follow_redirects,
)

_UNREACHABLE = "http://example.invalid:19999/unreachable"


class DomainExtractionTests(unittest.TestCase):
    def test_extracts_hostname_from_https_url(self):
        self.assertEqual(_domain("https://example.com/path"), "example.com")

    def test_extracts_hostname_from_http_url(self):
        self.assertEqual(_domain("http://paypal.com"), "paypal.com")

    def test_lowercases_hostname(self):
        self.assertEqual(_domain("https://EXAMPLE.COM/path"), "example.com")

    def test_returns_empty_string_for_invalid_url(self):
        self.assertEqual(_domain("not-a-url"), "")

    def test_ip_literal_is_not_collapsed_by_registrable_domain_lookup(self):
        self.assertEqual(_registrable_domain("http://192.0.2.10/login"), "192.0.2.10")
        self.assertEqual(_registrable_domain("http://192.0.2.11/login"), "192.0.2.11")


class RedirectResultContractTests(unittest.TestCase):
    """
    Verify the result dict always contains the required keys and that the
    function degrades gracefully when the target is unreachable.
    """

    REQUIRED_KEYS = {"final_url", "hops", "chain", "crossed_domain", "error"}

    def _assert_contract(self, result: dict, original_url: str) -> None:
        self.assertEqual(set(result.keys()), self.REQUIRED_KEYS)
        self.assertIsInstance(result["final_url"], str)
        self.assertIsInstance(result["hops"], int)
        self.assertIsInstance(result["chain"], list)
        self.assertIsInstance(result["crossed_domain"], bool)
        self.assertGreaterEqual(result["hops"], 0)
        self.assertGreaterEqual(len(result["chain"]), 1)
        self.assertEqual(result["chain"][0], original_url)

    def test_result_contract_on_unreachable_host(self):
        with patch("redirect._head", side_effect=ConnectionRefusedError("mocked")):
            result = follow_redirects(_UNREACHABLE, timeout=1)
        self._assert_contract(result, _UNREACHABLE)
        self.assertEqual(result["final_url"], _UNREACHABLE)
        self.assertEqual(result["hops"], 0)
        self.assertIsNotNone(result["error"])

    def test_result_contract_on_invalid_scheme(self):
        url = "ftp://example.com/file"
        result = follow_redirects(url, timeout=1)
        self._assert_contract(result, url)

    def test_chain_starts_with_original_url(self):
        with patch("redirect._head", side_effect=ConnectionRefusedError("mocked")):
            result = follow_redirects(_UNREACHABLE, timeout=1)
        self.assertEqual(result["chain"][0], _UNREACHABLE)

    def test_hops_equals_chain_length_minus_one(self):
        with patch("redirect._head", side_effect=ConnectionRefusedError("mocked")):
            result = follow_redirects(_UNREACHABLE, timeout=1)
        self.assertEqual(result["hops"], len(result["chain"]) - 1)

    def test_no_cross_domain_for_single_unreachable_url(self):
        with patch("redirect._head", side_effect=ConnectionRefusedError("mocked")):
            result = follow_redirects(_UNREACHABLE, timeout=1)
        self.assertFalse(result["crossed_domain"])

    def test_credential_url_uses_hostname_not_netloc(self):
        """netloc includes userinfo; _head must connect to the real host only."""
        addresses = [(2, 1, 6, ("8.8.8.8", 80))]
        with patch("redirect._resolve_public_addresses", return_value=addresses), patch(
            "redirect.socket.socket"
        ) as sock, patch("redirect.http.client.HTTPConnection") as connection:
            response = connection.return_value.getresponse.return_value
            response.status = 200
            response.getheader.return_value = None

            _head("http://paypal.com@evil.com/login", timeout=1)

        connection.assert_called_once_with("evil.com", port=None, timeout=1)
        sock.return_value.connect.assert_called_once_with(("8.8.8.8", 80))

    def test_cross_domain_redirect_distinguishes_ip_literals(self):
        with patch(
            "redirect._head",
            side_effect=[
                (302, "http://192.0.2.11/secure-login"),
                (200, None),
            ],
        ):
            result = follow_redirects("http://192.0.2.10/login", timeout=1)

        self.assertTrue(result["crossed_domain"])
        self.assertEqual(result["hops"], 1)


class SsrfProtectionTests(unittest.TestCase):
    """
    The redirect tracer is reachable from an untrusted network caller via
    `phishguard serve`, so every hop's destination must be checked before
    connecting. See _is_public_host's docstring for the threat model.
    """

    def test_loopback_ip_literal_is_rejected(self):
        self.assertFalse(_is_public_host("127.0.0.1", None, "http"))

    def test_private_rfc1918_ip_literal_is_rejected(self):
        self.assertFalse(_is_public_host("10.0.0.5", None, "http"))

    def test_cloud_metadata_link_local_ip_is_rejected(self):
        self.assertFalse(_is_public_host("169.254.169.254", None, "http"))

    def test_localhost_hostname_is_rejected_without_dns_lookup(self):
        with patch("redirect.socket.getaddrinfo") as getaddrinfo:
            self.assertFalse(_is_public_host("localhost", None, "http"))
        getaddrinfo.assert_not_called()

    def test_hostname_resolving_to_a_private_address_is_rejected(self):
        with patch(
            "redirect.socket.getaddrinfo",
            return_value=[(2, 1, 6, "", ("10.1.2.3", 80))],
        ):
            self.assertFalse(_is_public_host("internal.example", None, "http"))

    def test_unresolvable_hostname_is_rejected(self):
        with patch("redirect.socket.getaddrinfo", side_effect=OSError("no such host")):
            self.assertFalse(_is_public_host("does-not-resolve.example", None, "http"))

    def test_public_ip_literal_is_accepted(self):
        # 8.8.8.8 is a stable, well-known globally-routable address. Note
        # TEST-NET ranges like 192.0.2.0/24 (used elsewhere in this file for
        # string-handling tests) are *not* suitable here: Python's
        # ipaddress module correctly treats them as non-global/private.
        self.assertTrue(_is_public_host("8.8.8.8", None, "http"))

    def test_hostname_resolving_to_a_public_address_is_accepted(self):
        with patch(
            "redirect.socket.getaddrinfo",
            return_value=[(2, 1, 6, "", ("8.8.8.8", 443))],
        ):
            self.assertTrue(_is_public_host("public.example", None, "https"))

    def test_resolution_is_pinned_for_connection(self):
        dns_result = [(2, 1, 6, "", ("8.8.8.8", 443))]
        with patch(
            "redirect.socket.getaddrinfo", return_value=dns_result
        ) as getaddrinfo, patch("redirect.socket.socket") as sock, patch(
            "redirect.ssl.create_default_context"
        ) as create_context, patch(
            "redirect.http.client.HTTPSConnection"
        ) as connection:
            response = connection.return_value.getresponse.return_value
            response.status = 200
            response.getheader.return_value = None
            create_context.return_value.wrap_socket.return_value = object()

            _head("https://public.example/login", timeout=2)

        getaddrinfo.assert_called_once()
        sock.return_value.connect.assert_called_once_with(("8.8.8.8", 443))
        create_context.return_value.wrap_socket.assert_called_once_with(
            sock.return_value, server_hostname="public.example"
        )
        self.assertEqual(
            create_context.return_value.minimum_version,
            ssl.TLSVersion.TLSv1_2,
        )

    def test_mixed_public_and_private_dns_results_are_rejected(self):
        with patch(
            "redirect.socket.getaddrinfo",
            return_value=[
                (2, 1, 6, "", ("8.8.8.8", 443)),
                (2, 1, 6, "", ("127.0.0.1", 443)),
            ],
        ):
            with self.assertRaises(ValueError):
                _resolve_public_addresses("rebinding.example", None, "https")

    def test_blocked_target_degrades_to_a_chain_error_not_a_crash(self):
        result = follow_redirects("http://127.0.0.1/admin", timeout=1)
        self.assertEqual(result["hops"], 0)
        self.assertIsNotNone(result["error"])
        self.assertEqual(result["final_url"], "http://127.0.0.1/admin")


if __name__ == "__main__":
    unittest.main()
