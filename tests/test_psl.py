"""Tests for the bundled Public Suffix List parser (psl.py).

Covers issue #29: registrable-domain comparison must not flag same-organization
subdomain redirects, but must still separate independently-registrable
subdomains under private-section entries like github.io.
"""

import unittest

from psl import registrable_domain


class RegistrableDomainTests(unittest.TestCase):
    def test_subdomain_collapses_to_registrable_domain(self):
        self.assertEqual(registrable_domain("login.example.com"), "example.com")

    def test_bare_registrable_domain_is_unchanged(self):
        self.assertEqual(registrable_domain("example.com"), "example.com")

    def test_www_and_login_share_the_same_registrable_domain(self):
        self.assertEqual(
            registrable_domain("www.example.com"),
            registrable_domain("login.example.com"),
        )

    def test_lowercases_input(self):
        self.assertEqual(registrable_domain("Login.EXAMPLE.com"), "example.com")

    def test_strips_trailing_dot(self):
        self.assertEqual(registrable_domain("example.com."), "example.com")

    def test_multi_label_public_suffix_co_dot_uk(self):
        self.assertEqual(registrable_domain("www.example.co.uk"), "example.co.uk")

    def test_bare_two_label_public_suffix_has_no_further_registrable_domain(self):
        # "co.uk" is itself a public suffix; there is no label left to add.
        self.assertEqual(registrable_domain("co.uk"), "co.uk")

    def test_single_label_hostname_is_unchanged(self):
        self.assertEqual(registrable_domain("localhost"), "localhost")

    def test_empty_hostname_is_unchanged(self):
        self.assertEqual(registrable_domain(""), "")

    def test_private_section_entry_is_independently_registrable(self):
        # Each GitHub Pages account gets its own registrable unit.
        self.assertEqual(registrable_domain("alice.github.io"), "alice.github.io")

    def test_subdomain_of_private_section_entry_rolls_up_correctly(self):
        self.assertEqual(
            registrable_domain("foo.alice.github.io"), "alice.github.io"
        )

    def test_different_github_io_accounts_are_different_registrable_domains(self):
        self.assertNotEqual(
            registrable_domain("alice.github.io"),
            registrable_domain("bob.github.io"),
        )

    def test_exception_rule_keeps_its_own_label_registrable(self):
        # PSL lists "*.ck" as a wildcard but carves out "!www.ck" as an
        # exception, so www.ck is directly registrable rather than being
        # treated as a bare public suffix like foo.ck is.
        self.assertEqual(registrable_domain("www.ck"), "www.ck")

    def test_wildcard_rule_domain_is_its_own_public_suffix(self):
        self.assertEqual(registrable_domain("foo.ck"), "foo.ck")
        self.assertEqual(registrable_domain("bar.foo.ck"), "bar.foo.ck")

    def test_unknown_tld_uses_implicit_wildcard_rule(self):
        self.assertEqual(
            registrable_domain("login.example.unknownlocal"),
            "example.unknownlocal",
        )


if __name__ == "__main__":
    unittest.main()
