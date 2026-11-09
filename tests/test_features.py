import unittest

from features import (
    has_opaque_hostname_label,
    has_punycode,
    has_unicode_hostname,
    on_free_hosting_platform,
    subdomain_count,
)


class SubdomainCountTests(unittest.TestCase):
    def test_uses_multi_label_public_suffix_boundary(self):
        self.assertEqual(subdomain_count("https://www.example.co.uk/"), 0)
        self.assertEqual(subdomain_count("https://login.example.co.uk/"), 1)

    def test_respects_private_public_suffix_entries(self):
        self.assertEqual(subdomain_count("https://alice.github.io/"), 0)
        self.assertEqual(subdomain_count("https://foo.alice.github.io/"), 1)

    def test_filters_presentation_labels_above_registrable_domain(self):
        self.assertEqual(subdomain_count("https://www.login.example.co.uk/"), 1)


class IdnFeatureTests(unittest.TestCase):
    def test_detects_punycode_hostname_label(self):
        self.assertEqual(has_punycode("https://xn--bcher-kva.example/catalog"), 1)
        self.assertEqual(has_unicode_hostname("https://xn--bcher-kva.example/catalog"), 0)

    def test_detects_unicode_hostname(self):
        url = "https://b\u00fccher.example/catalog"

        self.assertEqual(has_unicode_hostname(url), 1)
        self.assertEqual(has_punycode(url), 0)

    def test_ignores_idn_markers_outside_hostname(self):
        self.assertEqual(has_punycode("https://example.com/xn--bcher-kva"), 0)
        self.assertEqual(has_unicode_hostname("https://example.com/\u00fcber"), 0)


class OpaqueHostnameFeatureTests(unittest.TestCase):
    def test_detects_long_compact_hostname_labels(self):
        self.assertEqual(has_opaque_hostname_label("https://chillicancorne.example/"), 1)
        self.assertEqual(has_opaque_hostname_label("https://nycmydreamx.example/client"), 1)

    def test_ignores_short_or_structured_hostname_labels(self):
        self.assertEqual(has_opaque_hostname_label("https://example.com"), 0)
        self.assertEqual(has_opaque_hostname_label("https://docs.python.org"), 0)
        self.assertEqual(has_opaque_hostname_label("https://secure-login.example"), 0)

    def test_ignores_long_non_reserved_hostname_labels(self):
        self.assertEqual(has_opaque_hostname_label("https://stackoverflow.com/questions"), 0)
        self.assertEqual(has_opaque_hostname_label("https://randomsitexyz.io/login"), 0)

    def test_ignores_punycode_hostname_labels(self):
        self.assertEqual(has_opaque_hostname_label("https://xn--bcher-kva.example/catalog"), 0)


class FreeHostingPlatformFeatureTests(unittest.TestCase):
    # Synthetic examples only -- these are not real registered phishing
    # pages. Added 2026-07-28 after a live-traffic validation (see
    # docs/BENCHMARK.md) found 32% of missed real phishing URLs were hosted
    # on platforms exactly like these.
    def test_detects_known_free_hosting_subdomains(self):
        self.assertEqual(on_free_hosting_platform("https://mybank-verify.pages.dev/"), 1)
        self.assertEqual(on_free_hosting_platform("https://secure-login.netlify.app/"), 1)
        self.assertEqual(on_free_hosting_platform("https://account-update.blogspot.com/"), 1)
        self.assertEqual(on_free_hosting_platform("https://someuser.github.io/portfolio"), 1)

    def test_ignores_the_platforms_own_root_domain(self):
        # Visiting the platform itself is not the same as a phishing page
        # hosted as a subdomain of it.
        self.assertEqual(on_free_hosting_platform("https://vercel.app/"), 0)
        self.assertEqual(on_free_hosting_platform("https://github.io/"), 0)

    def test_ignores_ordinary_production_domains(self):
        self.assertEqual(on_free_hosting_platform("https://example.com/"), 0)
        self.assertEqual(on_free_hosting_platform("https://chase.com/login"), 0)


if __name__ == "__main__":
    unittest.main()
