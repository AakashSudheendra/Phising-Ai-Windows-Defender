"""Stress-test the URL detector's false-positive rate on realistic URL shapes.

evaluate_live_traffic_benchmark.py's legitimate-domain sample is always a
bare root URL (``https://{domain}/``). That's the easy case: it says nothing
about the URL shapes a real security-relevant flow actually produces --
login pages, password-reset links with tokens, verification paths, or
branded subdomains -- which is also exactly the shape a phishing page is
built to imitate. This tool closes that gap by taking the same kind of
externally-supplied domain ranking (nothing bundled, matching
evaluate_live_traffic_benchmark.py's no-committed-third-party-data design)
and generating several realistic URL variants per domain instead of one
root URL, then reports the false-positive rate *per template* -- the
per-template breakdown is what makes a regression's root cause traceable,
rather than a single aggregate number that could hide which URL shape is
actually failing.

This is a snapshot metric like evaluate_live_traffic_benchmark.py's: the
domain ranking rotates over time, so exact counts will differ on a rerun
with a freshly downloaded file. Document the retrieval date when reporting
results. See docs/BENCHMARK.md for a dated result and full methodology.
"""

from __future__ import annotations

import argparse
import csv
import secrets
import sys
import time
from collections import defaultdict
from pathlib import Path
from typing import Callable

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from domain_age import domain_age_features
from model import classify, score_url


# Realistic security-relevant URL shapes, built from a bare registrable
# domain (e.g. "example.com"). Intentionally ordinary -- no adversarial
# tricks -- since the point is to measure how the detector behaves on the
# exact URL shapes real login, verification, and password-reset flows
# produce on real sites, not to construct a worst case.
PATH_TEMPLATES: dict[str, Callable[[str], str]] = {
    "root":                    lambda d: f"https://{d}/",
    "www_root":                lambda d: f"https://www.{d}/",
    "login_path":              lambda d: f"https://{d}/login",
    "signin_path":             lambda d: f"https://www.{d}/signin",
    "account_login_path":      lambda d: f"https://{d}/account/login",
    "verify_token_link":       lambda d: f"https://{d}/account/verify?token={secrets.token_hex(8)}",
    "password_reset_link":     lambda d: f"https://{d}/password/reset?token={secrets.token_hex(8)}&redirect=https://{d}/dashboard",
    "accounts_subdomain":      lambda d: f"https://accounts.{d}/signin",
    "secure_subdomain_login":  lambda d: f"https://secure.{d}/login",
    "support_verify_identity": lambda d: f"https://{d}/support/account/security/verify-identity",
}


def load_domains(path: str | Path, limit: int) -> list[str]:
    domains = []
    with open(path, newline="", encoding="utf-8") as handle:
        reader = csv.reader(handle)
        for row in reader:
            if len(domains) >= limit:
                break
            if len(row) < 2:
                continue
            domain = row[1].strip().lower()
            if not domain:
                continue
            domains.append(domain)
    return domains


def evaluate(
    domains: list[str],
    check_domain_age: bool = False,
    delay: float = 0.0,
) -> dict[str, dict[str, int]]:
    """Score every domain x template pair. Returns per-template verdict counts."""
    per_template: dict[str, dict[str, int]] = defaultdict(
        lambda: {"SAFE": 0, "SUSPICIOUS": 0, "PHISHING": 0}
    )
    total_pairs = len(domains) * len(PATH_TEMPLATES)
    pair_index = 0
    for domain in domains:
        for name, build in PATH_TEMPLATES.items():
            url = build(domain)
            extra = domain_age_features(url) if check_domain_age else None
            verdict = classify(score_url(url, extra_features=extra)[0])
            per_template[name][verdict] += 1
            pair_index += 1
            # Only sleep between requests that actually hit the network,
            # and never after the last one.
            if check_domain_age and delay > 0 and pair_index < total_pairs:
                time.sleep(delay)
    return per_template


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("legit_domains_csv", help="path to a rank,domain CSV (e.g. Tranco)")
    parser.add_argument(
        "--domain-limit", type=int, default=1000,
        help="how many top-ranked domains to sample (default: 1000)",
    )
    parser.add_argument(
        "--check-domain-age", action="store_true",
        help=(
            "Also score with RDAP-derived domain-age features. Makes one "
            "network call per unique registrable domain against the public "
            "rdap.org bootstrap -- use --domain-age-delay to stay polite to "
            "that shared, rate-limited service on a large --domain-limit."
        ),
    )
    parser.add_argument(
        "--domain-age-delay", type=float, default=0.3, metavar="SECONDS",
        help="Delay between RDAP lookups when --check-domain-age is set (default: 0.3)",
    )
    args = parser.parse_args(argv)

    domains = load_domains(args.legit_domains_csv, args.domain_limit)
    if not domains:
        print("error: input file must contain at least one domain", file=sys.stderr)
        return 1

    per_template = evaluate(domains, args.check_domain_age, args.domain_age_delay)
    total = len(domains) * len(PATH_TEMPLATES)

    overall = {"SAFE": 0, "SUSPICIOUS": 0, "PHISHING": 0}
    for counts in per_template.values():
        for verdict, n in counts.items():
            overall[verdict] += n

    flagged = overall["SUSPICIOUS"] + overall["PHISHING"]
    fp_rate = flagged / total if total else 0.0
    strict_fp_rate = overall["PHISHING"] / total if total else 0.0

    print(f"domains: {len(domains)}  (source: {args.legit_domains_csv})")
    print(f"templates: {len(PATH_TEMPLATES)}")
    print(f"domain-age features: {'on' if args.check_domain_age else 'off'}")
    print(f"total urls scored: {total}")
    print()
    print(f"overall false_positive_rate (flag = SUSPICIOUS or PHISHING): {fp_rate:.3f}  ({flagged}/{total})")
    print(f"overall strict_false_positive_rate (PHISHING only): {strict_fp_rate:.3f}  ({overall['PHISHING']}/{total})")
    print()
    print(f"{'template':<26} {'n':>6} {'flagged%':>9} {'strict%':>9}")
    for name in PATH_TEMPLATES:
        counts = per_template[name]
        n = counts["SAFE"] + counts["SUSPICIOUS"] + counts["PHISHING"]
        template_flagged = counts["SUSPICIOUS"] + counts["PHISHING"]
        template_flagged_rate = template_flagged / n if n else 0.0
        template_strict_rate = counts["PHISHING"] / n if n else 0.0
        print(f"{name:<26} {n:>6} {template_flagged_rate:>8.1%} {template_strict_rate:>8.1%}")
    print()
    print(
        "note: this is a point-in-time snapshot metric against a real "
        "domain ranking that rotates over time, so exact counts will "
        "differ on a rerun with a freshly downloaded file. The path "
        "templates are synthetic but structurally realistic, not "
        "adversarially crafted -- see docs/BENCHMARK.md for methodology."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
