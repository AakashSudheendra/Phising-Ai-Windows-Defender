"""Evaluate the URL detector against real, currently-live traffic samples.

Unlike the small, checked-in regression fixture (evaluate_url_benchmark.py),
this tool takes two *externally supplied* files so no phishing URLs or
third-party domain rankings are committed to this repository:

  - a phishing feed: one URL per line (e.g. the OpenPhish free feed at
    https://openphish.com/feed.txt)
  - a legitimate-domain ranking CSV: "rank,domain" per line (e.g. the Tranco
    list at https://tranco-list.eu)

Only the URL/domain *strings* are scored. No network request is made to any
listed site, and no page content is fetched -- this stays consistent with
PhishGuard's offline, string-only scoring design.

These are still snapshot metrics, not a permanent population-accuracy claim:
both source lists rotate over time, so exact counts will differ on a rerun
with freshly downloaded files. Document the retrieval date when reporting
results. See docs/BENCHMARK.md for a dated result and full methodology.
"""

from __future__ import annotations

import argparse
import csv
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from domain_age import domain_age_features
from model import classify, score_url


def load_phishing_urls(path: str | Path) -> list[str]:
    text = Path(path).read_text(encoding="utf-8")
    return [line.strip() for line in text.splitlines() if line.strip()]


def load_legitimate_urls(path: str | Path, limit: int) -> list[str]:
    urls = []
    with open(path, newline="", encoding="utf-8") as handle:
        reader = csv.reader(handle)
        for i, row in enumerate(reader):
            if i >= limit:
                break
            if len(row) < 2:
                continue
            urls.append(f"https://{row[1]}/")
    return urls


def evaluate(
    urls: list[str], check_domain_age: bool = False, delay: float = 0.0
) -> list[str]:
    verdicts = []
    for i, url in enumerate(urls):
        extra = domain_age_features(url) if check_domain_age else None
        verdicts.append(classify(score_url(url, extra_features=extra)[0]))
        # Only sleep between requests that actually hit the network, and
        # never after the last one.
        if check_domain_age and delay > 0 and i < len(urls) - 1:
            time.sleep(delay)
    return verdicts


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("phishing_feed", help="path to a phishing-feed file, one URL per line")
    parser.add_argument("legit_domains_csv", help="path to a rank,domain CSV (e.g. Tranco)")
    parser.add_argument(
        "--legit-limit", type=int, default=1000,
        help="how many top-ranked legitimate domains to sample (default: 1000)",
    )
    parser.add_argument(
        "--check-domain-age", action="store_true",
        help=(
            "Also score with RDAP-derived domain-age features. Makes one "
            "network call per unique registrable domain against the public "
            "rdap.org bootstrap -- use --domain-age-delay to stay polite to "
            "that shared, rate-limited service on a large --legit-limit."
        ),
    )
    parser.add_argument(
        "--domain-age-delay", type=float, default=0.3, metavar="SECONDS",
        help="Delay between RDAP lookups when --check-domain-age is set (default: 0.3)",
    )
    args = parser.parse_args(argv)

    phishing_urls = load_phishing_urls(args.phishing_feed)
    legit_urls = load_legitimate_urls(args.legit_domains_csv, args.legit_limit)

    if not phishing_urls or not legit_urls:
        print("error: both input files must contain at least one entry", file=sys.stderr)
        return 1

    phish_verdicts = evaluate(phishing_urls, args.check_domain_age, args.domain_age_delay)
    legit_verdicts = evaluate(legit_urls, args.check_domain_age, args.domain_age_delay)

    flagged = {"PHISHING", "SUSPICIOUS"}
    true_positive = sum(1 for v in phish_verdicts if v in flagged)
    false_negative = len(phish_verdicts) - true_positive
    false_positive = sum(1 for v in legit_verdicts if v in flagged)
    true_negative = len(legit_verdicts) - false_positive
    strict_true_positive = sum(1 for v in phish_verdicts if v == "PHISHING")

    precision = (
        true_positive / (true_positive + false_positive)
        if (true_positive + false_positive) else 0.0
    )
    recall = (
        true_positive / (true_positive + false_negative)
        if (true_positive + false_negative) else 0.0
    )
    fpr = (
        false_positive / (false_positive + true_negative)
        if (false_positive + true_negative) else 0.0
    )

    print(f"phishing samples: {len(phishing_urls)}  (source: {args.phishing_feed})")
    print(f"legitimate samples: {len(legit_urls)}  (source: {args.legit_domains_csv})")
    print(f"domain-age features: {'on' if args.check_domain_age else 'off'}")
    print()
    print(
        "confusion_matrix (flag = PHISHING or SUSPICIOUS): "
        f"tp={true_positive} fn={false_negative} fp={false_positive} tn={true_negative}"
    )
    print(f"strict_phishing_only_recall: {strict_true_positive}/{len(phish_verdicts)}")
    print()
    print(f"precision: {precision:.3f}")
    print(f"recall: {recall:.3f}")
    print(f"false_positive_rate: {fpr:.3f}")
    print()
    print(
        "note: these are point-in-time snapshot metrics against real, live "
        "traffic samples -- both source lists rotate over time, so exact "
        "counts will differ on a rerun with freshly downloaded files. This "
        "is stronger evidence than a small synthetic fixture, but still not "
        "a permanent, universal accuracy claim."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
