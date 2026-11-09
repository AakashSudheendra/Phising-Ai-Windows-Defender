#!/usr/bin/env python3
"""
PhishGuard AI — Intelligent phishing detection for URLs and emails.
Uses feature engineering + weighted scoring to classify threats in real time.
Author: Omobolaji Adeyan
"""

import argparse
import email as _email_lib
import email.policy
import re
import sys
from email_auth import (
    select_trusted_authentication_results,
    validate_authserv_id,
)
from domain_age import domain_age_features
from model import score_url, score_email, classify, THRESHOLD, URL_WEIGHTS
from redirect import follow_redirects
from reporting import write_report
from server import run_server


def configure_output() -> None:
    """Keep decorative output from crashing on limited console encodings."""
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if reconfigure is not None:
            reconfigure(errors="replace")


configure_output()

RED    = "\033[91m"
YELLOW = "\033[93m"
GREEN  = "\033[92m"
CYAN   = "\033[96m"
GRAY   = "\033[90m"
BOLD   = "\033[1m"
RESET  = "\033[0m"

VERDICT_COLOR = {
    "PHISHING":   RED,
    "SUSPICIOUS": YELLOW,
    "SAFE":       GREEN,
}

VERDICT_ICON = {
    "PHISHING":   "PHISHING",
    "SUSPICIOUS": "SUSPICIOUS",
    "SAFE":       "SAFE",
}

def style(text: str, *codes: str, plain: bool = False) -> str:
    if plain:
        return text
    return "".join(codes) + text + RESET


def separator(plain: bool = False) -> str:
    return "-" * 60 if plain else "─" * 60


def probability_bar(prob: float, plain: bool = False) -> str:
    filled = round(prob * 20)
    if plain:
        return "#" * filled + "-" * (20 - filled) + f"  {prob*100:.1f}%"

    color = RED if prob >= 0.75 else YELLOW if prob >= THRESHOLD else GREEN
    return color + "█" * filled + GRAY + "░" * (20 - filled) + RESET + f"  {prob*100:.1f}%"


def print_banner(plain: bool = False):
    if plain:
        print("""
  PHISHGUARD AI
  Explainable phishing detection | github.com/omobolajiadeyan
""")
        return

    print(f"""
{CYAN}{BOLD}
  ██████╗ ██╗  ██╗██╗███████╗██╗  ██╗ ██████╗ ██╗   ██╗ █████╗ ██████╗ ██████╗      █████╗ ██╗
  ██╔══██╗██║  ██║██║██╔════╝██║  ██║██╔════╝ ██║   ██║██╔══██╗██╔══██╗██╔══██╗    ██╔══██╗██║
  ██████╔╝███████║██║███████╗███████║██║  ███╗██║   ██║███████║██████╔╝██║  ██║    ███████║██║
  ██╔═══╝ ██╔══██║██║╚════██║██╔══██║██║   ██║██║   ██║██╔══██║██╔══██╗██║  ██║    ██╔══██║██║
  ██║     ██║  ██║██║███████║██║  ██║╚██████╔╝╚██████╔╝██║  ██║██║  ██║██████╔╝    ██║  ██║██║
  ╚═╝     ╚═╝  ╚═╝╚═╝╚══════╝╚═╝  ╚═╝ ╚═════╝  ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚═════╝     ╚═╝  ╚═╝╚═╝
{RESET}{GRAY}  Explainable phishing detection | github.com/omobolajiadeyan{RESET}
""")


def analyze_url(
    url: str,
    verbose: bool = False,
    plain: bool = False,
    follow_redirects_hops: int = 0,
    check_domain_age: bool = False,
) -> dict:
    chain_info: dict = {}
    extra: dict = {}

    if follow_redirects_hops > 0:
        chain_info = follow_redirects(url, max_hops=follow_redirects_hops)
        final_url = chain_info["final_url"]
        extra["redirect_hops"] = chain_info["hops"]
        extra["redirect_crossed_domain"] = int(chain_info["crossed_domain"])
    else:
        final_url = url

    if check_domain_age:
        extra.update(domain_age_features(final_url))

    prob, features = score_url(final_url, extra_features=extra or None)

    verdict = classify(prob)

    print(f"\n{separator(plain=plain)}")
    print(f"  URL     : {url}")
    if chain_info.get("hops", 0) > 0:
        print(f"  Final   : {final_url}")
        if verbose:
            for i, hop in enumerate(chain_info["chain"], 1):
                print(f"  Hop {i:<3} : {hop}")
        if chain_info["crossed_domain"]:
            print(style("  Warning : redirect crossed domain boundaries", YELLOW, plain=plain))
    if chain_info.get("error"):
        print(
            style(
                f"  Note    : redirect trace stopped early - {chain_info['error']}",
                GRAY,
                plain=plain,
            )
        )
    if check_domain_age:
        if "domain_newer_than_30d" in features:
            print(f"  Domain  : registered {'under 30 days ago' if features['domain_newer_than_30d'] else ('under 90 days ago' if features['domain_newer_than_90d'] else '90+ days ago')}")
        else:
            print(style("  Domain  : registration age unknown (no RDAP record or lookup failed)", GRAY, plain=plain))
    print(f"  Verdict : {style(verdict, VERDICT_COLOR[verdict], BOLD, plain=plain)}")
    print(f"  Risk    : {probability_bar(prob, plain=plain)}")

    if verbose:
        print(f"\n  {style('Feature breakdown:', GRAY, plain=plain)}")
        for feat, val in features.items():
            # A feature "triggered" the score only if it's actually
            # pushing toward PHISHING -- checking the real weight sign
            # (not just "value > 0", which mismarks domain_length: it
            # carries a negative weight, so a longer domain is slightly
            # *safer*, not a risk contributor). Previously hardcoded
            # has_https as the one exception; checking the sign directly
            # is correct for every feature, no special-casing needed --
            # matches the same fix already applied to the web demo's
            # app.js (isTriggered()).
            weight = URL_WEIGHTS.get(feat)
            triggered = isinstance(weight, (int, float)) and weight * val > 0
            flag = style("*", RED, plain=plain) if triggered else ""
            print(f"    {feat:<26}: {val}  {flag}")

    return {"url": url, "final_url": final_url, "verdict": verdict, "probability": prob, "features": features}


def analyze_eml(
    filepath: str,
    verbose: bool = False,
    plain: bool = False,
    follow_redirects_hops: int = 0,
    check_domain_age: bool = False,
    trusted_authserv_id: str | None = None,
) -> dict:
    """Parse a .eml file and run email + embedded-URL analysis."""
    try:
        with open(filepath, "rb") as fh:
            msg = _email_lib.message_from_binary_file(fh, policy=_email_lib.policy.default)
    except FileNotFoundError:
        print(style(f"Error: file '{filepath}' not found.", RED, plain=plain))
        sys.exit(1)
    except Exception as exc:
        print(style(f"Error reading .eml file: {exc}", RED, plain=plain))
        sys.exit(1)

    subject = str(msg.get("Subject", "(no subject)"))
    auth_headers = [
        str(value)
        for value in msg.get_all("Authentication-Results", [])
    ]
    auth_results = select_trusted_authentication_results(
        auth_headers,
        trusted_authserv_id,
    )

    # Prefer text/plain body; fall back to tag-stripped HTML.
    # For HTML parts, extract href/src URLs before stripping tags so links
    # hidden inside anchor elements are not lost.
    body = ""
    extracted_urls: list[str] = []
    if msg.is_multipart():
        for part in msg.walk():
            if part.get_content_disposition() == "attachment" or part.get_filename():
                continue
            ct = part.get_content_type()
            if ct == "text/plain" and not body:
                try:
                    body = part.get_content()
                except Exception:
                    body = ""
            elif ct == "text/html":
                try:
                    html = part.get_content()
                    extracted_urls.extend(re.findall(r'https?://[^\s<>"\']+', html))
                    if not body:
                        body = re.sub(r"<[^>]+>", " ", html)
                except Exception:
                    pass
    else:
        try:
            raw = msg.get_content()
            if msg.get_content_type() == "text/html":
                extracted_urls.extend(re.findall(r'https?://[^\s<>"\']+', raw))
                body = re.sub(r"<[^>]+>", " ", raw)
            else:
                body = raw
        except Exception:
            body = ""

    print(style(f"\nSource  : {filepath}", CYAN, plain=plain))
    if auth_headers and trusted_authserv_id is None:
        print(
            style(
                "  Auth    : embedded Authentication-Results ignored; "
                "set --trusted-authserv-id to use receiver evidence",
                GRAY,
                plain=plain,
            )
        )
    elif trusted_authserv_id is not None and auth_results is None:
        print(
            style(
                "  Auth    : no exact trusted authserv-id match; "
                "authentication evidence ignored",
                YELLOW,
                plain=plain,
            )
        )
    elif auth_results is not None:
        print(
            style(
                "  Auth    : using trusted Authentication-Results evidence",
                CYAN,
                plain=plain,
            )
        )
    result = analyze_email(
        subject=subject,
        body=str(body),
        authentication_results=auth_results,
        verbose=verbose,
        plain=plain,
    )
    result["source"] = filepath
    result["authentication_evidence"] = {
        "embedded_header_count": len(auth_headers),
        "trusted_authserv_id": trusted_authserv_id,
        "matched": auth_results is not None,
    }

    # Scan URLs found in the body and any extracted from HTML hrefs
    body_urls = extracted_urls + re.findall(r"https?://[^\s<>\"')\]]+", body)
    if body_urls:
        unique_urls = list(dict.fromkeys(body_urls))[:10]
        print(style(f"\n  Embedded URLs ({len(unique_urls)} unique):", CYAN, plain=plain))
        url_results = []
        for embedded_url in unique_urls:
            url_result = analyze_url(
                embedded_url,
                verbose=verbose,
                plain=plain,
                follow_redirects_hops=follow_redirects_hops,
                check_domain_age=check_domain_age,
            )
            url_results.append(url_result)
        result["body_urls"] = url_results

    return result


def analyze_email(
    subject: str,
    body: str,
    verbose: bool = False,
    plain: bool = False,
    authentication_results: str | None = None,
) -> dict:
    prob, features = score_email(subject, body, authentication_results)
    verdict = classify(prob)

    print(f"\n{separator(plain=plain)}")
    print(f"  Subject : {subject}")
    print(f"  Verdict : {style(verdict, VERDICT_COLOR[verdict], BOLD, plain=plain)}")
    print(f"  Risk    : {probability_bar(prob, plain=plain)}")

    if verbose:
        print(f"\n  {style('Feature breakdown:', GRAY, plain=plain)}")
        for feat, val in features.items():
            print(f"    {feat:<26}: {val}")

    return {"subject": subject, "verdict": verdict, "probability": prob, "features": features}


def batch_scan_urls(
    filepath: str,
    verbose: bool = False,
    plain: bool = False,
    follow_redirects_hops: int = 0,
) -> list:
    results = []
    try:
        with open(filepath, encoding="utf-8") as f:
            urls = []
            for line_num, line in enumerate(f, start=1):
                stripped = line.strip()
                if stripped and not stripped.startswith("#"):
                    urls.append((line_num, stripped))
    except FileNotFoundError:
        print(style(f"Error: File '{filepath}' not found.", RED, plain=plain))
        sys.exit(1)

    print(style(f"Scanning {len(urls)} URLs...", CYAN, plain=plain))
    phishing_count = 0
    for line_num, url in urls:
        result = analyze_url(
            url,
            verbose=verbose,
            plain=plain,
            follow_redirects_hops=follow_redirects_hops,
        )
        # Attach source metadata — additive, doesn't change verdict/probability
        result["source_path"] = filepath
        result["line_number"] = line_num
        results.append(result)
        if result["verdict"] == "PHISHING":
            phishing_count += 1

    print(style(f"\nSummary: {phishing_count}/{len(urls)} URLs classified as PHISHING", BOLD, plain=plain))
    return results


def add_output_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--output", "-o", help="Save results to a file")
    parser.add_argument(
        "--format",
        choices=("json", "sarif"),
        default="json",
        help="Output format used with --output (default: json)",
    )
    parser.add_argument(
        "--plain",
        "--no-unicode",
        action="store_true",
        help="Use ASCII-only output without color or Unicode decorations.",
    )


def add_redirect_argument(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--follow-redirects",
        metavar="N",
        type=int,
        default=0,
        help=(
            "Follow up to N HTTP redirects and score the final destination URL "
            "(default: 0, offline). Requires network access."
        ),
    )


def add_domain_age_argument(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--check-domain-age",
        action="store_true",
        help=(
            "Look up the domain's registration age via RDAP and weight newly "
            "registered domains as more suspicious (default: off, offline). "
            "Requires network access to the rdap.org bootstrap; not available "
            "on 'batch' because that public service rate-limits aggressively "
            "under repeated lookups."
        ),
    )


def main():
    parser = argparse.ArgumentParser(
        description="PhishGuard AI — Phishing detection for URLs and emails",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python phishguard.py url "http://paypa1-secure-login.xyz/verify"
  python phishguard.py url "https://bit.ly/abc123" --follow-redirects 5
  python phishguard.py url "http://freshly-registered.example" --check-domain-age
  python phishguard.py url "https://google.com" --verbose
  python phishguard.py email --subject "URGENT: Verify your account" --body "Click here immediately"
  python phishguard.py eml suspicious.eml --verbose
  python phishguard.py batch data/urls.txt
  python phishguard.py batch data/urls.txt --output results.sarif --format sarif
  python phishguard.py serve --port 8765
        """,
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    # URL command
    url_parser = subparsers.add_parser("url", help="Analyze a single URL")
    url_parser.add_argument("target", help="URL to analyze")
    url_parser.add_argument("--verbose", "-v", action="store_true")
    add_output_arguments(url_parser)
    add_redirect_argument(url_parser)
    add_domain_age_argument(url_parser)

    # Email command
    email_parser = subparsers.add_parser("email", help="Analyze an email subject and body")
    email_parser.add_argument("--subject", required=True, help="Email subject line")
    email_parser.add_argument("--body", required=True, help="Email body text")
    email_parser.add_argument(
        "--authentication-results",
        help="Trusted receiver's raw Authentication-Results header value",
    )
    email_parser.add_argument("--verbose", "-v", action="store_true")
    add_output_arguments(email_parser)

    # EML command
    eml_parser = subparsers.add_parser("eml", help="Analyze a .eml email file")
    eml_parser.add_argument("file", help="Path to the .eml file")
    eml_parser.add_argument(
        "--trusted-authserv-id",
        help=(
            "Use only an Authentication-Results header whose leading "
            "authserv-id exactly matches this trusted receiver"
        ),
    )
    eml_parser.add_argument("--verbose", "-v", action="store_true")
    add_output_arguments(eml_parser)
    add_redirect_argument(eml_parser)
    add_domain_age_argument(eml_parser)

    # Batch command
    batch_parser = subparsers.add_parser("batch", help="Scan a list of URLs from a file")
    batch_parser.add_argument("file", help="Path to file with one URL per line")
    batch_parser.add_argument("--verbose", "-v", action="store_true")
    add_output_arguments(batch_parser)
    add_redirect_argument(batch_parser)

    # Serve command
    serve_parser = subparsers.add_parser(
        "serve",
        help="Run a local REST API server and browser demo for URL and email scoring",
    )
    serve_parser.add_argument(
        "--host", default="127.0.0.1", help="Host to bind (default: 127.0.0.1)"
    )
    serve_parser.add_argument(
        "--port", type=int, default=8765, help="Port to bind (default: 8765)"
    )
    serve_parser.add_argument(
        "--rate-limit",
        type=int,
        default=30,
        metavar="N",
        help=(
            "Max POST /v1/* requests per client IP per --rate-limit-window "
            "seconds (default: 30). Pass 0 to disable."
        ),
    )
    serve_parser.add_argument(
        "--rate-limit-window",
        type=float,
        default=60.0,
        metavar="SECONDS",
        help="Rate limit window in seconds (default: 60)",
    )

    args = parser.parse_args()

    if args.command == "serve":
        run_server(args.host, args.port, args.rate_limit, args.rate_limit_window)
        return

    if args.format == "sarif" and not args.output:
        parser.error("--format sarif requires --output")

    if args.command == "eml" and args.trusted_authserv_id is not None:
        try:
            validate_authserv_id(args.trusted_authserv_id)
        except ValueError as exc:
            parser.error(str(exc))

    print_banner(plain=args.plain)

    if args.command == "url":
        result = analyze_url(
            args.target,
            verbose=args.verbose,
            plain=args.plain,
            follow_redirects_hops=args.follow_redirects,
            check_domain_age=args.check_domain_age,
        )
        if args.output:
            write_report(result, args.output, args.format)
            print(style(f"\nResult saved to {args.output}", GREEN, plain=args.plain))

    elif args.command == "email":
        result = analyze_email(
            args.subject,
            args.body,
            authentication_results=args.authentication_results,
            verbose=args.verbose,
            plain=args.plain,
        )
        if args.output:
            write_report(result, args.output, args.format)
            print(style(f"\nResult saved to {args.output}", GREEN, plain=args.plain))

    elif args.command == "eml":
        result = analyze_eml(
            args.file,
            verbose=args.verbose,
            plain=args.plain,
            follow_redirects_hops=args.follow_redirects,
            check_domain_age=args.check_domain_age,
            trusted_authserv_id=args.trusted_authserv_id,
        )
        if args.output:
            write_report(result, args.output, args.format)
            print(style(f"\nResult saved to {args.output}", GREEN, plain=args.plain))

    elif args.command == "batch":
        results = batch_scan_urls(
            args.file,
            verbose=args.verbose,
            plain=args.plain,
            follow_redirects_hops=args.follow_redirects,
        )
        if args.output:
            write_report(results, args.output, args.format)
            print(style(f"Results saved to {args.output}", GREEN, plain=args.plain))

    print()


if __name__ == "__main__":
    main()
