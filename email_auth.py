"""Parse trusted Authentication-Results values into explainable signals."""

from collections.abc import Iterable
import re


AUTH_METHODS = ("spf", "dkim", "dmarc")
AUTH_RESULTS = {"pass", "fail", "softfail", "neutral", "none"}
_RESULT_PATTERN = re.compile(
    r"(?:^|[;\s])(?P<method>spf|dkim|dmarc)\s*=\s*"
    r"(?P<result>[a-z][a-z0-9_-]*)",
    re.IGNORECASE,
)
_AUTHSERV_ID_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,254}$")


def validate_authserv_id(value: str) -> str:
    """Return a normalized authserv-id or raise for an unsafe value."""
    if not isinstance(value, str):
        raise ValueError("trusted authserv-id must be a string")

    normalized = value.strip()
    if not normalized or not _AUTHSERV_ID_PATTERN.fullmatch(normalized):
        raise ValueError(
            "trusted authserv-id must contain only letters, digits, dots, "
            "underscores, and hyphens"
        )

    return normalized.casefold()


def select_trusted_authentication_results(
    values: Iterable[str],
    trusted_authserv_id: str | None,
) -> str | None:
    """Select the first exact authserv-id match from top-to-bottom headers.

    Authentication-Results headers are attacker-controlled until a receiving
    system establishes their provenance. Without an explicitly configured
    authserv-id, no header is selected.
    """
    if trusted_authserv_id is None:
        return None

    expected = validate_authserv_id(trusted_authserv_id)
    for value in values:
        if not isinstance(value, str):
            continue

        authority, separator, _ = value.partition(";")
        if not separator:
            continue

        tokens = authority.strip().split()
        if tokens and tokens[0].casefold() == expected:
            return value

    return None


def parse_authentication_results(value: str | None) -> dict[str, str]:
    """Return normalized SPF, DKIM, and DMARC results from one header value."""
    results = {method: "unknown" for method in AUTH_METHODS}
    if not value:
        return results

    for match in _RESULT_PATTERN.finditer(value):
        method = match.group("method").lower()
        result = match.group("result").lower()
        if results[method] == "unknown" and result in AUTH_RESULTS:
            results[method] = result

    return results


def extract_authentication_features(value: str | None) -> dict[str, str | float]:
    """Return categorical authentication results and conservative risk values."""
    results = parse_authentication_results(value)
    spf_risk = {"fail": 1.0, "softfail": 0.5}.get(results["spf"], 0.0)

    return {
        "spf_result": results["spf"],
        "dkim_result": results["dkim"],
        "dmarc_result": results["dmarc"],
        "spf_auth_risk": spf_risk,
        "dkim_auth_risk": float(results["dkim"] == "fail"),
        "dmarc_auth_risk": float(results["dmarc"] == "fail"),
    }
