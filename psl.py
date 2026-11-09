"""Registrable-domain (eTLD+1) lookup using a bundled Mozilla Public Suffix List.

Bundling the data file keeps the zero-dependency promise: no package such as
`tldextract` is required. See data/public_suffix_list.dat for provenance
(source URL, retrieval date, and license) and tools/update_public_suffix_list.py
to refresh it.

Implements the matching algorithm described at https://publicsuffix.org/list/:
the longest matching rule wins; an exception rule beats every rule regardless
of length and removes its own leftmost label from the public suffix; an
unmatched hostname falls back to the implicit "*" rule (its last label).
"""

from __future__ import annotations

import pathlib
import sysconfig

_DATA_PATH = pathlib.Path(__file__).parent / "data" / "public_suffix_list.dat"
_INSTALLED_DATA_PATH = (
    pathlib.Path(sysconfig.get_path("data")) / "data" / "public_suffix_list.dat"
)


def _load_rules(path: pathlib.Path) -> tuple[set[str], set[str], set[str]]:
    """Parse the PSL data file into (normal_rules, wildcard_bases, exceptions).

    `wildcard_bases` stores a rule "*.ck" as "ck" — the base a wildcard's
    single extra label attaches to. Missing files degrade to empty rule sets
    rather than raising, so callers fall back to the last-label default.
    """
    normal: set[str] = set()
    wildcard_bases: set[str] = set()
    exceptions: set[str] = set()
    if not path.exists():
        return normal, wildcard_bases, exceptions

    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("//"):
            continue
        rule = line.split()[0].lower()
        if rule.startswith("!"):
            exceptions.add(rule[1:])
        elif rule.startswith("*."):
            wildcard_bases.add(rule[2:])
        else:
            normal.add(rule)
    return normal, wildcard_bases, exceptions


_NORMAL, _WILDCARD_BASES, _EXCEPTIONS = _load_rules(
    _DATA_PATH if _DATA_PATH.exists() else _INSTALLED_DATA_PATH
)


def _public_suffix_length(labels: list[str]) -> int:
    """Return how many trailing *labels* make up the public suffix."""
    n = len(labels)
    best: int | None = None
    for i in range(n):
        num_labels = n - i
        candidate = ".".join(labels[i:])

        if candidate in _EXCEPTIONS:
            # An exception rule prevails over any other match and contributes
            # one fewer label than it matched (its own leftmost label is
            # excluded from the public suffix).
            return num_labels - 1

        if candidate in _NORMAL and (best is None or num_labels > best):
            best = num_labels

        if num_labels >= 2:
            remainder = ".".join(labels[i + 1 :])
            if remainder in _WILDCARD_BASES and (best is None or num_labels > best):
                best = num_labels

    return best if best is not None else 1  # implicit "*" rule


def registrable_domain(hostname: str) -> str:
    """Return the eTLD+1 registrable domain for *hostname*.

    Examples: "login.example.com" and "www.example.com" both return
    "example.com"; "alice.github.io" returns itself, since GitHub Pages
    subdomains are each independently registrable per the Public Suffix List.
    Falls back to *hostname* unchanged when it has one label, is the public
    suffix itself, or the bundled list failed to load.
    """
    hostname = hostname.strip(".").lower()
    if not hostname or "." not in hostname:
        return hostname

    labels = hostname.split(".")
    suffix_len = _public_suffix_length(labels)
    if suffix_len >= len(labels):
        return hostname

    return ".".join(labels[-(suffix_len + 1) :])
