"""Refresh the bundled Mozilla Public Suffix List and record its provenance.

Run from the repository root:

    python tools/update_public_suffix_list.py

Downloads the current list from publicsuffix.org, writes it to
data/public_suffix_list.dat, and prints the retrieval date and SHA-256 so the
commit message / changelog can record exactly which snapshot is bundled. The
file itself is Mozilla Public License 2.0 (see its header comment); redistributing
it verbatim as a bundled data file is permitted.
"""

from __future__ import annotations

import argparse
import datetime
import hashlib
import urllib.request
from pathlib import Path

try:
    from tools.generate_public_suffix_js import generate
except ModuleNotFoundError:  # Direct execution sets tools/ as sys.path[0].
    from generate_public_suffix_js import generate

SOURCE_URL = "https://publicsuffix.org/list/public_suffix_list.dat"
DEST_PATH = Path(__file__).parent.parent / "data" / "public_suffix_list.dat"


def fetch(url: str, timeout: int) -> bytes:
    with urllib.request.urlopen(url, timeout=timeout) as resp:  # noqa: S310 - fixed https source
        return resp.read()


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--timeout", type=int, default=20)
    args = parser.parse_args()

    data = fetch(SOURCE_URL, args.timeout)
    DEST_PATH.write_bytes(data)
    generate()

    digest = hashlib.sha256(data).hexdigest()
    retrieved_on = datetime.date.today().isoformat()
    print(f"Wrote {DEST_PATH} ({len(data)} bytes)")
    print(f"retrieved_on: {retrieved_on}")
    print(f"sha256: {digest}")
    print("Record these two values in the commit message or CHANGELOG.")


if __name__ == "__main__":
    main()
