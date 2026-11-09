"""Follow HTTP redirect chains to reveal the final destination URL.

Uses only the Python standard library so the zero-dependency promise is kept.
Network access is always optional: every error is caught and returned in the
result dict so the caller can decide whether to surface it or continue silently.
"""

from __future__ import annotations

import http.client
import ipaddress
import socket
import ssl
import urllib.parse

from psl import registrable_domain

_USER_AGENT = "PhishGuard-AI/0.5 redirect-tracer (+https://github.com/omobolajiadeyan/phishguard-ai)"
_REDIRECT_CODES = frozenset({301, 302, 303, 307, 308})
_BLOCKED_HOSTNAMES = frozenset({"localhost"})


def _is_blocked_ip(ip_str: str) -> bool:
    try:
        ip = ipaddress.ip_address(ip_str)
    except ValueError:
        return True
    return (
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_multicast
        or ip.is_reserved
        or ip.is_unspecified
    )


def _resolve_public_addresses(
    hostname: str, port: int | None, scheme: str
) -> list[tuple[int, int, int, tuple]]:
    """Resolve *hostname* once and return its public, routable addresses.

    The redirect tracer is reachable from an untrusted network caller via
    ``phishguard serve``, so every hop's destination — not just the URL a
    caller typed in directly — must be checked before connecting; otherwise
    a redirect chain could be used to make this process issue requests to
    internal services on the caller's behalf (SSRF), including the
    169.254.169.254 cloud metadata endpoint. The returned addresses are
    connected to directly while the original hostname remains in the HTTP
    Host header and TLS SNI. Validation and connection therefore use the
    same DNS result, closing the DNS-rebinding gap without breaking
    name-based virtual hosting.
    """
    if hostname.lower() in _BLOCKED_HOSTNAMES:
        raise ValueError(f"Refusing blocked hostname: {hostname}")

    default_port = 443 if scheme == "https" else 80
    results = socket.getaddrinfo(
        hostname,
        port or default_port,
        type=socket.SOCK_STREAM,
        proto=socket.IPPROTO_TCP,
    )
    if not results:
        raise OSError(f"No addresses found for {hostname}")
    if any(_is_blocked_ip(sockaddr[0]) for *_rest, sockaddr in results):
        raise ValueError(f"Refusing private or internal address for {hostname}")
    return [
        (family, socktype, proto, sockaddr)
        for family, socktype, proto, _canonname, sockaddr in results
    ]


def _is_public_host(hostname: str, port: int | None, scheme: str) -> bool:
    """True when a host resolves exclusively to public addresses."""
    try:
        _resolve_public_addresses(hostname, port, scheme)
    except (OSError, ValueError):
        return False
    return True


def _domain(url: str) -> str:
    try:
        return (urllib.parse.urlparse(url).hostname or "").lower()
    except Exception:
        return ""


def _registrable_domain(url: str) -> str:
    """eTLD+1 for *url*, e.g. "login.example.com" -> "example.com".

    Used for cross-domain redirect comparison so that same-organization
    subdomain redirects (www -> login) are not flagged merely for having
    different hostnames. See docs/DETECTION_MODEL.md and issue #29.
    """
    hostname = _domain(url)
    try:
        ipaddress.ip_address(hostname)
    except ValueError:
        return registrable_domain(hostname)
    return hostname


def _head(url: str, timeout: int) -> tuple[int, str | None]:
    """
    Send a single HEAD request and return (status_code, Location_header).
    Raises on connection failure so the caller can record the error.
    """
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme not in {"http", "https"}:
        raise ValueError(f"Unsupported redirect scheme: {parsed.scheme or '(missing)'}")
    if not parsed.hostname:
        raise ValueError("Redirect URL is missing a hostname")

    hostname = parsed.hostname or ""
    port = parsed.port  # None means use the scheme default
    path = parsed.path or "/"
    if parsed.query:
        path = f"{path}?{parsed.query}"

    try:
        addresses = _resolve_public_addresses(hostname, port, parsed.scheme)
    except (OSError, ValueError) as exc:
        raise ValueError(
            f"Refusing to fetch a redirect target that resolves to a "
            f"private or internal address: {hostname}"
        ) from exc

    headers = {"User-Agent": _USER_AGENT, "Connection": "close"}

    last_error: OSError | None = None
    for family, socktype, proto, sockaddr in addresses:
        if parsed.scheme == "https":
            ctx = ssl.create_default_context()
            ctx.minimum_version = ssl.TLSVersion.TLSv1_2
            conn: http.client.HTTPConnection = http.client.HTTPSConnection(
                hostname, port=port, timeout=timeout, context=ctx
            )
        else:
            conn = http.client.HTTPConnection(hostname, port=port, timeout=timeout)

        raw_sock = socket.socket(family, socktype, proto)
        raw_sock.settimeout(timeout)
        try:
            raw_sock.connect(sockaddr)
            conn.sock = raw_sock
            if parsed.scheme == "https":
                conn.sock = ctx.wrap_socket(raw_sock, server_hostname=hostname)
            conn.request("HEAD", path, headers=headers)
            resp = conn.getresponse()
            return resp.status, resp.getheader("Location")
        except OSError as exc:
            last_error = exc
        finally:
            conn.close()

    raise last_error or OSError(f"Could not connect to {hostname}")


def follow_redirects(
    url: str,
    max_hops: int = 5,
    timeout: int = 5,
) -> dict:
    """
    Follow HTTP redirects up to *max_hops* and return chain metadata.

    Result keys
    -----------
    final_url       : last URL reached (original URL on any error)
    hops            : number of redirects successfully followed
    chain           : ordered list of every URL visited (includes the start)
    crossed_domain  : True when any hop left the original registrable domain
    error           : human-readable error string, or None on clean completion
    """
    chain: list[str] = [url]
    origin = _registrable_domain(url)
    crossed = False
    error: str | None = None
    current = url

    for _ in range(max_hops):
        try:
            status, location = _head(current, timeout)
        except Exception as exc:
            error = str(exc)
            break

        if status not in _REDIRECT_CODES:
            break

        if not location:
            error = f"Redirect {status} with no Location header"
            break

        next_url = urllib.parse.urljoin(current, location)
        if _registrable_domain(next_url) != origin:
            crossed = True

        chain.append(next_url)
        current = next_url

    return {
        "final_url": chain[-1],
        "hops": len(chain) - 1,
        "chain": chain,
        "crossed_domain": crossed,
        "error": error,
    }
