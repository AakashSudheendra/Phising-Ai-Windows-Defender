"""
PhishGuard AI HTTP server — stdlib-only REST API and browser demo for URL
and email scoring.

Intended for SIEM/proxy integrations that want a long-running scoring
endpoint instead of shelling out to the CLI per lookup, and for a
zero-install browser demo (GET / serves web/index.html, which calls the
same API). Binds to loopback (127.0.0.1) by default; if you bind to a
wider host to expose this publicly, the built-in per-IP rate limit is a
basic safeguard, not a substitute for your own network controls.
"""

import functools
import json
import sysconfig
import threading
import time
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from domain_age import domain_age_features
from model import classify, score_email, score_url
from redirect import follow_redirects

MAX_BODY_BYTES = 1_000_000
MAX_FOLLOW_REDIRECTS = 20
CLIENT_SOCKET_TIMEOUT = 10

# Mirrors psl.py's pattern: prefer the web/ directory next to this file
# (repo checkout, editable install), fall back to where `data-files` in
# pyproject.toml puts it for a real wheel install.
_REPO_WEB_DIR = Path(__file__).resolve().parent / "web"
_INSTALLED_WEB_DIR = Path(sysconfig.get_path("data")) / "web"
_WEB_DIR = _REPO_WEB_DIR if _REPO_WEB_DIR.is_dir() else _INSTALLED_WEB_DIR
_STATIC_ROUTES = {
    "/": ("index.html", "text/html; charset=utf-8"),
    "/index.html": ("index.html", "text/html; charset=utf-8"),
    "/app.js": ("app.js", "text/javascript; charset=utf-8"),
    "/public-suffix.js": ("public-suffix.js", "text/javascript; charset=utf-8"),
    "/scoring.js": ("scoring.js", "text/javascript; charset=utf-8"),
    "/style.css": ("style.css", "text/css; charset=utf-8"),
}


@functools.lru_cache(maxsize=1)
def _static_assets() -> dict:
    """Load the demo UI's files once and cache them by route.

    Only the exact filenames named in _STATIC_ROUTES are ever read — no
    path is built from request input, so this cannot be used for path
    traversal outside web/.
    """
    assets = {}
    for route, (filename, content_type) in _STATIC_ROUTES.items():
        path = _WEB_DIR / filename
        if path.is_file():
            assets[route] = (path.read_bytes(), content_type)
    return assets


class _RateLimiter:
    """Sliding-window per-key request limiter, safe for concurrent threads.

    Deliberately simple for a small demo/API server: memory grows with the
    number of distinct keys seen (stale entries are trimmed lazily on next
    use, not on a background timer), which is fine at the traffic level
    this is meant for but would need revisiting for high-cardinality abuse.
    """

    def __init__(self, max_requests: int, window_seconds: float):
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self._lock = threading.Lock()
        self._hits: dict[str, list[float]] = {}

    def allow(self, key: str) -> bool:
        if self.max_requests <= 0:
            return True
        now = time.monotonic()
        cutoff = now - self.window_seconds
        with self._lock:
            hits = self._hits.setdefault(key, [])
            while hits and hits[0] < cutoff:
                hits.pop(0)
            if len(hits) >= self.max_requests:
                return False
            hits.append(now)
            return True


class PhishGuardRequestHandler(BaseHTTPRequestHandler):
    server_version = "PhishGuardAI/1"

    def setup(self):
        super().setup()
        self.connection.settimeout(CLIENT_SOCKET_TIMEOUT)

    def log_message(self, format, *args):  # noqa: A002 - stdlib signature
        pass

    def _send_json(
        self, status: int, payload: dict, headers: dict[str, str] | None = None
    ) -> None:
        body = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        for name, value in (headers or {}).items():
            self.send_header(name, value)
        self.end_headers()
        self.wfile.write(body)

    def _send_bytes(self, status: int, body: bytes, content_type: str) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _read_json_body(self):
        try:
            length = int(self.headers.get("Content-Length", 0))
        except ValueError:
            length = 0
        if length <= 0 or length > MAX_BODY_BYTES:
            return None
        raw = self.rfile.read(length)
        try:
            data = json.loads(raw)
        except (json.JSONDecodeError, UnicodeDecodeError):
            return None
        return data if isinstance(data, dict) else None

    def _rate_limited(self) -> bool:
        limiter = getattr(self.server, "rate_limiter", None)
        if limiter is None or limiter.allow(self.client_address[0]):
            return False
        self._send_json(
            429,
            {"error": "rate limit exceeded, try again shortly"},
            {"Retry-After": str(int(limiter.window_seconds))},
        )
        return True

    def do_GET(self):
        path = urllib.parse.urlsplit(self.path).path
        if path == "/healthz":
            self._send_json(200, {"status": "ok"})
            return
        asset = _static_assets().get(path)
        if asset is not None:
            self._send_bytes(200, *asset)
            return
        self._send_json(404, {"error": "not found"})

    def do_POST(self):
        path = urllib.parse.urlsplit(self.path).path
        if path not in ("/v1/url", "/v1/email"):
            self._send_json(404, {"error": "not found"})
            return
        if self._rate_limited():
            return
        if path == "/v1/url":
            self._handle_url()
        else:
            self._handle_email()

    def _handle_url(self):
        data = self._read_json_body()
        if data is None or not isinstance(data.get("url"), str) or not data["url"]:
            self._send_json(
                400, {"error": "expected a JSON body with a non-empty 'url' string"}
            )
            return

        hops = data.get("follow_redirects", 0)
        if not isinstance(hops, int) or isinstance(hops, bool) or not (
            0 <= hops <= MAX_FOLLOW_REDIRECTS
        ):
            self._send_json(
                400,
                {
                    "error": (
                        "'follow_redirects' must be an integer between 0 and "
                        f"{MAX_FOLLOW_REDIRECTS}"
                    )
                },
            )
            return

        check_age = data.get("check_domain_age", False)
        if not isinstance(check_age, bool):
            self._send_json(
                400, {"error": "'check_domain_age' must be a boolean"}
            )
            return

        url = data["url"]
        chain_info = {}
        extra: dict = {}
        if hops > 0:
            chain_info = follow_redirects(url, max_hops=hops)
            final_url = chain_info["final_url"]
            extra["redirect_hops"] = chain_info["hops"]
            extra["redirect_crossed_domain"] = int(chain_info["crossed_domain"])
        else:
            final_url = url

        if check_age:
            # Bounded well under CLIENT_SOCKET_TIMEOUT so a slow or
            # rate-limited RDAP lookup can't stall the response past the
            # client's own socket timeout; degrades to "unknown" either way.
            extra.update(domain_age_features(final_url, timeout=4.0))

        probability, features = score_url(final_url, extra_features=extra or None)

        response = {
            "url": url,
            "final_url": final_url,
            "verdict": classify(probability),
            "probability": probability,
            "features": features,
        }
        if chain_info:
            response["redirect_chain"] = {
                "hops": chain_info["hops"],
                "crossed_domain": chain_info["crossed_domain"],
            }
        self._send_json(200, response)

    def _handle_email(self):
        data = self._read_json_body()
        if data is None:
            self._send_json(400, {"error": "expected a JSON body"})
            return

        subject = data.get("subject")
        body = data.get("body")
        if not isinstance(subject, str) or not isinstance(body, str):
            self._send_json(
                400, {"error": "expected 'subject' and 'body' strings"}
            )
            return

        auth_results = data.get("authentication_results")
        if auth_results is not None and not isinstance(auth_results, str):
            self._send_json(
                400, {"error": "'authentication_results' must be a string"}
            )
            return

        probability, features = score_email(
            subject, body, authentication_results=auth_results
        )
        self._send_json(
            200,
            {
                "verdict": classify(probability),
                "probability": probability,
                "features": features,
            },
        )


def run_server(
    host: str = "127.0.0.1",
    port: int = 8765,
    rate_limit: int = 30,
    rate_limit_window: float = 60.0,
) -> None:
    """Start the server. *rate_limit* is the max POST /v1/* requests allowed
    per client IP per *rate_limit_window* seconds; pass 0 to disable it
    (e.g. for local development)."""
    server = ThreadingHTTPServer((host, port), PhishGuardRequestHandler)
    server.rate_limiter = _RateLimiter(rate_limit, rate_limit_window)
    print(f"PhishGuard AI serving on http://{host}:{port}")
    print("Browser demo: GET /   |   API: POST /v1/url, POST /v1/email, GET /healthz")
    if rate_limit > 0:
        print(f"Rate limit: {rate_limit} requests / {rate_limit_window:.0f}s per IP")
    print("Press Ctrl+C to stop.")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
