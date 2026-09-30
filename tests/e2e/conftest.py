"""End-to-end test harness: a real local HTTP target + the real engine binaries.

Unlike the unit tests (which inject a fake tool runner), these run the ACTUAL ProjectDiscovery
engines against a controlled server and assert real results come back. This is the layer that
would have caught this session's bugs — the pipeline silently returning 0 because targets were
passed on argv instead of stdin, and secrets never being scanned. Skipped automatically where
the engine binaries are not installed (so `pytest` still passes on a bare dev box); CI installs
them and runs this for real.
"""

from __future__ import annotations

import http.server
import shutil
import threading

import pytest

# Valid-format planted secrets (AWS access key id + Google API key) in a served JS bundle.
PLANTED_AWS = "AKIAZ7QW3RTYUIOPLKJH"
PLANTED_GOOGLE = "AIzaSyD-ABCDEFGHIJKLMNOPQRSTUVWXYZ01234"
_JS_BODY = f'window.CFG={{aws:"{PLANTED_AWS}",gmaps:"{PLANTED_GOOGLE}",api:"/v1"}};'
_INDEX = '<html><body><a href="/app.js"></a><a href="/admin/login?next=/x"></a></body></html>'


class _Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        origin = self.headers.get("Origin")
        if self.path.split("?")[0] == "/app.js":
            body, ctype = _JS_BODY.encode(), "application/javascript"
        else:
            body, ctype = _INDEX.encode(), "text/html"
        self.send_response(200)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        # Reflect any Origin back with credentials -> a deliberate CORS misconfiguration.
        if origin:
            self.send_header("Access-Control-Allow-Origin", origin)
            self.send_header("Access-Control-Allow-Credentials", "true")
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *a):  # silence the server
        return


@pytest.fixture(scope="session")
def httpx_available():
    if shutil.which("httpx") is None:
        pytest.skip("httpx engine binary not on PATH (install ProjectDiscovery httpx)")
    return True


@pytest.fixture
def target_server():
    """Start the local target on an ephemeral port; yield (host:port, base_url)."""
    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    port = srv.server_address[1]
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        yield f"127.0.0.1:{port}", f"http://127.0.0.1:{port}"
    finally:
        srv.shutdown()
