"""Подмена HTTP-адреса не должна менять чужой API или останавливать выбранный worker."""

import os
import subprocess
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from threading import Thread

import recovery_smoke as recovery


def test_foreign_http_address_is_rejected_before_worker_stop_and_registration():
    requests = []

    class ForeignAPI(BaseHTTPRequestHandler):
        def do_POST(self):
            requests.append(self.path)
            self.send_response(500)
            self.end_headers()
            self.wfile.write(b'{"detail":"foreign API"}')

        def log_message(self, *args):
            pass

    worker = subprocess.check_output(
        ["docker", "compose", "ps", "-q", "worker"], cwd=recovery.ROOT, text=True
    ).strip()
    assert worker

    def started_at():
        return subprocess.check_output(
            ["docker", "inspect", "--format", "{{.State.StartedAt}}", worker], text=True
        ).strip()

    before = started_at()
    server = ThreadingHTTPServer(("127.0.0.1", 0), ForeignAPI)
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        result = subprocess.run(
            [sys.executable, "scripts/recovery_smoke.py"],
            cwd=recovery.ROOT,
            env={**os.environ, "BASE_URL": f"http://127.0.0.1:{server.server_port}"},
            capture_output=True,
            text=True,
            timeout=60,
        )
        assert result.returncode != 0
        assert (requests, started_at() == before) == ([], True)
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)
