"""Fixed HTTP gateway from loopback into one SANDBOX target container."""
from __future__ import annotations

from http.client import HTTPConnection
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import os


TARGET_HOST = os.getenv("SANDBOX_TARGET_HOST", "target")
TARGET_PORT = int(os.getenv("SANDBOX_TARGET_PORT", "8000"))
LISTEN_PORT = int(os.getenv("SANDBOX_GATEWAY_PORT", "8080"))
MAX_BODY = 10 * 1024 * 1024
HOP_BY_HOP = {"connection", "keep-alive", "proxy-authenticate", "proxy-authorization", "te", "trailers", "transfer-encoding", "upgrade"}


class GatewayHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def _forward(self) -> None:
        if "://" in self.path:
            self.send_error(400, "absolute URLs are not allowed")
            return
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            self.send_error(400, "invalid content length")
            return
        if length < 0 or length > MAX_BODY:
            self.send_error(413, "request body too large")
            return
        body = self.rfile.read(length) if length else None
        headers = {
            key: value for key, value in self.headers.items()
            if key.lower() not in HOP_BY_HOP and key.lower() != "host"
        }
        headers["Host"] = f"{TARGET_HOST}:{TARGET_PORT}"
        connection = HTTPConnection(TARGET_HOST, TARGET_PORT, timeout=15)
        try:
            connection.request(self.command, self.path or "/", body=body, headers=headers)
            response = connection.getresponse()
            payload = response.read(MAX_BODY + 1)
            if len(payload) > MAX_BODY:
                self.send_error(502, "target response too large")
                return
            self.send_response(response.status, response.reason)
            for key, value in response.getheaders():
                if key.lower() not in HOP_BY_HOP and key.lower() != "content-length":
                    self.send_header(key, value)
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            if self.command != "HEAD":
                self.wfile.write(payload)
        except OSError as exc:
            payload = f"SANDBOX target unavailable: {type(exc).__name__}".encode()
            self.send_response(502)
            self.send_header("Content-Type", "text/plain; charset=utf-8")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            if self.command != "HEAD":
                self.wfile.write(payload)
        finally:
            connection.close()

    do_GET = _forward
    do_HEAD = _forward
    do_OPTIONS = _forward
    do_POST = _forward

    def log_message(self, _format: str, *_args: object) -> None:
        return


if __name__ == "__main__":
    ThreadingHTTPServer(("0.0.0.0", LISTEN_PORT), GatewayHandler).serve_forever()
