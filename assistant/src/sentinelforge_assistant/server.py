"""Small HTTP service exposing read-only evidence-grounded investigations."""

from __future__ import annotations

import json
import hmac
import ipaddress
import logging
import os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any
from urllib.parse import urlparse

from .assistant import from_environment

LOG = logging.getLogger("sentinelforge.assistant")


def main() -> int:
    logging.basicConfig(level=os.getenv("SF_LOG_LEVEL", "INFO"))
    assistant = from_environment()
    token = os.getenv("SF_ASSISTANT_BEARER_TOKEN")

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:  # noqa: N802
            if urlparse(self.path).path == "/healthz":
                self._write(200, {"status": "ok"})
            else:
                self._write(404, {"error": "not found"})

        def do_POST(self) -> None:  # noqa: N802
            path = urlparse(self.path).path
            if path not in {
                "/v1/investigate", "/v1/explain-alert", "/v1/investigate-incident"
            }:
                self._write(404, {"error": "not found"})
                return
            if token and not hmac.compare_digest(
                self.headers.get("Authorization", ""), f"Bearer {token}"
            ):
                self._write(401, {"error": "unauthorized"})
                return
            try:
                length = int(self.headers.get("Content-Length", "0"))
                if length < 1 or length > 64_000:
                    self._write(413, {"error": "request body must be between 1 and 64,000 bytes"})
                    return
                payload: Any = json.loads(self.rfile.read(length))
                if not isinstance(payload, dict):
                    self._write(400, {"error": "request must be a JSON object"})
                    return
                if path == "/v1/explain-alert":
                    result = assistant.explain_alert(
                        payload.get("alert_id", ""), limit=payload.get("limit", 100)
                    )
                elif path == "/v1/investigate-incident":
                    result = assistant.investigate_incident(
                        payload.get("incident_id", ""), limit=payload.get("limit", 100)
                    )
                else:
                    result = assistant.investigate(
                        payload.get("question", ""),
                        host_id=payload.get("host_id"),
                        event_id=payload.get("event_id"),
                        limit=payload.get("limit", 100),
                    )
                self._write(200, result)
            except (json.JSONDecodeError, UnicodeDecodeError, ValueError) as exc:
                self._write(400, {"error": str(exc)})
            except Exception:
                LOG.exception("investigation request failed")
                self._write(502, {"error": "investigation service could not complete the request"})

        def _write(self, status: int, payload: dict[str, Any]) -> None:
            body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Cache-Control", "no-store")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, fmt: str, *args: Any) -> None:
            LOG.info("%s - %s", self.address_string(), fmt % args)

    address = os.getenv("SF_ASSISTANT_ADDR", "127.0.0.1:8090")
    host, _, port = address.rpartition(":")
    try:
        is_loopback = ipaddress.ip_address(host or "127.0.0.1").is_loopback
    except ValueError:
        is_loopback = (host or "").lower() == "localhost"
    if not is_loopback and not token:
        assistant.close()
        raise ValueError("set SF_ASSISTANT_BEARER_TOKEN before binding outside loopback")
    server = ThreadingHTTPServer((host or "127.0.0.1", int(port)), Handler)
    LOG.info("assistant listening on %s (read-only)", address)
    try:
        server.serve_forever(poll_interval=0.5)
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
        assistant.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
