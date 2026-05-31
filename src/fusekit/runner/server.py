"""Live local control-room server."""

from __future__ import annotations

import json
import os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

from fusekit.errors import FuseKitError
from fusekit.runner.control_room import (
    control_room_payload as build_control_room_payload,
)
from fusekit.runner.control_room import (
    render_control_room,
)
from fusekit.runner.job import JobState


def serve_control_room(job_state: Path, host: str = "127.0.0.1", port: int = 8765) -> str:
    """Serve a live control room until interrupted."""

    if not _is_loopback(host) and os.environ.get("FUSEKIT_ALLOW_REMOTE_CONTROL_ROOM") != "1":
        raise FuseKitError(
            "Control room serves local job metadata and is local-only by default. "
            "Set FUSEKIT_ALLOW_REMOTE_CONTROL_ROOM=1 to bind a non-loopback host."
        )
    handler = _handler(job_state)
    server = ThreadingHTTPServer((host, port), handler)
    url = f"http://{host}:{server.server_port}"
    try:
        server.serve_forever()
    finally:
        server.server_close()
    return url


def control_room_payload(job_state: Path) -> dict[str, Any]:
    """Return the live control-room payload."""

    job = JobState.load(job_state)
    return build_control_room_payload(job, gate_path=job_state.parent / "gates.json")


def _handler(job_state: Path) -> type[BaseHTTPRequestHandler]:
    class ControlRoomHandler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:  # noqa: N802
            if self.path == "/api/job":
                self._write_json(control_room_payload(job_state))
                return
            if self.path in {"/", "/index.html"}:
                job = JobState.load(job_state)
                self._write_html(_live_html(job, job_state))
                return
            self.send_response(404)
            self.end_headers()

        def log_message(self, format: str, *args: object) -> None:
            return

        def _write_json(self, payload: dict[str, Any]) -> None:
            data = json.dumps(payload, indent=2, sort_keys=True).encode("utf-8")
            self.send_response(200)
            self.send_header("content-type", "application/json")
            self.send_header("content-length", str(len(data)))
            self._write_security_headers()
            self.end_headers()
            self.wfile.write(data)

        def _write_html(self, html: str) -> None:
            data = html.encode("utf-8")
            self.send_response(200)
            self.send_header("content-type", "text/html; charset=utf-8")
            self.send_header("content-length", str(len(data)))
            self._write_security_headers()
            self.end_headers()
            self.wfile.write(data)

        def _write_security_headers(self) -> None:
            self.send_header("cache-control", "no-store")
            self.send_header("x-content-type-options", "nosniff")
            self.send_header("referrer-policy", "no-referrer")
            self.send_header("x-frame-options", "DENY")
            self.send_header(
                "content-security-policy",
                "default-src 'self'; "
                "connect-src 'self'; "
                "img-src 'self' data:; "
                "style-src 'unsafe-inline'; "
                "script-src 'unsafe-inline'; "
                "base-uri 'none'; "
                "form-action 'none'; "
                "frame-ancestors 'none'",
            )

    return ControlRoomHandler


def _live_html(job: JobState, job_state: Path) -> str:
    return render_control_room(job, gate_path=job_state.parent / "gates.json")


def _is_loopback(host: str) -> bool:
    normalized = host.strip().lower().strip("[]")
    return normalized in {"127.0.0.1", "localhost", "::1"}
