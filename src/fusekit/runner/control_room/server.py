"""Live local control-room server."""

from __future__ import annotations

import json
import os
import secrets
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, unquote, urlparse

from fusekit.errors import FuseKitError
from fusekit.runner.control_room import (
    control_room_payload as build_control_room_payload,
)
from fusekit.runner.control_room import (
    render_control_room,
)
from fusekit.runner.gates import GateService
from fusekit.runner.job import JobState


def serve_control_room(job_state: Path, host: str = "127.0.0.1", port: int = 8765) -> str:
    """Serve a live control room until interrupted."""

    if not _is_loopback(host):
        if os.environ.get("FUSEKIT_ALLOW_REMOTE_CONTROL_ROOM") != "1":
            raise FuseKitError(
                "Control room serves local job metadata and is local-only by default. "
                "Set FUSEKIT_ALLOW_REMOTE_CONTROL_ROOM=1 to bind a non-loopback host."
            )
        if not os.environ.get("FUSEKIT_CONTROL_ROOM_TOKEN"):
            raise FuseKitError("Remote control room binding requires FUSEKIT_CONTROL_ROOM_TOKEN.")
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
            route = urlparse(self.path)
            if not self._authorize_request(route):
                return
            if route.path == "/api/job":
                self._write_json(control_room_payload(job_state))
                return
            if route.path in {"/", "/index.html"}:
                job = JobState.load(job_state)
                self._write_html(_live_html(job, job_state))
                return
            self.send_response(404)
            self.end_headers()

        def do_POST(self) -> None:  # noqa: N802
            route = urlparse(self.path)
            if not self._authorize_request(route):
                return
            if self.headers.get("x-fusekit-control-room") != "resume":
                self._write_json({"ok": False, "error": "missing control-room header"}, status=403)
                return
            if not _trusted_browser_origin(self.headers.get("Origin"), self.headers.get("Host")):
                self._write_json({"ok": False, "error": "untrusted origin"}, status=403)
                return
            prefix = "/api/gates/"
            suffix = "/pass"
            if route.path.startswith(prefix) and route.path.endswith(suffix):
                gate_id = unquote(route.path[len(prefix) : -len(suffix)])
                service = GateService.load(job_state.parent / "gates.json")
                if gate_id not in service.records:
                    self._write_json({"ok": False, "error": "gate not found"}, status=404)
                    return
                service.pass_gate(gate_id)
                self._write_json({"ok": True, "gate_id": gate_id})
                return
            self.send_response(404)
            self.end_headers()

        def log_message(self, format: str, *args: object) -> None:
            return

        def _authorize_request(self, route: Any) -> bool:
            expected = os.environ.get("FUSEKIT_CONTROL_ROOM_TOKEN", "")
            if not expected:
                return True
            token = self._request_token(route)
            if token and secrets.compare_digest(token, expected):
                if token == _query_token(route):
                    self._set_control_room_cookie = True
                return True
            self._write_json({"ok": False, "error": "invalid control-room token"}, status=403)
            return False

        def _request_token(self, route: Any) -> str:
            query_token = _query_token(route)
            if query_token:
                return query_token
            authorization = self.headers.get("Authorization", "")
            if authorization.lower().startswith("bearer "):
                return authorization[7:].strip()
            cookie_header = self.headers.get("Cookie", "")
            if cookie_header:
                cookies = SimpleCookie()
                cookies.load(cookie_header)
                morsel = cookies.get("fusekit_control_room")
                if morsel is not None:
                    return morsel.value
            return ""

        def _write_json(self, payload: dict[str, Any], status: int = 200) -> None:
            data = json.dumps(payload, indent=2, sort_keys=True).encode("utf-8")
            self.send_response(status)
            self.send_header("content-type", "application/json")
            self.send_header("content-length", str(len(data)))
            self._write_security_headers()
            self._write_control_room_cookie()
            self.end_headers()
            self.wfile.write(data)

        def _write_html(self, html: str) -> None:
            data = html.encode("utf-8")
            self.send_response(200)
            self.send_header("content-type", "text/html; charset=utf-8")
            self.send_header("content-length", str(len(data)))
            self._write_security_headers()
            self._write_control_room_cookie()
            self.end_headers()
            self.wfile.write(data)

        def _write_control_room_cookie(self) -> None:
            expected = os.environ.get("FUSEKIT_CONTROL_ROOM_TOKEN", "")
            if not expected or not getattr(self, "_set_control_room_cookie", False):
                return
            self.send_header(
                "set-cookie",
                f"fusekit_control_room={expected}; HttpOnly; SameSite=Lax; Path=/",
            )

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
                "frame-src http: https:; "
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


def _trusted_browser_origin(origin: str | None, host: str | None) -> bool:
    """Allow same-origin browser posts while preserving curl/test compatibility."""

    if not origin:
        return True
    normalized_origin = origin.lower().removeprefix("http://").removeprefix("https://")
    normalized_origin = normalized_origin.rstrip("/")
    normalized_host = (host or "").lower()
    if os.environ.get("FUSEKIT_CONTROL_ROOM_TOKEN") and normalized_origin == normalized_host:
        return True
    return normalized_origin == normalized_host and _is_loopback(
        _hostname_without_port(normalized_host)
    )


def _query_token(route: Any) -> str:
    values = parse_qs(getattr(route, "query", ""), keep_blank_values=False).get("token", [])
    return values[0] if values else ""


def _hostname_without_port(value: str) -> str:
    if value.startswith("[") and "]" in value:
        return value[1 : value.index("]")]
    return value.split(":", 1)[0]
