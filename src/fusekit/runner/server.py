"""Live local control-room server."""

from __future__ import annotations

import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

from fusekit.runner.control_room import render_control_room
from fusekit.runner.gates import GateService
from fusekit.runner.job import JobState


def serve_control_room(job_state: Path, host: str = "127.0.0.1", port: int = 8765) -> str:
    """Serve a live control room until interrupted."""

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
    payload = job.to_dict()
    payload["gates"] = _gate_records(job_state)
    return payload


def _gate_records(job_state: Path) -> list[dict[str, str | int | float]]:
    gate_path = job_state.parent / "gates.json"
    service = GateService.load(gate_path)
    return [record.to_dict() for record in service.records.values()]


def _handler(job_state: Path) -> type[BaseHTTPRequestHandler]:
    class ControlRoomHandler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:  # noqa: N802
            if self.path == "/api/job":
                self._write_json(control_room_payload(job_state))
                return
            if self.path in {"/", "/index.html"}:
                job = JobState.load(job_state)
                self._write_html(_live_html(job))
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
            self.end_headers()
            self.wfile.write(data)

        def _write_html(self, html: str) -> None:
            data = html.encode("utf-8")
            self.send_response(200)
            self.send_header("content-type", "text/html; charset=utf-8")
            self.send_header("content-length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

    return ControlRoomHandler


def _live_html(job: JobState) -> str:
    return render_control_room(job)
