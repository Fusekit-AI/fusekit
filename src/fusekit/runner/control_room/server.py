"""Live local control-room server."""

from __future__ import annotations

import json
import os
import re
import secrets
import shutil
import subprocess
import time
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
from fusekit.security.url import require_safe_url
from fusekit.vault import Vault

GATE_OPEN_DEBOUNCE_SECONDS = 20.0


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
        def do_OPTIONS(self) -> None:  # noqa: N802
            self.send_response(405)
            self._write_security_headers()
            self.end_headers()

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
            if not _trusted_fetch_site(self.headers.get("Sec-Fetch-Site")):
                self._write_json({"ok": False, "error": "cross-site request"}, status=403)
                return
            prefix = "/api/gates/"
            if route.path.startswith(prefix) and route.path.endswith("/pass"):
                gate_id = unquote(route.path[len(prefix) : -len("/pass")])
                service = GateService.load(job_state.parent / "gates.json")
                if gate_id not in service.records:
                    self._write_json({"ok": False, "error": "gate not found"}, status=404)
                    return
                service.request_resume(gate_id)
                self._write_json(
                    {
                        "ok": True,
                        "gate_id": gate_id,
                        "status": "resume_requested",
                        "message": "Resume requested. FuseKit will retry provider verification.",
                    }
                )
                return
            if route.path.startswith(prefix) and route.path.endswith("/open"):
                gate_id = unquote(route.path[len(prefix) : -len("/open")])
                service = GateService.load(job_state.parent / "gates.json")
                gate = service.records.get(gate_id)
                if gate is None:
                    self._write_json({"ok": False, "error": "gate not found"}, status=404)
                    return
                safe_url = require_safe_url(gate.resume_url, label="Provider gate URL")
                if _recently_opened_gate(gate, safe_url):
                    self._write_json(
                        {
                            "ok": True,
                            "gate_id": gate_id,
                            "browser": "",
                            "reused": True,
                            "message": (
                                "Provider gate is already open in the shared VM browser."
                            ),
                        }
                    )
                    return
                try:
                    browser = _open_gate_url_in_visual_browser(job_state, safe_url)
                except FuseKitError as exc:
                    self._write_json({"ok": False, "error": str(exc)}, status=400)
                    return
                service.mark_opened(gate_id, safe_url)
                self._write_json(
                    {
                        "ok": True,
                        "gate_id": gate_id,
                        "browser": browser,
                        "reused": False,
                        "message": "Provider gate opened inside the shared VM browser.",
                    }
                )
                return
            if route.path.startswith(prefix) and route.path.endswith("/capture-clipboard"):
                gate_id = unquote(route.path[len(prefix) : -len("/capture-clipboard")])
                try:
                    body = self._read_json_body()
                    captured = _capture_gate_clipboard_secret(
                        job_state,
                        gate_id,
                        str(body.get("target", "")),
                    )
                except FuseKitError as exc:
                    self._write_json({"ok": False, "error": str(exc)}, status=400)
                    return
                self._write_json({"ok": True, **captured})
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

        def _read_json_body(self) -> dict[str, Any]:
            try:
                length = int(self.headers.get("content-length", "0"))
            except ValueError:
                length = 0
            if length <= 0:
                return {}
            if length > 4096:
                raise FuseKitError("Control-room request body is too large.")
            raw = self.rfile.read(length)
            try:
                data = json.loads(raw.decode("utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                raise FuseKitError("Control-room request body must be JSON.") from exc
            if not isinstance(data, dict):
                raise FuseKitError("Control-room request body must be a JSON object.")
            return data

        def _write_control_room_cookie(self) -> None:
            expected = os.environ.get("FUSEKIT_CONTROL_ROOM_TOKEN", "")
            if not expected or not getattr(self, "_set_control_room_cookie", False):
                return
            if not _safe_cookie_value(expected):
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


def _open_gate_url_in_visual_browser(job_state: Path, url: str) -> str:
    safe_url = require_safe_url(url, label="Provider gate URL")
    browser = _visual_browser_binary()
    if not browser:
        raise FuseKitError("No VM browser binary is available for provider gate launch.")
    profile_dir = job_state.parent.parent / "visual" / "chrome-provider-profile"
    try:
        profile_dir.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        raise FuseKitError(f"Could not prepare VM browser profile: {exc}") from exc
    display = _visual_display(job_state)
    command = [
        browser,
        "--no-sandbox",
        "--disable-dev-shm-usage",
        "--disable-gpu",
        "--start-maximized",
        f"--user-data-dir={profile_dir}",
        safe_url,
    ]
    env = {**os.environ, "DISPLAY": display}
    try:
        subprocess.Popen(
            command,
            env=env,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.STDOUT,
            start_new_session=True,
        )
    except OSError as exc:
        raise FuseKitError(f"Could not open provider gate in VM browser: {exc}") from exc
    return browser


def _recently_opened_gate(gate: Any, safe_url: str) -> bool:
    """Return whether the same provider gate was already launched moments ago."""

    if str(getattr(gate, "last_opened_url", "") or "") != safe_url:
        return False
    opened_at = float(getattr(gate, "last_opened_at", 0.0) or 0.0)
    return opened_at > 0 and time.time() - opened_at < GATE_OPEN_DEBOUNCE_SECONDS


def _capture_gate_clipboard_secret(
    job_state: Path,
    gate_id: str,
    target: str,
) -> dict[str, Any]:
    service = GateService.load(job_state.parent / "gates.json")
    gate = service.records.get(gate_id)
    if gate is None:
        raise FuseKitError("Gate not found.")
    if gate.status not in {"waiting", "resurfaced", "resume_requested"}:
        raise FuseKitError("Gate is not waiting for capture.")
    target = target.strip().upper()
    allowed_targets = _gate_capture_targets(gate.target)
    if target not in allowed_targets:
        raise FuseKitError("This gate is not allowed to capture that value.")
    value = _vm_clipboard_text(job_state).strip()
    if not value:
        raise FuseKitError("The VM clipboard is empty.")
    if len(value) > 8192:
        raise FuseKitError("The VM clipboard value is too large to capture.")
    if "\x00" in value:
        raise FuseKitError("The VM clipboard value is not valid text.")
    vault_path = _job_vault_path(job_state)
    passphrase = _control_room_vault_passphrase(job_state)
    vault = Vault.open(vault_path, passphrase) if vault_path.exists() else Vault.empty()
    record_id, kind, provider = _capture_record_for_target(gate.provider, target)
    vault.put(record_id, kind, provider, target, value, {"env": target, "source": "vm-clipboard"})
    vault.save(vault_path, passphrase)
    service.mark_captured(gate_id, target)
    gate = service.records[gate_id]
    captured_targets = set(gate.captured_targets)
    status = "captured"
    message = (
        f"{target} captured into the encrypted vault. "
        "Capture the remaining required values to continue."
    )
    if allowed_targets.issubset(captured_targets):
        service.request_resume(gate_id)
        status = "resume_requested"
        message = (
            "All required values were captured into the encrypted vault. "
            "FuseKit will retry provider verification."
        )
    _append_capture_audit(job_state, gate_id, target, record_id)
    return {
        "gate_id": gate_id,
        "target": target,
        "record_id": record_id,
        "status": status,
        "captured_targets": sorted(captured_targets),
        "message": message,
    }


def _gate_capture_targets(raw_target: str) -> set[str]:
    return {
        item
        for item in (part.strip().upper() for part in raw_target.split(","))
        if re.fullmatch(r"[A-Z][A-Z0-9_]{2,}", item)
    }


def _vm_clipboard_text(job_state: Path) -> str:
    display = _visual_display(job_state)
    for command in (("xclip", "-selection", "clipboard", "-o"), ("xsel", "-ob")):
        if not shutil.which(command[0]):
            continue
        try:
            completed = subprocess.run(
                command,
                check=False,
                capture_output=True,
                text=True,
                timeout=5,
                env={**os.environ, "DISPLAY": display},
            )
        except (OSError, subprocess.TimeoutExpired):
            continue
        if completed.returncode == 0:
            return completed.stdout
    raise FuseKitError("Could not read the VM clipboard.")


def _job_vault_path(job_state: Path) -> Path:
    try:
        job = JobState.load(job_state)
    except (OSError, ValueError):
        job = None
    if job is not None:
        vault = job.artifacts.get("vault")
        if vault:
            return Path(vault)
    return job_state.parent / "fusekit.vault.json"


def _control_room_vault_passphrase(job_state: Path) -> str:
    candidates = [
        Path(os.environ.get("FUSEKIT_PASSPHRASE_FILE", "")),
        job_state.parent.parent.parent / "passphrase",
    ]
    for path in candidates:
        if str(path) and path.is_file():
            return path.read_text(encoding="utf-8").strip()
    raise FuseKitError("Vault passphrase file is not available to the control room.")


def _capture_record_for_target(
    gate_provider: str,
    target: str,
) -> tuple[str, str, str]:
    provider = gate_provider.lower() or target.split("_", 1)[0].lower()
    if target.endswith("_API_KEY") or target.endswith("_TOKEN"):
        record_id = f"provider.{provider}.{target.lower()}"
        return record_id, "provider_token", provider
    record_id = f"app.{provider}.{target.lower()}"
    return record_id, "app_env", provider


def _append_capture_audit(
    job_state: Path,
    gate_id: str,
    target: str,
    record_id: str,
) -> None:
    try:
        job = JobState.load(job_state)
    except (OSError, ValueError):
        return
    audit_path = job.artifacts.get("audit_log")
    if not audit_path:
        return
    payload = {
        "action": "control_room.clipboard_capture",
        "gate_id": gate_id,
        "target": target,
        "record_id": record_id,
    }
    try:
        with Path(audit_path).open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(payload, sort_keys=True) + "\n")
    except OSError:
        return


def _visual_browser_binary() -> str:
    configured = os.environ.get("FUSEKIT_VISUAL_BROWSER", "").strip()
    if configured:
        return configured
    for root in (
        Path(os.environ.get("PLAYWRIGHT_BROWSERS_PATH", "")),
        Path("/opt/fusekit-playwright-browsers"),
    ):
        if not str(root):
            continue
        for candidate in sorted(root.glob("chromium-*/chrome-linux*/chrome")):
            if candidate.is_file() and os.access(candidate, os.X_OK):
                return str(candidate)
    for name in ("google-chrome", "chromium-browser", "chromium", "xdg-open"):
        resolved = shutil.which(name)
        if resolved:
            return resolved
    return ""


def _visual_display(job_state: Path) -> str:
    visual_path = job_state.parent / "visual.json"
    try:
        visual = json.loads(visual_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        visual = {}
    if isinstance(visual, dict):
        display = str(visual.get("display", "") or "").strip()
        if display:
            return display
    return os.environ.get("FUSEKIT_VISUAL_DISPLAY", ":99")


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


def _trusted_fetch_site(value: str | None) -> bool:
    """Reject browser-declared cross-site state changes."""

    if not value:
        return True
    return value.strip().lower() in {"same-origin", "none"}


def _safe_cookie_value(value: str) -> bool:
    return not any(char in value for char in ("\r", "\n", ";", ","))


def _query_token(route: Any) -> str:
    values = parse_qs(getattr(route, "query", ""), keep_blank_values=False).get("token", [])
    return values[0] if values else ""


def _hostname_without_port(value: str) -> str:
    if value.startswith("[") and "]" in value:
        return value[1 : value.index("]")]
    return value.split(":", 1)[0]
