from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).parents[1]
SYSTEMD_DIR = ROOT / "deploy/oci/systemd"
TMPFILES = ROOT / "deploy/oci/tmpfiles/fusekit.conf"
RELEASE_SCRIPT = ROOT / "deploy/oci/release/fusekit-hosted-release.sh"


def _unit(name: str) -> dict[str, list[str]]:
    values: dict[str, list[str]] = {}
    for line in (SYSTEMD_DIR / name).read_text(encoding="utf-8").splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith(("#", "[")):
            continue
        key, separator, value = stripped.partition("=")
        if separator:
            values.setdefault(key, []).append(value)
    return values


def test_oci_systemd_units_match_host_posture_hardening_contract() -> None:
    for unit_name, protect_system in {
        "fusekit-hosted.service": "full",
        "fusekit-worker-dispatch.service": "strict",
    }.items():
        unit = _unit(unit_name)

        assert unit["User"] == ["fusekit"]
        assert unit["Group"] == ["fusekit"]
        assert unit["WorkingDirectory"] == ["/opt/fusekit/current"]
        assert unit["EnvironmentFile"] == [
            "/etc/fusekit/hosted-secrets.env",
            "-/etc/fusekit/hosted-provenance.env",
        ]
        assert unit["UMask"] == ["0077"]
        assert unit["NoNewPrivileges"] == ["true"]
        assert unit["PrivateTmp"] == ["true"]
        assert unit["ProtectSystem"] == [protect_system]
        assert unit["ProtectHome"] == ["true"]
        assert unit["PrivateDevices"] == ["true"]
        assert unit["RestrictSUIDSGID"] == ["true"]
        assert unit["LockPersonality"] == ["true"]
        assert unit["SystemCallArchitectures"] == ["native"]
        assert unit["ProtectKernelTunables"] == ["true"]
        assert unit["ProtectKernelModules"] == ["true"]
        assert unit["ProtectKernelLogs"] == ["true"]
        assert unit["ProtectControlGroups"] == ["true"]
        assert unit["RestrictNamespaces"] == ["true"]
        assert unit["RestrictRealtime"] == ["true"]
        assert unit["MemoryDenyWriteExecute"] == ["true"]
        assert unit["CapabilityBoundingSet"] == [""]
        assert unit["AmbientCapabilities"] == [""]
        assert unit["RestrictAddressFamilies"] == ["AF_UNIX AF_INET AF_INET6"]
        assert unit["StateDirectory"] == ["fusekit"]
        assert unit["StateDirectoryMode"] == ["0750"]
        assert unit["LogsDirectory"] == ["fusekit"]
        assert unit["LogsDirectoryMode"] == ["0750"]
        assert unit["RuntimeDirectory"] == ["fusekit"]
        assert unit["RuntimeDirectoryMode"] == ["0750"]
        assert unit["ReadWritePaths"] == ["/var/lib/fusekit /var/log/fusekit /run/fusekit"]
        writable = unit["ReadWritePaths"][0].split()
        assert "/" not in writable
        assert "/etc" not in writable
        assert "/usr" not in writable
        assert "/var" not in writable


def test_oci_systemd_units_bind_only_to_loopback_ports() -> None:
    hosted = _unit("fusekit-hosted.service")
    dispatch = _unit("fusekit-worker-dispatch.service")

    assert hosted["Environment"] == [
        "FUSEKIT_HOSTED_BIND=127.0.0.1",
        "FUSEKIT_HOSTED_PORT=8080",
    ]
    assert "FUSEKIT_HOSTED_BIND=127.0.0.1" in (
        SYSTEMD_DIR / "fusekit-hosted.service"
    ).read_text(encoding="utf-8")
    assert hosted["ExecStart"] == ["/opt/fusekit/current/.venv/bin/fusekit-hosted"]
    assert dispatch["ExecStart"][0].endswith(
        "fusekit-hosted-worker-dispatch --host 127.0.0.1 --port 8766"
    )
    assert dispatch["ExecStart"][0].startswith("/opt/fusekit/current/.venv/bin/")
    assert "--host 0.0.0.0" not in dispatch["ExecStart"][0]


def test_oci_tmpfiles_create_only_constrained_fusekit_paths() -> None:
    rows = [
        line.split()
        for line in TMPFILES.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]

    assert rows
    for row in rows:
        assert row[0] == "d"
        assert row[1].startswith(
            ("/etc/fusekit", "/var/lib/fusekit", "/var/log/fusekit", "/run/fusekit")
        )
        assert row[2] == "0750"
        if row[1].startswith("/etc/fusekit"):
            assert row[3] == "root"
            assert row[4] == "root"
        else:
            assert row[3] == "fusekit"
            assert row[4] == "fusekit"


def test_oci_release_script_is_narrow_and_reviewable() -> None:
    script = RELEASE_SCRIPT.read_text(encoding="utf-8")
    mode = RELEASE_SCRIPT.stat().st_mode

    assert mode & 0o111
    assert "https://github.com/Fusekit-AI/fusekit.git" in script
    assert "^[0-9a-f]{40}$" in script
    assert "refusing non-canonical FuseKit repository URL" in script
    assert 'RELEASE_ROOT="${FUSEKIT_RELEASE_ROOT:-/opt/fusekit/releases}"' in script
    assert 'CURRENT_LINK="${FUSEKIT_CURRENT_LINK:-/opt/fusekit/current}"' in script
    assert "ln -sfn" in script
    assert "mv -Tf" in script
    assert "/etc/fusekit/hosted-provenance.env" in script
    assert "/etc/fusekit/hosted-secrets.env" in script
    assert "cat /etc/fusekit/hosted-secrets.env" not in script
    assert (
        'PROVENANCE_FILE="${FUSEKIT_HOSTED_PROVENANCE_FILE:-'
        '/etc/fusekit/hosted-provenance.env}"'
    ) in script
    assert 'systemctl restart "${HOSTED_SERVICE}" "${DISPATCH_SERVICE}"' in script
    assert "fusekit-hosted.service" in script
    assert "fusekit-worker-dispatch.service" in script
    assert "fusekit.oci-hosted-release-receipt.v1" in script
    assert "fusekit-hosted-verify --origin https://fusekit.snowmanai.org" in script
    assert "cloudflare" not in script.lower()
    assert "mailpilot" not in script.lower()
