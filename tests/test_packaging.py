from __future__ import annotations

from pathlib import Path


def test_heavy_runner_dependencies_are_not_base_install_dependencies() -> None:
    pyproject = Path("pyproject.toml").read_text()

    base_dependencies = _array_body_before(pyproject, "[project.optional-dependencies]")
    assert "oci>=" not in base_dependencies
    assert "playwright>=" not in base_dependencies

    assert "oci>=" in _extra_body(pyproject, "oci")
    assert "playwright>=" in _extra_body(pyproject, "browser")
    assert "oci>=" in _extra_body(pyproject, "runner")
    assert "playwright>=" in _extra_body(pyproject, "runner")
    assert "oci>=" in _extra_body(pyproject, "dev")
    assert "playwright>=" in _extra_body(pyproject, "dev")


def _array_body_before(pyproject: str, stop_marker: str) -> str:
    prefix = pyproject.split(stop_marker, 1)[0]
    return prefix.split("dependencies = [", 1)[1].split("]", 1)[0].lower()


def _extra_body(pyproject: str, extra: str) -> str:
    return pyproject.split(f"{extra} = [", 1)[1].split("]", 1)[0].lower()
