"""Detonation cleanup for plaintext worker state."""

from __future__ import annotations

import shutil
from pathlib import Path


class DetonationScopeError(ValueError):
    """Raised when cleanup targets escape the declared disposable workspace."""


def detonate(
    paths: list[Path],
    preserve: list[Path] | None = None,
    *,
    workspace_root: Path | None = None,
) -> list[str]:
    """Remove plaintext worker-state paths while preserving approved artifacts."""

    root = workspace_root.resolve() if workspace_root is not None else None
    preserved = {_resolve(path) for path in (preserve or [])}
    removed: list[str] = []
    for path in paths:
        resolved = _resolve(path)
        if root is not None:
            _require_workspace_child(resolved, root)
        if resolved in preserved or not path.exists():
            continue
        if path.is_dir() and not path.is_symlink():
            shutil.rmtree(path)
        else:
            path.unlink()
        removed.append(str(path))
    return removed


def _resolve(path: Path) -> Path:
    return path.expanduser().resolve(strict=False)


def _require_workspace_child(path: Path, root: Path) -> None:
    if path == root:
        raise DetonationScopeError(f"refusing to detonate workspace root: {root}")
    try:
        path.relative_to(root)
    except ValueError as exc:
        raise DetonationScopeError(
            f"refusing to detonate path outside workspace root: {path}"
        ) from exc
