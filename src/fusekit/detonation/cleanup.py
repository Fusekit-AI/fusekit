"""Detonation cleanup for plaintext worker state."""

from __future__ import annotations

import shutil
from pathlib import Path


def detonate(paths: list[Path], preserve: list[Path] | None = None) -> list[str]:
    """Remove plaintext worker-state paths while preserving approved artifacts."""

    preserved = {path.resolve() for path in (preserve or [])}
    removed: list[str] = []
    for path in paths:
        resolved = path.resolve()
        if resolved in preserved or not path.exists():
            continue
        if path.is_dir():
            shutil.rmtree(path)
        else:
            path.unlink()
        removed.append(str(path))
    return removed
