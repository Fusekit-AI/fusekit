"""WSGI entrypoint for the hosted FuseKit launcher."""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent / "src"))

from fusekit.hosted.server import application as app  # noqa: E402,F401
