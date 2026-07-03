"""Helpers for embedding public hosted JSON in browser pages."""

from __future__ import annotations

import json


def json_script_payload(payload: dict[str, object]) -> str:
    """Return JSON that remains parseable inside a raw-text script element."""

    return (
        json.dumps(payload, sort_keys=True)
        .replace("&", "\\u0026")
        .replace("<", "\\u003c")
        .replace(">", "\\u003e")
        .replace("\u2028", "\\u2028")
        .replace("\u2029", "\\u2029")
    )
