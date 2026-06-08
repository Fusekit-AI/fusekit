"""Public-text redaction helpers."""

from __future__ import annotations

import re
from pathlib import Path


def redact_public_text(value: object) -> str:
    """Redact token-like material while preserving useful text shape."""

    redacted = str(value or "")
    patterns = (
        r"sk-[A-Za-z0-9_-]{12,}",
        r"sk_(?:live|test|prod)_[A-Za-z0-9_-]{12,}",
        r"pk_(?:live|test|prod)_[A-Za-z0-9_-]{12,}",
        r"gh[pousr]_[A-Za-z0-9_]{12,}",
        r"github_pat_[A-Za-z0-9_]{12,}",
        r"whsec_[A-Za-z0-9_]{12,}",
        r"rk_[A-Za-z0-9_-]{12,}",
        r"re_[A-Za-z0-9_-]{12,}",
        r"plaid-[A-Za-z0-9_-]{12,}",
        r"eyJ[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{8,}",
        r"\b[A-Za-z0-9_-]{36,}\b",
        (
            r"([?&](?:access_token|auth_token|token|api_key|key|secret|code|password|"
            r"passphrase|signature)=)[^&#\s]+"
        ),
    )
    for pattern in patterns:
        replacement = r"\1[redacted]" if pattern.startswith("([?&]") else "[redacted]"
        redacted = re.sub(pattern, replacement, redacted, flags=re.IGNORECASE)
    return redacted


def redact_public_path(value: object) -> str:
    """Return a stable public path without local home/tmp prefixes."""

    raw = str(value or "")
    if not raw:
        return ""
    if not Path(raw).is_absolute():
        return raw
    path = Path(raw)
    parts = path.parts
    if ".fusekit" in parts:
        index = parts.index(".fusekit")
        return str(Path(*parts[index:]))
    return path.name
