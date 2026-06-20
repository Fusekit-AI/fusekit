"""Public-text redaction helpers."""

from __future__ import annotations

import re
from pathlib import Path


def redact_public_text(value: object) -> str:
    """Redact token-like material while preserving useful text shape."""

    redacted = str(value or "")
    patterns = (
        r"\bsk-[A-Za-z0-9_-]{12,}",
        r"\bsk_(?:live|test|prod)_[A-Za-z0-9_-]{12,}",
        r"\bpk_(?:live|test|prod)_[A-Za-z0-9_-]{12,}",
        r"\bgh[pousr]_[A-Za-z0-9_]{12,}",
        r"\bgithub_pat_[A-Za-z0-9_]{12,}",
        r"\bwhsec_[A-Za-z0-9_]{12,}",
        r"\brk_[A-Za-z0-9_-]{12,}",
        r"\bre_[A-Za-z0-9_-]{12,}",
        r"\bplaid-[A-Za-z0-9_-]{12,}",
        r"\beyJ[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{8,}",
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


def contains_durable_secret_text(value: str) -> bool:
    """Return true when durable public proof still contains credential-looking text."""

    lowered = value.lower()
    token_patterns = (
        r"\bsk-[A-Za-z0-9_-]{12,}",
        r"\bsk_(?:live|test|prod)_[A-Za-z0-9_-]{12,}",
        r"\bpk_(?:live|test|prod)_[A-Za-z0-9_-]{12,}",
        r"\bgh[pousr]_[A-Za-z0-9_]{12,}",
        r"\bgithub_pat_[A-Za-z0-9_]{12,}",
        r"\bwhsec_[A-Za-z0-9_]{12,}",
        r"\brk_[A-Za-z0-9_-]{12,}",
        r"\bre_[A-Za-z0-9_-]{12,}",
        r"\bplaid-[A-Za-z0-9_-]{12,}",
        r"\beyJ[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{8,}",
    )
    if any(re.search(pattern, value, flags=re.IGNORECASE) for pattern in token_patterns):
        return True
    redacted_boundary = r"(?:$|[&#\s,;\.\"'\]\})])"
    if re.search(
        (
            r"([?&](?:access_token|auth_token|token|api_key|key|secret|code|password|"
            r"passphrase|signature)=)(?!\[redacted\](?:[&#]|"
            + redacted_boundary
            + r"))[^&#\s]+"
        ),
        value,
        flags=re.IGNORECASE,
    ):
        return True
    if re.search(r"\bbearer\s+(?!\[redacted\]" + redacted_boundary + r")[^\s,;]+", lowered):
        return True
    return bool(
        re.search(
            (
                r"\b(?:access[_-]?token|auth[_-]?token|api[_-]?key|token|secret|"
                r"password|private[-_ ]?key|passphrase|signature)\s*[:=]\s*"
                r"(?!\[redacted\]"
                + redacted_boundary
                + r"|redacted\b|none\b|null\b|false\b|true\b|$)"
                r"[^\s,;]+"
            ),
            lowered,
        )
    )
