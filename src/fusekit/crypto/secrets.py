"""Secret generation helpers."""

from __future__ import annotations

import secrets
import string


def token_urlsafe(length: int = 48) -> str:
    """Generate a high-entropy URL-safe secret."""

    return secrets.token_urlsafe(length)


def password(length: int = 32) -> str:
    """Generate a service password."""

    alphabet = string.ascii_letters + string.digits + "-_+=.@%"
    return "".join(secrets.choice(alphabet) for _ in range(length))
