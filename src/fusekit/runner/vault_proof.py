"""Shared public vault metadata proof shape for launch gates."""

from __future__ import annotations

VAULT_SECRET_FIELD_NAMES = frozenset(
    {
        "value",
        "raw_value",
        "secret_value",
        "token_value",
        "password",
        "passphrase",
        "private_key",
    }
)
VAULT_KEYS = frozenset(
    {
        "record_count",
        "records",
    }
)
VAULT_RECORD_FIELDS = (
    "id",
    "kind",
    "provider",
    "label",
)
VAULT_RECORD_KEYS = frozenset(VAULT_RECORD_FIELDS)
