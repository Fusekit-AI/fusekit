from __future__ import annotations

import json
import stat

import pytest

from fusekit.errors import VaultError
from fusekit.vault.bundle import Vault


def test_vault_encrypts_and_rejects_wrong_passphrase(tmp_path) -> None:
    vault_path = tmp_path / "fusekit.vault.json"
    secret = "test-stripe-secret-value"
    vault = Vault.empty()
    vault.put("stripe.token", "api_key", "stripe", "Stripe API key", secret)

    vault.save(vault_path, "correct horse battery staple")

    raw = vault_path.read_text(encoding="utf-8")
    assert secret not in raw
    assert "Stripe API key" not in raw
    parsed = json.loads(raw)
    assert parsed["cipher"] == "AES-256-GCM"

    opened = Vault.open(vault_path, "correct horse battery staple")
    assert opened.require("stripe.token").value == secret

    with pytest.raises(VaultError):
        Vault.open(vault_path, "wrong passphrase")


def test_vault_writes_owner_only_permissions(tmp_path) -> None:
    vault_path = tmp_path / "fusekit.vault.json"
    vault = Vault.empty()
    vault.put("provider.token", "provider_token", "test", "token", "secret-value")

    vault.save(vault_path, "passphrase")

    mode = stat.S_IMODE(vault_path.stat().st_mode)
    assert mode == 0o600


def test_public_index_contains_no_values(tmp_path) -> None:
    vault_path = tmp_path / "fusekit.vault.json"
    vault = Vault.empty()
    vault.put(
        "webhook.secret",
        "webhook_secret",
        "fusekit",
        "Webhook secret",
        "test-webhook-secret",
    )
    vault.save(vault_path, "passphrase")

    opened = Vault.open(vault_path, "passphrase")
    public_index = opened.public_index()

    assert public_index[0]["id"] == "webhook.secret"
    assert "value" not in public_index[0]
    assert "test-webhook-secret" not in json.dumps(public_index)
