from __future__ import annotations

import json
import stat

import pytest

from fusekit.errors import VaultError
from fusekit.vault.bundle import Vault
from fusekit.vault.session import create_vault_session, open_vault_with_session


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


def test_short_lived_vault_session_token_unlocks_without_persisting_token(tmp_path) -> None:
    vault_path = tmp_path / "fusekit.vault.json"
    session_path = tmp_path / "vault.session.json"
    vault = Vault.empty()
    vault.put("provider.token", "provider_token", "test", "token", "session-secret-value")
    vault.save(vault_path, "passphrase")

    session = create_vault_session(
        vault_path=vault_path,
        passphrase="passphrase",
        session_path=session_path,
        ttl_seconds=60,
        now=1000,
    )
    token = str(session["session_token"])

    raw_session = session_path.read_text(encoding="utf-8")
    assert token not in raw_session
    assert "passphrase" not in raw_session
    assert "session-secret-value" not in raw_session
    assert stat.S_IMODE(session_path.stat().st_mode) == 0o600

    opened = open_vault_with_session(
        vault_path=vault_path,
        session_token=token,
        session_path=session_path,
        now=1010,
    )
    assert opened.require("provider.token").value == "session-secret-value"

    with pytest.raises(VaultError, match="expired"):
        open_vault_with_session(
            vault_path=vault_path,
            session_token=token,
            session_path=session_path,
            now=2000,
        )

    with pytest.raises(VaultError, match="invalid"):
        open_vault_with_session(
            vault_path=vault_path,
            session_token="wrong-token",
            session_path=session_path,
            now=1010,
        )
