from __future__ import annotations

import pytest

from fusekit.capabilities.runtime import CapabilityBroker
from fusekit.errors import PolicyError
from fusekit.vault import Vault


def test_capability_broker_denies_raw_secret_export() -> None:
    vault = Vault.empty()
    vault.put("api.key", "api_key", "test", "API key", "secret-value")
    broker = CapabilityBroker(vault)

    with pytest.raises(PolicyError):
        broker.request("secret.raw")

    response = broker.request("vault.index")
    assert "secret-value" not in str(response)
    assert response["records"][0]["id"] == "api.key"
