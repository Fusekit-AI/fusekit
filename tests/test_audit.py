from __future__ import annotations

import json

from fusekit.audit import AuditLog, Receipt


def test_audit_and_receipt_redact_secret_fields(tmp_path) -> None:
    secret = "super-secret-token"
    audit_path = tmp_path / "audit.jsonl"
    receipt_path = tmp_path / "receipt.json"

    audit = AuditLog(audit_path)
    audit.record("provider.token", {"provider": "github", "token": secret})

    receipt = Receipt(app_name="app", vault_path="vault.json")
    receipt.add_action("github.secret", "ok", {"secret": secret, "name": "API_KEY"})
    receipt.write_json(receipt_path)

    audit_text = audit_path.read_text(encoding="utf-8")
    receipt_text = receipt_path.read_text(encoding="utf-8")

    assert secret not in audit_text
    assert secret not in receipt_text
    assert "[REDACTED" in audit_text
    assert json.loads(receipt_text)["raw_secrets_exposed"] == 0
