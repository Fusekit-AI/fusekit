from __future__ import annotations

from fusekit.providers.resend import _record_from_resend


def test_resend_dns_record_accepts_auto_ttl() -> None:
    record = _record_from_resend(
        {
            "name": "send",
            "type": "MX",
            "value": "feedback-smtp.us-east-1.amazonses.com",
            "ttl": "Auto",
            "priority": 10,
        },
        "moonlite.rsvp",
    )

    assert record.name == "send.moonlite.rsvp"
    assert record.type == "MX"
    assert record.value == "feedback-smtp.us-east-1.amazonses.com"
    assert record.ttl == 300
    assert record.priority == 10
