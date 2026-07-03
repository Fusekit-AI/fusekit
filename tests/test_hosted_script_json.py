from __future__ import annotations

import json

from fusekit.hosted.script_json import json_script_payload


def test_json_script_payload_is_parseable_and_script_safe() -> None:
    payload = {
        "schema_version": "fusekit.test.v1",
        "label": "</script><script>alert(1)</script>",
        "ampersand": "a&b",
    }

    rendered = json_script_payload(payload)

    assert "&quot;" not in rendered
    assert "</script" not in rendered.lower()
    assert "<script" not in rendered.lower()
    assert json.loads(rendered) == payload
