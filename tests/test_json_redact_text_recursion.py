import json

import pytest

from guard_core._utils.request_logging import _json_redact_text


def test_a_json_text_the_parser_overruns_is_redacted_whole(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def overrun(text: str, **kwargs: object) -> object:
        raise RecursionError

    monkeypatch.setattr(json, "loads", overrun)
    assert _json_redact_text('{"a": 1}', frozenset(), frozenset(), 32) == "[REDACTED]"
