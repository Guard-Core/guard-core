import json
from typing import Any

import pytest

from guard_core.sync._utils.logging_utils import _try_redact_nested_json_leaf
from guard_core.sync._utils.pair_value_scan import _redact_embedded_json_value
from guard_core.sync._utils.request_logging import redact_url_for_display

PAST_EVERY_PARSER_LIMIT = "[" * 100_000 + "]" * 100_000


def test_an_embedded_value_past_the_parser_limit_is_redacted_whole() -> None:
    result = _redact_embedded_json_value(
        PAST_EVERY_PARSER_LIMIT, frozenset({"password"}), frozenset(), 32
    )
    assert result == "%5BREDACTED%5D"


def test_a_nested_leaf_past_the_parser_limit_is_redacted_whole() -> None:
    result = _try_redact_nested_json_leaf(
        PAST_EVERY_PARSER_LIMIT, frozenset({"password"}), frozenset(), 32
    )
    assert result == "[REDACTED]"


def test_a_url_whose_value_overruns_the_parser_is_displayed_redacted(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    real_loads = json.loads

    def overrun(text: str, **kwargs: Any) -> Any:
        if text.startswith("["):
            raise RecursionError
        return real_loads(text, **kwargs)

    monkeypatch.setattr(json, "loads", overrun)
    deep = "%5B" * 1000 + "1" + "%5D" * 1000
    shown = redact_url_for_display(f"/api?data={deep}", frozenset())
    assert deep not in shown
    assert "REDACTED" in shown
