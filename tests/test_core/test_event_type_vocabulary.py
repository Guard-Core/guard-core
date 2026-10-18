from __future__ import annotations

import ast
from pathlib import Path

import pytest

import guard_core
from guard_core.core.events import event_types
from guard_core.core.events.enricher import _THREAT_SCORE_MAP
from guard_core.core.events.event_types import EVENT_TYPE_VALUES

_SINK_CALL_NAMES = frozenset(
    {
        "SecurityEvent",
        "send_middleware_event",
        "send_agent_event",
        "_send_pattern_event",
    }
)

_SINK_POSITIONAL_EVENT_TYPE_INDEX: dict[str, int] = {
    "send_agent_event": 1,
}


def _call_name(node: ast.Call) -> str | None:
    func = node.func
    if isinstance(func, ast.Name):
        return func.id
    if isinstance(func, ast.Attribute):
        return func.attr
    return None


def _call_event_type_expr(node: ast.Call, name: str) -> ast.expr | None:
    for keyword in node.keywords:
        if keyword.arg != "event_type":
            continue
        return keyword.value
    index = _SINK_POSITIONAL_EVENT_TYPE_INDEX.get(name)
    if index is not None and len(node.args) > index:
        return node.args[index]
    return None


def _dict_event_type_expr(node: ast.Dict) -> ast.expr | None:
    for key, value in zip(node.keys, node.values, strict=True):
        if isinstance(key, ast.Constant) and key.value == "event_type":
            return value
    return None


def _is_literal_event_type(value: ast.expr) -> bool:
    return not isinstance(value, ast.Name)


def _violations_in_source(source: str, label: str) -> list[str]:
    violations = []
    tree = ast.parse(source, filename=label)
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            name = _call_name(node)
            if name not in _SINK_CALL_NAMES:
                continue
            value = _call_event_type_expr(node, name)
            sink_label = name
        elif isinstance(node, ast.Dict):
            value = _dict_event_type_expr(node)
            sink_label = "<dict>"
        else:
            continue
        if value is not None and _is_literal_event_type(value):
            violations.append(
                f"{label}:{node.lineno} {sink_label}(event_type={ast.unparse(value)})"
            )
    return violations


def _guard_core_root() -> Path:
    return Path(guard_core.__file__).resolve().parent


def _async_source_files() -> list[Path]:
    root = _guard_core_root()
    return [
        path for path in root.rglob("*.py") if path.relative_to(root).parts[0] != "sync"
    ]


def _event_type_constant_names() -> set[str]:
    return {
        name
        for name in dir(event_types)
        if name.startswith("EVENT_") and name != "EVENT_TYPE_VALUES"
    }


_NON_EMITTER_FILE_NAMES = frozenset({"event_types.py", "enricher.py"})


def _referenced_event_constant_names(constant_names: set[str]) -> set[str]:
    referenced: set[str] = set()
    for path in _async_source_files():
        if path.name in _NON_EMITTER_FILE_NAMES:
            continue
        tree = ast.parse(path.read_text(), filename=str(path))
        for node in ast.walk(tree):
            if isinstance(node, ast.Name) and node.id in constant_names:
                referenced.add(node.id)
    return referenced


def test_call_name_resolves_plain_and_attribute_calls_only() -> None:
    tree = ast.parse("send_agent_event(x)\nself.send_middleware_event(x)\n(a + b)(x)\n")
    calls = [node for node in ast.walk(tree) if isinstance(node, ast.Call)]
    assert _call_name(calls[0]) == "send_agent_event"
    assert _call_name(calls[1]) == "send_middleware_event"
    assert _call_name(calls[2]) is None


def test_call_event_type_expr_prefers_keyword_over_positional() -> None:
    tree = ast.parse(
        "send_agent_event(h, event_type='by_kw', ip='x')\n"
        "send_agent_event(h, 'by_pos', ip='x')\n"
        "send_agent_event(h)\n"
        "send_middleware_event(x)\n"
    )
    calls = [node for node in ast.walk(tree) if isinstance(node, ast.Call)]
    by_kw = _call_event_type_expr(calls[0], "send_agent_event")
    assert isinstance(by_kw, ast.Constant)
    assert by_kw.value == "by_kw"
    by_pos = _call_event_type_expr(calls[1], "send_agent_event")
    assert isinstance(by_pos, ast.Constant)
    assert by_pos.value == "by_pos"
    assert _call_event_type_expr(calls[2], "send_agent_event") is None
    assert _call_event_type_expr(calls[3], "send_middleware_event") is None


def test_dict_event_type_expr_finds_string_key_only() -> None:
    tree = ast.parse("{'event_type': 'oops', 'ip': 'x'}\n{'ip': 'x'}\n{**other}\n{}\n")
    dicts = [node for node in ast.walk(tree) if isinstance(node, ast.Dict)]
    match = _dict_event_type_expr(dicts[0])
    assert isinstance(match, ast.Constant)
    assert match.value == "oops"
    assert _dict_event_type_expr(dicts[1]) is None
    assert _dict_event_type_expr(dicts[2]) is None
    assert _dict_event_type_expr(dicts[3]) is None


def test_is_literal_event_type_flags_everything_except_name() -> None:
    name_node = ast.parse("EVENT_X", mode="eval").body
    literal_node = ast.parse("'literal'", mode="eval").body
    assert _is_literal_event_type(name_node) is False
    assert _is_literal_event_type(literal_node) is True


def test_violations_in_source_flags_calls_and_dicts_but_not_names() -> None:
    source = (
        "SecurityEvent(event_type='oops')\n"
        "SecurityEvent(event_type=EVENT_OK)\n"
        "some_other_call(event_type='fine')\n"
        "send_agent_event(h, 'by_pos')\n"
        "{'event_type': f'dyn_{x}'}\n"
        "{'event_type': EVENT_OK}\n"
        "x = 1\n"
    )
    violations = _violations_in_source(source, "<memory>")
    assert violations == [
        "<memory>:1 SecurityEvent(event_type='oops')",
        "<memory>:4 send_agent_event(event_type='by_pos')",
        "<memory>:5 <dict>(event_type=f'dyn_{x}')",
    ]


def test_no_literal_event_type_at_known_sinks_in_guard_core() -> None:
    violations = []
    for path in _async_source_files():
        violations.extend(_violations_in_source(path.read_text(), str(path)))
    assert violations == []


def test_every_event_type_constant_is_referenced_by_an_emitter() -> None:
    constant_names = _event_type_constant_names()
    referenced = _referenced_event_constant_names(constant_names)
    dead = sorted(constant_names - referenced)
    assert dead == []


def test_enricher_threat_score_map_covers_every_event_type() -> None:
    assert set(_THREAT_SCORE_MAP.keys()) == EVENT_TYPE_VALUES


# The first guard-agent release after 3.2.4 knows ip_ban_refused (guard-agent 9c2722c).
_GUARD_AGENT_ALIGNED_KNOWN_EVENT_TYPES_VERSION = (3, 2, 5)


def _guard_agent_version_tuple(raw: str) -> tuple[int, int, int]:
    parts = raw.split(".")[:3]
    numbers: list[int] = []
    for part in parts:
        digits = ""
        for char in part:
            if not char.isdigit():
                break
            digits += char
        numbers.append(int(digits) if digits else 0)
    while len(numbers) < 3:
        numbers.append(0)
    return (numbers[0], numbers[1], numbers[2])


def test_guard_agent_version_tuple_parses_and_pads_and_defaults_to_zero() -> None:
    assert _guard_agent_version_tuple("2.9.1") == (2, 9, 1)
    assert _guard_agent_version_tuple("2.10") == (2, 10, 0)
    assert _guard_agent_version_tuple("2.10.1rc1") == (2, 10, 1)
    assert _guard_agent_version_tuple("dev.1.2") == (0, 1, 2)


def test_guard_agent_known_event_types_are_all_in_guard_core_vocabulary() -> None:
    guard_agent = pytest.importorskip("guard_agent")
    from guard_agent import models as guard_agent_models

    guard_agent_types = set(guard_agent_models.KNOWN_EVENT_TYPES)
    guard_core_types = set(EVENT_TYPE_VALUES)
    missing_in_guard_core = sorted(guard_agent_types - guard_core_types)

    assert missing_in_guard_core == [], (
        f"guard_agent=={getattr(guard_agent, '__version__', 'unknown')} "
        "KNOWN_EVENT_TYPES names that guard-core does not emit: "
        f"{missing_in_guard_core}"
    )


def test_guard_core_event_types_are_all_known_to_guard_agent() -> None:
    guard_agent = pytest.importorskip("guard_agent")
    installed_version_raw = getattr(guard_agent, "__version__", "0.0.0")
    installed_version = _guard_agent_version_tuple(installed_version_raw)
    if installed_version < _GUARD_AGENT_ALIGNED_KNOWN_EVENT_TYPES_VERSION:
        aligned = ".".join(
            str(n) for n in _GUARD_AGENT_ALIGNED_KNOWN_EVENT_TYPES_VERSION
        )
        pytest.skip(
            f"guard_agent=={installed_version_raw} predates {aligned}; its "
            "KNOWN_EVENT_TYPES has not yet picked up guard-core's newest event types"
        )
    from guard_agent import models as guard_agent_models

    guard_agent_types = set(guard_agent_models.KNOWN_EVENT_TYPES)
    guard_core_types = set(EVENT_TYPE_VALUES)
    missing_in_guard_agent = sorted(guard_core_types - guard_agent_types)

    assert missing_in_guard_agent == [], (
        f"guard_agent=={installed_version_raw} KNOWN_EVENT_TYPES is missing "
        f"guard-core event types: {missing_in_guard_agent}"
    )
