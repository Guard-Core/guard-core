from pydantic import ValidationError

from guard_core._config_field_revalidators import _validate_str_list_field_value
from guard_core._utils.pattern_source_redaction import _SensitiveNameSets


def _validate_blocked_user_agents_structure(v: object) -> list[str]:
    return _validate_str_list_field_value(v, field_name="blocked_user_agents")


def _reject_redos_unsafe_blocked_user_agents(
    patterns: list[str], redaction_names: _SensitiveNameSets | None = None
) -> None:
    from guard_core._utils.detection_scan import _redact_pattern_source
    from guard_core.detection_engine.compiler import PatternCompiler
    from guard_core.utils import _MAX_USER_AGENT_MATCH_LENGTH

    compiler = PatternCompiler(redaction_names=redaction_names)
    for pattern in patterns:
        is_safe, reason = compiler.validate_pattern_safety(
            pattern, max_content_length=_MAX_USER_AGENT_MATCH_LENGTH
        )
        if not is_safe:
            raise ValueError(
                f"blocked_user_agents pattern rejected by ReDoS validator: "
                f"{_redact_pattern_source(pattern, redaction_names)!r} ({reason})"
            )


def _reject_redos_unsafe_blocked_user_agents_at_field(
    title: str, patterns: list[str], redaction_names: _SensitiveNameSets | None
) -> None:
    from guard_core._utils.detection_scan import _redact_pattern_source

    try:
        _reject_redos_unsafe_blocked_user_agents(patterns, redaction_names)
    except ValueError as error:
        redacted = [_redact_pattern_source(p, redaction_names) for p in patterns]
        raise ValidationError.from_exception_data(
            title,
            [
                {
                    "type": "value_error",
                    "loc": ("blocked_user_agents",),
                    "input": redacted,
                    "ctx": {"error": error},
                }
            ],
            hide_input=True,
        ) from None


def _validate_blocked_user_agents_value(
    v: object, redaction_names: _SensitiveNameSets | None = None
) -> list[str]:
    patterns = _validate_blocked_user_agents_structure(v)
    _reject_redos_unsafe_blocked_user_agents(patterns, redaction_names)
    return patterns
