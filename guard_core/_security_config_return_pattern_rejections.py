from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from guard_core._security_config_fields import RequestT
    from guard_core._utils.pattern_source_redaction import _ConfigSensitiveNames
    from guard_core.models import SecurityConfig


def _reject_non_numeric_status_pattern(
    pattern: str, names: "_ConfigSensitiveNames | None"
) -> None:
    from guard_core._utils.detection_scan import _redact_pattern_source

    try:
        int(pattern.partition(":")[2])
    except ValueError:
        shown = _redact_pattern_source(pattern, names)
        raise ValueError(
            f"return_pattern rule with pattern {shown!r}"
            " has no status code after 'status:'. This rule would never match: "
            "use 'status:' followed by an integer such as 'status:404'."
        ) from None


def _reject_unsafe_return_pattern_regex(
    pattern: str,
    config: "SecurityConfig[RequestT] | None",
    names: "_ConfigSensitiveNames | None",
) -> None:
    import re

    from guard_core._utils.detection_scan import _redact_pattern_source
    from guard_core.detection_engine.compiler import PatternCompiler

    cap = (
        config.behavior_max_response_body_inspect_bytes
        if config is not None
        else 262144
    )
    is_safe, reason = PatternCompiler(redaction_names=names).validate_pattern_safety(
        pattern.partition(":")[2], max_content_length=cap, flags=re.IGNORECASE
    )
    if not is_safe:
        raise ValueError(
            "return_pattern regex rejected by ReDoS validator or does not compile: "
            f"{_redact_pattern_source(pattern, names)!r} ({reason}). The pattern "
            "runs on the event loop over the response body."
        )
