import importlib
import re

import pytest
from pydantic import ValidationError

from guard_core import _lazy_patterns
from guard_core.models import SecurityConfig
from guard_core.protocols.request_protocol import GuardRequest

# Every name a star import of these modules exported at landing-6e-stack10 and
# lost in the merge with the lazy-pattern work (LEDGER 6.533).
_LOST_STAR_NAMES = [
    ("guard_core._security_config_fields", "DEFAULT_MAX_LOCAL_BANS"),
    ("guard_core._security_config_fields", "ThreatBanConfig"),
    ("guard_core._security_headers_defaults", "copy"),
    ("guard_core._security_headers_override", "re"),
    ("guard_core._staged_defaults", "redis_is_configured"),
    ("guard_core._utils.logging_utils", "re"),
    ("guard_core._utils.pair_value_scan", "re"),
    ("guard_core._utils.source_path_shapes", "re"),
    ("guard_core._utils.rule_attribution", "DynamicRuleManager"),
    ("guard_core._utils.rule_attribution", "RuleAttribution"),
    ("guard_core.detection_engine.base64_decode", "NON_DATA_RE"),
    ("guard_core.detection_engine.base64_decode", "NON_RUN_CHAR_RE"),
    ("guard_core.detection_engine.base64_decode", "WHITESPACE_RE"),
    ("guard_core.detection_engine.compiler", "BodyReadFailedError"),
    ("guard_core.detection_engine.compiler", "TransientReason"),
    (
        "guard_core.detection_engine.encoding_decoders",
        "HTML_HEX_ENTITY_WITHOUT_SEMICOLON_RE",
    ),
    ("guard_core.detection_engine.encoding_decoders", "OCTAL_ESCAPE_RE"),
    ("guard_core.detection_engine.encoding_decoders", "PERCENT_BYTE_RUN_RE"),
    ("guard_core.handlers._suspatterns_candidate_gates", "NAMED_FLOOR_TOKEN_PATTERNS"),
    ("guard_core.handlers._suspatterns_named_floor", "CMS_TOKEN_PATTERN"),
    ("guard_core.handlers._suspatterns_pattern_table", "CMS_TOKEN_PATTERN"),
    ("guard_core.handlers._suspatterns_pattern_table", "NAMED_FLOOR_TOKEN_PATTERNS"),
    ("guard_core.handlers._suspatterns_pattern_table", "re"),
    ("guard_core.handlers._suspatterns_whole_value_rows", "re"),
    ("guard_core.handlers.dynamic_rule_handler", "AppManagers"),
]


@pytest.mark.parametrize(("module", "name"), _LOST_STAR_NAMES)
def test_a_star_import_still_exports_the_name_it_exported_at_stack10(
    module: str, name: str
) -> None:
    namespace: dict[str, object] = {}
    exec(f"from {module} import *", namespace)

    assert name in namespace
    assert namespace[name] is getattr(importlib.import_module(module), name)


def test_the_percent_byte_run_pattern_keeps_its_stack10_source_and_flags() -> None:
    from guard_core.detection_engine import encoding_decoders

    assert encoding_decoders.PERCENT_BYTE_RUN_RE.pattern == "(?:%[0-9a-fA-F]{2})+"
    assert encoding_decoders.PERCENT_BYTE_RUN_RE.flags == re.compile("").flags
    assert encoding_decoders.PERCENT_BYTE_RUN_RE.sub("", "a%41%42b") == "ab"


def test_a_reexport_lookup_reads_the_owner_and_refuses_an_unknown_name() -> None:
    lookup = _lazy_patterns.module_reexport_lookup({"sqrt": "math"})

    assert lookup("sqrt") is importlib.import_module("math").sqrt
    with pytest.raises(AttributeError):
        lookup("cbrt")


class _Construct:
    def __call__(
        self, input_value: object, /, *_: object
    ) -> SecurityConfig[GuardRequest]:
        return SecurityConfig[GuardRequest].model_validate(input_value)


def test_the_stack10_wrap_validator_is_callable_by_name_and_signature() -> None:
    config = SecurityConfig[GuardRequest].reject_redos_unsafe_blocked_user_agents(
        {"blocked_user_agents": ["curl"], "fail_on_misconfiguration": False},
        _Construct(),
    )

    assert config.blocked_user_agents == ["curl"]
    with pytest.raises(ValidationError, match="rejected by ReDoS validator"):
        SecurityConfig[GuardRequest].reject_redos_unsafe_blocked_user_agents(
            {"blocked_user_agents": ["(a+)+$"], "fail_on_misconfiguration": False},
            _Construct(),
        )
    with pytest.raises(ValidationError, match="rejected by ReDoS validator"):
        SecurityConfig(blocked_user_agents=["(a+)+$"], fail_on_misconfiguration=False)
