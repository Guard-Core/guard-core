from guard_core.handlers.behavior_handler import BehaviorRule

_ESCAPE_PRONE = BehaviorRule(
    "return_pattern", threshold=3, window=60, pattern="body:<ü/ñ>&", action="throttle"
)


def test_rule_id_is_compact_json_with_raw_utf8_and_unescaped_slash_and_markup() -> None:
    assert _ESCAPE_PRONE.discriminator().encode("utf-8") == (
        b'["return_pattern","body:<\xc3\xbc/\xc3\xb1>&",60,3,"throttle"]'
    )


def test_rule_id_of_a_usage_rule_has_a_null_pattern() -> None:
    rule = BehaviorRule("usage", threshold=5, window=3600)
    assert rule.discriminator() == '["usage",null,3600,5,"log"]'


def test_matched_rule_id_is_uuid5_of_the_rule_id_in_the_url_namespace() -> None:
    assert _ESCAPE_PRONE.matched_rule_id() == "424a3b2a-0758-5512-821f-c3f78eb8ea6a"
    usage = BehaviorRule("usage", threshold=5, window=3600)
    assert usage.matched_rule_id() == "151310c6-8783-51f6-ad36-6ac3790c5cfe"
