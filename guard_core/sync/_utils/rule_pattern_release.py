def _patterns_the_survivors_rules_hold(survivors: list[object]) -> set[str]:
    from guard_core.sync._utils.rule_attribution_shared import _APP_RULE_MANAGERS

    held: set[str] = set()
    for other in survivors:
        rules = getattr(_APP_RULE_MANAGERS.resolve(other), "current_rules", None)
        held.update(getattr(rules, "suspicious_patterns", ()))
    return held


def withdraw_rule_patterns(config: object) -> None:
    """Remove the patterns the rules of the released app created from a pattern
    default another app still shares, unless that app's current rule set holds the
    same pattern. It is the same list work as ``remove_default_pattern_rows``, with
    no await. No cache needs clearing: the compiler keeps compiled regexes by
    pattern text and compiled sets by the blocked user-agent list, the monitor keeps
    timing stats, and the per-request detection result lives on the request state,
    so none carries a verdict made past the release. A default no other app shares
    is handed back whole by ``release_app`` and needs nothing here."""
    from guard_core.sync._utils.rule_attribution_shared import _APP_RULE_MANAGERS
    from guard_core.sync.handlers._suspatterns_registry import (
        remove_default_pattern_rows,
    )
    from guard_core.sync.handlers.suspatterns_handler import _APP_PATTERN_MANAGERS

    survivors: list[object] = list(
        _APP_PATTERN_MANAGERS.other_apps_on_the_default(config)
    )
    owner = _APP_RULE_MANAGERS.resolve(config)
    patterns = _APP_PATTERN_MANAGERS.served_default()
    if not survivors or owner is None or patterns is None:
        return
    kept = _patterns_the_survivors_rules_hold(survivors)
    for pattern in [p for p in owner._owned_patterns if p not in kept]:
        remove_default_pattern_rows(patterns, pattern)


def stop_the_applies_of_the_released_app(config: object) -> None:
    """First step of a release: the rule manager the app held ends every apply,
    expiry and revoke that started before it, unless another app still shares it."""
    from guard_core.sync._utils.rule_attribution_shared import _APP_RULE_MANAGERS

    owner = _APP_RULE_MANAGERS.resolve(config)
    if owner is not None and not _APP_RULE_MANAGERS.other_apps_on_the_default(config):
        owner.mark_released()
