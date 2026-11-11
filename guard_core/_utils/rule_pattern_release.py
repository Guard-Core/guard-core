def withdraw_rule_patterns(config: object) -> None:
    """Remove the patterns the rules of the released app created from a pattern
    default another app still shares, unless that app's current rule set holds the
    same pattern. It is the same list work as ``remove_default_pattern_rows``, with
    no await. No cache needs clearing: the compiler keeps compiled regexes by
    pattern text and compiled sets by the blocked user-agent list, the monitor keeps
    timing stats, and the per-request detection result lives on the request state,
    so none carries a verdict made past the release. A default no other app shares
    is handed back whole by ``release_app`` and needs nothing here."""
    from guard_core._utils.rule_attribution_shared import _APP_RULE_MANAGERS
    from guard_core.handlers._suspatterns_registry import remove_default_pattern_rows
    from guard_core.handlers.suspatterns_handler import _APP_PATTERN_MANAGERS

    survivors = _APP_PATTERN_MANAGERS.other_apps_on_the_default(config)
    owner = _APP_RULE_MANAGERS.resolve(config)
    patterns = _APP_PATTERN_MANAGERS.served_default()
    if not survivors or owner is None or patterns is None:
        return
    held_by_survivors: set[str] = set()
    for other in survivors:
        rules = getattr(_APP_RULE_MANAGERS.resolve(other), "current_rules", None)
        if rules is not None:
            held_by_survivors.update(rules.suspicious_patterns)
    for pattern in list(owner._owned_patterns):
        if pattern not in held_by_survivors:
            remove_default_pattern_rows(patterns, pattern)
