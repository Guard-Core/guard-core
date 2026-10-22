from guard_core.sync._utils.request_logging import (
    _DEFAULT_SENSITIVE_LOG_FIELDS,
    _merge_sensitive_names,
)


def test_the_same_extra_names_are_merged_once_and_lowercased() -> None:
    _merge_sensitive_names.cache_clear()
    extra = frozenset({"X-Internal-Token", "Session_Id"})

    merged = [
        _merge_sensitive_names(_DEFAULT_SENSITIVE_LOG_FIELDS, extra) for _ in range(3)
    ]

    assert merged[0] == _DEFAULT_SENSITIVE_LOG_FIELDS | {
        "x-internal-token",
        "session_id",
    }
    assert merged[0] is merged[1] is merged[2]
    info = _merge_sensitive_names.cache_info()
    assert (info.misses, info.hits) == (1, 2)


def test_no_extra_names_returns_the_defaults_themselves() -> None:
    assert (
        _merge_sensitive_names(_DEFAULT_SENSITIVE_LOG_FIELDS, None)
        is _DEFAULT_SENSITIVE_LOG_FIELDS
    )
