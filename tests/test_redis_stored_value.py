from guard_core.handlers._redis_handler_support import as_stored_value


def test_as_stored_value_returns_the_reply_unchanged() -> None:
    assert as_stored_value("text") == "text"
    assert as_stored_value(None) is None
