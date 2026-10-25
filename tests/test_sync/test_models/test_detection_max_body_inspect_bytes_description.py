from guard_core.models import SecurityConfig


def _description() -> str:
    description = SecurityConfig.model_fields[
        "detection_max_body_inspect_bytes"
    ].description
    assert description is not None
    return " ".join(description.split())


def test_the_description_states_what_a_bounded_reader_does_past_the_cap() -> None:
    assert (
        "A body past it is never passed unscanned: an adapter with a bounded "
        "reader (read_body_prefix) has its first N bytes scanned and, when "
        "they are clean, the request gets the body-read failure outcome"
        in _description()
    )


def test_the_description_states_what_no_bounded_reader_does_past_the_cap() -> None:
    assert (
        "an adapter without one has the body left unread and gets the same "
        "outcome. That outcome is a 400 when fail_secure is on, an event and "
        "no strike" in _description()
    )
