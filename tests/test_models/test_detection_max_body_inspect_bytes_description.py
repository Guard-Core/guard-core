from guard_core.models import SecurityConfig


def _description() -> str:
    description = SecurityConfig.model_fields[
        "detection_max_body_inspect_bytes"
    ].description
    assert description is not None
    return " ".join(description.split())


def test_the_description_states_what_a_bounded_reader_does_past_the_cap() -> None:
    assert (
        "Past this cap an adapter with a bounded reader (read_body_prefix) has "
        "its first N bytes scanned" in _description()
    )


def test_the_description_states_what_no_bounded_reader_does_past_the_cap() -> None:
    assert (
        "An adapter without one gets the body-read failure outcome: the body "
        "is not read, the request is answered 400 when fail_secure is on, an "
        "event is sent and no strike is recorded" in _description()
    )
