import pytest

from guard_core.sync.handlers.redis_handler import _redact_redis_url


@pytest.mark.parametrize(
    ("url", "expected"),
    [
        ("redis://cache:6379/0?password=hunter2", "redis://cache:6379/0"),
        (
            "redis://cache:6379/0?password=hunter2&socket_timeout=5",
            "redis://cache:6379/0?socket_timeout=5",
        ),
        (
            "rediss://cache:6380?username=svc&password=hunter2",
            "rediss://cache:6380",
        ),
        (
            "redis://cache:6379?Password=hunter2&db=1&USERNAME=svc",
            "redis://cache:6379?db=1",
        ),
        ("redis://u:p@cache:6379/0?db=1", "redis://cache:6379/0?db=1"),
        ("redis://cache:6379/0?passwords=kept", "redis://cache:6379/0?passwords=kept"),
    ],
)
def test_query_credentials_are_dropped_and_other_parameters_kept(
    url: str, expected: str
) -> None:
    assert _redact_redis_url(url) == expected
