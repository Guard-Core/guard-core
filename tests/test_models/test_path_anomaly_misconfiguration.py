import logging
import warnings
from typing import Any

import pytest

from guard_core.models import SecurityConfig

ANOMALOUS_PATHS = [
    "/a/../b",
    "/a//b",
    "/a%2fb",
    "/a%2Fb",
    "/a%5cb",
    "/a%5Cb",
    "/a%252fb",
    "/a\\b",
    "/a/./b",
    "/a/%2e%2e/b",
    "/a/..;x/b",
]


def _build(**settings: object) -> SecurityConfig:
    return SecurityConfig(enable_redis=False, **settings)


def _settings(field: str, path: str) -> dict[str, Any]:
    if field == "exclude_paths":
        return {"exclude_paths": [path]}
    return {"endpoint_rate_limits": {path: (5, 60)}}


@pytest.mark.parametrize("field", ["exclude_paths", "endpoint_rate_limits"])
@pytest.mark.parametrize("path", ANOMALOUS_PATHS)
class TestAnomalousPathSpelling:
    def test_unset_flag_refuses_naming_the_entry_and_the_old_value(
        self, field: str, path: str
    ) -> None:
        with pytest.raises(ValueError) as caught:
            _build(**_settings(field, path))

        message = str(caught.value)
        assert field in message
        assert repr(path) in message
        assert "fail_on_misconfiguration=False" in message

    def test_true_raises(self, field: str, path: str) -> None:
        with pytest.raises(ValueError, match=field):
            _build(fail_on_misconfiguration=True, **_settings(field, path))

    def test_false_logs_one_warning_and_starts(
        self, field: str, path: str, caplog: pytest.LogCaptureFixture
    ) -> None:
        with caplog.at_level(logging.WARNING, logger="guard_core"):
            with warnings.catch_warnings():
                warnings.simplefilter("error")
                _build(fail_on_misconfiguration=False, **_settings(field, path))

        messages = [r.getMessage() for r in caplog.records if repr(path) in r.message]
        assert len(messages) == 1
        assert "keeps starting" in messages[0]


@pytest.mark.parametrize("field", ["exclude_paths", "endpoint_rate_limits"])
@pytest.mark.parametrize(
    "path",
    [
        "/api/v1.2/users",
        "/files/a.b.c",
        "/a/b/",
        "/a%20b",
        "/health",
        "/downloads/file..txt",
        "/static",
        "/api/v1/",
    ],
)
def test_a_plain_path_never_warns(field: str, path: str) -> None:
    with warnings.catch_warnings():
        warnings.simplefilter("error")
        _build(fail_on_misconfiguration=True, **_settings(field, path))


def test_the_default_exclude_paths_never_warn() -> None:
    with warnings.catch_warnings():
        warnings.simplefilter("error")
        _build(fail_on_misconfiguration=True)


def test_a_dot_dot_entry_still_normalizes_and_matches_as_before() -> None:
    config = _build(fail_on_misconfiguration=False, exclude_paths=["/a/../b"])
    assert config.exclude_paths == ["/a/../b"]
