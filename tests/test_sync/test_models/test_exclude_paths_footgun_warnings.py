import logging
import warnings

import pytest

from guard_core.models import SyncSecurityConfig

GLOBS = ["/static/*", "/static/**", "/h*", "/health?x=1", "/a#frag"]


@pytest.mark.parametrize("entry", GLOBS)
class TestGlobEntry:
    def test_unset_flag_refuses_an_entry_that_excludes_nothing(
        self, entry: str
    ) -> None:
        with pytest.raises(ValueError) as caught:
            SyncSecurityConfig(enable_redis=False, exclude_paths=[entry])

        message = str(caught.value)
        assert f"exclude_paths entry {entry!r}" in message
        assert "excludes nothing" in message
        assert "fail_on_misconfiguration=False" in message

    def test_true_raises(self, entry: str) -> None:
        with pytest.raises(ValueError, match="excludes nothing"):
            SyncSecurityConfig(
                enable_redis=False, exclude_paths=[entry], fail_on_misconfiguration=True
            )

    def test_false_logs_one_warning_and_starts(
        self, entry: str, caplog: pytest.LogCaptureFixture
    ) -> None:
        with caplog.at_level(logging.WARNING, logger="guard_core"):
            with warnings.catch_warnings():
                warnings.simplefilter("error")
                config = SyncSecurityConfig(
                    enable_redis=False,
                    exclude_paths=[entry],
                    fail_on_misconfiguration=False,
                )

        messages = [r.getMessage() for r in caplog.records if repr(entry) in r.message]
        assert len(messages) == 1
        assert "keeps starting" in messages[0]
        assert config.exclude_paths == [entry]


def test_each_glob_entry_is_reported_once(caplog: pytest.LogCaptureFixture) -> None:
    with caplog.at_level(logging.WARNING, logger="guard_core"):
        SyncSecurityConfig(
            enable_redis=False,
            fail_on_misconfiguration=False,
            exclude_paths=["/a/*", "/B", "/ok", "/c?"],
        )

    assert len([r for r in caplog.records if "is not a glob" in r.message]) == 2


def test_literal_entries_never_warn_even_with_upper_case() -> None:
    with warnings.catch_warnings():
        warnings.simplefilter("error")
        SyncSecurityConfig(
            enable_redis=False,
            fail_on_misconfiguration=True,
            exclude_paths=["/health", "/static", "/v1/status", "/Docs"],
        )
