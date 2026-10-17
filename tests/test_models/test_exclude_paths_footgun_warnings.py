import logging
import warnings

import pytest

from guard_core.models import SecurityConfig

GLOBS = ["/static/*", "/static/**", "/h*", "/health?x=1", "/a#frag"]


@pytest.mark.parametrize("entry", GLOBS)
class TestGlobEntry:
    def test_unset_flag_warns_that_the_entry_excludes_nothing(
        self, entry: str, caplog: pytest.LogCaptureFixture
    ) -> None:
        with caplog.at_level(logging.WARNING, logger="guard_core"):
            with pytest.warns(DeprecationWarning) as caught:
                config = SecurityConfig(enable_redis=False, exclude_paths=[entry])

        message = str(caught[0].message)
        assert f"exclude_paths entry {entry!r}" in message
        assert "excludes nothing" in message
        assert "fail_on_misconfiguration is not set" in message
        assert any(repr(entry) in r.getMessage() for r in caplog.records)
        assert config.exclude_paths == [entry]

    def test_true_raises(self, entry: str) -> None:
        with pytest.raises(ValueError, match="excludes nothing"):
            SecurityConfig(
                enable_redis=False, exclude_paths=[entry], fail_on_misconfiguration=True
            )

    def test_false_warns_without_the_not_set_part(self, entry: str) -> None:
        with pytest.warns(DeprecationWarning, match="keeps starting") as caught:
            SecurityConfig(
                enable_redis=False,
                exclude_paths=[entry],
                fail_on_misconfiguration=False,
            )
        assert "is not set" not in str(caught[0].message)


def test_each_glob_entry_is_reported_once() -> None:
    with pytest.warns(DeprecationWarning) as caught:
        SecurityConfig(enable_redis=False, exclude_paths=["/a/*", "/B", "/ok", "/c?"])

    assert len(caught) == 2


def test_literal_entries_never_warn_even_with_upper_case() -> None:
    with warnings.catch_warnings():
        warnings.simplefilter("error")
        SecurityConfig(
            enable_redis=False,
            fail_on_misconfiguration=True,
            exclude_paths=["/health", "/static", "/v1/status", "/Docs"],
        )
