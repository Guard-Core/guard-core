import logging
from collections.abc import Generator

import pytest

from guard_core.sync.handlers import _suspatterns_shell_validators as validators
from guard_core.sync.handlers import suspatterns_handler
from guard_core.sync.handlers.ipban_handler import IPBanManager, _ObservableTTLCache

# The two glued-keyword regexes as v4.4.0 wrote them (66f3072e,
# guard_core/handlers/_suspatterns_shell_sources.py:110-117); the linear
# validators of 796d5af0 read their own window variants (LEDGER 6.545).
_V440_GLUED_PREFIX = (
    r"(?i)\b(?:SELECT|FROM|WHERE|INSERT|UPDATE|DELETE|JOIN|VALUES|ORDER\s+BY|"
    r"GROUP\s+BY)\Z"
)
_V440_GLUED_SUFFIX = (
    r"(?i)\A(?:SELECT|FROM|WHERE|INSERT|UPDATE|DELETE|JOIN|VALUES|ORDER\s+BY|"
    r"GROUP\s+BY)\b"
)

_V440_OVERFLOW_WARNING = "IP ban cache full; %d entries evicted (silent overflow)"


@pytest.mark.parametrize(
    ("name", "v440_pattern"),
    [
        ("_STRONG_SQL_KEYWORD_GLUED_PREFIX_RE", _V440_GLUED_PREFIX),
        ("_STRONG_SQL_KEYWORD_GLUED_SUFFIX_RE", _V440_GLUED_SUFFIX),
    ],
)
@pytest.mark.parametrize("module", [suspatterns_handler, validators])
def test_the_glued_keyword_regex_reads_as_it_did_at_v440(
    module: object, name: str, v440_pattern: str
) -> None:
    regex = getattr(module, name)
    assert regex.pattern == v440_pattern
    assert regex.flags == 34


@pytest.fixture
def ban_manager() -> Generator[IPBanManager, None, None]:
    IPBanManager._instance = None
    manager = IPBanManager()
    manager.redis_handler = None
    manager.banned_ips = _ObservableTTLCache(
        maxsize=1, ttl=300, on_evict=manager._on_eviction
    )
    yield manager
    IPBanManager._instance = None


def test_the_overflow_warning_keeps_its_v440_text(
    ban_manager: IPBanManager, caplog: pytest.LogCaptureFixture
) -> None:
    caplog.set_level(logging.INFO, logger="guard_core.sync.handlers.ipban")

    ban_manager.ban_ip("8.8.0.1", duration=300, reason="t")
    ban_manager.ban_ip("8.8.0.2", duration=300, reason="t")

    warnings = [r.getMessage() for r in caplog.records if r.levelno == logging.WARNING]
    assert warnings == [_V440_OVERFLOW_WARNING % 1]


def test_the_overflow_advice_to_use_redis_is_still_logged(
    ban_manager: IPBanManager, caplog: pytest.LogCaptureFixture
) -> None:
    caplog.set_level(logging.INFO, logger="guard_core.sync.handlers.ipban")

    ban_manager.ban_ip("8.8.0.1", duration=300, reason="t")
    ban_manager.ban_ip("8.8.0.2", duration=300, reason="t")

    assert any(
        "use Redis to keep a large number of bans" in r.getMessage()
        for r in caplog.records
    )
