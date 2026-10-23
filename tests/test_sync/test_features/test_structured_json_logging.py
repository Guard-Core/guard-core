import json
import logging
from collections.abc import Iterator
from pathlib import Path

import pytest

from guard_core.sync.utils import JsonFormatter, setup_custom_logging


@pytest.fixture(autouse=True)
def _restore_logger_state() -> Iterator[None]:
    root_logger = logging.getLogger()
    guard_logger = logging.getLogger("guard_core")
    original_root_handlers = root_logger.handlers[:]
    original_root_level = root_logger.level
    original_guard_level = guard_logger.level
    yield
    for handler in root_logger.handlers[:]:
        if handler not in original_root_handlers:
            handler.close()
    root_logger.handlers = original_root_handlers
    root_logger.setLevel(original_root_level)
    guard_logger.setLevel(original_guard_level)


def test_text_format_default() -> None:
    logger = setup_custom_logging(log_format="text")
    handler = logger.handlers[0]
    assert not isinstance(handler.formatter, JsonFormatter)


def test_json_format_produces_valid_json(
    capfd: pytest.CaptureFixture[str],
) -> None:
    logging.getLogger().handlers = []
    logger = setup_custom_logging(log_format="json")
    logger.info("test message")

    captured = capfd.readouterr()
    parsed = json.loads(captured.err.strip())

    assert parsed["level"] == "INFO"
    assert parsed["message"] == "test message"
    assert parsed["logger"] == "guard_core"
    assert "timestamp" in parsed


def test_json_format_fields_are_correct() -> None:
    formatter = JsonFormatter()
    record = logging.LogRecord(
        name="test_logger",
        level=logging.WARNING,
        pathname="test.py",
        lineno=1,
        msg="warning message",
        args=(),
        exc_info=None,
    )
    output = formatter.format(record)
    parsed = json.loads(output)

    assert parsed["level"] == "WARNING"
    assert parsed["logger"] == "test_logger"
    assert parsed["message"] == "warning message"
    assert "timestamp" in parsed


def test_json_format_with_file_handler(tmp_path: Path) -> None:
    log_file = str(tmp_path / "test.log")
    logger = setup_custom_logging(log_file=log_file, log_format="json")
    logger.info("file test")

    with open(log_file) as f:
        line = f.readline().strip()
    parsed = json.loads(line)
    assert parsed["message"] == "file test"
    assert parsed["level"] == "INFO"


def test_text_format_not_json() -> None:
    formatter = logging.Formatter(
        "[%(name)s] %(asctime)s - %(levelname)s - %(message)s"
    )
    record = logging.LogRecord(
        name="test",
        level=logging.INFO,
        pathname="test.py",
        lineno=1,
        msg="hello",
        args=(),
        exc_info=None,
    )
    output = formatter.format(record)
    with pytest.raises(json.JSONDecodeError):
        json.loads(output)


def test_config_log_format_default() -> None:
    from guard_core.models import SyncSecurityConfig

    config = SyncSecurityConfig(enable_redis=False)
    assert config.log_format == "text"


def test_config_log_format_json() -> None:
    from guard_core.models import SyncSecurityConfig

    config = SyncSecurityConfig(enable_redis=False, log_format="json")
    assert config.log_format == "json"
