import logging
from pathlib import Path

import pytest
from pytest_mock import MockerFixture

from guard_core.sync._utils.logging_utils import setup_custom_logging


def _file_handler(logger: logging.Logger) -> logging.FileHandler:
    [handler] = [h for h in logger.handlers if isinstance(h, logging.FileHandler)]
    return handler


def _record(logger: logging.Logger, message: str) -> logging.LogRecord:
    return logger.makeRecord("guard_core", logging.INFO, __file__, 1, message, (), None)


def test_a_late_record_on_a_replaced_file_handler_does_not_reopen_the_file(
    tmp_path: Path,
) -> None:
    log_file = tmp_path / "guard.log"
    logger = setup_custom_logging(str(log_file))
    try:
        old = _file_handler(logger)
        setup_custom_logging(str(log_file))
        size_after_close = log_file.stat().st_size

        old.handle(_record(logger, "late record from a thread holding the old handler"))

        assert vars(old)["stream"] is None
        assert log_file.stat().st_size == size_after_close
        assert "late record" not in log_file.read_text()
    finally:
        for installed in list(logger.handlers):
            installed.close()
            logger.removeHandler(installed)


def test_a_live_file_handler_still_writes_its_records(tmp_path: Path) -> None:
    log_file = tmp_path / "guard.log"
    logger = setup_custom_logging(str(log_file))
    try:
        handler = _file_handler(logger)
        handler.handle(_record(logger, "record on the live handler"))
        handler.flush()

        assert "record on the live handler" in log_file.read_text()
    finally:
        for installed in list(logger.handlers):
            installed.close()
            logger.removeHandler(installed)


def test_replacing_an_engine_handler_while_file_handler_is_patched_still_warns(
    tmp_path: Path, caplog: pytest.LogCaptureFixture, mocker: MockerFixture
) -> None:
    logger = setup_custom_logging(str(tmp_path / "guard.log"))
    try:
        mocker.patch(
            "guard_core.sync._utils.logging_utils.logging.FileHandler",
            side_effect=PermissionError("cannot create log file"),
        )
        caplog.set_level(logging.WARNING, logger="guard_core")

        setup_custom_logging(str(tmp_path / "other.log"))

        assert f"Failed to create log file {tmp_path / 'other.log'}" in caplog.text
    finally:
        mocker.stopall()
        for installed in list(logger.handlers):
            installed.close()
            logger.removeHandler(installed)
