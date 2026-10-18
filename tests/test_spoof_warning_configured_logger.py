from pathlib import Path

from guard_core._utils.logging_utils import setup_custom_logging
from guard_core.models import SecurityConfig
from guard_core.utils import extract_client_ip
from tests.conftest import MockGuardRequest

UNTRUSTED_PUBLIC_PEER = "8.8.4.4"


async def test_the_spoof_warning_goes_through_the_configured_logger_once_a_minute(
    tmp_path: Path,
) -> None:
    log_file = tmp_path / "guard.log"
    logger = setup_custom_logging(str(log_file))
    config = SecurityConfig(enable_redis=False, trusted_proxies=["10.0.0.5"])

    for _ in range(5):
        request = MockGuardRequest(
            client_host=UNTRUSTED_PUBLIC_PEER,
            headers={"X-Forwarded-For": "203.0.113.7"},
        )
        await extract_client_ip(request, config)
    for handler in logger.handlers:
        handler.flush()

    lines = [
        line
        for line in log_file.read_text().splitlines()
        if "Potential IP spoof attempt" in line
    ]
    assert len(lines) == 1
    assert UNTRUSTED_PUBLIC_PEER in lines[0]
