import subprocess
import sys

_BUILD_PIPELINE_WITHOUT_CLOUD_BLOCKING = (
    "import sys\n"
    "from unittest.mock import MagicMock, Mock\n"
    "from guard_core.sync.core.checks import build_default_pipeline\n"
    "from guard_core.models import SecurityConfig, SyncSecurityConfig\n"
    "middleware = Mock()\n"
    "middleware.config = SyncSecurityConfig()\n"
    "middleware.logger = Mock()\n"
    "middleware.event_bus = Mock()\n"
    "middleware.create_error_response = MagicMock(return_value=Mock(status_code=500))\n"
    "decorator = Mock()\n"
    "decorator._route_configs = {}\n"
    "middleware.guard_decorator = decorator\n"
    "build_default_pipeline(middleware)\n"
    "print('guard_core.handlers.cloud_handler' in sys.modules)\n"
)


def test_eliminated_cloud_checks_never_import_cloud_handler() -> None:
    result = subprocess.run(
        [sys.executable, "-c", _BUILD_PIPELINE_WITHOUT_CLOUD_BLOCKING],
        capture_output=True,
        text=True,
        check=True,
    )
    assert result.stdout.strip() == "False"
