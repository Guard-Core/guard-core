import logging
from types import SimpleNamespace

from guard_core.models import SyncSecurityConfig
from guard_core.sync.core.checks import build_default_pipeline


def test_factory_propagates_muted_check_logs() -> None:
    mw = SimpleNamespace(
        config=SyncSecurityConfig(muted_check_logs={"rate_limit"}),
        logger=logging.getLogger("t"),
    )
    pipe = build_default_pipeline(mw)
    assert pipe.muted_check_logs == {"rate_limit"}
