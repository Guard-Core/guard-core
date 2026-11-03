from types import SimpleNamespace
from unittest.mock import MagicMock

from guard_core.models import SyncSecurityConfig
from guard_core.sync.core.checks.base import SecurityCheck
from guard_core.sync.core.checks.pipeline import SecurityCheckPipeline
from guard_core.sync.protocols.middleware_protocol import SyncGuardMiddlewareProtocol
from guard_core.sync.protocols.request_protocol import SyncGuardRequest


class _Named(SecurityCheck):
    def __init__(self, middleware: SyncGuardMiddlewareProtocol, name: str) -> None:
        super().__init__(middleware)
        self.name = name

    @property
    def check_name(self) -> str:
        return self.name

    def check(self, request: SyncGuardRequest) -> None:
        return None


def _rig() -> tuple[SecurityCheckPipeline, MagicMock, SimpleNamespace]:
    middleware = MagicMock()
    middleware.config = SyncSecurityConfig()
    revision = SimpleNamespace(value=0)

    def rebuild() -> list[SecurityCheck]:
        return [_Named(middleware, "base"), _Named(middleware, "second")]

    pipeline = SecurityCheckPipeline(
        rebuild(),
        config=middleware.config,
        rebuild_checks=rebuild,
        route_config_revision=lambda: revision.value,
    )
    return pipeline, middleware, revision


def _rebuild(pipeline: SecurityCheckPipeline, revision: SimpleNamespace) -> None:
    revision.value += 1
    pipeline._rebuild_if_stale()


def test_an_added_check_survives_a_rebuild() -> None:
    pipeline, middleware, revision = _rig()
    pipeline.add_check(_Named(middleware, "custom"))

    _rebuild(pipeline, revision)

    assert pipeline.get_check_names() == ["base", "second", "custom"]


def test_an_inserted_check_keeps_its_position_across_a_rebuild() -> None:
    pipeline, middleware, revision = _rig()
    pipeline.insert_check(1, _Named(middleware, "custom"))

    _rebuild(pipeline, revision)
    _rebuild(pipeline, revision)

    assert pipeline.get_check_names() == ["base", "custom", "second"]


def test_a_removed_check_stays_removed_across_a_rebuild() -> None:
    pipeline, _, revision = _rig()
    assert pipeline.remove_check("base") is True

    _rebuild(pipeline, revision)

    assert pipeline.get_check_names() == ["second"]


def test_removing_a_check_that_is_not_there_changes_nothing() -> None:
    pipeline, _, revision = _rig()

    assert pipeline.remove_check("absent") is False
    _rebuild(pipeline, revision)

    assert pipeline.get_check_names() == ["base", "second"]
