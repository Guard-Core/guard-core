import copy

from guard_core._utils.sampling import CountedKeys, PerApp, SampledKeys
from guard_core.models import SecurityConfig


def _config() -> SecurityConfig:
    return SecurityConfig(enable_redis=False)


def test_a_copy_of_a_config_is_the_same_app_and_shares_its_table() -> None:
    tables: PerApp[SampledKeys] = PerApp("copy_probe", SampledKeys)
    config = _config()
    table = tables.for_app(config)

    assert tables.for_app(copy.copy(config)) is table
    assert tables.for_app(copy.deepcopy(config)) is table
    assert tables.for_app(_config()) is not table


def test_no_config_or_one_that_cannot_hold_a_table_uses_the_process_table() -> None:
    tables: PerApp[CountedKeys] = PerApp("unheld_probe", CountedKeys)

    class Slotted:
        __slots__ = ()

    assert tables.for_app(None) is tables.for_app(None)
    assert tables.for_app(Slotted()) is tables.for_app(None)
    assert tables.for_app(_config()) is not tables.for_app(None)


def test_clear_forgets_the_process_table_and_leaves_the_table_of_an_app() -> None:
    tables: PerApp[CountedKeys] = PerApp("clear_probe", CountedKeys)
    config = _config()
    tables.for_app(None).entries["peer"] = (1.0, 2)
    tables.for_app(None).evicted_pending = 3
    tables.for_app(config).entries["peer"] = (1.0, 2)

    tables.clear()

    assert not tables.for_app(None).entries
    assert tables.for_app(None).evicted_pending == 0
    assert "peer" in tables.for_app(config).entries
