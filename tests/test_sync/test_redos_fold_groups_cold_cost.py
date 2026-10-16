import time
from unittest.mock import patch

from guard_core.sync.detection_engine import _redos_ignorecase_fold as fold
from guard_core.sync.detection_engine._redos_intervals import MAX_CODE_POINT


def _reference_fold_groups() -> tuple[frozenset[int], ...]:
    parent: dict[int, int] = {}
    owner: dict[str, int] = {}
    for code_point in range(MAX_CODE_POINT + 1):
        char = chr(code_point)
        for variant in (char.lower(), char.upper(), char.casefold()):
            fold._register_fold_variant(parent, owner, code_point, char, variant)
    return fold._multi_member_groups(parent)


def test_building_the_fold_groups_skips_code_points_without_case_variants() -> None:
    registered = [0]
    original = fold._register_fold_variant

    def counting(
        parent: dict[int, int],
        owner: dict[str, int],
        code_point: int,
        char: str,
        variant: str,
    ) -> None:
        registered[0] += 1
        original(parent, owner, code_point, char, variant)

    with patch.object(fold, "_register_fold_variant", counting):
        fold._build_fold_groups()

    assert registered[0] < 60_000


def test_the_skip_fast_path_builds_exactly_the_reference_groups() -> None:
    assert set(fold._build_fold_groups()) == set(_reference_fold_groups())


def test_the_build_yields_the_interpreter_while_it_scans() -> None:
    with patch.object(time, "sleep") as sleep:
        fold._build_fold_groups()
    assert sleep.call_count >= 100
