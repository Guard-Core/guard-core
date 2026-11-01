import pytest

from tests import host_load_factor as module


@pytest.mark.parametrize(
    ("measured", "expected"), [(0.25, 1.0), (1.0, 1.0), (2.9, 2.9), (8.0, 8.0)]
)
def test_the_host_load_factor_never_relaxes_below_the_nominal_budget(
    monkeypatch: pytest.MonkeyPatch, measured: float, expected: float
) -> None:
    monkeypatch.setattr(module, "_measure_host_load_factor", lambda: measured)
    assert module.host_load_factor() == expected


def test_the_larger_of_the_factor_before_and_after_the_run_is_used(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    readings = iter([1.0, 3.2])
    monkeypatch.setattr(module, "_measure_host_load_factor", lambda: next(readings))
    result, factor = module.run_with_host_load_factor(lambda: "ran")
    assert (result, factor) == ("ran", 3.2)
