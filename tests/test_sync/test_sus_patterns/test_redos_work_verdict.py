import sys

import pytest

from guard_core.sync.detection_engine.compiler import PatternCompiler

pytestmark = pytest.mark.redos_timing

_CDATA_PATTERN = r"<!\[CDATA\[.*?\]\]>"
_V440_SAFE_CAP = 10000
_LOWEST_MIRROR_CAP = 13000 if sys.version_info < (3, 11) else 12000
_REFUSED_CAPS = sorted({_LOWEST_MIRROR_CAP, 13000, 14000, 16000})


def test_the_cdata_pattern_v440_accepted_at_its_safe_cap_is_accepted() -> None:
    safe, reason = PatternCompiler().validate_pattern_safety(
        _CDATA_PATTERN, max_content_length=_V440_SAFE_CAP
    )
    assert safe, reason


@pytest.mark.parametrize("cap", _REFUSED_CAPS)
def test_the_cdata_pattern_over_the_work_budget_is_refused(cap: int) -> None:
    safe, reason = PatternCompiler().validate_pattern_safety(
        _CDATA_PATTERN, max_content_length=cap
    )
    assert not safe, reason
