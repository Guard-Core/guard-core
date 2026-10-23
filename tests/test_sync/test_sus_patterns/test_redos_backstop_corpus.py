import time

import coverage
import pytest

from guard_core.models import SyncSecurityConfig
from guard_core.sync.handlers.suspatterns_handler import sus_patterns_handler

_DEFAULT_MAX_SCAN_LENGTH = 10000
_PER_PAYLOAD_CPU_TIME_CEILING_SECONDS = 5.0


def _cov_scale() -> float:
    return 1.0 + 1.0 * (coverage.Coverage.current() is not None)


def _repeated(unit: str, length: int = _DEFAULT_MAX_SCAN_LENGTH) -> str:
    reps = length // len(unit) + 1
    return (unit * reps)[:length]


ADVERSARIAL_REDOS_CORPUS = [
    pytest.param(_repeated("<script"), id="xss_script_tag_adjacent_quantifiers"),
    pytest.param(_repeated("<object"), id="xss_object_tag_adjacent_quantifiers"),
    pytest.param(_repeated("<embed"), id="xss_embed_tag_adjacent_quantifiers"),
    pytest.param(_repeated("<applet"), id="xss_applet_tag_adjacent_quantifiers"),
    pytest.param(_repeated(";$("), id="cmd_injection_dollar_paren_unterminated"),
    pytest.param(
        _repeated("=http://x/"), id="file_inclusion_rfi_double_ext_unterminated"
    ),
    pytest.param(_repeated("<!ENTITY "), id="xml_external_entity_system_unterminated"),
    pytest.param(_repeated("<!DOCTYPE "), id="xml_doctype_bracket_unterminated"),
    pytest.param(_repeated("#{x"), id="template_ssti_hashbrace_unterminated"),
]


@pytest.mark.parametrize("payload", ADVERSARIAL_REDOS_CORPUS)
def test_adversarial_payload_stays_under_cpu_time_ceiling(payload: str) -> None:
    sus_patterns_handler.configure(SyncSecurityConfig())

    samples: list[float] = []
    for _ in range(5):
        start = time.process_time()
        sus_patterns_handler.detect(
            content=payload, ip_address="203.0.113.9", context="request_body"
        )
        samples.append(time.process_time() - start)

    elapsed = min(samples)
    ceiling = _PER_PAYLOAD_CPU_TIME_CEILING_SECONDS * _cov_scale()
    assert elapsed < ceiling, (
        f"adversarial payload of length {len(payload)} took {elapsed:.3f}s, "
        f"exceeding the {ceiling:.1f}s ceiling"
    )
