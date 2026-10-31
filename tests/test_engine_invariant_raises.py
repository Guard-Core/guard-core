import re

import pytest

from guard_core._utils.scan_remainder import _SurfaceRemainder
from guard_core.detection_engine._redos_class_intersection import (
    _advance_pairing_chain,
)
from guard_core.detection_engine._redos_intervals import _IntervalSet
from guard_core.detection_engine._redos_parse_slots import _PairingAtom
from guard_core.detection_engine._redos_stray_chooser import _StrayContext
from guard_core.handlers import (
    _suspatterns_file_upload,
    _suspatterns_templates,
    _suspatterns_xml_xxe,
)

_NEVER_MATCHES = re.compile(r"(?!)")


def test_remainder_piece_outside_a_scan_names_the_broken_invariant() -> None:
    with pytest.raises(RuntimeError, match="outside a detection scan"):
        _SurfaceRemainder().add("piece")


def test_pairing_chain_names_an_overlap_without_a_member(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(_IntervalSet, "first_member", lambda self: None)
    letters = _IntervalSet.from_range(65, 66)
    slot = _PairingAtom(letters, allows_zero=False, unbounded=True)
    ctx = _StrayContext("a+", 0, "", letters)
    with pytest.raises(RuntimeError, match="no first member"):
        _advance_pairing_chain([], slot, letters, slot, None, [], ctx)


def test_file_upload_span_names_a_validated_span_that_did_not_match(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setitem(
        _suspatterns_file_upload._PATTERNS,
        "_FILE_UPLOAD_VALIDATED_SPAN_RE",
        _NEVER_MATCHES,
    )
    with pytest.raises(RuntimeError, match="validated file upload span"):
        _suspatterns_file_upload._file_upload_scan_matches(
            'filename="x.php"',
            re.compile(_suspatterns_file_upload._FILE_UPLOAD_DANGEROUS_EXTENSION_RE),
        )


def test_template_frame_names_a_region_that_did_not_match(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        _suspatterns_templates, "_template_regex", lambda source, flags: _NEVER_MATCHES
    )
    with pytest.raises(RuntimeError, match="template frame"):
        _suspatterns_templates._template_frame("{{ x }}", "{{", "}}", 0, 7, 0)


def test_xml_span_names_a_validated_span_that_did_not_match(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setitem(
        _suspatterns_xml_xxe._PATTERNS, "_XML_XXE_VALIDATED_SPAN_RE", _NEVER_MATCHES
    )
    with pytest.raises(RuntimeError, match="validated XML span"):
        _suspatterns_xml_xxe._xml_validated_match("<a/>", 0, 4)
