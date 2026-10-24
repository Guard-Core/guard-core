import re
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from typing import NamedTuple

from guard_core._utils.detection_scan import (
    _SCAN_TIME_BUDGET_EXHAUSTED_PATTERN,
    LazyPreview,
    _check_request_component,
    _fresh_value_budget,
    _scan_skips,
    _semantic_excluded_headers,
    _whole_value_rows_only,
    logger,
)
from guard_core.detection_engine.truncation import reusing_attack_regions
from guard_core.exceptions import BodyReadFailedError
from guard_core.handlers._suspatterns_literals import reusing_literal_presence


@contextmanager
def _scanning_whole_value_rows_only() -> Iterator[None]:
    token = _whole_value_rows_only.set(True)
    try:
        yield
    finally:
        _whole_value_rows_only.reset(token)


_UNIT_PASS_MAX_CHARS = 1024
_WHOLE_BASE64_RE = re.compile(r"[A-Za-z0-9+/_-]{16,}={0,2}")


@contextmanager
def _unit_scan_mode(unit: str) -> Iterator[None]:
    if _WHOLE_BASE64_RE.fullmatch(unit):
        yield
        return
    with _scanning_whole_value_rows_only():
        yield


_RemainderKey = tuple[frozenset[str] | None, bool]
_REDACTED_PIECE = "[REDACTED]"
_REMAINDER_PREVIEW_CHARS = 1024


class _Skipped(NamedTuple):
    piece: str
    sensitive: bool
    units: tuple[str, ...]


class _SurfaceRemainder:
    """The items of one surface the budgets skipped, grouped by scan settings.

    A group is every skipped item that would have been scanned with the same
    categories and the same semantic exclusion, so its block gets exactly the
    settings the walk would have used for each of its items. A piece flagged
    sensitive is scanned like any other but never shown in a log or an event.
    The units of an item are the separate texts the walk would have scanned (a
    name and a value), which the rows anchored to a whole value need.
    """

    __slots__ = ("_groups",)

    def __init__(self) -> None:
        self._groups: dict[_RemainderKey, list[_Skipped]] = {}

    def add(
        self, piece: str, sensitive: bool = False, units: tuple[str, ...] = ()
    ) -> None:
        skips = _scan_skips.get()
        assert skips is not None
        key = (skips.categories, skips.semantic_excluded)
        self._groups.setdefault(key, []).append(
            _Skipped(piece, sensitive, units or (piece,))
        )

    def __bool__(self) -> bool:
        return bool(self._groups)

    def groups(self) -> Iterator[tuple[_RemainderKey, list[_Skipped]]]:
        yield from self._groups.items()


def _wire_pair(name: str, value: str) -> str:
    """One query or form pair as it sits in a block joined by ``&``.

    Nothing is escaped: a percent sequence the walk would decode must need the same
    number of decode rounds in the block, and escaping ``/`` or ``.`` made a plain
    ``../relative`` value decode to a traversal the raw text never held. The space
    after ``=`` keeps a row that anchors on ``=`` (the remote file inclusion row)
    from matching the ``=`` this rendering supplies: the walk scans the value alone.
    """
    return f"{name}= {value}"


def _body_remainder_display(
    sensitive_params: frozenset[str], sensitive_body_fields: frozenset[str]
) -> Callable[[str], str | None]:
    from guard_core._utils.request_logging import redact_blob_for_display

    return lambda piece: redact_blob_for_display(
        piece, sensitive_params, sensitive_body_fields
    )


def _remainder_preview(
    skipped: list[_Skipped],
    separator: str,
    preview_of: Callable[[str], str | None],
) -> "LazyPreview":
    def build() -> str:
        shown: list[str] = []
        length = 0
        for piece, sensitive, _units in skipped:
            shown.append(_REDACTED_PIECE if sensitive else (preview_of(piece) or piece))
            length += len(shown[-1])
            if length >= _REMAINDER_PREVIEW_CHARS:
                break
        return separator.join(shown)

    return LazyPreview(build)


_UNIT_PASS_MAX_SCANS = 256
_UNIT_NEEDS_DECODING_RE = re.compile(r"[%&\\\x80-\U0010ffff]")


async def _whole_value_rows() -> list[re.Pattern]:
    from guard_core.handlers._suspatterns_regex import _CONTEXT_SENSITIVE_ROW_SOURCES
    from guard_core.handlers._suspatterns_whole_value_rows import (
        row_needs_the_whole_value,
    )
    from guard_core.handlers.suspatterns_handler import active_sus_patterns

    return [
        pattern
        for pattern, _contexts, _category in (
            await active_sus_patterns().get_all_compiled_patterns()
        )
        if row_needs_the_whole_value(pattern.pattern, _CONTEXT_SENSITIVE_ROW_SOURCES)
    ]


def _unit_needs_its_own_scan(unit: str, rows: list[re.Pattern]) -> bool:
    return (
        _UNIT_NEEDS_DECODING_RE.search(unit) is not None
        or _WHOLE_BASE64_RE.fullmatch(unit) is not None
        or any(row.search(unit) for row in rows)
    )


async def _scan_whole_value_rows_per_unit(
    skipped: list[_Skipped],
    context: str,
    component_name: str,
    client_ip: str,
    correlation_id: str,
    categories: frozenset[str] | None,
    log_level: str | None,
    preview_of: Callable[[str], str | None],
) -> tuple[bool, str, list[dict]]:
    rows = await _whole_value_rows()
    scans_left = _UNIT_PASS_MAX_SCANS
    for _piece, sensitive, units in skipped:
        for unit in units:
            if len(unit) > _UNIT_PASS_MAX_CHARS or not _unit_needs_its_own_scan(
                unit, rows
            ):
                continue
            if scans_left == 0:
                return False, "", []
            scans_left -= 1
            with _fresh_value_budget(), _unit_scan_mode(unit):
                detected, trigger, threats = await _check_request_component(
                    unit,
                    context,
                    component_name,
                    client_ip,
                    correlation_id,
                    None if categories is None else set(categories),
                    log_level,
                    scan_embedded_json=False,
                    content_preview=_REDACTED_PIECE
                    if sensitive
                    else (preview_of(unit) or unit),
                )
            if detected:
                return True, f"{component_name}: {trigger}", threats
    return False, "", []


async def _scan_surface_remainder(
    remainder: _SurfaceRemainder,
    separator: str,
    context_kind: str,
    component_name: str,
    client_ip: str,
    correlation_id: str,
    log_level: str | None,
    preview_of: Callable[[str], str | None],
) -> tuple[bool, str, list[dict]]:
    logger.info(
        "%s skipped past the scan budget for client %s; scanning them once "
        "more as one block",
        component_name,
        client_ip,
    )
    with reusing_attack_regions(), reusing_literal_presence():
        for (categories, semantic_excluded), skipped in remainder.groups():
            excluded_name = next(iter(_semantic_excluded_headers.get()), "")
            context = (
                f"{context_kind}:{excluded_name}"
                if semantic_excluded
                else f"{context_kind}:remainder block"
            )
            with _fresh_value_budget():
                detected, trigger, threats = await _check_request_component(
                    separator.join(piece for piece, _, _ in skipped),
                    context,
                    component_name,
                    client_ip,
                    correlation_id,
                    None if categories is None else set(categories),
                    log_level,
                    scan_embedded_json=False,
                    content_preview=_remainder_preview(skipped, separator, preview_of),
                )
            if detected and _only_the_time_budget_ended(threats):
                raise BodyReadFailedError(
                    f"the scan time budget ended before the {component_name.lower()} "
                    "were scanned"
                )
            unit_hit = await _scan_whole_value_rows_per_unit(
                skipped,
                context,
                component_name,
                client_ip,
                correlation_id,
                categories,
                log_level,
                preview_of,
            )
            if detected or unit_hit[0]:
                return (
                    True,
                    f"{component_name}: {trigger if detected else unit_hit[1]}",
                    [*threats, *unit_hit[2]],
                )
        return False, "", []


def _only_the_time_budget_ended(threats: list[dict]) -> bool:
    return bool(threats) and all(
        threat.get("pattern") == _SCAN_TIME_BUDGET_EXHAUSTED_PATTERN
        for threat in threats
    )
