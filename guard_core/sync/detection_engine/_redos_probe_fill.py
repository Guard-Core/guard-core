import functools
import itertools
from collections.abc import Callable

from guard_core.sync.detection_engine._redos_ambiguous_tail import (
    _group_inner_is_ambiguous,
    _parse_flat_quantified_atoms_with_text,
    _representative_char_for_atom,
)
from guard_core.sync.detection_engine._redos_class_intersection import (
    _class_intersection_probe_units,
)
from guard_core.sync.detection_engine._redos_literal_runs import (
    _adversarial_literal_runs,
)
from guard_core.sync.detection_engine._redos_prefixed_probe import (
    _group_unit_builders,
    _prefixed_repeat_probe,
    _prefixed_unit_builders,
)
from guard_core.sync.detection_engine._redos_reach_probe import (
    _synthesize_reaching_probe,
)
from guard_core.sync.detection_engine._redos_repeat_alphabet import (
    _repeat_alphabet_fills,
)
from guard_core.sync.detection_engine._redos_repeat_prefix import (
    _repeat_reaching_prefixes,
)
from guard_core.sync.detection_engine._redos_repeat_units import _repeat_group_units
from guard_core.sync.detection_engine._redos_stray_chooser import (
    _build_stray_context,
    _fill_to_length,
    _leading_literal_prefix,
    _pattern_complement_chars,
    _repeat_probe_to_length,
    _StrayContext,
    choose_repeat_unit_stray,
)
from guard_core.sync.detection_engine._redos_structure import (
    GroupNestingTooDeep,
    _iter_quantified_group_bodies,
)

_REACH_PROBE_PREFIX_CUT_LENGTHS = (20, 30, 50)
_REACH_PROBE_MAX_RUN_VARIANTS = 12


def _repeat_unit_builder(ctx: _StrayContext, unit: str) -> Callable[[int], str]:
    stray = choose_repeat_unit_stray(ctx, unit)
    return functools.partial(_repeat_probe_to_length, unit, stray=stray)


def _literal_run_builders(
    pattern: str, ctx: _StrayContext
) -> list[Callable[[int], str]]:
    runs = _adversarial_literal_runs(pattern)[:_REACH_PROBE_MAX_RUN_VARIANTS]
    return [_repeat_unit_builder(ctx, run) for run in runs]


def _reach_probe_prefix_builders(
    pattern: str, ctx: _StrayContext
) -> list[Callable[[int], str]]:
    full_probe = _synthesize_reaching_probe(pattern)
    if not full_probe:
        return []
    body_only = full_probe[:-1].replace("?", "")
    builders: list[Callable[[int], str]] = []
    for cut in _REACH_PROBE_PREFIX_CUT_LENGTHS:
        prefix = body_only[:cut]
        if len(prefix) >= 2:
            builders.append(_repeat_unit_builder(ctx, prefix))
    return builders


def _class_intersection_builders(
    pattern: str, flags: int, ctx: _StrayContext | None = None
) -> list[Callable[[int], str]]:
    prefix = _leading_literal_prefix(pattern)
    return [
        functools.partial(_fill_to_length, prefix, fill_char, stray)
        for fill_char, stray in _class_intersection_probe_units(pattern, flags, ctx)
    ]


def _ambiguous_group_fill_unit(inner: str) -> str | None:
    atoms = _parse_flat_quantified_atoms_with_text(inner)
    if atoms is None:
        return None
    chars = [_representative_char_for_atom(text) for text, _o, _u, _v in atoms]
    if any(char is None for char in chars):
        return None
    unit = "".join(char for char in chars if char is not None)
    return unit if unit else None


def _ambiguous_group_fill_builders(
    pattern: str, ctx: _StrayContext
) -> list[Callable[[int], str]]:
    builders: list[Callable[[int], str]] = []
    try:
        group_bodies = list(_iter_quantified_group_bodies(pattern))
    except GroupNestingTooDeep:
        return builders
    for _start, _end, inner in group_bodies:
        if not _group_inner_is_ambiguous(inner):
            continue
        unit = _ambiguous_group_fill_unit(inner)
        if unit is not None:
            builders.append(_repeat_unit_builder(ctx, unit))
    return builders


def _reach_probe_candidate_builders(
    pattern: str, flags: int, deadline: float | None = None
) -> list[Callable[[int], str]]:
    ctx = _build_stray_context(pattern, flags, deadline)
    repeat_fills = _repeat_alphabet_fills(pattern, flags, deadline)
    class_units = _class_intersection_probe_units(
        pattern, flags, ctx, include_bounded=True
    )
    group_pairs = _repeat_group_units(pattern, flags, deadline)
    group_strays = _pattern_complement_chars(pattern, flags)
    prefixed_builders = _group_unit_builders(
        group_pairs, group_strays, functools.partial(choose_repeat_unit_stray, ctx)
    )
    class_prefix_units = itertools.chain(
        class_units,
        ((fill, stray) for fill, _stray in class_units for stray in group_strays),
    )
    class_prefixes = (
        [""]
        + _repeat_reaching_prefixes(pattern, flags, deadline, require_reachable=True)
        if class_units
        else []
    )
    return (
        [
            functools.partial(_fill_to_length, ctx.prefix, fill, fill)
            for fill in repeat_fills
        ]
        + _class_intersection_builders(pattern, flags, ctx)
        + _prefixed_unit_builders(class_prefixes, class_prefix_units)
        + prefixed_builders
        + _literal_run_builders(pattern, ctx)
        + _reach_probe_prefix_builders(pattern, ctx)
        + [
            functools.partial(_prefixed_repeat_probe, ctx.prefix, fill, stray, False)
            for fill, stray in class_units
        ]
        + _ambiguous_group_fill_builders(pattern, ctx)
    )
