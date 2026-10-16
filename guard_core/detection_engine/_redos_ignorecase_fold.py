from __future__ import annotations

import time

from guard_core.detection_engine._redos_intervals import MAX_CODE_POINT, _IntervalSet

_FOLD_GROUPS: tuple[frozenset[int], ...] | None = None
_FOLD_GROUP_BY_CODE_POINT: dict[int, frozenset[int]] | None = None
_EXPAND_IGNORECASE_MEMBER_SCAN_CEILING = 4096
_FOLD_BLOCK_SIZE = 256
_FOLD_BUILD_YIELD_BLOCKS = 32


def _uf_find(parent: dict[int, int], code_point: int) -> int:
    parent.setdefault(code_point, code_point)
    root = code_point
    while parent[root] != root:
        root = parent[root]
    while parent[code_point] != root:
        parent[code_point], code_point = root, parent[code_point]
    return root


def _uf_union(parent: dict[int, int], first: int, second: int) -> None:
    first_root, second_root = _uf_find(parent, first), _uf_find(parent, second)
    if first_root != second_root:
        parent[second_root] = first_root


def _register_fold_variant(
    parent: dict[int, int],
    multi_char_fold_owner: dict[str, int],
    code_point: int,
    char: str,
    variant: str,
) -> None:
    if len(variant) == 1:
        if variant != char:
            _uf_union(parent, code_point, ord(variant))
        return
    owner = multi_char_fold_owner.get(variant)
    if owner is None:
        multi_char_fold_owner[variant] = code_point
    else:
        _uf_union(parent, owner, code_point)


def _multi_member_groups(
    parent: dict[int, int],
) -> tuple[frozenset[int], ...]:
    groups: dict[int, set[int]] = {}
    for code_point in parent:
        groups.setdefault(_uf_find(parent, code_point), set()).add(code_point)
    return tuple(frozenset(group) for group in groups.values() if len(group) > 1)


def _block_has_case_variants(block: str) -> bool:
    return not (
        block.lower() == block and block.upper() == block and block.casefold() == block
    )


def _build_fold_groups() -> tuple[frozenset[int], ...]:
    parent: dict[int, int] = {}
    multi_char_fold_owner: dict[str, int] = {}
    for start in range(0, MAX_CODE_POINT + 1, _FOLD_BLOCK_SIZE):
        stop = min(start + _FOLD_BLOCK_SIZE, MAX_CODE_POINT + 1)
        block = "".join(map(chr, range(start, stop)))
        if (start // _FOLD_BLOCK_SIZE) % _FOLD_BUILD_YIELD_BLOCKS == 0:
            time.sleep(0)
        if not _block_has_case_variants(block):
            continue
        for code_point, char in enumerate(block, start):
            for variant in (char.lower(), char.upper(), char.casefold()):
                _register_fold_variant(
                    parent, multi_char_fold_owner, code_point, char, variant
                )
    return _multi_member_groups(parent)


def _fold_groups() -> tuple[frozenset[int], ...]:
    global _FOLD_GROUPS
    if _FOLD_GROUPS is None:
        _FOLD_GROUPS = _build_fold_groups()
    return _FOLD_GROUPS


def _fold_group_by_code_point() -> dict[int, frozenset[int]]:
    global _FOLD_GROUP_BY_CODE_POINT
    if _FOLD_GROUP_BY_CODE_POINT is None:
        mapping: dict[int, frozenset[int]] = {}
        for group in _fold_groups():
            for code_point in group:
                mapping[code_point] = group
        _FOLD_GROUP_BY_CODE_POINT = mapping
    return _FOLD_GROUP_BY_CODE_POINT


def _fold_partners(group: frozenset[int], ascii_only: bool) -> frozenset[int]:
    if not ascii_only:
        return group
    return frozenset(code_point for code_point in group if code_point < 128)


def _add_fold_candidates(
    result: _IntervalSet, candidates: frozenset[int]
) -> _IntervalSet:
    for candidate in candidates:
        if not result.contains(candidate):
            result = result.union(_IntervalSet.single(candidate))
    return result


def _expand_ignorecase_by_member_scan(
    interval_set: _IntervalSet, ascii_only: bool
) -> _IntervalSet:
    fold_map = _fold_group_by_code_point()
    result = interval_set
    seen_groups: set[frozenset[int]] = set()
    for low, high in interval_set._intervals:
        for code_point in range(low, high + 1):
            if ascii_only and code_point >= 128:
                continue
            group = fold_map.get(code_point)
            if group is None or group in seen_groups:
                continue
            seen_groups.add(group)
            result = _add_fold_candidates(result, _fold_partners(group, ascii_only))
    return result


def _group_scan_matches(interval_set: _IntervalSet, candidates: frozenset[int]) -> bool:
    return len(candidates) >= 2 and any(
        interval_set.contains(code_point) for code_point in candidates
    )


def _expand_ignorecase_by_group_scan(
    interval_set: _IntervalSet, ascii_only: bool
) -> _IntervalSet:
    result = interval_set
    for group in _fold_groups():
        candidates = _fold_partners(group, ascii_only)
        if not _group_scan_matches(interval_set, candidates):
            continue
        result = _add_fold_candidates(result, candidates)
    return result


def expand_ignorecase(interval_set: _IntervalSet, ascii_only: bool) -> _IntervalSet:
    member_count = sum(high - low + 1 for low, high in interval_set._intervals)
    if member_count <= _EXPAND_IGNORECASE_MEMBER_SCAN_CEILING:
        return _expand_ignorecase_by_member_scan(interval_set, ascii_only)
    return _expand_ignorecase_by_group_scan(interval_set, ascii_only)
