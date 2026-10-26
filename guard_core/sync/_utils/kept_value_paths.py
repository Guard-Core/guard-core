from collections.abc import Mapping

_NOTHING_TO_KEEP = object()


def _keep_list_paths(items: list[object], wanted: frozenset[str]) -> object:
    kept_items = []
    for item in items:
        kept_item = _keep_only_values(item, wanted)
        if kept_item is not _NOTHING_TO_KEEP:
            kept_items.append(kept_item)
    return kept_items or _NOTHING_TO_KEEP


def _keep_dict_paths(
    entries: Mapping[object, object], wanted: frozenset[str]
) -> object:
    kept: dict[object, object] = {}
    for key, item in entries.items():
        kept_item = _keep_only_values(item, wanted)
        if kept_item is not _NOTHING_TO_KEEP:
            kept[key] = kept_item
        elif str(key) in wanted:
            kept[key] = ""
    return kept or _NOTHING_TO_KEEP


def _keep_only_values(data: object, wanted: frozenset[str]) -> object:
    # A copy of the tree with only the paths to a leaf or a key whose text is in
    # `wanted`, so the walk keeps every key path its exclusions need. One frame per
    # level: the parse depth cap (512) keeps it under the interpreter's limit.
    if isinstance(data, str):
        return data if data in wanted else _NOTHING_TO_KEEP
    if isinstance(data, list):
        return _keep_list_paths(data, wanted)
    if isinstance(data, dict):
        return _keep_dict_paths(data, wanted)
    return _NOTHING_TO_KEEP
