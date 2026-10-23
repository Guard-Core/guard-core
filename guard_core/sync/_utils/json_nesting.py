import re

# json.loads accepts 993 nested arrays on 3.10 and 3.11 (951 under a 40 frame call
# stack), 9997 on 3.12, 9998 on 3.13 and 74373 on 3.14. One fixed limit below the
# lowest keeps every interpreter on the same path.
MAX_JSON_PARSE_DEPTH = 512

_QUOTE_RUN_OR_BRACKET = re.compile(r'(?<!\\)\\*"|[\[\]{}]')


def _offset_nesting_exceeds(value: str, limit: int) -> int | None:
    if value.count("[") + value.count("{") <= limit:
        return None
    depth = 0
    in_string = False
    for found in _QUOTE_RUN_OR_BRACKET.finditer(value):
        token = found.group()
        if token[-1] == '"':
            in_string ^= len(token) % 2 == 1
        elif not in_string:
            depth += 1 if token in "[{" else -1
            if depth > limit:
                return found.start()
    return None


def _nests_deeper_than(value: str, limit: int) -> bool:
    return _offset_nesting_exceeds(value, limit) is not None
