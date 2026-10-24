import re

# json.loads accepts 993 nested arrays on 3.10 and 3.11 (951 under a 40 frame call
# stack), 9997 on 3.12, 9998 on 3.13 and 74373 on 3.14. One fixed limit just below
# the 3.10 figure gives a request body the 3.10 outcome on every interpreter.
MAX_JSON_PARSE_DEPTH = 900

_QUOTE_RUN_OR_BRACKET = re.compile(r'(?<!\\)\\*"|[\[\]{}]')


def _offset_nesting_exceeds(value: str, limit: int) -> int | None:
    if value.count("[") + value.count("{") <= limit:
        return None
    depth = 0
    in_string = False
    for found in _QUOTE_RUN_OR_BRACKET.finditer(value):
        piece = found.group()
        if piece[-1] == '"':
            in_string ^= len(piece) % 2 == 1
        elif not in_string:
            depth += 1 if piece in "[{" else -1
            if depth > limit:
                return found.start()
    return None


def _nests_deeper_than(value: str, limit: int) -> bool:
    return _offset_nesting_exceeds(value, limit) is not None
