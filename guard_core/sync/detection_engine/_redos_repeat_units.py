import re

from guard_core.sync.detection_engine._redos_parse_nodes import _Body
from guard_core.sync.detection_engine._redos_parse_slots import _regex_parser
from guard_core.sync.detection_engine._redos_repeat_prefix import _PrefixWalk
from guard_core.sync.detection_engine._redos_repeat_prefix_state import (
    _RepeatPrefixState,
)

_REPEAT_UNIT_PAIR_LIMIT = 4096
_REPEAT_UNIT_TEXT_BUDGET = 1000000


def _repeated_body_units(body: _Body, flags: int, deadline: float | None) -> list[str]:
    states = _PrefixWalk(flags, [], deadline, False).walk(
        body, [_RepeatPrefixState("")]
    )
    return [state.text for state in states if len(state.text) > 1]


def _repeat_group_units(
    pattern: str, flags: int, deadline: float | None = None
) -> list[tuple[str, str]]:
    try:
        parsed = _regex_parser.parse(pattern, flags)
    except re.error:
        return []
    pairs: dict[tuple[str, str], None] = {}
    pair_text_size = 0

    def collect(
        body: _Body, local_flags: int, states: list[_RepeatPrefixState]
    ) -> None:
        nonlocal pair_text_size
        units = _repeated_body_units(body, local_flags, deadline)
        for state in states:
            prefix = state.text + state.pending
            for unit in units:
                pair = (prefix, unit)
                if pair not in pairs:
                    pairs[pair] = None
                    pair_text_size += len(prefix) + len(unit)
                if len(pairs) > _REPEAT_UNIT_PAIR_LIMIT:
                    raise TimeoutError("Pattern validation repeat-unit budget exceeded")
                if pair_text_size > _REPEAT_UNIT_TEXT_BUDGET:
                    raise TimeoutError(
                        "Pattern validation repeat-unit text budget exceeded"
                    )

    _PrefixWalk(
        parsed.state.flags,
        [],
        deadline,
        False,
        repeat_collector=collect,
        canonical_optionals=True,
        require_reachable=True,
    ).walk(parsed.data, [_RepeatPrefixState("")])
    return list(pairs)
