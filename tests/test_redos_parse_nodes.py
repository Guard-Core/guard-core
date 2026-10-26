import pytest

from guard_core.detection_engine import _redos_parse_nodes as nodes
from guard_core.detection_engine._redos_parse_slots import (
    _parse_pattern,
    _regex_parser,
)


def _first_av(pattern: str, op_name: str) -> object:
    for op, av in _parse_pattern(pattern, 0).data:
        if op == getattr(_regex_parser, op_name):
            return av
    raise AssertionError(f"{pattern} has no {op_name} node")


def test_the_accessors_read_the_shapes_sre_produces() -> None:
    low, high, body = nodes._repeat_parts(_first_av("a{2,3}", "MAX_REPEAT"))
    assert (low, high, len(body)) == (2, 3, 1)
    group, add_flags, del_flags, group_body = nodes._group_parts(
        _first_av("(ab)", "SUBPATTERN")
    )
    assert (group, add_flags, del_flags, len(group_body)) == (1, 0, 0, 2)
    direction, assertion_body = nodes._assertion_parts(_first_av("(?=a)", "ASSERT"))
    assert (direction, len(assertion_body)) == (1, 1)
    assert len(nodes._branch_alternatives(_first_av("ab|cd", "BRANCH"))) == 2
    cond_group, yes_branch, no_branch = nodes._conditional_parts(
        _first_av("(a)(?(1)b|c)", "GROUPREF_EXISTS")
    )
    assert (cond_group, len(yes_branch), len(no_branch or [])) == (1, 1, 1)
    assert nodes._group_number_of(_first_av("(a)\\1", "GROUPREF")) == 1
    assert nodes._body_of(_parse_pattern("ab", 0).data) is not None
    range_node = nodes._body_of(_first_av("[a-z]", "IN"))[0]
    assert nodes._range_bounds(range_node[1]) == (97, 122)
    assert nodes._code_point_of(_first_av("a", "LITERAL")) == 97


@pytest.mark.parametrize(
    "accessor",
    [
        nodes._repeat_parts,
        nodes._group_parts,
        nodes._assertion_parts,
        nodes._branch_alternatives,
        nodes._conditional_parts,
        nodes._group_number_of,
        nodes._body_of,
        nodes._code_point_of,
        nodes._range_bounds,
    ],
)
def test_a_malformed_node_is_a_type_error_naming_the_shape(accessor: object) -> None:
    assert callable(accessor)
    with pytest.raises(TypeError, match="node is|group body"):
        accessor(None)
