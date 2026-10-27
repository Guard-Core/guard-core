import pytest

from guard_core.sync.handlers._suspatterns_literals import (
    _requirements,
    parse_required_literals,
)


def test_a_literal_node_holding_text_is_refused() -> None:
    with pytest.raises(TypeError):
        _requirements([("LITERAL", "x")])


def test_a_subpattern_node_without_a_tuple_argument_is_refused() -> None:
    with pytest.raises(TypeError):
        _requirements([("SUBPATTERN", 3)])


def test_a_subpattern_node_whose_body_is_not_parsed_nodes_is_refused() -> None:
    with pytest.raises(TypeError):
        _requirements([("SUBPATTERN", (1, 0, 0, 5))])


def test_a_branch_node_whose_alternatives_are_not_a_list_is_refused() -> None:
    with pytest.raises(TypeError):
        _requirements([("BRANCH", (None, 5))])


def test_a_repeat_node_with_a_non_numeric_minimum_adds_nothing() -> None:
    assert _requirements([("MAX_REPEAT", ("x", 2, [("LITERAL", 97)]))]) == []


def test_real_patterns_still_yield_their_required_literals() -> None:
    assert parse_required_literals("(?:select)(?:abc)+") == ("select",)
