from guard_core._utils.pair_value_scan import _unquoted_value_extent


def test_a_soft_whitespace_run_before_a_non_name_character_stays_in_the_value() -> None:
    assert _unquoted_value_extent("abc  ,def", 0) == 5
    assert _unquoted_value_extent("abc  ", 0) == 5


def test_a_soft_whitespace_run_before_a_pair_ends_the_value() -> None:
    assert _unquoted_value_extent("abc  k=v", 0) == 3
