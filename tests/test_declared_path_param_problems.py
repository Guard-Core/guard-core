from guard_core._utils.route_gate import declared_path_param_problems


def test_a_name_missing_from_the_template_has_its_problem() -> None:
    assert declared_path_param_problems("/files/{name}", ["other"]) == {
        "other": "is not in the route template '/files/{name}', so it exempts nothing."
    }


def test_a_name_with_no_literal_segment_before_it_has_its_problem() -> None:
    assert declared_path_param_problems("/{name}", ["name"]) == {
        "name": (
            "has no literal segment before it in the route template '/{name}': it "
            "would exempt the whole path from the probe rows, so the whole path is "
            "scanned."
        )
    }


def test_a_sound_declaration_has_no_problem() -> None:
    assert declared_path_param_problems("/files/{name}", ["name"]) == {}


def test_no_declared_names_have_no_problem() -> None:
    assert declared_path_param_problems("/{name}", []) == {}
