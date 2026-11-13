import pytest

from guard_core._misconfiguration_kinds import Problem
from guard_core.sync._utils.route_gate import (
    declared_path_param_problems,
    detection_exclusion_path_param_problems,
)


def test_the_helper_builds_the_text_every_adapter_used_to_build() -> None:
    [problem] = detection_exclusion_path_param_problems(
        "items.get", "/items/{item_id:int}", ["ghost"]
    )

    assert problem == (
        "@detection_exclusion(path_params=...) on route 'items.get' declares "
        "'ghost', which is not in the route template '/items/{item_id:int}', so it "
        "exempts nothing."
    )


@pytest.mark.parametrize(
    ("template", "declared", "kind"),
    [
        (
            "/items/{item_id}",
            "ghost",
            "decorator.detection_exclusion.param_not_in_template",
        ),
        (
            "/{tail:path}",
            "tail",
            "decorator.detection_exclusion.param_without_literal_segment",
        ),
    ],
)
def test_each_problem_carries_its_kind_and_the_declared_name_as_subject(
    template: str, declared: str, kind: str
) -> None:
    [problem] = detection_exclusion_path_param_problems("r", template, [declared])

    assert isinstance(problem, Problem)
    assert (problem.kind, problem.subject, problem.severity) == (
        kind,
        declared,
        "error",
    )


def test_the_helper_and_the_engine_text_agree_name_by_name() -> None:
    template = "/{tail:path}"
    declared = ["tail", "ghost"]

    helped = {
        p.subject: str(p)
        for p in detection_exclusion_path_param_problems("r", template, declared)
    }

    for name, text in declared_path_param_problems(template, declared).items():
        assert helped[name].endswith(text)


def test_a_clean_declaration_has_no_problem() -> None:
    assert detection_exclusion_path_param_problems("r", "/items/{id}", ["id"]) == []
