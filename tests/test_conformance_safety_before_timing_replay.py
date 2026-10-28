from generate_safety_gates import (
    RETIRED_CASES,
    decided_before_timing,
)
from run_fixtures import check_safety_case, suite_cases

COMPILE_FAILED_05 = "safety_test_strings_compile_failed_05"


async def test_cases_decided_before_timing_replay_green_on_every_python() -> None:
    cases = decided_before_timing(suite_cases("safety_gates"))
    assert len(cases) >= 60
    failures = [
        failure
        for case in cases
        if (failure := await check_safety_case("safety_gates", case)) is not None
    ]
    assert not failures, (
        f"CONFORMANCE DRIFT: {len(failures)}/{len(cases)} cases differ\n"
        + "\n".join(f"  {failure}" for failure in failures)
    )


def test_the_interpreter_dependent_case_is_retired_and_its_pool_ids_stay_stable() -> (
    None
):
    ids = {case["id"]: case for case in suite_cases("safety_gates")}
    assert COMPILE_FAILED_05 in {entry["id"] for entry in RETIRED_CASES}
    assert COMPILE_FAILED_05 not in ids
    assert all(case["input"]["pattern"] != "(?>a)+" for case in ids.values())
    assert [
        ids[f"safety_test_strings_compile_failed_0{n}"]["input"]["pattern"]
        for n in (6, 7, 8)
    ] == [
        "(?P<1bad>x)",
        "(?P=n)",
        "(?P=n)+$",
    ]
