import pytest

from guard_core.models import SecurityConfig
from guard_core.utils import detect_penetration_attempt
from tests.conftest import MockGuardRequest
from tests.test_detection.benign_prompt_corpus import BENIGN_PROMPTS


@pytest.mark.parametrize("prompt", BENIGN_PROMPTS, ids=lambda p: p[:40])
async def test_prompts_and_code_questions_stay_clean_in_a_json_body(
    prompt: str,
) -> None:
    import json

    body = json.dumps({"messages": [{"role": "user", "content": prompt}]}).encode()
    request = MockGuardRequest(
        method="POST",
        path="/v1/chat",
        headers={"content-type": "application/json", "content-length": str(len(body))},
        body_content=body,
    )

    result = await detect_penetration_attempt(request, SecurityConfig())

    assert result.is_threat is False, result.threat_categories
