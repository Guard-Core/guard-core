from pathlib import Path

from guard_core.models import SecurityConfig

_DOC = Path(__file__).resolve().parent.parent / "docs/configuration/security-config.md"


def _description() -> str:
    description = SecurityConfig.model_fields["enable_dynamic_rules"].description
    assert description is not None
    return description


def test_the_description_says_which_settings_a_rule_adds_merges_and_replaces() -> None:
    text = _description()

    assert (
        "adds its blocked_countries, block_cloud_providers and blocked_user_agents"
        in text
    )
    assert "merges its endpoint_rate_limits per endpoint with the static map" in text
    assert "and replaces whitelist_countries, rate_limit, rate_limit_window" in text
    assert "replaces blocked_countries" not in text


def test_the_configuration_page_carries_the_same_sentence() -> None:
    text = _description()
    start = text.index("adds its blocked_countries")
    end = text.index("while it is active.") + len("while it is active.")

    assert text[start:end] in _DOC.read_text(encoding="utf-8")
