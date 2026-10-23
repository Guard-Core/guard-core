from typing import Any, get_args

import pytest

from guard_core.models import VALID_CLOUD_PROVIDERS, CloudProvider


def test_cloud_provider_literal_members() -> None:
    assert get_args(CloudProvider) == (
        "AWS",
        "GCP",
        "Azure",
        "DigitalOcean",
        "Linode",
        "Vultr",
    )


def test_valid_cloud_providers_is_frozenset_of_literal_members() -> None:
    assert isinstance(VALID_CLOUD_PROVIDERS, frozenset)
    assert VALID_CLOUD_PROVIDERS == frozenset(
        {"AWS", "GCP", "Azure", "DigitalOcean", "Linode", "Vultr"}
    )


def test_valid_cloud_providers_immutable() -> None:
    with pytest.raises(AttributeError):
        providers: Any = VALID_CLOUD_PROVIDERS
        providers.add("DigitalOcean")
