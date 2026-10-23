from typing import Any, cast

import pytest

from guard_core.models import VALID_CLOUD_PROVIDERS, SyncSecurityConfig


def test_block_cloud_providers_none_construction_stays_none() -> None:
    config = SyncSecurityConfig(block_cloud_providers=None)
    assert config.block_cloud_providers is None


def test_block_cloud_providers_unset_default_is_none() -> None:
    assert SyncSecurityConfig().block_cloud_providers is None


def test_block_cloud_providers_reassignment_to_none_stores_none() -> None:
    config = SyncSecurityConfig(block_cloud_providers={"AWS"})

    config.block_cloud_providers = None

    assert config.block_cloud_providers is None


def test_block_cloud_providers_rejects_invalid_entry() -> None:
    with pytest.raises(ValueError, match="Unknown cloud providers"):
        SyncSecurityConfig(block_cloud_providers={"AWS", "Bogus", "GCP"})


def test_block_cloud_providers_accepts_full_valid_set() -> None:
    config = SyncSecurityConfig(block_cloud_providers={"AWS", "GCP", "Azure"})
    assert config.block_cloud_providers == {"AWS", "GCP", "Azure"}
    assert isinstance(config.block_cloud_providers, frozenset)


def test_block_cloud_providers_accepts_region_carve_out() -> None:
    config = SyncSecurityConfig(block_cloud_providers={"GCP:!us-central1"})
    assert config.block_cloud_providers == {"GCP:!us-central1"}


def test_block_cloud_providers_validator_uses_module_constant() -> None:
    assert VALID_CLOUD_PROVIDERS == frozenset(
        {"AWS", "GCP", "Azure", "DigitalOcean", "Linode", "Vultr"}
    )


def test_block_cloud_providers_rejects_all_invalid_entries() -> None:
    with pytest.raises(ValueError, match="Unknown cloud providers"):
        SyncSecurityConfig(block_cloud_providers={"Bogus1", "Bogus2"})


def test_block_cloud_providers_in_place_mutation_is_rejected() -> None:
    config = SyncSecurityConfig(block_cloud_providers={"AWS"})
    providers: Any = config.block_cloud_providers

    with pytest.raises(AttributeError):
        providers.add("GCP")


def test_block_cloud_providers_reassignment_revalidates() -> None:
    config = SyncSecurityConfig(block_cloud_providers={"AWS"})

    with pytest.raises(ValueError, match="Unknown cloud providers"):
        config.block_cloud_providers = cast(frozenset[str], {"Bogus"})

    assert config.block_cloud_providers == frozenset({"AWS"})


def test_block_cloud_providers_reassignment_accepts_valid_entries() -> None:
    config = SyncSecurityConfig(block_cloud_providers={"AWS"})

    config.block_cloud_providers = cast(frozenset[str], {"GCP", "Azure"})

    assert config.block_cloud_providers == frozenset({"GCP", "Azure"})
    assert isinstance(config.block_cloud_providers, frozenset)


def test_block_cloud_providers_model_copy_update_revalidates() -> None:
    base = SyncSecurityConfig(block_cloud_providers={"AWS"})

    with pytest.raises(ValueError, match="Unknown cloud providers"):
        base.model_copy(update={"block_cloud_providers": {"Bogus"}})

    assert base.block_cloud_providers == frozenset({"AWS"})


def test_block_cloud_providers_model_copy_update_accepts_valid_entries() -> None:
    base = SyncSecurityConfig(block_cloud_providers={"AWS"})

    copied = base.model_copy(update={"block_cloud_providers": {"GCP"}})

    assert copied.block_cloud_providers == frozenset({"GCP"})
    assert isinstance(copied.block_cloud_providers, frozenset)


def test_block_cloud_providers_accepts_digitalocean_linode_vultr() -> None:
    config = SyncSecurityConfig(
        block_cloud_providers={"DigitalOcean", "Linode", "Vultr"}
    )
    assert config.block_cloud_providers == frozenset(
        {"DigitalOcean", "Linode", "Vultr"}
    )


def test_block_cloud_providers_accepts_expanded_provider_carve_out() -> None:
    config = SyncSecurityConfig(block_cloud_providers={"DigitalOcean:!nyc3"})
    assert config.block_cloud_providers == frozenset({"DigitalOcean:!nyc3"})


def test_block_cloud_providers_canonicalizes_lowercase_expanded_names() -> None:
    config = SyncSecurityConfig(block_cloud_providers={"digitalocean"})
    assert config.block_cloud_providers == frozenset({"DigitalOcean"})


def test_block_cloud_providers_rejects_misspelled_names() -> None:
    with pytest.raises(ValueError, match="digitalocen"):
        SyncSecurityConfig(block_cloud_providers={"digitalocen"})
