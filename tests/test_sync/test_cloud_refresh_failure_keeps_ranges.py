import ipaddress
from unittest.mock import patch

from guard_core.sync.handlers.cloud_handler import cloud_handler

AWS_RANGE = ipaddress.ip_network("198.51.100.0/24")


def _seed_aws_ranges() -> None:
    cloud_handler.redis_handler = None
    cloud_handler.ip_ranges["AWS"] = {AWS_RANGE}
    cloud_handler.network_regions["AWS"] = {str(AWS_RANGE): "us-east-1"}


def test_a_failed_refresh_without_redis_keeps_the_previous_ranges() -> None:
    _seed_aws_ranges()

    with patch(
        "guard_core.sync.handlers.cloud_handler.fetch_aws_ip_ranges",
        side_effect=RuntimeError("provider unreachable"),
    ):
        cloud_handler.refresh({"AWS"})

    assert cloud_handler.is_cloud_ip("198.51.100.7", {"AWS"})
    assert cloud_handler.network_regions["AWS"] == {str(AWS_RANGE): "us-east-1"}


def test_a_first_failed_fetch_still_records_an_empty_provider() -> None:
    cloud_handler.ip_ranges = {}
    cloud_handler.redis_handler = None

    with patch(
        "guard_core.sync.handlers.cloud_handler.fetch_aws_ip_ranges",
        side_effect=RuntimeError("provider unreachable"),
    ):
        cloud_handler.refresh({"AWS"})

    assert cloud_handler.ip_ranges["AWS"] == set()
