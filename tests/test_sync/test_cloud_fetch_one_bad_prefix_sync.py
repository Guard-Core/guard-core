import pytest
import requests

from guard_core.sync.handlers import _cloud_provider_fetchers as fetchers


class _Response:
    def __init__(self, document: object) -> None:
        self.document = document

    def raise_for_status(self) -> None:
        return None

    def json(self) -> object:
        return self.document


class _Session:
    def __init__(self, document: object) -> None:
        self.document = document

    def __enter__(self) -> "_Session":
        return self

    def __exit__(self, *_args: object) -> None:
        return None

    def get(self, *_args: object, **_kwargs: object) -> _Response:
        return _Response(self.document)


def _serve(monkeypatch: pytest.MonkeyPatch, document: object) -> None:
    monkeypatch.setattr(requests, "Session", lambda *a, **k: _Session(document))


def test_aws_keeps_the_valid_prefixes(monkeypatch: pytest.MonkeyPatch) -> None:
    _serve(
        monkeypatch,
        {
            "prefixes": [
                {"service": "AMAZON", "ip_prefix": "3.5.140.0/22", "region": "x"},
                {"service": "AMAZON", "ip_prefix": "3.5.140.7/22", "region": "x"},
                {"service": "AMAZON", "region": "x"},
                {"ip_prefix": "3.6.0.0/16"},
            ]
        },
    )

    networks, regions = fetchers.fetch_aws_ip_ranges()

    assert {str(network) for network in networks} == {"3.5.140.0/22"}
    assert regions == {"3.5.140.0/22": "x"}


def test_gcp_keeps_the_valid_prefixes(monkeypatch: pytest.MonkeyPatch) -> None:
    _serve(
        monkeypatch,
        {"prefixes": [{"ipv4Prefix": "34.80.0.0/15"}, {"ipv4Prefix": "34.80.0.9/15"}]},
    )

    networks, _ = fetchers.fetch_gcp_ip_ranges()

    assert {str(network) for network in networks} == {"34.80.0.0/15"}
