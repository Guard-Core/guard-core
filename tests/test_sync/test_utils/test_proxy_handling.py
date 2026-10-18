import logging
from unittest.mock import MagicMock, patch

import pytest

from guard_core.models import SecurityConfig
from guard_core.sync._utils import ip_extraction
from guard_core.sync.utils import _extract_from_forwarded_header, extract_client_ip
from tests.test_sync.conftest import SyncMockGuardRequest


@pytest.fixture(autouse=True)
def _reset_forwarded_header_preemption_warning() -> None:
    ip_extraction._forwarded_header_preemption_warned = False


def test_extract_client_ip_without_trusted_proxies() -> None:
    config = SecurityConfig()

    request = SyncMockGuardRequest(
        path="/",
        method="GET",
        headers={"X-Forwarded-For": "1.2.3.4"},
        client_host="127.0.0.1",
    )

    ip = extract_client_ip(request, config)
    assert ip == "127.0.0.1"


def test_extract_client_ip_with_trusted_proxies() -> None:
    config = SecurityConfig(trusted_proxies=["127.0.0.1"])

    request = SyncMockGuardRequest(
        path="/",
        method="GET",
        headers={"X-Forwarded-For": "1.2.3.4"},
        client_host="127.0.0.1",
    )

    ip = extract_client_ip(request, config)
    assert ip == "1.2.3.4"


def test_extract_client_ip_with_cidr_trusted_proxies() -> None:
    config = SecurityConfig(trusted_proxies=["127.0.0.0/8"])

    request = SyncMockGuardRequest(
        path="/",
        method="GET",
        headers={"X-Forwarded-For": "1.2.3.4"},
        client_host="127.0.0.1",
    )

    ip = extract_client_ip(request, config)
    assert ip == "1.2.3.4"


def test_extract_client_ip_with_proxy_depth() -> None:
    config = SecurityConfig(
        trusted_proxies=["127.0.0.1", "1.2.3.4"], trusted_proxy_depth=2
    )

    request = SyncMockGuardRequest(
        path="/",
        method="GET",
        headers={"X-Forwarded-For": "5.6.7.8, 1.2.3.4"},
        client_host="127.0.0.1",
    )

    ip = extract_client_ip(request, config)
    assert ip == "5.6.7.8"


def test_extract_client_ip_without_xforwarded() -> None:
    config = SecurityConfig(trusted_proxies=["127.0.0.1"])

    request = SyncMockGuardRequest(
        path="/",
        method="GET",
        headers={},
        client_host="127.0.0.1",
    )

    ip = extract_client_ip(request, config)
    assert ip == "127.0.0.1"


def test_extract_client_ip_with_untrusted_proxy() -> None:
    config = SecurityConfig(trusted_proxies=["10.0.0.1"])

    request = SyncMockGuardRequest(
        path="/",
        method="GET",
        headers={"X-Forwarded-For": "1.2.3.4"},
        client_host="127.0.0.1",
    )

    ip = extract_client_ip(request, config)
    assert ip == "127.0.0.1"


def test_extract_client_ip_untrusted_proxy_spoof_event_sets_handler_name() -> None:
    config = SecurityConfig(trusted_proxies=["10.0.0.1"])
    mock_agent = MagicMock()

    request = SyncMockGuardRequest(
        path="/",
        method="GET",
        headers={"X-Forwarded-For": "1.2.3.4"},
        client_host="203.0.113.9",
    )

    ip = extract_client_ip(request, config, mock_agent)

    assert ip == "203.0.113.9"
    mock_agent.send_event.assert_called_once()
    sent_event = mock_agent.send_event.call_args[0][0]
    assert sent_event.event_type == "suspicious_request"
    assert sent_event.handler_name == "ip_extraction"
    assert sent_event.decorator_type is None
    assert sent_event.rule_type is None


def test_extract_client_ip_error_handling(
    caplog: pytest.LogCaptureFixture,
) -> None:
    config = SecurityConfig(trusted_proxies=["127.0.0.1"])

    request = SyncMockGuardRequest(
        path="/",
        method="GET",
        headers={"X-Forwarded-For": "invalid-ip"},
        client_host="127.0.0.1",
    )

    with caplog.at_level(logging.WARNING):
        with patch(
            "guard_core.sync._utils.ip_extraction.ip_address",
            side_effect=ValueError("Invalid IP"),
        ):
            ip = extract_client_ip(request, config)
            assert ip == "127.0.0.1"
            assert "Potential IP spoof attempt" in caplog.text


def test_extract_client_ip_no_client() -> None:
    config = SecurityConfig(trusted_proxies=["127.0.0.1"])

    request = SyncMockGuardRequest(
        path="/",
        method="GET",
        headers={"X-Forwarded-For": "1.2.3.4"},
        client_host=None,
    )

    ip = extract_client_ip(request, config)
    assert ip == "unknown"


def test_extract_client_ip_unix_socket_resolves_from_forwarded_header() -> None:
    config = SecurityConfig(trusted_proxies=["unix"])

    request = SyncMockGuardRequest(
        path="/",
        method="GET",
        headers={"X-Forwarded-For": "1.2.3.4"},
        client_host=None,
    )

    ip = extract_client_ip(request, config)
    assert ip == "1.2.3.4"


def test_extract_client_ip_unix_socket_without_header_stays_unknown() -> None:
    config = SecurityConfig(trusted_proxies=["unix"])

    request = SyncMockGuardRequest(
        path="/",
        method="GET",
        headers={},
        client_host=None,
    )

    ip = extract_client_ip(request, config)
    assert ip == "unknown"


def test_extract_client_ip_fallback_to_connecting_ip() -> None:
    config = SecurityConfig(trusted_proxies=["127.0.0.1"], trusted_proxy_depth=3)

    request = SyncMockGuardRequest(
        path="/",
        method="GET",
        headers={"X-Forwarded-For": "1.2.3.4"},
        client_host="127.0.0.1",
    )

    ip = extract_client_ip(request, config)
    assert ip == "127.0.0.1"


def test_extract_client_ip_untrusted_without_forwarded() -> None:
    config = SecurityConfig(trusted_proxies=["10.0.0.1"])

    request = SyncMockGuardRequest(
        path="/",
        method="GET",
        headers={},
        client_host="127.0.0.1",
    )

    ip = extract_client_ip(request, config)
    assert ip == "127.0.0.1"


PREEMPTION_WARNING_TEXT = "already appears inside its own X-Forwarded-For chain"


def test_preemption_warning_fires_when_trusted_proxies_unset(
    caplog: pytest.LogCaptureFixture,
) -> None:
    config = SecurityConfig()

    request = SyncMockGuardRequest(
        path="/",
        method="GET",
        headers={"X-Forwarded-For": "9.9.0.1"},
        client_host="9.9.0.1",
    )

    with caplog.at_level(logging.WARNING):
        ip = extract_client_ip(request, config)

    assert ip == "9.9.0.1"
    assert PREEMPTION_WARNING_TEXT in caplog.text


def test_preemption_warning_fires_in_untrusted_peer_branch(
    caplog: pytest.LogCaptureFixture,
) -> None:
    config = SecurityConfig(trusted_proxies=["10.0.0.1"])

    request = SyncMockGuardRequest(
        path="/",
        method="GET",
        headers={"X-Forwarded-For": "9.9.0.1, 1.2.3.4"},
        client_host="9.9.0.1",
    )

    with caplog.at_level(logging.WARNING):
        ip = extract_client_ip(request, config)

    assert ip == "9.9.0.1"
    assert PREEMPTION_WARNING_TEXT in caplog.text
    assert "Potential IP spoof attempt" in caplog.text


def test_preemption_warning_absent_without_forwarded_header(
    caplog: pytest.LogCaptureFixture,
) -> None:
    config = SecurityConfig()

    request = SyncMockGuardRequest(
        path="/",
        method="GET",
        headers={},
        client_host="9.9.0.1",
    )

    with caplog.at_level(logging.WARNING):
        ip = extract_client_ip(request, config)

    assert ip == "9.9.0.1"
    assert PREEMPTION_WARNING_TEXT not in caplog.text


def test_preemption_warning_absent_when_peer_not_in_chain(
    caplog: pytest.LogCaptureFixture,
) -> None:
    config = SecurityConfig()

    request = SyncMockGuardRequest(
        path="/",
        method="GET",
        headers={"X-Forwarded-For": "1.2.3.4"},
        client_host="127.0.0.1",
    )

    with caplog.at_level(logging.WARNING):
        ip = extract_client_ip(request, config)

    assert ip == "127.0.0.1"
    assert PREEMPTION_WARNING_TEXT not in caplog.text


def test_preemption_warning_emitted_at_most_once(
    caplog: pytest.LogCaptureFixture,
) -> None:
    config = SecurityConfig()

    with caplog.at_level(logging.WARNING):
        for _ in range(5):
            request = SyncMockGuardRequest(
                path="/",
                method="GET",
                headers={"X-Forwarded-For": "9.9.0.1"},
                client_host="9.9.0.1",
            )
            ip = extract_client_ip(request, config)
            assert ip == "9.9.0.1"

    assert caplog.text.count(PREEMPTION_WARNING_TEXT) == 1


CHAIN_TOO_SHORT_WARNING_TEXT = "chain has only"


@pytest.fixture(autouse=True)
def _reset_chain_too_short_warning() -> None:
    ip_extraction._forwarded_header_chain_too_short_warned = False


def test_chain_too_short_warning_fires_on_depth_exceeding_chain_length(
    caplog: pytest.LogCaptureFixture,
) -> None:
    config = SecurityConfig(trusted_proxies=["127.0.0.1"], trusted_proxy_depth=3)

    request = SyncMockGuardRequest(
        path="/",
        method="GET",
        headers={"X-Forwarded-For": "1.2.3.4"},
        client_host="127.0.0.1",
    )

    with caplog.at_level(logging.WARNING):
        ip = extract_client_ip(request, config)

    assert ip == "127.0.0.1"
    assert (
        "The X-Forwarded-For chain has only 1 entries, fewer than the "
        "configured trusted_proxy_depth; chain was 1.2.3.4; falling back to "
        "the connecting peer as the client. This warning is logged once."
    ) in caplog.text


def test_chain_too_short_warning_absent_when_chain_meets_depth(
    caplog: pytest.LogCaptureFixture,
) -> None:
    config = SecurityConfig(
        trusted_proxies=["127.0.0.1", "1.2.3.4"], trusted_proxy_depth=2
    )

    request = SyncMockGuardRequest(
        path="/",
        method="GET",
        headers={"X-Forwarded-For": "5.6.7.8, 1.2.3.4"},
        client_host="127.0.0.1",
    )

    with caplog.at_level(logging.WARNING):
        ip = extract_client_ip(request, config)

    assert ip == "5.6.7.8"
    assert CHAIN_TOO_SHORT_WARNING_TEXT not in caplog.text


def test_chain_too_short_warning_emitted_at_most_once(
    caplog: pytest.LogCaptureFixture,
) -> None:
    config = SecurityConfig(trusted_proxies=["127.0.0.1"], trusted_proxy_depth=3)

    with caplog.at_level(logging.WARNING):
        for _ in range(5):
            request = SyncMockGuardRequest(
                path="/",
                method="GET",
                headers={"X-Forwarded-For": "1.2.3.4"},
                client_host="127.0.0.1",
            )
            extract_client_ip(request, config)

    assert caplog.text.count(CHAIN_TOO_SHORT_WARNING_TEXT) == 1


SELECTED_ENTRY_TRUSTED_PROXY_WARNING_TEXT = "is itself listed in trusted_proxies"


@pytest.fixture(autouse=True)
def _reset_selected_entry_trusted_proxy_warning() -> None:
    ip_extraction._forwarded_header_selected_entry_trusted_proxy_warned = False


def test_selected_entry_trusted_proxy_warning_fires_when_every_entry_is_trusted(
    caplog: pytest.LogCaptureFixture,
) -> None:
    config = SecurityConfig(
        trusted_proxies=["127.0.0.1", "10.0.0.1"], trusted_proxy_depth=2
    )

    request = SyncMockGuardRequest(
        path="/",
        method="GET",
        headers={"X-Forwarded-For": "10.0.0.1, 10.0.0.1"},
        client_host="127.0.0.1",
    )

    with caplog.at_level(logging.WARNING):
        ip = extract_client_ip(request, config)

    assert ip == "10.0.0.1"
    assert SELECTED_ENTRY_TRUSTED_PROXY_WARNING_TEXT in caplog.text


def test_selected_entry_trusted_proxy_warning_absent_for_real_client(
    caplog: pytest.LogCaptureFixture,
) -> None:
    config = SecurityConfig(trusted_proxies=["127.0.0.1"], trusted_proxy_depth=1)

    request = SyncMockGuardRequest(
        path="/",
        method="GET",
        headers={"X-Forwarded-For": "1.2.3.4"},
        client_host="127.0.0.1",
    )

    with caplog.at_level(logging.WARNING):
        ip = extract_client_ip(request, config)

    assert ip == "1.2.3.4"
    assert SELECTED_ENTRY_TRUSTED_PROXY_WARNING_TEXT not in caplog.text


def test_selected_entry_trusted_proxy_warning_emitted_at_most_once(
    caplog: pytest.LogCaptureFixture,
) -> None:
    config = SecurityConfig(
        trusted_proxies=["127.0.0.1", "10.0.0.1"], trusted_proxy_depth=2
    )

    with caplog.at_level(logging.WARNING):
        for _ in range(5):
            request = SyncMockGuardRequest(
                path="/",
                method="GET",
                headers={"X-Forwarded-For": "10.0.0.1, 10.0.0.1"},
                client_host="127.0.0.1",
            )
            extract_client_ip(request, config)

    assert caplog.text.count(SELECTED_ENTRY_TRUSTED_PROXY_WARNING_TEXT) == 1


DEPTH_OVERCOUNTS_HOPS_WARNING_TEXT = (
    "the declared depth over-counts the real proxy hops"
)


@pytest.fixture(autouse=True)
def _reset_depth_overcounts_hops_warning() -> None:
    ip_extraction._forwarded_header_depth_overcounts_hops_warned = False


@pytest.mark.parametrize(
    "rotated_prefix",
    [
        "1.1.1.1, 2.2.2.2",
        "3.3.3.3, 4.4.4.4",
        "5.5.5.5, 6.6.6.6",
        "7.7.7.7, 8.8.8.8",
    ],
)
def test_overcounted_depth_resolves_to_proxy_appended_real_address(
    rotated_prefix: str,
    caplog: pytest.LogCaptureFixture,
) -> None:
    config = SecurityConfig(trusted_proxies=["10.0.0.1"], trusted_proxy_depth=2)

    request = SyncMockGuardRequest(
        path="/",
        method="GET",
        headers={"X-Forwarded-For": f"{rotated_prefix}, 203.0.113.9"},
        client_host="10.0.0.1",
    )

    with caplog.at_level(logging.WARNING):
        ip = extract_client_ip(request, config)

    assert ip == "203.0.113.9"
    assert DEPTH_OVERCOUNTS_HOPS_WARNING_TEXT in caplog.text


def test_overcounted_depth_warning_emitted_at_most_once_across_rotations(
    caplog: pytest.LogCaptureFixture,
) -> None:
    config = SecurityConfig(trusted_proxies=["10.0.0.1"], trusted_proxy_depth=2)

    with caplog.at_level(logging.WARNING):
        for i in range(5):
            request = SyncMockGuardRequest(
                path="/",
                method="GET",
                headers={
                    "X-Forwarded-For": f"{i}.{i}.{i}.{i}, "
                    f"{i + 1}.{i + 1}.{i + 1}.{i + 1}, 203.0.113.9"
                },
                client_host="10.0.0.1",
            )
            extract_client_ip(request, config)

    assert caplog.text.count(DEPTH_OVERCOUNTS_HOPS_WARNING_TEXT) == 1


def test_correctly_declared_depth_resolves_with_no_overcount_warning(
    caplog: pytest.LogCaptureFixture,
) -> None:
    config = SecurityConfig(
        trusted_proxies=["10.0.0.1", "192.168.1.1"], trusted_proxy_depth=2
    )

    request = SyncMockGuardRequest(
        path="/",
        method="GET",
        headers={"X-Forwarded-For": "203.0.113.9, 192.168.1.1"},
        client_host="10.0.0.1",
    )

    with caplog.at_level(logging.WARNING):
        ip = extract_client_ip(request, config)

    assert ip == "203.0.113.9"
    assert DEPTH_OVERCOUNTS_HOPS_WARNING_TEXT not in caplog.text


def test_overcounted_depth_check_is_a_noop_with_empty_trusted_proxies() -> None:
    resolved = ip_extraction._resolve_client_ip_from_forwarded_chain(
        "10.0.0.1", "1.1.1.1, 2.2.2.2, 203.0.113.9", 2, []
    )

    assert resolved == "2.2.2.2"


def test_overcounted_depth_right_side_recognises_ipv4_mapped_trusted_proxy(
    caplog: pytest.LogCaptureFixture,
) -> None:
    config = SecurityConfig(
        trusted_proxies=["10.0.0.1", "192.168.1.1"], trusted_proxy_depth=2
    )

    request = SyncMockGuardRequest(
        path="/",
        method="GET",
        headers={"X-Forwarded-For": "203.0.113.9, ::ffff:192.168.1.1"},
        client_host="10.0.0.1",
    )

    with caplog.at_level(logging.WARNING):
        ip = extract_client_ip(request, config)

    assert ip == "203.0.113.9"
    assert DEPTH_OVERCOUNTS_HOPS_WARNING_TEXT not in caplog.text


def test_overcounted_depth_right_side_recognises_bracketed_ipv6_trusted_proxy(
    caplog: pytest.LogCaptureFixture,
) -> None:
    config = SecurityConfig(
        trusted_proxies=["10.0.0.1", "2001:db8::1"], trusted_proxy_depth=2
    )

    request = SyncMockGuardRequest(
        path="/",
        method="GET",
        headers={"X-Forwarded-For": "203.0.113.9, [2001:db8::1]"},
        client_host="10.0.0.1",
    )

    with caplog.at_level(logging.WARNING):
        ip = extract_client_ip(request, config)

    assert ip == "203.0.113.9"
    assert DEPTH_OVERCOUNTS_HOPS_WARNING_TEXT not in caplog.text


def test_rate_limit_e2e_rotating_prefix_is_limited_on_one_bucket() -> None:
    from guard_core.sync.handlers.ratelimit_handler import check_rate_limit_by_ip

    config = SecurityConfig(
        trusted_proxies=["10.0.0.1"],
        trusted_proxy_depth=2,
        enable_redis=False,
        rate_limit=2,
        rate_limit_window=60,
    )

    allowed_results = []
    for i in range(3):
        request = SyncMockGuardRequest(
            path="/",
            method="GET",
            headers={
                "X-Forwarded-For": f"{i}.{i}.{i}.{i}, {i + 100}.{i}.{i}.{i}, "
                "203.0.113.42"
            },
            client_host="10.0.0.1",
        )
        client_ip = extract_client_ip(request, config)
        allowed_results.append(check_rate_limit_by_ip(client_ip, config))

    assert allowed_results == [True, True, False]


def test_overcounted_depth_walk_skips_trusted_entries_to_its_right() -> None:
    config = SecurityConfig(trusted_proxies=["10.0.0.1"], trusted_proxy_depth=3)

    request = SyncMockGuardRequest(
        path="/",
        method="GET",
        headers={"X-Forwarded-For": "fake1, fake2, 203.0.113.9, 10.0.0.1"},
        client_host="10.0.0.1",
    )

    ip = extract_client_ip(request, config)

    assert ip == "203.0.113.9"


def test_overcounted_depth_walk_gives_the_malformed_identity_on_a_bad_entry() -> None:
    config = SecurityConfig(trusted_proxies=["10.0.0.1"], trusted_proxy_depth=2)

    request = SyncMockGuardRequest(
        path="/",
        method="GET",
        headers={"X-Forwarded-For": "fake1, *"},
        client_host="10.0.0.1",
    )

    ip = extract_client_ip(request, config)

    assert ip == "malformed-xff@10.0.0.1"


def test_resolve_forwarded_chain_right_to_left_returns_none_when_all_trusted() -> None:
    resolved = ip_extraction._resolve_forwarded_chain_right_to_left(
        ["10.0.0.1", "10.0.0.1"], ["10.0.0.1"]
    )

    assert resolved is None


def test_invalid_single_entry_chain_gets_the_malformed_identity_with_one_warning(
    caplog: pytest.LogCaptureFixture,
) -> None:
    config = SecurityConfig(trusted_proxies=["127.0.0.1"], trusted_proxy_depth=1)

    request = SyncMockGuardRequest(
        path="/",
        method="GET",
        headers={"X-Forwarded-For": "invalid-ip-format"},
        client_host="127.0.0.1",
    )

    with caplog.at_level(logging.WARNING):
        ip = extract_client_ip(request, config)

    assert ip == "malformed-xff@127.0.0.1"
    assert caplog.text.count("not an IP address") == 1


GLOB_METACHARACTERS = ("*", "?", "[", "]", "\\")


@pytest.mark.parametrize(
    "forwarded_for, proxy_depth",
    [
        ("", 1),
        ("*", 1),
        ("?", 1),
        ("[", 1),
        ("*:*", 1),
        ("*:*:*", 1),
        ("evil*", 1),
        ("*\n", 1),
        ("*, 5.6.7.8", 2),
        ("[evil, 5.6.7.8", 2),
        ("not-an-ip", 1),
        ("1.2.3.4", 3),
        ("1.2.3.4:abc", 1),
        ("1.2.3.4:5678:9", 1),
        ("[2001:db8::1]:abc", 1),
        ("[2001:db8::1", 1),
        ("[2001:db8::1]x", 1),
        ("[2001:db8::1]:", 1),
    ],
)
def test_extract_from_forwarded_header_rejects_non_ip_entries(
    forwarded_for: str, proxy_depth: int
) -> None:
    assert _extract_from_forwarded_header(forwarded_for, proxy_depth) is None


@pytest.mark.parametrize(
    "forwarded_for, proxy_depth, expected",
    [
        ("5.6.7.8", 1, "5.6.7.8"),
        ("5.6.7.8, 1.2.3.4", 2, "5.6.7.8"),
        ("::1", 1, "::1"),
        ("2001:db8::1", 1, "2001:db8::1"),
        ("[::1]", 1, "::1"),
        ("[2001:db8::1]", 1, "2001:db8::1"),
        ("fe80::1%eth0", 1, "fe80::1"),
        ("1.2.3.4:5678", 1, "1.2.3.4"),
        ("5.6.7.8:1234, 1.2.3.4", 2, "5.6.7.8"),
        ("[2001:db8::1]:5678", 1, "2001:db8::1"),
        ("[::1]:8080", 1, "::1"),
    ],
)
def test_extract_from_forwarded_header_returns_valid_ips(
    forwarded_for: str, proxy_depth: int, expected: str
) -> None:
    assert _extract_from_forwarded_header(forwarded_for, proxy_depth) == expected


@pytest.mark.parametrize(
    "forwarded_for",
    [
        "fe80::1%*",
        "fe80::1%[",
        "fe80::1%]",
        "fe80::1%?",
        "fe80::1%\\",
        "fe80::1%[a]b",
    ],
)
def test_extract_from_forwarded_header_rejects_glob_in_ipv6_zone_id(
    forwarded_for: str,
) -> None:
    assert _extract_from_forwarded_header(forwarded_for, 1) is None


@pytest.mark.parametrize(
    "forwarded_for",
    [
        "*",
        "?",
        "[",
        "evil*",
        "*:*",
        "*:*:*",
    ],
)
def test_glob_metacharacters_short_chain_falls_back_to_peer(
    forwarded_for: str,
) -> None:
    config = SecurityConfig(trusted_proxies=["127.0.0.1"], trusted_proxy_depth=2)

    request = SyncMockGuardRequest(
        path="/",
        method="GET",
        headers={"X-Forwarded-For": forwarded_for},
        client_host="127.0.0.1",
    )

    ip = extract_client_ip(request, config)

    assert ip == "127.0.0.1"
    assert not any(char in ip for char in GLOB_METACHARACTERS)


@pytest.mark.parametrize(
    "forwarded_for",
    [
        "*, 1.2.3.4",
        "*\n, 1.2.3.4",
        "fe80::1%*, 1.2.3.4",
        "fe80::1%[, 1.2.3.4",
        "fe80::1%], 1.2.3.4",
        "fe80::1%?, 1.2.3.4",
        "fe80::1%\\, 1.2.3.4",
        "fe80::1%[a]b, 1.2.3.4",
    ],
)
def test_glob_metacharacters_resolve_via_clean_right_entry(
    forwarded_for: str,
) -> None:
    config = SecurityConfig(trusted_proxies=["127.0.0.1"], trusted_proxy_depth=2)

    request = SyncMockGuardRequest(
        path="/",
        method="GET",
        headers={"X-Forwarded-For": forwarded_for},
        client_host="127.0.0.1",
    )

    ip = extract_client_ip(request, config)

    assert ip == "1.2.3.4"
    assert not any(char in ip for char in GLOB_METACHARACTERS)
