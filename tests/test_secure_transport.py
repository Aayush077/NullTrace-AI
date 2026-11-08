
import socket
import ssl
from unittest.mock import MagicMock, patch

import httpcore
import pytest
from httpcore import HTTPConnection, Origin
from httpcore._backends.sync import SyncBackend

from nulltrace.adapters.secure_transport import (
    DNSResolutionError,
    PinnedHTTPTransport,
    PinnedIPBackend,
    normalize_hostname,
    resolve_endpoint_addresses,
    resolve_public_addresses,
    validate_ip_address,
)


@pytest.mark.parametrize(
    "address",
    [
        "8.8.8.8",
        "1.1.1.1",
        "2606:4700:4700::1111",
    ],
)
def test_validate_accepts_global_addresses(address: str) -> None:
    assert str(validate_ip_address(address)) == address


@pytest.mark.parametrize(
    "address",
    [
        "127.0.0.1",
        "10.0.0.1",
        "172.16.0.1",
        "192.168.1.1",
        "169.254.169.254",
        "::1",
        "fc00::1",
        "fe80::1",
        "224.0.0.1",
    ],
)
def test_validate_rejects_non_global_addresses(address: str) -> None:
    with pytest.raises(DNSResolutionError):
        validate_ip_address(address)


def test_validate_rejects_invalid_ip() -> None:
    with pytest.raises(DNSResolutionError):
        validate_ip_address("not-an-ip")


def test_resolve_accepts_public_dns_records() -> None:
    records = [
        (
            socket.AF_INET,
            socket.SOCK_STREAM,
            socket.IPPROTO_TCP,
            "",
            ("8.8.8.8", 443),
        ),
        (
            socket.AF_INET,
            socket.SOCK_STREAM,
            socket.IPPROTO_TCP,
            "",
            ("1.1.1.1", 443),
        ),
    ]

    with patch(
        "nulltrace.adapters.secure_transport.socket.getaddrinfo",
        return_value=records,
    ):
        result = resolve_public_addresses("example.com", 443)

    assert result == ["8.8.8.8", "1.1.1.1"]


def test_resolve_rejects_mixed_public_and_private_records() -> None:
    records = [
        (
            socket.AF_INET,
            socket.SOCK_STREAM,
            socket.IPPROTO_TCP,
            "",
            ("8.8.8.8", 443),
        ),
        (
            socket.AF_INET,
            socket.SOCK_STREAM,
            socket.IPPROTO_TCP,
            "",
            ("192.168.1.10", 443),
        ),
    ]

    with patch(
        "nulltrace.adapters.secure_transport.socket.getaddrinfo",
        return_value=records,
    ):
        with pytest.raises(DNSResolutionError):
            resolve_public_addresses("example.com", 443)


def test_resolve_rejects_empty_dns_response() -> None:
    with patch(
        "nulltrace.adapters.secure_transport.socket.getaddrinfo",
        return_value=[],
    ):
        with pytest.raises(DNSResolutionError, match="no addresses"):
            resolve_public_addresses("example.com", 443)


def test_resolve_handles_dns_failure() -> None:
    with patch(
        "nulltrace.adapters.secure_transport.socket.getaddrinfo",
        side_effect=socket.gaierror,
    ):
        with pytest.raises(DNSResolutionError, match="Unable to resolve"):
            resolve_public_addresses("example.com", 443)


# ---------------------------------------------------------------------------
# Hostname normalization
# ---------------------------------------------------------------------------


def test_normalize_hostname_lowercases_and_strips_dot() -> None:
    assert normalize_hostname("API.Example.COM.") == "api.example.com"


def test_normalize_hostname_encodes_idna() -> None:
    assert normalize_hostname("münchen.example") == "xn--mnchen-3ya.example"


def test_normalize_hostname_canonicalizes_ip_literals() -> None:
    assert normalize_hostname("[::1]") == "::1"
    assert normalize_hostname("127.0.0.1") == "127.0.0.1"


def test_normalize_hostname_rejects_empty() -> None:
    with pytest.raises(DNSResolutionError):
        normalize_hostname("   ")


# ---------------------------------------------------------------------------
# PinnedIPBackend origin binding (regression tests for the host/port fix)
# ---------------------------------------------------------------------------


def _backend() -> PinnedIPBackend:
    return PinnedIPBackend(
        ["8.8.8.8"],
        expected_host="example.com",
        expected_port=443,
    )


def test_pinned_backend_rejects_empty_addresses() -> None:
    with pytest.raises(ValueError, match="At least one"):
        PinnedIPBackend([], expected_host="example.com", expected_port=443)


def test_pinned_backend_rejects_private_addresses() -> None:
    with pytest.raises(DNSResolutionError):
        PinnedIPBackend(
            ["127.0.0.1"], expected_host="example.com", expected_port=443
        )


def test_pinned_backend_rejects_invalid_expected_port() -> None:
    with pytest.raises(ValueError, match="port"):
        PinnedIPBackend(["8.8.8.8"], expected_host="example.com", expected_port=0)


def test_pinned_backend_connects_using_pinned_address() -> None:
    backend = _backend()
    expected_stream = object()

    with patch.object(
        SyncBackend,
        "connect_tcp",
        return_value=expected_stream,
    ) as connect:
        result = backend.connect_tcp(host="example.com", port=443)

    assert result is expected_stream
    connect.assert_called_once()
    assert connect.call_args.kwargs["host"] == "8.8.8.8"
    assert connect.call_args.kwargs["port"] == 443


def test_pinned_backend_refuses_unexpected_host() -> None:
    backend = _backend()

    with patch.object(SyncBackend, "connect_tcp") as connect:
        with pytest.raises(httpcore.ConnectError, match="does not match"):
            backend.connect_tcp(host="evil.example", port=443)

    connect.assert_not_called()


def test_pinned_backend_refuses_unexpected_port() -> None:
    backend = _backend()

    with patch.object(SyncBackend, "connect_tcp") as connect:
        with pytest.raises(httpcore.ConnectError, match="does not match"):
            backend.connect_tcp(host="example.com", port=8443)

    connect.assert_not_called()


def test_pinned_backend_accepts_case_variant_host() -> None:
    backend = _backend()
    expected_stream = object()

    with patch.object(
        SyncBackend,
        "connect_tcp",
        return_value=expected_stream,
    ):
        result = backend.connect_tcp(host="EXAMPLE.com", port=443)

    assert result is expected_stream


# ---------------------------------------------------------------------------
# PinnedHTTPTransport
# ---------------------------------------------------------------------------


def _transport() -> PinnedHTTPTransport:
    return PinnedHTTPTransport(
        ["8.8.8.8"],
        expected_host="example.com",
        expected_port=443,
    )


def test_pinned_transport_uses_custom_backend() -> None:
    transport = _transport()

    try:
        assert isinstance(
            transport._pool._network_backend,
            PinnedIPBackend,
        )
    finally:
        transport.close()


def test_pinned_transport_keeps_tls_verification_enabled() -> None:
    transport = _transport()

    try:
        context = transport._pool._ssl_context
        assert context is not None
        assert context.verify_mode == ssl.CERT_REQUIRED
        assert context.check_hostname is True
    finally:
        transport.close()


def test_pinned_transport_disables_connection_retries() -> None:
    transport = _transport()

    try:
        assert transport._pool._retries == 0
        assert transport._pool._max_keepalive_connections == 0
    finally:
        transport.close()


def test_pinned_transport_can_be_closed() -> None:
    transport = _transport()

    transport.close()

    assert transport._pool is not None


def test_http_connection_preserves_original_hostname_for_tls() -> None:
    backend = MagicMock()
    stream = MagicMock()

    backend.connect_tcp.return_value = stream
    stream.start_tls.return_value = stream

    connection = HTTPConnection(
        origin=Origin(
            scheme=b"https",
            host=b"api.example.test",
            port=443,
        ),
        network_backend=backend,
    )

    request = httpcore.Request(
        method=b"GET",
        url=httpcore.URL(
            scheme=b"https",
            host=b"api.example.test",
            port=443,
            target=b"/",
        ),
    )

    connection._connect(request)

    backend.connect_tcp.assert_called_once()
    assert backend.connect_tcp.call_args.kwargs["host"] == "api.example.test"

    stream.start_tls.assert_called_once()
    assert (
        stream.start_tls.call_args.kwargs["server_hostname"]
        == "api.example.test"
    )


# ---------------------------------------------------------------------------
# Loopback behavior
# ---------------------------------------------------------------------------


def test_loopback_validation_accepts_localhost_addresses() -> None:
    assert str(validate_ip_address("127.0.0.1", allow_loopback=True)) == "127.0.0.1"
    assert str(validate_ip_address("::1", allow_loopback=True)) == "::1"


@pytest.mark.parametrize(
    "address",
    [
        "192.168.1.10",
        "10.0.0.1",
        "169.254.169.254",
        "8.8.8.8",
    ],
)
def test_loopback_validation_rejects_non_loopback_addresses(
    address: str,
) -> None:
    with pytest.raises(DNSResolutionError):
        validate_ip_address(address, allow_loopback=True)


def test_loopback_dns_rejects_mixed_loopback_and_private_records() -> None:
    records = [
        (
            socket.AF_INET,
            socket.SOCK_STREAM,
            socket.IPPROTO_TCP,
            "",
            ("127.0.0.1", 8000),
        ),
        (
            socket.AF_INET,
            socket.SOCK_STREAM,
            socket.IPPROTO_TCP,
            "",
            ("192.168.1.10", 8000),
        ),
    ]

    with patch(
        "nulltrace.adapters.secure_transport.socket.getaddrinfo",
        return_value=records,
    ):
        with pytest.raises(DNSResolutionError):
            resolve_public_addresses(
                "localhost",
                8000,
                allow_loopback=True,
            )


def test_endpoint_resolution_rejects_http_for_remote_hosts() -> None:
    with pytest.raises(DNSResolutionError, match="localhost"):
        resolve_endpoint_addresses("http", "example.com", 80)


def test_endpoint_resolution_allows_loopback_literal_for_http() -> None:
    addresses, allow_loopback = resolve_endpoint_addresses(
        "http", "127.0.0.1", 8000
    )

    assert addresses == ["127.0.0.1"]
    assert allow_loopback is True


def test_endpoint_resolution_rejects_private_literal_for_https() -> None:
    with pytest.raises(DNSResolutionError):
        resolve_endpoint_addresses("https", "10.0.0.1", 443)
