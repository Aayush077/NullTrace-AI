"""Hardened HTTP transport with DNS validation and IP pinning.

Design notes
------------
The adapter resolves and validates the target hostname exactly once, then
pins the connection layer to the validated addresses.  This defends against
DNS rebinding (a second resolution returning a private address) and against
SSRF via DNS responses that mix public and private records.

``PinnedIPBackend`` additionally binds the *origin* of the connection: it
refuses to open a TCP connection for any host or port other than the one the
addresses were validated for.  Without that check, any request routed through
the transport (for example after connection-pool reuse or a programming error
elsewhere) would silently be connected to the pinned addresses regardless of
its actual destination.
"""

import ipaddress
import socket
import ssl
from collections.abc import Iterable

import httpcore
import httpx
from httpcore._backends.base import SOCKET_OPTION, NetworkStream
from httpcore._backends.sync import SyncBackend

try:  # idna is a dependency of httpx; mirror httpx's own hostname encoding.
    import idna as _idna
except ImportError:  # pragma: no cover - idna ships with httpx
    _idna = None  # type: ignore[assignment]


class DNSResolutionError(RuntimeError):
    """Raised when DNS resolution fails or returns unsafe addresses."""


def normalize_hostname(hostname: str) -> str:
    """Normalize a hostname to its lowercase IDNA (punycode) form.

    This matches the form httpx/httpcore use on the wire, so origin
    comparisons inside the pinned backend compare like with like.
    IP literals are returned in canonical form.
    """

    candidate = hostname.strip().lower().rstrip(".")

    if not candidate:
        raise DNSResolutionError("Hostname cannot be empty.")

    # IPv6 literals may arrive with surrounding brackets.
    if candidate.startswith("[") and candidate.endswith("]"):
        unbracketed = candidate[1:-1]
    else:
        unbracketed = candidate

    try:
        return str(ipaddress.ip_address(unbracketed))
    except ValueError:
        pass

    if candidate.isascii():
        return candidate

    if _idna is None:  # pragma: no cover - defensive fallback
        raise DNSResolutionError("Internationalized hostnames are not supported.")

    try:
        return _idna.encode(candidate, uts46=True).decode("ascii")
    except _idna.IDNAError as exc:
        raise DNSResolutionError("Hostname failed IDNA normalization.") from exc


def validate_ip_address(
    value: str,
    allow_loopback: bool = False,
) -> ipaddress.IPv4Address | ipaddress.IPv6Address:
    """Validate a globally routable IP or an explicitly permitted loopback IP."""

    try:
        address = ipaddress.ip_address(value)
    except ValueError as exc:
        raise DNSResolutionError("DNS returned an invalid IP address.") from exc

    if allow_loopback:
        if not address.is_loopback:
            raise DNSResolutionError(
                "Local endpoint resolved to a non-loopback address."
            )
    elif not address.is_global or address.is_multicast:
        raise DNSResolutionError(
            "DNS resolution returned a private, local, reserved, or multicast address."
        )

    return address


def resolve_public_addresses(
    hostname: str,
    port: int,
    allow_loopback: bool = False,
) -> list[str]:
    """Resolve a hostname and reject unsafe or mixed DNS responses."""

    try:
        records = socket.getaddrinfo(
            hostname,
            port,
            family=socket.AF_UNSPEC,
            type=socket.SOCK_STREAM,
        )
    except OSError as exc:
        raise DNSResolutionError("Unable to resolve the API hostname.") from exc

    if not records:
        raise DNSResolutionError("DNS returned no addresses.")

    addresses: list[str] = []

    for record in records:
        address = record[4][0]

        if not isinstance(address, str):
            raise DNSResolutionError("DNS returned an invalid address format.")

        validated = validate_ip_address(address, allow_loopback=allow_loopback)
        normalized = str(validated)

        if normalized not in addresses:
            addresses.append(normalized)

    return addresses


class PinnedIPBackend(SyncBackend):
    """Connect only to prevalidated IP addresses for one expected origin.

    The backend is bound to a single (host, port) pair at construction.  A
    connection attempt for any other host or port is refused rather than
    silently redirected to the pinned addresses.
    """

    def __init__(
        self,
        pinned_addresses: Iterable[str],
        expected_host: str,
        expected_port: int,
        allow_loopback: bool = False,
    ) -> None:
        self._addresses = tuple(pinned_addresses)

        if not self._addresses:
            raise ValueError("At least one pinned IP address is required.")

        if not expected_host:
            raise ValueError("An expected hostname is required.")

        if not 1 <= expected_port <= 65535:
            raise ValueError("Expected port must be between 1 and 65535.")

        for address in self._addresses:
            validate_ip_address(address, allow_loopback=allow_loopback)

        self._expected_host = normalize_hostname(expected_host)
        self._expected_port = expected_port

    def connect_tcp(
        self,
        host: str,
        port: int,
        timeout: float | None = None,
        local_address: str | None = None,
        socket_options: Iterable[SOCKET_OPTION] | None = None,
    ) -> NetworkStream:
        """Connect to a validated address, enforcing the expected origin."""

        requested_host = normalize_hostname(host)

        if requested_host != self._expected_host or port != self._expected_port:
            raise httpcore.ConnectError(
                "Refusing to connect: requested origin "
                f"{requested_host}:{port} does not match the validated origin "
                f"{self._expected_host}:{self._expected_port}."
            )

        last_error: httpcore.ConnectError | httpcore.ConnectTimeout | None = None

        for address in self._addresses:
            try:
                return super().connect_tcp(
                    host=address,
                    port=port,
                    timeout=timeout,
                    local_address=local_address,
                    socket_options=socket_options,
                )
            except (httpcore.ConnectError, httpcore.ConnectTimeout) as exc:
                last_error = exc

        if last_error is not None:
            raise last_error

        raise httpcore.ConnectError("Unable to connect to a validated IP address.")


class PinnedHTTPTransport(httpx.HTTPTransport):
    """HTTPX transport that connects only to prevalidated IP addresses."""

    def __init__(
        self,
        pinned_addresses: Iterable[str],
        expected_host: str,
        expected_port: int,
        allow_loopback: bool = False,
    ) -> None:
        addresses = tuple(pinned_addresses)

        if not addresses:
            raise ValueError("At least one pinned IP address is required.")

        backend = PinnedIPBackend(
            addresses,
            expected_host=expected_host,
            expected_port=expected_port,
            allow_loopback=allow_loopback,
        )

        super().__init__(
            verify=True,
            trust_env=False,
            retries=0,
            http1=True,
            http2=False,
        )

        self._pool.close()

        self._pool = httpcore.ConnectionPool(
            ssl_context=ssl.create_default_context(),
            max_connections=1,
            max_keepalive_connections=0,
            keepalive_expiry=0,
            http1=True,
            http2=False,
            retries=0,
            network_backend=backend,
        )


def resolve_endpoint_addresses(
    scheme: str,
    hostname: str,
    port: int,
) -> tuple[list[str], bool]:
    """Resolve and validate endpoint addresses.

    Returns:
        A tuple containing validated IP addresses and loopback mode.
    """

    normalized_hostname = normalize_hostname(hostname)

    local_hosts = {"localhost", "127.0.0.1", "::1"}

    if scheme == "http":
        if normalized_hostname not in local_hosts:
            raise DNSResolutionError(
                "HTTP is permitted only for explicit localhost endpoints."
            )

        allow_loopback = True
    else:
        allow_loopback = False

    try:
        literal_ip = ipaddress.ip_address(normalized_hostname)
    except ValueError:
        literal_ip = None

    if literal_ip is not None:
        validated = validate_ip_address(
            str(literal_ip),
            allow_loopback=allow_loopback,
        )
        return [str(validated)], allow_loopback

    addresses = resolve_public_addresses(
        normalized_hostname,
        port,
        allow_loopback=allow_loopback,
    )

    return addresses, allow_loopback
