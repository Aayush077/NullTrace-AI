"""Adapter for OpenAI-compatible chat completion APIs.

Supports single prompts, multi-turn conversations, and tool-call probing
(presenting synthetic tool definitions and parsing which calls the model
*attempted* — attempts are evidence, they are never executed).

Streaming and structured-output modes are not implemented; responses are
read fully, size-limited, and parsed defensively.
"""

import ipaddress
import json
import os
from typing import Any
from urllib.parse import urlsplit

import httpx

from nulltrace.adapters.base import TargetAdapter
from nulltrace.adapters.capabilities import (
    ConversationCapability,
    ToolCallAttempt,
    ToolCallProbeCapability,
    ToolCallProbeResult,
)
from nulltrace.adapters.secure_transport import (
    DNSResolutionError,
    PinnedHTTPTransport,
    resolve_endpoint_addresses,
)
from nulltrace.core.budget import RequestBudget, RequestBudgetExceeded

DEFAULT_MAX_RESPONSE_BYTES = 2 * 1024 * 1024

_VALID_ROLES = {"system", "user", "assistant"}


class AdapterError(RuntimeError):
    """Raised when an AI target adapter cannot complete a request."""


def validate_base_url(base_url: str) -> str:
    """Validate an OpenAI-compatible API base URL."""

    if not base_url or not base_url.strip():
        raise ValueError("Base URL cannot be empty.")

    if any(ord(char) < 32 or ord(char) == 127 for char in base_url):
        raise ValueError("Base URL contains invalid control characters.")

    if base_url != base_url.strip():
        raise ValueError("Base URL must not contain surrounding whitespace.")

    try:
        parsed = urlsplit(base_url)
        hostname = parsed.hostname
        port = parsed.port
    except ValueError as exc:
        raise ValueError("Base URL is malformed.") from exc

    if parsed.scheme not in {"https", "http"}:
        raise ValueError("Base URL must use HTTPS.")

    if not hostname:
        raise ValueError("Base URL must contain a valid hostname.")

    if parsed.username is not None or parsed.password is not None:
        raise ValueError("Credentials must not be embedded in the base URL.")

    if parsed.query or parsed.fragment or "?" in base_url or "#" in base_url:
        raise ValueError("Base URL must not contain a query or fragment.")

    if port == 0:
        raise ValueError("Port must be between 1 and 65535.")

    hostname = hostname.lower().rstrip(".")

    local_hosts = {"localhost", "127.0.0.1", "::1"}

    local_suffixes = (
        ".localhost",
        ".local",
        ".internal",
        ".lan",
        ".home.arpa",
    )

    is_local_hostname = (
        hostname == "localhost"
        or any(hostname.endswith(suffix) for suffix in local_suffixes)
    )

    if parsed.scheme == "http":
        if hostname not in local_hosts:
            raise ValueError(
                "HTTP is only permitted for explicit localhost endpoints. "
                "Use HTTPS for remote APIs."
            )

        return base_url.rstrip("/")

    if is_local_hostname:
        raise ValueError(
            "Local hostnames are not permitted for remote API endpoints."
        )

    try:
        ip_address = ipaddress.ip_address(hostname)
    except ValueError:
        ip_address = None

    if ip_address is not None and (
        not ip_address.is_global or ip_address.is_multicast
    ):
        raise ValueError(
            "Private, local, or reserved IP addresses are not permitted."
        )

    return base_url.rstrip("/")


def _validate_messages(messages: list[dict[str, str]]) -> None:
    if not messages:
        raise ValueError("Conversation cannot be empty.")

    for message in messages:
        role = message.get("role")
        content = message.get("content")

        if role not in _VALID_ROLES:
            raise ValueError(f"Invalid message role: {role!r}.")

        if not isinstance(content, str):
            raise ValueError("Message content must be a string.")


class OpenAICompatibleAdapter(
    TargetAdapter,
    ConversationCapability,
    ToolCallProbeCapability,
):
    """Adapter for APIs implementing the OpenAI chat completions format."""

    def __init__(
        self,
        model: str,
        base_url: str = "https://api.openai.com/v1",
        api_key_env: str = "OPENAI_API_KEY",
        timeout: float = 30.0,
        max_response_bytes: int = DEFAULT_MAX_RESPONSE_BYTES,
        request_budget: RequestBudget | None = None,
        transport: httpx.BaseTransport | None = None,
    ) -> None:
        if not model.strip():
            raise ValueError("Model name cannot be empty.")

        if timeout <= 0:
            raise ValueError("Timeout must be greater than zero.")

        if max_response_bytes <= 0:
            raise ValueError("Maximum response size must be greater than zero.")

        self.model = model
        self.base_url = validate_base_url(base_url)
        self.api_key_env = api_key_env
        self.timeout = timeout
        self.max_response_bytes = max_response_bytes
        self.request_budget = request_budget
        self.transport = transport

    @property
    def target_name(self) -> str:
        return f"openai-compatible:{self.model}"

    # ------------------------------------------------------------------
    # Public interface
    # ------------------------------------------------------------------

    def send_prompt(self, prompt: str) -> str:
        """Send a text prompt and return the API's text response."""

        if not prompt.strip():
            raise ValueError("Prompt cannot be empty.")

        return self.send_conversation([{"role": "user", "content": prompt}])

    def send_conversation(self, messages: list[dict[str, str]]) -> str:
        """Send a multi-turn conversation and return the final reply text."""

        _validate_messages(messages)

        data = self._execute({"model": self.model, "messages": messages})
        message = self._first_message(data)
        content = message.get("content")

        if not isinstance(content, str):
            raise AdapterError("The AI API returned a non-text response.")

        return content

    def request_with_tools(
        self,
        messages: list[dict[str, str]],
        tools: list[dict[str, object]],
    ) -> ToolCallProbeResult:
        """Present tool definitions and parse attempted tool calls.

        Attempted calls are returned as structured evidence; nothing is
        ever executed by the framework.
        """

        _validate_messages(messages)

        if not tools:
            raise ValueError("At least one tool definition is required.")

        data = self._execute(
            {"model": self.model, "messages": messages, "tools": tools}
        )
        message = self._first_message(data)

        content = message.get("content")
        text = content if isinstance(content, str) else ""

        raw_calls = message.get("tool_calls")
        attempts: list[ToolCallAttempt] = []

        if raw_calls is not None:
            if not isinstance(raw_calls, list):
                raise AdapterError(
                    "The AI API returned an unexpected response format."
                )

            for raw_call in raw_calls:
                try:
                    function = raw_call["function"]
                    name = function["name"]
                    arguments = function.get("arguments", "{}")
                except (TypeError, KeyError) as exc:
                    raise AdapterError(
                        "The AI API returned an unexpected response format."
                    ) from exc

                if not isinstance(name, str) or not isinstance(arguments, str):
                    raise AdapterError(
                        "The AI API returned an unexpected response format."
                    )

                attempts.append(
                    ToolCallAttempt(name=name, arguments_json=arguments)
                )

        return ToolCallProbeResult(text=text, tool_calls=tuple(attempts))

    # ------------------------------------------------------------------
    # Request execution
    # ------------------------------------------------------------------

    def _create_transport(self) -> httpx.BaseTransport:
        """Create a fresh pinned transport for a network request."""

        parsed = urlsplit(self.base_url)
        hostname = parsed.hostname

        if hostname is None:
            raise AdapterError("The configured API hostname is invalid.")

        port = parsed.port or (443 if parsed.scheme == "https" else 80)

        try:
            addresses, allow_loopback = resolve_endpoint_addresses(
                parsed.scheme,
                hostname,
                port,
            )
        except DNSResolutionError as exc:
            raise AdapterError(
                "The API hostname failed DNS or endpoint security validation."
            ) from exc

        return PinnedHTTPTransport(
            addresses,
            expected_host=hostname,
            expected_port=port,
            allow_loopback=allow_loopback,
        )

    @staticmethod
    def _first_message(data: Any) -> dict[str, Any]:
        try:
            message = data["choices"][0]["message"]
        except (KeyError, IndexError, TypeError) as exc:
            raise AdapterError(
                "The AI API returned an unexpected response format."
            ) from exc

        if not isinstance(message, dict):
            raise AdapterError(
                "The AI API returned an unexpected response format."
            )

        return message

    def _execute(self, payload: dict[str, Any]) -> Any:
        """Send one bounded, budgeted request and return parsed JSON."""

        api_key = os.getenv(self.api_key_env)

        if not api_key:
            raise AdapterError(
                f"API key environment variable '{self.api_key_env}' is not set."
            )

        # Avoid DNS resolution when the request budget is already exhausted.
        if (
            self.request_budget is not None
            and self.request_budget.remaining <= 0
        ):
            raise AdapterError("Assessment request budget exhausted.")

        url = f"{self.base_url}/chat/completions"

        headers = {
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
        }

        timeout = httpx.Timeout(
            connect=self.timeout,
            read=self.timeout,
            write=self.timeout,
            pool=self.timeout,
        )

        active_transport = self.transport
        owns_transport = active_transport is None

        try:
            if active_transport is None:
                active_transport = self._create_transport()

            with httpx.Client(
                transport=active_transport,
                timeout=timeout,
                follow_redirects=False,
                trust_env=False,
            ) as client:
                if self.request_budget is not None:
                    try:
                        self.request_budget.consume()
                    except RequestBudgetExceeded as exc:
                        raise AdapterError(
                            "Assessment request budget exhausted."
                        ) from exc

                with client.stream(
                    "POST",
                    url,
                    headers=headers,
                    json=payload,
                ) as response:
                    if response.is_redirect:
                        raise AdapterError(
                            "The AI API returned a redirect. "
                            "Redirects are not permitted."
                        )

                    response.raise_for_status()

                    content_length = response.headers.get("content-length")

                    if content_length is not None:
                        try:
                            declared_size = int(content_length)
                        except ValueError as exc:
                            raise AdapterError(
                                "The AI API returned an invalid Content-Length header."
                            ) from exc

                        if (
                            declared_size < 0
                            or declared_size > self.max_response_bytes
                        ):
                            raise AdapterError(
                                "The AI API response exceeds the configured size limit."
                            )

                    body = bytearray()

                    for chunk in response.iter_bytes():
                        if len(body) + len(chunk) > self.max_response_bytes:
                            raise AdapterError(
                                "The AI API response exceeds the configured size limit."
                            )

                        body.extend(chunk)

            try:
                return json.loads(bytes(body))
            except ValueError as exc:
                raise AdapterError(
                    "The AI API returned an unexpected response format."
                ) from exc

        except AdapterError:
            raise

        except httpx.TimeoutException as exc:
            raise AdapterError("The AI API request timed out.") from exc

        except httpx.HTTPStatusError as exc:
            status = exc.response.status_code
            raise AdapterError(
                f"The AI API returned HTTP status {status}."
            ) from exc

        except httpx.RequestError as exc:
            raise AdapterError(
                "Unable to connect to the configured AI API endpoint."
            ) from exc

        finally:
            if owns_transport and active_transport is not None:
                active_transport.close()
