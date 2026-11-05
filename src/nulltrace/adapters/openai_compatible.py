
import os
from urllib.parse import urlsplit

import httpx

from nulltrace.adapters.base import TargetAdapter
from nulltrace.core.budget import RequestBudget

DEFAULT_MAX_RESPONSE_BYTES = 2 * 1024 * 1024


class AdapterError(RuntimeError):
    """Raised when an AI target adapter cannot complete a request."""


def validate_base_url(base_url: str) -> str:
    """Validate an OpenAI-compatible API base URL."""

    if not base_url.strip():
        raise ValueError("Base URL cannot be empty.")

    parsed = urlsplit(base_url)

    if parsed.scheme not in {"https", "http"}:
        raise ValueError("Base URL must use HTTPS.")

    if not parsed.hostname:
        raise ValueError("Base URL must contain a valid hostname.")

    if parsed.username or parsed.password:
        raise ValueError("Credentials must not be embedded in the base URL.")

    if parsed.query or parsed.fragment:
        raise ValueError("Base URL must not contain a query or fragment.")

    hostname = parsed.hostname.lower()
    local_hosts = {"localhost", "127.0.0.1", "::1"}

    if parsed.scheme == "http" and hostname not in local_hosts:
        raise ValueError(
            "HTTP is only permitted for localhost. Use HTTPS for remote APIs."
        )

    return base_url.rstrip("/")


class OpenAICompatibleAdapter(TargetAdapter):
    """Adapter for APIs implementing the OpenAI chat completions format."""

    def __init__(
        self,
        model: str,
        base_url: str = "https://api.openai.com/v1",
        api_key_env: str = "OPENAI_API_KEY",
        timeout: float = 30.0,
        max_response_bytes: int = DEFAULT_MAX_RESPONSE_BYTES,
        request_budget: RequestBudget | None = None,
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

    @property
    def target_name(self) -> str:
        return f"openai-compatible:{self.model}"

    def send_prompt(self, prompt: str) -> str:
        if not prompt.strip():
            raise ValueError("Prompt cannot be empty.")

        api_key = os.getenv(self.api_key_env)

        if not api_key:
            raise AdapterError(
                f"API key environment variable '{self.api_key_env}' is not set."
            )

        url = f"{self.base_url}/chat/completions"

        headers = {
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
        }

        payload = {
            "model": self.model,
            "messages": [{"role": "user", "content": prompt}],
        }

        timeout = httpx.Timeout(
            connect=self.timeout,
            read=self.timeout,
            write=self.timeout,
            pool=self.timeout,
        )

        try:
            with httpx.Client(
                timeout=timeout,
                follow_redirects=False,
                trust_env=False,
            ) as client:

                # Consume budget immediately before the outbound request.
                if self.request_budget is not None:
                    self.request_budget.consume()

                with client.stream(
                    "POST",
                    url,
                    headers=headers,
                    json=payload,
                ) as response:
                    if response.is_redirect:
                        raise AdapterError(
                            "The AI API returned a redirect. Redirects are not permitted."
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
                data = httpx.Response(
                    status_code=200,
                    content=bytes(body),
                ).json()

                content = data["choices"][0]["message"]["content"]

            except (ValueError, KeyError, IndexError, TypeError) as exc:
                raise AdapterError(
                    "The AI API returned an unexpected response format."
                ) from exc

            if not isinstance(content, str):
                raise AdapterError("The AI API returned a non-text response.")

            return content

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

