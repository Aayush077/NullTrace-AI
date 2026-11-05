import httpx
import pytest

from nulltrace.adapters.openai_compatible import (
    AdapterError,
    OpenAICompatibleAdapter,
    validate_base_url,
)


def test_adapter_uses_openai_compatible_request(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("TEST_API_KEY", "test-secret")

    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.path == "/v1/chat/completions"
        assert request.headers["Authorization"] == "Bearer test-secret"

        return httpx.Response(
            200,
            json={
                "choices": [
                    {"message": {"content": "Synthetic response"}}
                ]
            },
        )

    transport = httpx.MockTransport(handler)
    original_client = httpx.Client

    monkeypatch.setattr(
        httpx,
        "Client",
        lambda **kwargs: original_client(transport=transport, **kwargs),
    )

    adapter = OpenAICompatibleAdapter(
        model="test-model",
        base_url="https://example.test/v1",
        api_key_env="TEST_API_KEY",
    )

    assert adapter.send_prompt("Hello") == "Synthetic response"


def test_adapter_requires_api_key(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("TEST_API_KEY", raising=False)

    adapter = OpenAICompatibleAdapter(
        model="test-model",
        api_key_env="TEST_API_KEY",
    )

    with pytest.raises(AdapterError, match="not set"):
        adapter.send_prompt("Hello")


def test_adapter_rejects_empty_prompt(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("TEST_API_KEY", "test-secret")

    adapter = OpenAICompatibleAdapter(
        model="test-model",
        api_key_env="TEST_API_KEY",
    )

    with pytest.raises(ValueError, match="cannot be empty"):
        adapter.send_prompt("   ")


def test_adapter_handles_http_errors(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("TEST_API_KEY", "test-secret")

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(401, json={"error": "Unauthorized"})

    transport = httpx.MockTransport(handler)
    original_client = httpx.Client

    monkeypatch.setattr(
        httpx,
        "Client",
        lambda **kwargs: original_client(transport=transport, **kwargs),
    )

    adapter = OpenAICompatibleAdapter(
        model="test-model",
        api_key_env="TEST_API_KEY",
    )

    with pytest.raises(AdapterError, match="HTTP status 401"):
        adapter.send_prompt("Hello")


@pytest.mark.parametrize(
    "url",
    [
        "https://api.openai.com/v1",
        "https://example.com/v1",
        "https://example.com:443/v1",
        "http://localhost:8000/v1",
        "http://127.0.0.1:8000/v1",
        "http://[::1]:8000/v1",
    ],
)
def test_valid_base_urls(url: str) -> None:
    assert validate_base_url(url) == url


@pytest.mark.parametrize(
    "url",
    [
        "",
        "   ",
        " https://example.com/v1",
        "https://",
        "ftp://example.com",
        "http://example.com/v1",
        "https://user:password@example.com/v1",
        "https://example.com/v1?token=secret",
        "https://example.com/v1#fragment",
        "https://127.0.0.1/v1",
        "https://10.0.0.1/v1",
        "https://172.16.0.1/v1",
        "https://192.168.1.10/v1",
        "https://169.254.169.254/latest",
        "https://0.0.0.0/v1",
        "https://[::1]/v1",
        "https://[fc00::1]/v1",
        "https://[fe80::1]/v1",
        "https://localhost/v1",
        "https://service.local/v1",
        "https://service.internal/v1",
        "http://127.0.0.2/v1",
        "https://example.com:0/v1",
        "https://example.com:99999/v1",
        "https://example.com:abc/v1",
        "https://example.com:65536/v1",
    ],
)
def test_invalid_base_urls(url: str) -> None:
    with pytest.raises(ValueError):
        validate_base_url(url)


def test_base_url_trailing_slash_is_removed() -> None:
    assert validate_base_url("https://example.com/v1/") == (
        "https://example.com/v1"
    )


def test_base_url_rejects_control_characters() -> None:
    with pytest.raises(ValueError, match="control characters"):
        validate_base_url("https://example.com/v1\n")


def test_adapter_rejects_redirect(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("OPENAI_API_KEY", "test-key")

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            302,
            headers={"Location": "https://example.org/redirected"},
        )

    transport = httpx.MockTransport(handler)
    original_client = httpx.Client

    monkeypatch.setattr(
        httpx,
        "Client",
        lambda **kwargs: original_client(transport=transport, **kwargs),
    )

    adapter = OpenAICompatibleAdapter(model="test-model")

    with pytest.raises(AdapterError, match="redirect"):
        adapter.send_prompt("Test prompt")


def test_adapter_rejects_oversized_response(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("OPENAI_API_KEY", "test-key")

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json={"choices": [{"message": {"content": "A" * 100}}]},
        )

    transport = httpx.MockTransport(handler)
    original_client = httpx.Client

    monkeypatch.setattr(
        httpx,
        "Client",
        lambda **kwargs: original_client(transport=transport, **kwargs),
    )

    adapter = OpenAICompatibleAdapter(
        model="test-model",
        max_response_bytes=50,
    )

    with pytest.raises(AdapterError, match="size limit"):
        adapter.send_prompt("Test prompt")


def test_adapter_rejects_invalid_content_length(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("OPENAI_API_KEY", "test-key")

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            headers={"Content-Length": "invalid"},
            content=b"{}",
        )

    transport = httpx.MockTransport(handler)
    original_client = httpx.Client

    monkeypatch.setattr(
        httpx,
        "Client",
        lambda **kwargs: original_client(transport=transport, **kwargs),
    )

    adapter = OpenAICompatibleAdapter(model="test-model")

    with pytest.raises(AdapterError, match="invalid Content-Length"):
        adapter.send_prompt("Test prompt")


def test_adapter_rejects_zero_response_limit() -> None:
    with pytest.raises(ValueError, match="greater than zero"):
        OpenAICompatibleAdapter(
            model="test-model",
            max_response_bytes=0,
        )
