from nulltrace.core.redaction import REDACTED, redact_text


def test_known_secret_values_are_redacted() -> None:
    text = "the key is super-secret-value-123 okay"
    assert (
        redact_text(text, ["super-secret-value-123"])
        == f"the key is {REDACTED} okay"
    )


def test_short_known_secrets_are_not_replaced_globally() -> None:
    # Values shorter than 4 characters would redact half the text.
    assert redact_text("a cat sat", ["a"]) == "a cat sat"


def test_openai_style_keys_are_redacted() -> None:
    result = redact_text("here: sk-abcdef1234567890 done")
    assert "sk-abcdef1234567890" not in result
    assert REDACTED in result


def test_bearer_tokens_are_redacted() -> None:
    result = redact_text("Authorization: Bearer abc123def456ghi")
    assert "abc123def456ghi" not in result


def test_key_value_assignments_are_redacted() -> None:
    result = redact_text("api_key=verysecretvalue")
    assert "verysecretvalue" not in result
    assert "api_key=" in result


def test_aws_and_github_tokens_are_redacted() -> None:
    result = redact_text(
        "AKIAIOSFODNN7EXAMPLE and ghp_abcdefghij1234567890abcd"
    )
    assert "AKIA" not in result.replace(REDACTED, "")
    assert "ghp_" not in result.replace(REDACTED, "")


def test_synthetic_markers_survive_redaction() -> None:
    # Synthetic markers are deliberately shaped so they are NOT redacted:
    # they are the evidence.
    text = "leak: SYNTHETIC-SECRET-NT-000-DEMO and NT-SYS-CANARY-4f7a2b"
    assert redact_text(text) == text


def test_plain_text_is_untouched() -> None:
    text = "The quick brown fox jumps over the lazy dog."
    assert redact_text(text) == text
