"""Tests for the versioned probe corpus and deterministic mutation engine."""

import pytest

from nulltrace.probes import corpus
from nulltrace.probes.model import ProbeSpec
from nulltrace.probes.mutation import STRATEGIES, base_variant, expand, mutate
from nulltrace.probes.triggers import (
    CROSS_USER_TRIGGERS,
    EXTRACTION_TRIGGERS,
    INJECTION_TRIGGERS,
    SECRET_TRIGGERS,
)


def test_corpus_version_and_families() -> None:
    assert corpus.CORPUS_VERSION == "1.0"
    assert set(corpus.FAMILIES) == {
        "prompt_injection.direct",
        "prompt_injection.role",
        "prompt_injection.boundary",
        "prompt_injection.indirect",
        "info_disclosure.system_prompt",
        "info_disclosure.secret",
        "info_disclosure.cross_user",
    }


def test_every_probe_has_complete_metadata() -> None:
    seen_ids: set[str] = set()
    for spec in corpus.all_probes():
        assert isinstance(spec, ProbeSpec)
        assert spec.probe_id and spec.probe_id not in seen_ids
        seen_ids.add(spec.probe_id)
        assert spec.objective
        assert spec.template
        assert spec.expected_secure_behavior
        assert spec.detection in {
            "token_compliance",
            "canary",
            "secret_marker",
            "private_data_marker",
        }
        assert spec.severity_rationale


def test_token_probes_render_the_token() -> None:
    for name in (
        "prompt_injection.direct",
        "prompt_injection.role",
        "prompt_injection.boundary",
        "prompt_injection.indirect",
    ):
        for spec in corpus.get_family(name):
            assert spec.detection == "token_compliance"
            assert "{token}" not in spec.render("NTPROBE-abc")
            assert "NTPROBE-abc" in spec.render("NTPROBE-abc")


def test_depth_slices_are_monotonic() -> None:
    for name in corpus.FAMILIES:
        d1 = corpus.family_slice(name, 1)
        d2 = corpus.family_slice(name, 2)
        d3 = corpus.family_slice(name, 3)
        assert len(d1) == 1
        assert len(d1) <= len(d2) <= len(d3)
        assert d3 == corpus.get_family(name)
        # Deeper slices extend shallower ones (stable ordering).
        assert d2[: len(d1)] == d1
        assert d3[: len(d2)] == d2


def test_unknown_family_raises() -> None:
    with pytest.raises(KeyError):
        corpus.get_family("nope")


def test_corpus_probes_align_with_simulation_triggers() -> None:
    """Each probe family's base probe must contain a phrase the synthetic
    simulations recognize, so the corpus and fixtures stay in sync."""

    def _hits(text: str, vocab: tuple[str, ...]) -> bool:
        lowered = text.lower()
        return any(phrase in lowered for phrase in vocab)

    first = corpus.get_family("prompt_injection.direct")[0].render("T")
    assert _hits(first, INJECTION_TRIGGERS)
    assert _hits(
        corpus.get_family("info_disclosure.system_prompt")[0].render("T"),
        EXTRACTION_TRIGGERS,
    )
    assert _hits(
        corpus.get_family("info_disclosure.secret")[0].render("T"),
        SECRET_TRIGGERS,
    )
    assert _hits(
        corpus.get_family("info_disclosure.cross_user")[0].render("T"),
        CROSS_USER_TRIGGERS,
    )


# --- Mutation engine -------------------------------------------------------


def test_mutation_is_deterministic_and_traceable() -> None:
    spec = corpus.get_family("prompt_injection.direct")[0]
    base = spec.render("TKN")

    for strategy in STRATEGIES:
        a = mutate(spec, strategy, base, seed="s1")
        b = mutate(spec, strategy, base, seed="s1")
        assert a.text == b.text  # deterministic
        assert a.mutation == strategy
        assert a.variant_id == f"{spec.probe_id}+{strategy}"
        assert a.seed  # recorded seed


def test_mutation_changes_text_but_preserves_token() -> None:
    spec = corpus.get_family("prompt_injection.direct")[0]
    base = spec.render("TKN-KEEP")
    for strategy in STRATEGIES:
        variant = mutate(spec, strategy, base, seed="x")
        assert "TKN-KEEP" in variant.text  # detection signal preserved
        if strategy != "whitespace":
            assert variant.text != base


def test_expand_returns_base_plus_mutations() -> None:
    spec = corpus.get_family("prompt_injection.direct")[0]
    base = spec.render("TKN")
    variants = expand(spec, base, mutations=2, seed="seed")
    assert variants[0] == base_variant(spec, base)
    assert len(variants) == 3
    assert [v.mutation for v in variants] == ["none", "whitespace", "politeness"]


def test_unknown_mutation_strategy_raises() -> None:
    spec = corpus.get_family("prompt_injection.direct")[0]
    with pytest.raises(ValueError):
        mutate(spec, "teleport", spec.render("T"), seed="s")
