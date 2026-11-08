"""Tests for the repeated-sampling and consistency engine."""

from collections.abc import Callable

from nulltrace.core.budget import RequestBudget
from nulltrace.core.models import Confidence
from nulltrace.core.sampling import (
    SamplingConfig,
    SamplingPolicy,
    run_samples,
)


def _responder(pattern: list[bool]) -> Callable[[], str]:
    """A probe that returns 'HIT' on True steps, 'safe' on False steps."""

    state = {"i": 0}

    def probe() -> str:
        value = pattern[state["i"] % len(pattern)]
        state["i"] += 1
        return "HIT" if value else "safe"

    return probe


def _detector(response: str) -> bool:
    return "HIT" in response


def test_single_policy_one_sample() -> None:
    result = run_samples(
        _responder([True]),
        _detector,
        SamplingConfig(policy=SamplingPolicy.SINGLE),
    )
    assert result.samples_taken == 1
    assert result.is_violation()
    # Attribution ceiling preserved for a single conclusive sample.
    assert result.confidence(Confidence.HIGH) is Confidence.HIGH


def test_repeated_majority_violation() -> None:
    result = run_samples(
        _responder([True, True, False]),
        _detector,
        SamplingConfig(policy=SamplingPolicy.REPEATED, samples=3),
    )
    assert result.samples_taken == 3
    assert result.violations == 2
    assert result.is_violation()  # majority
    assert 0.66 < result.violation_rate < 0.67


def test_repeated_minority_is_not_violation() -> None:
    result = run_samples(
        _responder([True, False, False]),
        _detector,
        SamplingConfig(policy=SamplingPolicy.REPEATED, samples=3),
    )
    assert not result.is_violation()
    assert result.confidence(Confidence.HIGH) is Confidence.LOW


def test_strict_requires_unanimity() -> None:
    mixed = run_samples(
        _responder([True, True, False]),
        _detector,
        SamplingConfig(policy=SamplingPolicy.STRICT, samples=3),
    )
    assert not mixed.is_violation()

    unanimous = run_samples(
        _responder([True]),
        _detector,
        SamplingConfig(policy=SamplingPolicy.STRICT, samples=3),
    )
    assert unanimous.is_violation()
    assert unanimous.consistency == 1.0


def test_statistical_threshold() -> None:
    config = SamplingConfig(
        policy=SamplingPolicy.STATISTICAL, samples=5, threshold=0.6
    )
    below = run_samples(_responder([True, True, False, False, False]), _detector, config)
    assert not below.is_violation()  # 0.4 < 0.6

    above = run_samples(_responder([True, True, True, True, False]), _detector, config)
    assert above.is_violation()  # 0.8 >= 0.6


def test_inconsistent_sampling_downgrades_confidence() -> None:
    # 3/5 violations: majority violation, but low consistency (0.6).
    result = run_samples(
        _responder([True, True, True, False, False]),
        _detector,
        SamplingConfig(policy=SamplingPolicy.REPEATED, samples=5),
    )
    assert result.is_violation()
    # Attribution ceiling HIGH is downgraded by poor reproducibility.
    assert result.confidence(Confidence.HIGH) is Confidence.MEDIUM


def test_high_consistency_keeps_ceiling() -> None:
    result = run_samples(
        _responder([True, True, True, True, False]),
        _detector,
        SamplingConfig(policy=SamplingPolicy.REPEATED, samples=5),
    )
    assert result.is_violation()
    assert result.consistency == 0.8
    assert result.confidence(Confidence.HIGH) is Confidence.HIGH


def test_sampling_never_exceeds_budget() -> None:
    budget = RequestBudget(max_requests=2)
    result = run_samples(
        _responder([True]),
        _detector,
        SamplingConfig(policy=SamplingPolicy.REPEATED, samples=10),
        budget=budget,
    )
    assert result.samples_taken == 2  # capped by remaining budget


def test_summary_reports_distinct_properties() -> None:
    result = run_samples(
        _responder([True, True, False, True, True]),
        _detector,
        SamplingConfig(policy=SamplingPolicy.REPEATED, samples=5),
    )
    summary = result.summary(Confidence.HIGH)
    # violation_rate, consistency, and confidence are separate fields.
    assert summary["violation_rate"] == 0.8
    assert summary["consistency"] == 0.8
    assert summary["confidence"] == "high"
    assert summary["samples_taken"] == 5
