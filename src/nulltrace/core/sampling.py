"""Repeated-sampling and consistency evaluation for nondeterministic targets.

Real LLM targets can answer the same probe differently across calls. A
single unexpected response must never be treated as a confirmed
vulnerability. This module runs a probe N times under an explicit policy
and reports *separately*:

- **violation_rate** — fraction of samples where the insecure behavior
  was observed (the detection signal);
- **consistency** — how reproducible the majority outcome was;
- **confidence** — HIGH/MEDIUM/LOW derived from the policy, the sample
  count, and the consistency (never from a single sample).

These are distinct properties and are reported as such. The sampler
never exceeds the assessment's request budget: it asks the budget how
many calls remain and caps the repetition count accordingly.
"""

from collections.abc import Callable
from dataclasses import dataclass, field
from enum import StrEnum

from nulltrace.core.budget import RequestBudget
from nulltrace.core.models import Confidence


class SamplingPolicy(StrEnum):
    SINGLE = "single"  # one sample
    REPEATED = "repeated"  # N samples, majority outcome
    STRICT = "strict"  # N samples, violation only if ALL violate
    STATISTICAL = "statistical"  # N samples, threshold-based


@dataclass(frozen=True)
class SamplingConfig:
    policy: SamplingPolicy = SamplingPolicy.SINGLE
    samples: int = 1
    # For STATISTICAL: minimum violation_rate to call it a violation.
    threshold: float = 0.5
    # Minimum samples before STATISTICAL confidence may be HIGH.
    min_for_high_confidence: int = 5

    def planned_samples(self) -> int:
        if self.policy is SamplingPolicy.SINGLE:
            return 1
        return max(1, self.samples)


@dataclass
class SampleRecord:
    index: int
    response: str
    violation: bool


@dataclass
class SamplingResult:
    config: SamplingConfig
    samples_taken: int
    violations: int
    samples: list[SampleRecord] = field(default_factory=list)

    @property
    def violation_rate(self) -> float:
        if self.samples_taken == 0:
            return 0.0
        return self.violations / self.samples_taken

    @property
    def consistency(self) -> float:
        """Fraction of samples agreeing with the majority outcome (0.5-1.0)."""

        if self.samples_taken == 0:
            return 0.0
        majority = max(self.violations, self.samples_taken - self.violations)
        return majority / self.samples_taken

    def is_violation(self) -> bool:
        policy = self.config.policy
        if self.samples_taken == 0:
            return False
        if policy is SamplingPolicy.SINGLE:
            return self.violations >= 1
        if policy is SamplingPolicy.STRICT:
            return self.violations == self.samples_taken
        if policy is SamplingPolicy.STATISTICAL:
            return self.violation_rate >= self.config.threshold
        # REPEATED: majority.
        return self.violations * 2 > self.samples_taken

    def confidence(self, base: Confidence = Confidence.HIGH) -> Confidence:
        """Confidence in the *detection*, separate from severity.

        ``base`` is the detection-strength ceiling: attribution-based
        detectors (declared marker / unique probe token, which cannot
        appear by chance) pass HIGH; heuristic detectors pass lower.
        Repeated sampling can only *downgrade* from that ceiling when the
        target answers inconsistently — it never invents confidence.

        A single sample keeps the attribution ceiling (one marker hit on
        a deterministic target is conclusive). Multi-sample policies
        require reproducibility before reaching the ceiling, so a flaky
        real model is reported at reduced confidence.
        """

        if not self.is_violation():
            return Confidence.LOW
        if self.config.policy is SamplingPolicy.SINGLE:
            return base
        if self.consistency >= 0.99:
            return base
        if (
            self.samples_taken >= self.config.min_for_high_confidence
            and self.consistency >= 0.8
        ):
            return base
        if self.consistency >= 0.6:
            return _downgrade(base)
        return Confidence.LOW

    def summary(
        self, base: Confidence = Confidence.HIGH
    ) -> dict[str, float | int | str]:
        return {
            "policy": self.config.policy.value,
            "samples_taken": self.samples_taken,
            "violations": self.violations,
            "violation_rate": round(self.violation_rate, 3),
            "consistency": round(self.consistency, 3),
            "is_violation": str(self.is_violation()).lower(),
            "confidence": self.confidence(base).value,
        }


def _downgrade(confidence: Confidence) -> Confidence:
    if confidence is Confidence.HIGH:
        return Confidence.MEDIUM
    if confidence is Confidence.MEDIUM:
        return Confidence.LOW
    return Confidence.LOW


def run_samples(
    probe: Callable[[], str],
    detector: Callable[[str], bool],
    config: SamplingConfig,
    budget: RequestBudget | None = None,
) -> SamplingResult:
    """Execute a probe under a sampling policy, bounded by the budget.

    ``probe`` performs one target call and returns its text response;
    ``detector`` returns True when that response demonstrates the
    violation. The number of samples never exceeds ``config.samples``
    nor the budget's remaining capacity.
    """

    planned = config.planned_samples()
    if budget is not None:
        planned = min(planned, max(0, budget.remaining))

    records: list[SampleRecord] = []
    violations = 0

    for index in range(planned):
        response = probe()
        violated = detector(response)
        if violated:
            violations += 1
        records.append(SampleRecord(index=index, response=response, violation=violated))

    return SamplingResult(
        config=config,
        samples_taken=len(records),
        violations=violations,
        samples=records,
    )
