"""Base class and helpers for security checks.

A check probes one behavior of the target and returns a ``CheckResult``.
Statuses describe the *security outcome*:

- ``PASS``          — the target resisted the probe.
- ``FAIL``          — the probed insecure behavior was observed, with evidence.
- ``INCONCLUSIVE``  — behavior could not be attributed with confidence
                      (typical for black-box targets without declared markers).
- ``ERROR``         — the check itself could not execute.
- ``SKIPPED``       — the target lacks a required capability.

A rejected or accepted prompt alone never proves a vulnerability; checks
attribute evidence through markers (canaries, synthetic secrets, probe
tokens) wherever possible and lower their confidence when they cannot.
"""

from abc import ABC, abstractmethod
from collections.abc import Callable, Mapping
from dataclasses import dataclass

from nulltrace.adapters.base import TargetAdapter
from nulltrace.adapters.capabilities import ConversationCapability
from nulltrace.core.context import AssessmentContext
from nulltrace.core.models import (
    CheckResult,
    CheckStatus,
    Confidence,
    Evidence,
    Finding,
    Severity,
)
from nulltrace.core.sampling import SamplingResult, run_samples
from nulltrace.probes import corpus
from nulltrace.probes.model import ProbeSpec, ProbeVariant
from nulltrace.probes.mutation import expand

#: Detection-strength ceilings per probe detection strategy. Attribution
#: detectors (unique token / declared marker) cannot fire by chance.
_ATTRIBUTION_DETECTORS = {
    "token_compliance",
    "canary",
    "secret_marker",
    "private_data_marker",
    "action_marker",
}


@dataclass
class FamilyOutcome:
    """Aggregate result of running one probe family against a target."""

    violated: bool
    triggering: ProbeVariant | None
    sampling: SamplingResult | None
    evidence: list[Evidence]
    probe_ids: list[str]
    attributable: bool


class Check(ABC):
    """Base class for independently executable security checks."""

    check_id: str
    module: str
    title: str
    description: str = ""
    references: list[str] = []
    #: Name of a capability class the target must implement, or None.
    required_capability: type | None = None

    @abstractmethod
    def run(self, target: TargetAdapter, context: AssessmentContext) -> CheckResult:
        """Execute this security check against a target adapter."""
        raise NotImplementedError

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def evidence(
        self,
        context: AssessmentContext,
        probe: str,
        response: str,
        note: str = "",
    ) -> Evidence:
        return Evidence(
            probe=probe,
            response=response,
            note=note,
            synthetic=context.synthetic_target,
        )

    def result(
        self,
        status: CheckStatus,
        details: str,
        evidence: list[Evidence] | None = None,
        findings: list[Finding] | None = None,
        error: str = "",
    ) -> CheckResult:
        return CheckResult(
            check_id=self.check_id,
            module=self.module,
            title=self.title,
            status=status,
            details=details,
            objective=self.description,
            evidence=evidence or [],
            findings=findings or [],
            error=error,
        )

    def finding(
        self,
        *,
        description: str,
        severity: Severity,
        confidence: Confidence,
        evidence: list[Evidence],
        expected_behavior: str,
        actual_behavior: str,
        impact: str,
        remediation: str,
        reproduction_steps: list[str],
        title: str | None = None,
        affected_component: str = "",
        probe_ids: list[str] | None = None,
        reproducibility: Mapping[str, object] | None = None,
    ) -> Finding:
        """Build a finding; the runner assigns IDs and assessment linkage."""

        return Finding(
            finding_id="",
            check_id=self.check_id,
            title=title or self.title,
            description=description,
            category=self.module,
            affected_component=affected_component,
            severity=severity,
            confidence=confidence,
            evidence=evidence,
            reproduction_steps=reproduction_steps,
            expected_behavior=expected_behavior,
            actual_behavior=actual_behavior,
            impact=impact,
            remediation=remediation,
            references=list(self.references),
            probe_ids=probe_ids or [],
            reproducibility=dict(reproducibility or {}),
        )


def contains_any(text: str, markers: tuple[str, ...]) -> str | None:
    """Return the first marker present in ``text``, if any."""

    for marker in markers:
        if marker and marker in text:
            return marker
    return None


class CorpusCheck(Check):
    """Base for checks that execute a versioned probe family.

    Subclasses declare ``family`` (a corpus family name). The runner
    renders each probe at the configured depth, applies deterministic
    mutations at deep depth, and evaluates each variant under the
    assessment's sampling policy. The first variant whose sampling result
    counts as a violation fails the check, with full attributable
    evidence and the originating probe/variant ID recorded.
    """

    family: str

    def _detector(
        self, context: AssessmentContext, spec: ProbeSpec, token: str
    ) -> Callable[[str], bool]:
        detection = spec.detection
        if detection == "token_compliance":
            return lambda response: token in response

        marker_sets = {
            "canary": context.hints.canaries,
            "secret_marker": context.hints.secret_markers,
            "private_data_marker": context.hints.private_data_markers,
            "action_marker": context.hints.action_markers,
        }
        markers = marker_sets.get(detection)
        if markers is not None:
            return lambda response: contains_any(response, markers) is not None

        raise ValueError(f"Unsupported detection strategy: {spec.detection}")

    def _marker_hints_available(
        self, context: AssessmentContext, detection: str
    ) -> bool:
        if detection == "token_compliance":
            return True  # token is always available
        if detection == "canary":
            return bool(context.hints.canaries)
        if detection == "secret_marker":
            return bool(context.hints.secret_markers)
        if detection == "private_data_marker":
            return bool(context.hints.private_data_markers)
        if detection == "action_marker":
            return bool(context.hints.action_markers)
        return False

    def run_family(
        self, target: TargetAdapter, context: AssessmentContext
    ) -> FamilyOutcome:
        token = context.probe_token(self.check_id)
        specs = corpus.family_slice(self.family, context.corpus_depth)
        evidence: list[Evidence] = []
        probe_ids: list[str] = []
        any_attributable = False

        for spec in specs:
            attributable = self._marker_hints_available(context, spec.detection)
            any_attributable = any_attributable or attributable
            detector = self._detector(context, spec, token)
            base_text = spec.render(token)
            mutations = context.mutations if context.corpus_depth >= 3 else 0
            variants = expand(spec, base_text, mutations, seed=context.assessment_id)

            for variant in variants:
                if spec.capability == "conversation" and not isinstance(
                    target, ConversationCapability
                ):
                    continue
                def _probe(text: str = variant.text) -> str:
                    return target.send_prompt(text)

                result = run_samples(
                    probe=_probe,
                    detector=detector,
                    config=context.sampling,
                    budget=None,
                )
                probe_ids.append(variant.variant_id)
                sample = result.samples[0] if result.samples else None
                response = sample.response if sample else ""
                evidence.append(
                    self.evidence(
                        context,
                        variant.text,
                        response,
                        note=(
                            f"probe={variant.variant_id} "
                            f"detection={spec.detection} "
                            f"sampling={result.summary()}"
                        ),
                    )
                )
                if result.is_violation():
                    return FamilyOutcome(
                        violated=True,
                        triggering=variant,
                        sampling=result,
                        evidence=evidence,
                        probe_ids=probe_ids,
                        attributable=attributable,
                    )

        return FamilyOutcome(
            violated=False,
            triggering=None,
            sampling=None,
            evidence=evidence,
            probe_ids=probe_ids,
            attributable=any_attributable,
        )
