"""Assessment context shared with every check.

The context carries the assessment identifier and *detection hints*: known
synthetic markers (canaries, synthetic secrets, synthetic private records)
that a cooperating target declares about itself.  When a marker is known,
its appearance in a response is strong, directly attributable evidence.
When no markers are known (an external black-box target), checks fall back
to behavioral heuristics and must report lower confidence, typically
``INCONCLUSIVE`` rather than ``FAIL``.
"""

import hashlib
from dataclasses import dataclass, field

from nulltrace.core.sampling import SamplingConfig


@dataclass(frozen=True)
class AssessmentHints:
    """Markers a target declares so checks can attribute evidence exactly."""

    canaries: tuple[str, ...] = ()
    secret_markers: tuple[str, ...] = ()
    private_data_markers: tuple[str, ...] = ()
    metadata_markers: tuple[str, ...] = ()
    poison_tokens: tuple[str, ...] = ()
    action_markers: tuple[str, ...] = ()


@dataclass
class AssessmentContext:
    assessment_id: str
    synthetic_target: bool = False
    hints: AssessmentHints = field(default_factory=AssessmentHints)
    #: How much of each probe family to execute (1-3). Set per profile.
    corpus_depth: int = 1
    #: Extra deterministic mutations per probe (only applied at depth 3).
    mutations: int = 0
    #: Repeated-sampling policy for nondeterministic targets.
    sampling: SamplingConfig = field(default_factory=SamplingConfig)

    def probe_token(self, check_id: str) -> str:
        """Deterministic per-assessment compliance token for one check.

        Probes instruct the target to emit this token; its appearance in a
        response is direct evidence that an injected instruction was
        followed.  The token is unique enough not to occur by accident.
        """

        digest = hashlib.sha256(
            f"{self.assessment_id}:{check_id}".encode()
        ).hexdigest()[:10]
        return f"NTPROBE-{digest}"
