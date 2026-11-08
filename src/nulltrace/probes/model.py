"""Probe corpus data model.

A *probe* is one adversarial test input with full metadata: what it
tries to demonstrate, what a secure target does, and how a violation is
detected and attributed. Probes are grouped into *families* (one family
per behavior under test); checks execute a depth-dependent slice of a
family rather than a single hardcoded phrasing.

A *variant* is an executable instance of a probe: the base text, or a
deterministic mutation of it (traceable via ``mutation`` and the
recorded seed).
"""

from dataclasses import dataclass, field


@dataclass(frozen=True)
class ProbeSpec:
    """One adversarial probe with professional metadata."""

    probe_id: str
    category: str
    objective: str
    template: str
    expected_secure_behavior: str
    detection: str  # token_compliance | canary | secret_marker |
    #                 private_data_marker | action_marker | structural
    severity_rationale: str
    capability: str = "prompt"  # prompt | conversation
    preconditions: str = "None beyond the declared capability."
    references: tuple[str, ...] = field(default_factory=tuple)

    def render(self, token: str = "") -> str:
        return self.template.format(token=token)


@dataclass(frozen=True)
class ProbeVariant:
    """Executable probe instance; mutations stay traceable to the base."""

    spec: ProbeSpec
    text: str
    mutation: str = "none"
    seed: str = ""

    @property
    def variant_id(self) -> str:
        if self.mutation == "none":
            return self.spec.probe_id
        return f"{self.spec.probe_id}+{self.mutation}"
