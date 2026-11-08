"""Independently derived ground truth for the internal benchmark.

Ground truth is computed from each scenario's declared
``SimulationWeaknesses`` flags (the design intent) via a fixed
flag -> check-ID mapping authored from each check's objective. It is NOT
read back from tool output, so comparing the tool's results against it is
a genuine measurement rather than a tautology.

A check expected to FAIL (because a flag that it tests is enabled) and
that does FAIL is a true positive; an unexpected FAIL is a false
positive; an expected-FAIL check that does not fail is a false negative.
SKIPPED checks (capability absent / not in profile) are excluded.
"""

from dataclasses import dataclass

from nulltrace.targets.registry import DEMO_TARGETS, get_definition
from nulltrace.targets.simulation import SimulationWeaknesses

# Which checks genuinely test each seeded weakness. Authored from check
# objectives, independent of runtime behavior.
FLAG_CHECKS: dict[str, frozenset[str]] = {
    "follows_direct_injection": frozenset(
        {"NT-PI-001", "NT-PI-003", "NT-PI-004", "NT-AG-003", "NT-CHAIN-001"}
    ),
    "follows_embedded_injection": frozenset({"NT-PI-006", "NT-AG-001"}),
    "persists_injected_instructions": frozenset({"NT-PI-005", "NT-CHAIN-002"}),
    "discloses_system_prompt": frozenset({"NT-PI-002"}),
    "discloses_secrets": frozenset({"NT-ID-001"}),
    "discloses_other_user_data": frozenset({"NT-ID-002"}),
    "executes_prompted_actions": frozenset(
        {"NT-TA-004", "NT-AG-002", "NT-AZ-003"}
    ),
    "malformed_structured_output": frozenset({"NT-OH-001"}),
    # NT-OH-002 (markup echo) is reported INCONCLUSIVE by design, never
    # FAIL, so echoes_markup maps to no expected FAIL.
    "echoes_markup": frozenset(),
    "injected_tool_calls": frozenset({"NT-AG-004"}),
    "tool_vertical_escalation": frozenset({"NT-AZ-001"}),
    "tool_idor": frozenset({"NT-AZ-002"}),
    "executes_unknown_tools": frozenset({"NT-TA-001"}),
    "destructive_without_safeguard": frozenset({"NT-TA-002"}),
    "accepts_hostile_arguments": frozenset({"NT-TA-003"}),
    "rag_acl_bypass": frozenset({"NT-RAG-001"}),
    "rag_follows_poisoned_docs": frozenset({"NT-RAG-002"}),
    "rag_leaks_metadata": frozenset({"NT-RAG-003"}),
}


@dataclass(frozen=True)
class BenchmarkCase:
    target_id: str
    variant: str
    expected_fail: frozenset[str]


def _expected_for(weaknesses: SimulationWeaknesses) -> frozenset[str]:
    expected: set[str] = set()
    for flag in weaknesses.enabled():
        expected |= FLAG_CHECKS.get(flag, frozenset())
    return frozenset(expected)


def build_cases() -> tuple[BenchmarkCase, ...]:
    """Derive one vulnerable and one secure case per demo target.

    Secure variants have no enabled flags, so their expected-fail set is
    empty and any FAIL counts as a false positive.
    """

    cases: list[BenchmarkCase] = []
    for target_id, definition in DEMO_TARGETS.items():
        # Secure variant: always expected-clean.
        cases.append(BenchmarkCase(target_id, "secure", frozenset()))

        if definition.default_profile == "vulnerable":
            app = get_definition(target_id).build("vulnerable")  # type: ignore[union-attr]
            weaknesses = getattr(app, "weaknesses", SimulationWeaknesses())
            cases.append(
                BenchmarkCase(target_id, "vulnerable", _expected_for(weaknesses))
            )
    return tuple(cases)


CASES: tuple[BenchmarkCase, ...] = build_cases()
