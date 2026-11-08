"""Registry of assessment modules, their checks, and assessment profiles."""

from dataclasses import dataclass

from nulltrace.checks import (
    agent_security,
    attack_chains,
    authorization,
    baseline,
    info_disclosure,
    output_handling,
    prompt_injection,
    rag_security,
    tool_abuse,
)
from nulltrace.checks.base import Check

MODULES: dict[str, list[type[Check]]] = {
    "baseline": baseline.CHECKS,
    "prompt_injection": prompt_injection.CHECKS,
    "info_disclosure": info_disclosure.CHECKS,
    "authorization": authorization.CHECKS,
    "tool_abuse": tool_abuse.CHECKS,
    "output_handling": output_handling.CHECKS,
    "rag_security": rag_security.CHECKS,
    "agent_security": agent_security.CHECKS,
    "attack_chains": attack_chains.CHECKS,
}

# Modules included in the single-turn "full" sweep. attack_chains is a
# multi-turn module reserved for the professional comprehensive/deep
# profiles, so legacy "full" coverage and counts are unchanged.
_FULL = [name for name in MODULES if name != "attack_chains"]

_CORE = [
    "baseline",
    "prompt_injection",
    "info_disclosure",
    "authorization",
    "tool_abuse",
    "output_handling",
]

PROFILES: dict[str, list[str]] = {
    "quick": ["baseline", "prompt_injection"],
    "standard": list(_CORE),
    "full": list(_FULL),
    # Professional engagement profiles add the multi-turn attack-chain
    # module on top of the full single-turn sweep.
    "comprehensive": list(MODULES),
    "deep": list(MODULES),
    "regression": list(_FULL),
}


@dataclass(frozen=True)
class ProfileExecution:
    """Depth and sampling policy for a profile.

    ``corpus_depth`` (1-3) selects how much of each probe family runs;
    ``mutations`` adds deterministic variants at deep depth; the sampling
    fields configure repeated-sampling for nondeterministic targets.
    Expected request consumption is documented per profile.
    """

    corpus_depth: int
    mutations: int
    sampling_policy: str
    samples: int
    description: str


PROFILE_EXECUTION: dict[str, ProfileExecution] = {
    "quick": ProfileExecution(
        1, 0, "single", 1,
        "Depth 1 (one probe/family), single sample. Fast regression; "
        "lowest request consumption.",
    ),
    "standard": ProfileExecution(
        2, 0, "single", 1,
        "Depth 2 (three probes/family), single sample. Balanced default.",
    ),
    "comprehensive": ProfileExecution(
        3, 0, "single", 1,
        "Depth 3 (full families), single sample. Broad phrasing coverage.",
    ),
    "deep": ProfileExecution(
        3, 4, "repeated", 5,
        "Depth 3 plus deterministic mutations, repeated sampling (5x) with "
        "consistency scoring. Highest request consumption; intended for "
        "nondeterministic real targets.",
    ),
    "regression": ProfileExecution(
        2, 0, "strict", 3,
        "Depth 2, strict sampling (violation only if all samples agree). "
        "Low-false-positive CI gate.",
    ),
    "full": ProfileExecution(
        3, 0, "single", 1,
        "Alias of comprehensive (kept for compatibility).",
    ),
}


def resolve_modules(
    modules: list[str] | None = None,
    profile: str = "standard",
) -> list[str]:
    """Resolve the module list for a run; explicit modules win over profile."""

    if modules:
        unknown = [name for name in modules if name not in MODULES]
        if unknown:
            raise ValueError(
                f"Unknown assessment module(s): {', '.join(sorted(unknown))}. "
                f"Available: {', '.join(MODULES)}."
            )
        return list(dict.fromkeys(modules))

    if profile not in PROFILES:
        raise ValueError(
            f"Unknown profile '{profile}'. Available: {', '.join(PROFILES)}."
        )

    return list(PROFILES[profile])


def checks_for_modules(module_names: list[str]) -> list[Check]:
    """Instantiate the checks for the given modules, in stable order."""

    return [
        check_class()
        for name in module_names
        for check_class in MODULES[name]
    ]
