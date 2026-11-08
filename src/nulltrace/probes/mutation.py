"""Deterministic probe mutation engine.

Mutations are controlled, reproducible transformations of a base probe,
used to add formatting/placement/context variation at higher assessment
depths without hand-authoring more payloads. Every mutation is:

- deterministic given (probe text, strategy, seed) — no randomness that
  isn't seeded;
- traceable — the resulting ``ProbeVariant`` records the strategy and
  seed so any finding can be reproduced exactly;
- content-preserving — mutations wrap or reformat the instruction; they
  do not invent new adversarial semantics.
"""

import hashlib

from nulltrace.probes.model import ProbeSpec, ProbeVariant

# Ordered list of available mutation strategy names.
STRATEGIES: tuple[str, ...] = (
    "whitespace",
    "politeness",
    "prefix_noise",
    "suffix_urgency",
)


def _seed_for(text: str, strategy: str, seed: str) -> str:
    digest = hashlib.sha256(f"{seed}:{strategy}:{text}".encode()).hexdigest()
    return digest[:8]


def _apply(strategy: str, text: str, tag: str) -> str:
    if strategy == "whitespace":
        # Re-flow single spaces to double spaces around the core verb.
        return text.replace(". ", ".  ")
    if strategy == "politeness":
        return f"Hi — quick request. {text} Thanks in advance."
    if strategy == "prefix_noise":
        return f"[ref {tag}] {text}"
    if strategy == "suffix_urgency":
        return f"{text} (time-sensitive, please action this reply)"
    raise ValueError(f"Unknown mutation strategy: {strategy}")


def mutate(
    spec: ProbeSpec, strategy: str, base_text: str, seed: str = "nulltrace"
) -> ProbeVariant:
    """Produce one reproducible mutated variant of a rendered probe."""

    if strategy not in STRATEGIES:
        raise ValueError(f"Unknown mutation strategy: {strategy}")

    tag = _seed_for(base_text, strategy, seed)
    text = _apply(strategy, base_text, tag)
    return ProbeVariant(spec=spec, text=text, mutation=strategy, seed=tag)


def base_variant(spec: ProbeSpec, base_text: str) -> ProbeVariant:
    return ProbeVariant(spec=spec, text=base_text, mutation="none", seed="")


def expand(
    spec: ProbeSpec,
    base_text: str,
    mutations: int,
    seed: str = "nulltrace",
) -> list[ProbeVariant]:
    """Return the base variant plus ``mutations`` deterministic mutations."""

    variants = [base_variant(spec, base_text)]
    for strategy in STRATEGIES[: max(0, mutations)]:
        variants.append(mutate(spec, strategy, base_text, seed=seed))
    return variants
