"""Benchmark harness: run the suite against the lab and measure accuracy.

Metrics are computed from actual assessment execution — every number
here comes from running the real checks against the synthetic targets,
not from any stored or hardcoded result.
"""

from dataclasses import dataclass, field
from typing import Any

from nulltrace.benchmark.ground_truth import CASES, BenchmarkCase
from nulltrace.core.models import CheckStatus
from nulltrace.core.runner import run_assessment
from nulltrace.targets.registry import get_definition


@dataclass
class Confusion:
    tp: int = 0
    fp: int = 0
    fn: int = 0
    tn: int = 0

    def add(self, other: "Confusion") -> None:
        self.tp += other.tp
        self.fp += other.fp
        self.fn += other.fn
        self.tn += other.tn

    @property
    def precision(self) -> float:
        denom = self.tp + self.fp
        return self.tp / denom if denom else 1.0

    @property
    def recall(self) -> float:
        denom = self.tp + self.fn
        return self.tp / denom if denom else 1.0

    @property
    def f1(self) -> float:
        p, r = self.precision, self.recall
        return 2 * p * r / (p + r) if (p + r) else 0.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "tp": self.tp,
            "fp": self.fp,
            "fn": self.fn,
            "tn": self.tn,
            "precision": round(self.precision, 4),
            "recall": round(self.recall, 4),
            "f1": round(self.f1, 4),
        }


@dataclass
class CaseResult:
    target_id: str
    variant: str
    confusion: Confusion
    false_positives: list[str]
    false_negatives: list[str]
    checks_executed: int
    checks_skipped: int
    findings: int
    per_module: dict[str, Confusion] = field(default_factory=dict)


@dataclass
class BenchmarkReport:
    profile: str
    corpus_version: str
    cases: list[CaseResult] = field(default_factory=list)
    overall: Confusion = field(default_factory=Confusion)
    per_module: dict[str, Confusion] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "benchmark_type": "internal_synthetic",
            "disclaimer": (
                "Measured against NullTrace AI's own deterministic Demo "
                "Target Lab fixtures. NOT external validation against "
                "third-party vulnerable applications. No network calls."
            ),
            "profile": self.profile,
            "corpus_version": self.corpus_version,
            "overall": self.overall.to_dict(),
            "per_module": {
                module: conf.to_dict()
                for module, conf in sorted(self.per_module.items())
            },
            "cases": [
                {
                    "target_id": case.target_id,
                    "variant": case.variant,
                    "confusion": case.confusion.to_dict(),
                    "false_positives": case.false_positives,
                    "false_negatives": case.false_negatives,
                    "checks_executed": case.checks_executed,
                    "checks_skipped": case.checks_skipped,
                    "findings": case.findings,
                }
                for case in self.cases
            ],
        }


def _score_case(case: BenchmarkCase, profile: str) -> CaseResult:
    definition = get_definition(case.target_id)
    if definition is None:
        raise ValueError(f"Unknown benchmark target: {case.target_id}")

    report = run_assessment(
        definition.build(case.variant), profile=profile, mode="mock"
    )

    confusion = Confusion()
    per_module: dict[str, Confusion] = {}
    false_positives: list[str] = []
    false_negatives: list[str] = []
    skipped = 0

    for result in report.results:
        if result.status == CheckStatus.SKIPPED:
            skipped += 1
            continue

        module_conf = per_module.setdefault(result.module, Confusion())
        expected = result.check_id in case.expected_fail
        failed = result.status == CheckStatus.FAIL

        if expected and failed:
            confusion.tp += 1
            module_conf.tp += 1
        elif failed and not expected:
            confusion.fp += 1
            module_conf.fp += 1
            false_positives.append(result.check_id)
        elif expected and not failed:
            confusion.fn += 1
            module_conf.fn += 1
            false_negatives.append(result.check_id)
        else:
            confusion.tn += 1
            module_conf.tn += 1

    return CaseResult(
        target_id=case.target_id,
        variant=case.variant,
        confusion=confusion,
        false_positives=false_positives,
        false_negatives=false_negatives,
        checks_executed=len(report.results) - skipped,
        checks_skipped=skipped,
        findings=len(report.findings),
        per_module=per_module,
    )


def run_benchmark(profile: str = "full") -> BenchmarkReport:
    """Execute the benchmark and return measured metrics."""

    from nulltrace.probes import corpus

    report = BenchmarkReport(profile=profile, corpus_version=corpus.CORPUS_VERSION)

    for case in CASES:
        case_result = _score_case(case, profile)
        report.cases.append(case_result)
        report.overall.add(case_result.confusion)
        for module, conf in case_result.per_module.items():
            report.per_module.setdefault(module, Confusion()).add(conf)

    return report
