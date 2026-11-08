"""Tests for the internal synthetic benchmark harness."""

import pytest

from nulltrace.benchmark import run_benchmark
from nulltrace.benchmark.ground_truth import CASES, build_cases
from nulltrace.benchmark.harness import Confusion


def test_cases_cover_all_targets_secure_and_vulnerable() -> None:
    target_ids = {case.target_id for case in CASES}
    assert len(target_ids) == 5
    # Every target has a secure case; vulnerable ones also have a vuln case.
    secure = {c.target_id for c in CASES if c.variant == "secure"}
    assert secure == target_ids


def test_secure_cases_expect_no_failures() -> None:
    for case in CASES:
        if case.variant == "secure":
            assert case.expected_fail == frozenset()


def test_vulnerable_cases_have_nonempty_ground_truth() -> None:
    vuln = [c for c in CASES if c.variant == "vulnerable"]
    assert vuln
    for case in vuln:
        assert case.expected_fail, case.target_id


def test_confusion_metrics_math() -> None:
    c = Confusion(tp=8, fp=2, fn=0, tn=10)
    assert c.precision == 0.8
    assert c.recall == 1.0
    assert round(c.f1, 4) == round(2 * 0.8 * 1.0 / 1.8, 4)


def test_empty_confusion_is_neutral() -> None:
    c = Confusion()
    assert c.precision == 1.0
    assert c.recall == 1.0


@pytest.mark.parametrize("profile", ["standard", "comprehensive"])
def test_benchmark_is_measured_and_clean(profile: str) -> None:
    report = run_benchmark(profile=profile)

    # Internal synthetic benchmark must be explicitly labeled as such.
    data = report.to_dict()
    assert data["benchmark_type"] == "internal_synthetic"
    assert "NOT external validation" in data["disclaimer"]

    # No false positives (secure variants clean) and no false negatives
    # (vulnerable variants fully detected) on the deterministic fixtures.
    assert report.overall.fp == 0, report.overall.to_dict()
    assert report.overall.fn == 0, report.overall.to_dict()
    assert report.overall.tp > 0
    assert report.overall.precision == 1.0
    assert report.overall.recall == 1.0


def test_benchmark_metrics_come_from_execution_not_hardcoding() -> None:
    # Rebuilding cases and re-running must agree (reproducible), and the
    # case count must match the derived cases.
    report = run_benchmark(profile="standard")
    assert len(report.cases) == len(build_cases())
    # Each vulnerable case actually executed checks and produced findings.
    for case in report.cases:
        if case.variant == "vulnerable":
            assert case.checks_executed > 0
            assert case.findings > 0
