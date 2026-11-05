from nulltrace.core.runner import run_local_assessment


def test_local_assessment_runs_three_checks() -> None:
    report = run_local_assessment()
    assert report.target == "local-mock-agent"
    assert len(report.findings) == 3
    assert all(item.status == "passed" for item in report.findings)


def test_report_notes_state_local_only() -> None:
    report = run_local_assessment()
    assert any("no external target" in note for note in report.notes)
