from nulltrace.core.runner import run_local_assessment
from nulltrace.reporting.render import to_markdown


def test_markdown_report_contains_target_and_findings() -> None:
    rendered = to_markdown(run_local_assessment().to_dict())
    assert "local-mock-agent" in rendered
    assert "NT-AGENT-001" in rendered
