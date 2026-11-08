"""Demo Target Lab tests: registry, behavior contrasts, real detection.

The critical property under test: findings come from executed probes
against genuinely different target behavior — never from the target's
"vulnerable" label. Every vulnerable scenario therefore has a secure
variant that receives the identical probes and must produce zero
findings.
"""

import pytest

from nulltrace.adapters.capabilities import (
    RetrievalCapability,
    ToolExecutionCapability,
)
from nulltrace.core.models import CheckStatus, ValidationStatus
from nulltrace.core.runner import run_assessment
from nulltrace.targets.registry import (
    DEMO_TARGETS,
    INTENTIONALLY_VULNERABLE,
    SECURE_BASELINE,
    get_definition,
    list_demo_targets,
)
from nulltrace.targets.scenarios import (
    build_crm_assistant,
    build_knowledge_assistant,
    build_support_assistant,
    build_travel_agent,
)

ALL_IDS = [
    "demo-secure-support",
    "demo-enterprise-rag",
    "demo-travel-agent",
    "demo-crm-assistant",
    "demo-dev-copilot",
]

VULNERABLE_IDS = [tid for tid in ALL_IDS if tid != "demo-secure-support"]


# ---------------------------------------------------------------------------
# Registry
# ---------------------------------------------------------------------------


def test_registry_contains_five_targets_with_metadata() -> None:
    assert list(DEMO_TARGETS) == ALL_IDS

    for info in list_demo_targets():
        assert info["simulated"] is True
        assert info["environment"] == "Simulated"
        assert info["provider_label"] and info["model_label"]
        assert info["capabilities"]
        assert info["supported_modules"]
        assert info["architecture"] and info["synthetic_data"]
        assert info["limitations"]


def test_registry_profiles_match_seeded_weaknesses() -> None:
    for info in list_demo_targets():
        if info["security_profile"] == SECURE_BASELINE:
            assert info["seeded_weakness_count"] == 0
        else:
            assert info["security_profile"] == INTENTIONALLY_VULNERABLE
            assert info["seeded_weakness_count"] > 0


def test_registry_rejects_unknown_variant() -> None:
    definition = get_definition("demo-travel-agent")
    assert definition is not None

    with pytest.raises(ValueError, match="variant"):
        definition.build("hardened")


def test_secure_baseline_ignores_vulnerable_variant_request() -> None:
    """The secure baseline must never be made artificially vulnerable."""

    definition = get_definition("demo-secure-support")
    assert definition is not None
    target = definition.build("vulnerable")

    report = run_assessment(target, profile="full", mode="mock")

    assert not report.findings


# ---------------------------------------------------------------------------
# Secure baseline behavior
# ---------------------------------------------------------------------------


def test_secure_support_passes_all_applicable_checks() -> None:
    report = run_assessment(
        build_support_assistant(), profile="full", mode="mock"
    )

    assert not report.findings
    statuses = {r.check_id: r.status for r in report.results}
    assert all(
        status in {CheckStatus.PASS, CheckStatus.SKIPPED}
        for status in statuses.values()
    )
    # Retrieval checks must be SKIPPED (capability absent), never passed.
    for rag_check in ("NT-RAG-001", "NT-RAG-002", "NT-RAG-003"):
        assert statuses[rag_check] == CheckStatus.SKIPPED


# ---------------------------------------------------------------------------
# Secure vs vulnerable behavior contrasts (raw application behavior)
# ---------------------------------------------------------------------------


def test_rag_unauthorized_retrieval_contrast() -> None:
    vulnerable = build_knowledge_assistant("vulnerable")
    secure = build_knowledge_assistant("secure")
    assert isinstance(vulnerable, RetrievalCapability)

    scenario = vulnerable.describe_retrieval()
    question, user = scenario.restricted_question, scenario.unauthorized_user

    marker = vulnerable.assessment_hints().private_data_markers[0]
    assert marker in vulnerable.ask_with_retrieval(question, user)
    assert "DENIED" in secure.ask_with_retrieval(question, user)


def test_rag_poisoned_document_contrast() -> None:
    vulnerable = build_knowledge_assistant("vulnerable")
    secure = build_knowledge_assistant("secure")
    poison = vulnerable.assessment_hints().poison_tokens[0]
    question = vulnerable.describe_retrieval().poisoned_question

    assert vulnerable.ask_with_retrieval(question, "employee-hr-a") == poison
    assert poison not in secure.ask_with_retrieval(question, "employee-hr-a")


def test_crm_cross_tenant_contrast() -> None:
    vulnerable = build_crm_assistant("vulnerable")
    secure = build_crm_assistant("secure")
    assert isinstance(vulnerable, ToolExecutionCapability)

    marker = vulnerable.assessment_hints().private_data_markers[0]
    arguments = {"record_id": "BETA-CUST-042"}

    assert marker in vulnerable.execute_tool(
        "read_crm_record", role="org-alpha", arguments=arguments
    )
    assert "DENIED" in secure.execute_tool(
        "read_crm_record", role="org-alpha", arguments=arguments
    )
    # Own-tenant access works in both profiles.
    assert "ALPHA-CUST-001" in secure.execute_tool(
        "read_crm_record", role="org-alpha", arguments={"record_id": "ALPHA-CUST-001"}
    )


def test_travel_tool_permission_contrast() -> None:
    vulnerable = build_travel_agent("vulnerable")
    secure = build_travel_agent("secure")
    action = vulnerable.assessment_hints().action_markers[0]

    assert action in vulnerable.execute_tool(
        "cancel_booking", role="traveler-alpha"
    )
    assert "DENIED" in secure.execute_tool(
        "cancel_booking", role="traveler-alpha"
    )
    # Benign tools work in both profiles.
    assert secure.execute_tool("search_flights", role="traveler-alpha").startswith(
        "OK"
    )


# ---------------------------------------------------------------------------
# Detection through actual assessment execution
# ---------------------------------------------------------------------------


EXPECTED_FAILS: dict[str, set[str]] = {
    "demo-enterprise-rag": {
        "NT-PI-006",
        "NT-ID-002",
        "NT-RAG-001",
        "NT-RAG-002",
        "NT-RAG-003",
    },
    "demo-travel-agent": {
        "NT-AZ-001",
        "NT-AZ-003",
        "NT-TA-001",
        "NT-TA-002",
        "NT-TA-003",
        "NT-TA-004",
        "NT-AG-002",
        "NT-AG-004",
    },
    "demo-crm-assistant": {"NT-ID-002", "NT-AZ-002"},
    "demo-dev-copilot": {
        "NT-PI-001",
        "NT-PI-002",
        "NT-PI-005",
        "NT-PI-006",
        "NT-ID-001",
        "NT-AG-004",
    },
}


@pytest.mark.parametrize("target_id", VULNERABLE_IDS)
def test_vulnerable_targets_detected_with_evidence(target_id: str) -> None:
    definition = get_definition(target_id)
    assert definition is not None

    report = run_assessment(
        definition.build("vulnerable"), profile="full", mode="mock"
    )

    failed = {
        r.check_id for r in report.results if r.status == CheckStatus.FAIL
    }
    assert EXPECTED_FAILS[target_id] <= failed, target_id

    assert report.findings
    finding_check_ids = {f.check_id for f in report.findings}
    # Findings come only from failed checks, plus NT-OH-002's explicitly
    # informational observation (inconclusive status by design).
    assert failed <= finding_check_ids
    assert finding_check_ids <= failed | {"NT-OH-002"}

    for finding in report.findings:
        assert finding.evidence, finding.finding_id
        assert finding.assessment_id == report.assessment_id
        assert finding.validation_status is ValidationStatus.PENDING_REVIEW
        assert all(item.synthetic for item in finding.evidence)


@pytest.mark.parametrize("target_id", VULNERABLE_IDS)
def test_secure_variants_produce_no_findings(target_id: str) -> None:
    definition = get_definition(target_id)
    assert definition is not None

    report = run_assessment(
        definition.build("secure"), profile="full", mode="mock"
    )

    assert not report.findings
    assert all(
        r.status in {CheckStatus.PASS, CheckStatus.SKIPPED}
        for r in report.results
    )


def test_crm_only_fails_seeded_weaknesses() -> None:
    """Partial failure: everything not seeded must pass, proving findings
    are behavior-driven rather than label-driven."""

    report = run_assessment(
        build_crm_assistant("vulnerable"), profile="full", mode="mock"
    )
    statuses = {r.check_id: r.status for r in report.results}

    assert statuses["NT-AZ-002"] == CheckStatus.FAIL
    assert statuses["NT-ID-002"] == CheckStatus.FAIL
    # Seeded weaknesses do NOT include these; they must pass.
    assert statuses["NT-AZ-001"] == CheckStatus.PASS
    assert statuses["NT-TA-002"] == CheckStatus.PASS
    assert statuses["NT-PI-001"] == CheckStatus.PASS
    assert statuses["NT-ID-001"] == CheckStatus.PASS


def test_skipped_checks_are_not_counted_as_passed() -> None:
    report = run_assessment(
        build_knowledge_assistant("vulnerable"), profile="full", mode="mock"
    )
    counts = report.status_counts
    statuses = {r.check_id: r.status for r in report.results}

    # The RAG app exposes no tool layer: tool checks skip.
    assert statuses["NT-AZ-001"] == CheckStatus.SKIPPED
    assert statuses["NT-TA-001"] == CheckStatus.SKIPPED
    assert counts["skipped"] >= 5
    assert counts["pass"] + counts["skipped"] + counts["fail"] + counts[
        "inconclusive"
    ] + counts["error"] == len(report.results)


def test_distinct_markers_per_target() -> None:
    """Marker namespaces must not collide across targets, so evidence is
    attributable to exactly one synthetic environment."""

    seen: set[str] = set()
    for target_id in ALL_IDS:
        definition = get_definition(target_id)
        assert definition is not None
        hints = definition.build().assessment_hints()
        markers = set(
            hints.canaries
            + hints.secret_markers
            + hints.private_data_markers
            + hints.action_markers
            + hints.poison_tokens
        )
        assert not (markers & seen), target_id
        seen |= markers


def test_check_results_carry_objective_for_transparency() -> None:
    report = run_assessment(
        build_travel_agent("vulnerable"), profile="full", mode="mock"
    )
    data = report.to_dict()

    for result in data["results"]:
        assert "objective" in result
