"""Tests for multi-turn attack chains."""

from nulltrace.adapters.base import TargetAdapter
from nulltrace.adapters.mock_agent import LocalMockAgent
from nulltrace.checks.attack_chains import (
    ContextThenOverrideChain,
    PersistenceThenTriggerChain,
)
from nulltrace.core.context import AssessmentContext
from nulltrace.core.models import CheckStatus


def _context() -> AssessmentContext:
    agent = LocalMockAgent(profile="vulnerable")
    return AssessmentContext(
        assessment_id="NTA-chain",
        synthetic_target=True,
        hints=agent.assessment_hints(),
    )


def test_persistence_chain_detects_vulnerable_target() -> None:
    result = PersistenceThenTriggerChain().run(
        LocalMockAgent(profile="vulnerable"), _context()
    )
    assert result.status == CheckStatus.FAIL
    assert result.findings
    finding = result.findings[0]
    assert finding.probe_ids == ["CHN-PERSIST-TRIGGER"]
    assert finding.evidence  # full transcript recorded
    assert "turn" in finding.evidence[0].response


def test_persistence_chain_passes_hardened_target() -> None:
    result = PersistenceThenTriggerChain().run(
        LocalMockAgent(profile="hardened"), _context()
    )
    assert result.status == CheckStatus.PASS
    assert not result.findings


def test_chains_skipped_without_conversation_capability() -> None:
    class PromptOnly(TargetAdapter):
        @property
        def target_name(self) -> str:
            return "prompt-only"

        def send_prompt(self, prompt: str) -> str:
            return "ok"

    for check in (ContextThenOverrideChain(), PersistenceThenTriggerChain()):
        result = check.run(PromptOnly(), _context())
        assert result.status == CheckStatus.SKIPPED
        assert not result.findings


def test_context_override_chain_runs_and_is_deterministic() -> None:
    target = LocalMockAgent(profile="hardened")
    first = ContextThenOverrideChain().run(target, _context())
    second = ContextThenOverrideChain().run(target, _context())
    assert first.status == second.status == CheckStatus.PASS
