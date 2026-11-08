"""Demo Target Lab registry.

Each entry pairs descriptive metadata (shown in the dashboard) with a
factory that builds the actual synthetic application the orchestrator
assesses. Findings come from executing checks against that application
— never from the metadata.

``provider_label``/``model_label`` are simulated model configuration
labels only: no provider API is contacted and no seeded weakness
describes any real model or provider.
"""

from collections.abc import Callable
from dataclasses import asdict, dataclass, field
from typing import Any

from nulltrace.adapters.base import TargetAdapter
from nulltrace.targets import scenarios

SECURE_BASELINE = "secure_baseline"
INTENTIONALLY_VULNERABLE = "intentionally_vulnerable"


@dataclass(frozen=True)
class DemoTargetInfo:
    id: str
    display_name: str
    category: str
    description: str
    provider_label: str
    model_label: str
    environment: str
    security_profile: str
    capabilities: tuple[str, ...]
    supported_modules: tuple[str, ...]
    seeded_weaknesses: tuple[str, ...]
    complexity: str
    architecture: str
    synthetic_data: str
    limitations: tuple[str, ...] = field(default_factory=tuple)

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["seeded_weakness_count"] = len(self.seeded_weaknesses)
        data["simulated"] = True
        return data


@dataclass(frozen=True)
class DemoTargetDefinition:
    info: DemoTargetInfo
    factory: Callable[[str], TargetAdapter]
    default_profile: str

    def build(self, variant: str | None = None) -> TargetAdapter:
        profile = variant or self.default_profile
        if profile not in {"secure", "vulnerable"}:
            raise ValueError("Target variant must be 'secure' or 'vulnerable'.")
        return self.factory(profile)


_COMMON_LIMITATIONS = (
    "Fully synthetic environment: deterministic, rule-based simulation, "
    "not a live LLM.",
    "The model name is display metadata for the simulated configuration; "
    "no provider API is contacted and the seeded weaknesses do not "
    "describe the real model.",
    "Only the listed capabilities exist; checks needing others are "
    "skipped, never guessed.",
)

DEMO_TARGETS: dict[str, DemoTargetDefinition] = {
    "demo-secure-support": DemoTargetDefinition(
        info=DemoTargetInfo(
            id="demo-secure-support",
            display_name="Secure Customer Support Assistant",
            category="Customer Support AI",
            description=(
                "A customer-support AI application that follows secure "
                "authorization, instruction hierarchy, and data isolation "
                "rules. The secure baseline: it should produce no "
                "confirmed findings."
            ),
            provider_label="OpenAI",
            model_label="GPT-4o",
            environment="Simulated",
            security_profile=SECURE_BASELINE,
            capabilities=(
                "prompts",
                "multi-turn conversation",
                "synthetic tools",
                "tool-call probing",
            ),
            supported_modules=(
                "baseline",
                "prompt_injection",
                "info_disclosure",
                "authorization",
                "tool_abuse",
                "output_handling",
                "agent_security",
            ),
            seeded_weaknesses=(),
            complexity="Low — baseline control case",
            architecture=(
                "Chat assistant over a synthetic order/customer store with "
                "three tools (order lookup, record read, account close). "
                "Authorization is enforced in the tool layer; destructive "
                "operations sit behind a simulated human-confirmation gate."
            ),
            synthetic_data=(
                "Two synthetic customers (alice, bob) with clearly labeled "
                "synthetic records; no real data."
            ),
            limitations=_COMMON_LIMITATIONS,
        ),
        factory=scenarios.build_support_assistant,
        default_profile="secure",
    ),
    "demo-enterprise-rag": DemoTargetDefinition(
        info=DemoTargetInfo(
            id="demo-enterprise-rag",
            display_name="Enterprise Knowledge Assistant",
            category="Enterprise RAG",
            description=(
                "An enterprise assistant answering employee questions from "
                "a synthetic document store. Intentionally seeded with "
                "retrieval ACL, document-injection, and disclosure "
                "weaknesses."
            ),
            provider_label="Anthropic",
            model_label="Claude 3.7 Sonnet",
            environment="Simulated",
            security_profile=INTENTIONALLY_VULNERABLE,
            capabilities=("prompts", "multi-turn conversation", "retrieval"),
            supported_modules=(
                "baseline",
                "prompt_injection",
                "info_disclosure",
                "rag_security",
            ),
            seeded_weaknesses=(
                "Cross-user document retrieval (missing document ACL)",
                "Indirect prompt injection via a poisoned public document",
                "Retrieval metadata (source path) leakage",
                "Cross-user data disclosure through plain prompts",
                "Embedded-instruction following in quoted content",
            ),
            complexity="Medium — retrieval boundary scenario",
            architecture=(
                "RAG pipeline over three synthetic documents (public "
                "onboarding FAQ with an embedded instruction, HR policy "
                "owned by employee A, finance budget owned by employee B). "
                "The vulnerable profile skips document-ACL filtering and "
                "passes document text straight into the instruction "
                "channel."
            ),
            synthetic_data=(
                "Employee A (HR) and employee B (finance) with synthetic "
                "documents; the finance document carries a synthetic "
                "record marker and a synthetic storage path."
            ),
            limitations=_COMMON_LIMITATIONS,
        ),
        factory=scenarios.build_knowledge_assistant,
        default_profile="vulnerable",
    ),
    "demo-travel-agent": DemoTargetDefinition(
        info=DemoTargetInfo(
            id="demo-travel-agent",
            display_name="Travel Booking AI Agent",
            category="AI Agent with Tools",
            description=(
                "An AI travel assistant with synthetic flight/hotel search "
                "and booking tools. Intentionally seeded with tool "
                "authorization, safeguard, and autonomy weaknesses."
            ),
            provider_label="Google",
            model_label="Gemini 2.5 Pro",
            environment="Simulated",
            security_profile=INTENTIONALLY_VULNERABLE,
            capabilities=(
                "prompts",
                "multi-turn conversation",
                "synthetic tools",
                "tool-call probing",
            ),
            supported_modules=(
                "baseline",
                "prompt_injection",
                "info_disclosure",
                "authorization",
                "tool_abuse",
                "agent_security",
            ),
            seeded_weaknesses=(
                "Vertical tool escalation (privileged cancel_booking for "
                "an unprivileged traveler)",
                "Unregistered tool execution (no dispatch allowlist)",
                "Destructive action without a confirmation safeguard",
                "Unvalidated tool arguments (path traversal accepted)",
                "Destructive tool call triggered by untrusted content",
                "Conversational destructive actions without approval",
                "Embedded-instruction following in simulated tool output",
            ),
            complexity="High — multi-tool agent scenario",
            architecture=(
                "Agent over five synthetic tools (search_flights, "
                "search_hotels, get_booking_details, create_booking, "
                "cancel_booking) and a synthetic booking store. The "
                "vulnerable profile removes the dispatch allowlist, role "
                "checks, argument validation, and confirmation gates. All "
                "destructive operations are simulated and recorded as "
                "synthetic action markers only."
            ),
            synthetic_data=(
                "Travelers alpha and beta with synthetic bookings "
                "BK-ALPHA-100 and BK-BETA-200; no real bookings, payments, "
                "or external services."
            ),
            limitations=_COMMON_LIMITATIONS,
        ),
        factory=scenarios.build_travel_agent,
        default_profile="vulnerable",
    ),
    "demo-crm-assistant": DemoTargetDefinition(
        info=DemoTargetInfo(
            id="demo-crm-assistant",
            display_name="Multi-Tenant CRM Assistant",
            category="Multi-Tenant SaaS AI",
            description=(
                "An AI assistant over a synthetic CRM used by two "
                "organizations. Intentionally seeded with cross-tenant "
                "access-control weaknesses (IDOR)."
            ),
            provider_label="OpenAI",
            model_label="GPT-4o-mini",
            environment="Simulated",
            security_profile=INTENTIONALLY_VULNERABLE,
            capabilities=(
                "prompts",
                "multi-turn conversation",
                "synthetic tools",
            ),
            supported_modules=(
                "baseline",
                "prompt_injection",
                "info_disclosure",
                "authorization",
                "tool_abuse",
            ),
            seeded_weaknesses=(
                "IDOR: tenant Alpha can read tenant Beta's record by ID",
                "Cross-tenant record disclosure through plain prompts",
            ),
            complexity="Medium — tenancy boundary scenario",
            architecture=(
                "CRM assistant over synthetic records for organizations "
                "Alpha and Beta with record read/list/delete tools. The "
                "vulnerable profile skips object-level ownership "
                "validation on reads; everything else (role checks, "
                "safeguards, injection resistance) stays enforced to show "
                "a realistic partial failure."
            ),
            synthetic_data=(
                "Org Alpha record ALPHA-CUST-001 and org Beta record "
                "BETA-CUST-042 (synthetic markers only)."
            ),
            limitations=_COMMON_LIMITATIONS,
        ),
        factory=scenarios.build_crm_assistant,
        default_profile="vulnerable",
    ),
    "demo-dev-copilot": DemoTargetDefinition(
        info=DemoTargetInfo(
            id="demo-dev-copilot",
            display_name="Developer Copilot Assistant",
            category="Developer Tooling AI",
            description=(
                "A synthetic AI coding assistant wired into a mock code "
                "review environment. Intentionally seeded with disclosure, "
                "injection, and output-handling weaknesses."
            ),
            provider_label="Anthropic",
            model_label="Claude 3.7 Sonnet",
            environment="Simulated",
            security_profile=INTENTIONALLY_VULNERABLE,
            capabilities=(
                "prompts",
                "multi-turn conversation",
                "tool-call probing",
            ),
            supported_modules=(
                "baseline",
                "prompt_injection",
                "info_disclosure",
                "output_handling",
                "agent_security",
            ),
            seeded_weaknesses=(
                "System prompt disclosure (canary leak)",
                "Synthetic configuration/credential disclosure",
                "Direct and embedded prompt-injection compliance",
                "Injected instructions persist across turns",
                "Verbatim markup passthrough to downstream consumers",
                "Destructive tool call triggered by untrusted content",
            ),
            complexity="Medium — disclosure and output scenario",
            architecture=(
                "Chat copilot that reviews quoted (untrusted) code-review "
                "content and can propose tool calls in OpenAI function "
                "format. Proposed calls are parsed as evidence only; the "
                "framework never executes them. No OS commands are run."
            ),
            synthetic_data=(
                "Synthetic repository notes and a clearly labeled "
                "synthetic credential in the simulated system prompt."
            ),
            limitations=_COMMON_LIMITATIONS,
        ),
        factory=scenarios.build_dev_copilot,
        default_profile="vulnerable",
    ),
}


def get_definition(target_id: str) -> DemoTargetDefinition | None:
    return DEMO_TARGETS.get(target_id)


def list_demo_targets() -> list[dict[str, Any]]:
    return [definition.info.to_dict() for definition in DEMO_TARGETS.values()]
