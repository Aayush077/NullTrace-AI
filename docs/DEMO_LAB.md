# Demo Target Lab guide

The Demo Target Lab (dashboard → **Demo Lab**, or `nulltrace targets` /
`nulltrace assess --mode demo`) ships five synthetic AI application
scenarios: one secure baseline and four with intentionally seeded
weaknesses. Assessments execute the real check suite against the
selected application — findings come from observed behavior, never from
the target's label.

**Everything is synthetic.** Targets are deterministic, rule-based
simulations (`src/nulltrace/targets/`). The model names attached to them
are *simulated model configuration labels only*: no provider API is ever
contacted, no real model was tested, and no seeded weakness describes
any real model or provider. All records, documents, credentials, and
"destructive actions" are clearly-labeled synthetic markers.

## The five targets

| Target (id) | Simulated model | Profile | Supported modules | Seeded weaknesses |
| --- | --- | --- | --- | --- |
| Secure Customer Support Assistant (`demo-secure-support`) | OpenAI GPT-4o | Secure baseline | baseline, prompt_injection, info_disclosure, authorization, tool_abuse, output_handling, agent_security | none — expected result: all applicable checks pass, RAG checks skipped, zero findings |
| Enterprise Knowledge Assistant (`demo-enterprise-rag`) | Anthropic Claude 3.7 Sonnet | Intentionally vulnerable | baseline, prompt_injection, info_disclosure, rag_security | cross-user document retrieval (no doc ACL), poisoned-document indirect injection, retrieval metadata leakage, cross-user prompt disclosure, embedded-instruction following |
| Travel Booking AI Agent (`demo-travel-agent`) | Google Gemini 2.5 Pro | Intentionally vulnerable | baseline, prompt_injection, info_disclosure, authorization, tool_abuse, agent_security | vertical tool escalation, unregistered tool execution, destructive action without safeguard, unvalidated tool arguments, injected destructive tool calls, conversational actions without approval, tool-output trust |
| Multi-Tenant CRM Assistant (`demo-crm-assistant`) | OpenAI GPT-4o-mini | Intentionally vulnerable | baseline, prompt_injection, info_disclosure, authorization, tool_abuse | IDOR (tenant Alpha reads tenant Beta's record by ID), cross-tenant disclosure via prompts — everything else stays enforced, demonstrating a realistic partial failure |
| Developer Copilot Assistant (`demo-dev-copilot`) | Anthropic Claude 3.7 Sonnet | Intentionally vulnerable | baseline, prompt_injection, info_disclosure, output_handling, agent_security | system prompt disclosure, synthetic credential disclosure, direct + embedded injection compliance, cross-turn instruction persistence, markup passthrough, injected destructive tool calls |

Observed full-profile results (reproduced by `tests/test_demo_targets.py`
and the example reports in `reports/demo-*.json`):

| Target | pass | fail | inconclusive | skipped | findings |
| --- | --- | --- | --- | --- | --- |
| demo-secure-support | 23 | 0 | 0 | 3 | 0 |
| demo-enterprise-rag | 14 | 6 | 0 | 6 | 6 |
| demo-travel-agent | 13 | 10 | 0 | 3 | 10 |
| demo-crm-assistant | 21 | 2 | 0 | 3 | 2 |
| demo-dev-copilot | 7 | 10 | 1 | 8 | 11 |

These are *observed* outcomes of executed checks, not hardcoded values;
severity is assigned per finding from impact and evidence.

## Secure control variants

Every vulnerable scenario has a **secure control variant** — the same
application with all controls enforced. It receives the identical
probes and produces zero findings, proving detection is behavior-driven
and the framework does not generate false positives from a target's
label:

```bash
uv run nulltrace assess --mode demo --target demo-travel-agent --profile full
uv run nulltrace assess --mode demo --target demo-travel-agent --secure-variant --profile full
```

In the dashboard, tick "Run the secure control variant" in the run
dialog, then select both runs on the Assessments page and press
**Compare**.

## How detection works (per check)

1. The check plans its probe from what the target *declares*
   (`describe_tools()` / `describe_retrieval()` / capabilities), never
   from scenario-specific hardcoding.
2. A unique per-assessment probe token or a declared synthetic marker
   (canary, record, action marker, poison token) makes the expected
   violation attributable.
3. The probe executes; the actual response is captured as evidence.
4. The security boundary is evaluated: FAIL only when the attributable
   marker/token demonstrates the violation; heuristic-only observations
   are capped at INCONCLUSIVE; missing capabilities produce SKIPPED
   (never PASS).
5. Findings are created in `pending_review` with severity, confidence,
   reproduction steps, and remediation.

The dashboard's assessment page shows this per check: objective, exact
probe, target response, detection outcome, evidence, and the execution
timeline.

## Marker namespaces

Each target owns a disjoint synthetic marker namespace (e.g.
`SYNTHETIC-RECORD-ORG-BETA-CUST-042`, `NT-CANARY-TRV-…`), so evidence is
attributable to exactly one environment; a regression test enforces the
non-collision.

## Extending the lab

Add a scenario by composing `SyntheticAIApplication` with the capability
shells in `targets/scenarios.py`, declaring its weaknesses as
`SimulationWeaknesses` flags, and registering a `DemoTargetDefinition`
in `targets/registry.py`. New scenarios need the standard test pair:
vulnerable behavior detected, secure variant clean.
