# Industry-readiness gap analysis — baseline v0.4.0 (2026-11-06)

Independently verified against the codebase (not the docs) before this
milestone's implementation work began. Status column is updated as the
work lands; anything not completed in this milestone stays listed as a
gap — gaps are never closed on paper.

## Priority matrix

| # | Gap | Verified current state | Impact | Priority | Resolution plan | Done-when |
| --- | --- | --- | --- | --- | --- | --- |
| 1 | Probe corpus: ~1–2 fixed phrasings per check (grep: one `prompt_template`/`_PROBES` pair per check class) | Confirmed | A target resisting exact phrasings passes → false negatives | **Critical** | Versioned structured corpus, probe families per category, seeded mutation engine, depth-aware profiles | Corpus v1 ships with per-probe metadata; checks execute families; tests prove variant detection |
| 2 | No nondeterminism handling: every probe fires once (`send_prompt` called once per probe) | Confirmed | Flaky results against real sampled models; single response treated as ground truth | **Critical** | Repeated-sampling engine: configurable samples, violation/pass rates, consistency + reproducibility recorded separately from confidence | Sampling configurable per profile/run; rates in evidence; budget-capped |
| 3 | No multi-turn attack chains (only single planted-instruction persistence PI-005) | Confirmed | Misses staged attacks that real engagements exercise | **Critical** | `attack_chains` module: staged false-context, injection→elicitation, grooming→action chains with per-step evidence | Chains run vs lab matrix; secure variants clean |
| 4 | Marker-dependent detection; black-box capability undocumented | Confirmed (checks degrade to INCONCLUSIVE without hints) | Limited value vs arbitrary targets | **High** | Explicit detection modes (cooperative / black-box / hybrid) declared per check and documented; token/structural checks flagged black-box-capable | Mode matrix published; per-check mode in results |
| 5 | No benchmark measurement (no TP/FP/FN accounting anywhere) | Confirmed | Detection quality asserted, never measured | **High** | Internal benchmark harness over the lab matrix with ground truth; precision/recall/F1 per category; honest "internal synthetic" labeling | `nulltrace benchmark` produces measured report from real runs |
| 6 | No authentication/authorization on web platform (`require_token` shared-secret only) | Confirmed | Single-operator only; no professional deployment | **High** | Users (scrypt), sessions, roles (admin/researcher/viewer), login UI, open-local-mode fallback when no users exist | Auth enforced when users exist; role matrix tested |
| 7 | No audit logging | Confirmed | No accountability trail for engagements | **High** | `audit_log` table + hooks on login/assessment/review/report/user events; admin-only API | Events recorded + tested; no secrets in log |
| 8 | SQLite-only persistence | Confirmed | Fine locally; not multi-node | Medium | Keep SQLite; document PostgreSQL migration path. **Deferred — not implemented this milestone** | (pending) |
| 9 | Transport uses httpcore private interfaces; no independent review | Confirmed (`_pool`, `_backends` imports) | Security tool's own transport unaudited | **High** (review prep) | Internal re-audit + `SECURITY_REVIEW.md` with unresolved concerns; external review explicitly **pending** | Review doc exists; no "reviewed" claim anywhere |
| 10 | External vulnerable-lab validation absent | Confirmed | No third-party measured efficacy | Medium | Harness supports external targets behind authorization gates; live validation **deferred** (no live calls in automated work) | Harness ready; external runs marked pending |
| 11 | No packaging/release workflow (no Dockerfile, no release doc) | Confirmed | Unreproducible deployments | Medium | Dockerfile (built + smoke-tested), release levels + checklist docs, CI release gates | Image builds and serves; docs shipped |
| 12 | Report lacks engagement sections (no executive summary/methodology/scope sections in renderer) | Confirmed | Not client-ready | Medium | Report schema 1.1: executive summary, methodology (corpus version, sampling, detection modes), scope/limitations | Rendered + validated + tested |
| 13 | Real-system adapters: tool/authz/RAG/agent modules only reach synthetic fixtures | Confirmed | The strongest modules can't assess real apps | **High** | Generic HTTP RAG/tool adapter interfaces where verifiable offline; framework integrations (LangChain etc.) **deferred** — superficial integrations explicitly rejected | Interfaces + mocked-transport tests; deferred items documented |
| 14 | Request budgets count requests, not samples×probes | Confirmed | Deep profiles could surprise users | Medium | Profiles document expected request consumption; sampling bounded by budget | Documented per profile; enforced by existing budget |
| 15 | Password reset, orgs/projects, assessment resumption | Absent | Enterprise features | Low | **Deferred**, documented in RELEASE_LEVELS | (pending) |

## Items verified as already sound (no action)

- Evidence-first finding model, human-review gating, redaction,
  deduplication (0.2.0+); SSRF-hardened origin-pinned transport with 38
  regression tests (0.2.0/0.3.0); deterministic offline test discipline
  (258 tests at baseline); honest statuses incl. SKIPPED ≠ PASS.

## Explicitly out of scope for this milestone (honest deferrals)

PostgreSQL backend, organizations/projects multi-tenancy, password
reset flow, PDF export, LangChain/LlamaIndex/AutoGen/CrewAI adapters,
live external benchmark runs, independent third-party security review
(prepared, not performed), assessment resumption. Each appears in
`RELEASE_LEVELS.md` as a gate for the level that requires it.
