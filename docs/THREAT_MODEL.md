# Threat model

## Assets

Target credentials (API keys), assessment evidence and reports, the
local execution environment, and the target system itself (which must
not be harmed by assessment).

## Threats and controls

| Threat | Controls |
| --- | --- |
| Unauthorized target testing | offline mock default; api mode requires `--allow-network` and explicit target configuration; ethics policy |
| SSRF / DNS rebinding via the configured endpoint | strict base-URL validation (no credentials, query, fragment; no private/reserved/multicast IPs; no non-localhost HTTP); single DNS resolution with rejection of mixed/unsafe answers; connections pinned to validated IPs **and** validated host:port origin; redirects refused; proxies disabled |
| TLS downgrade / wrong-host certificates | certificate verification always on; SNI and hostname verification use the original (IDNA-normalized) hostname, never the pinned IP |
| Excessive traffic against the target | request budget (checked before DNS and before each send), bounded timeouts, response-size limits, no retries, no keepalive, sequential execution |
| Secret leakage into evidence/reports | API keys only via environment variables; redaction of known secret values and common credential patterns in evidence, findings, and errors; schema validation before writing |
| Malicious target output attacking the assessor | responses treated as data; size limits; JSON parsed defensively; no rendering or execution of target output; markdown evidence wrapped in code spans |
| Analyzer prompt injection (target content changing framework behavior) | the framework never feeds target output into its own decision logic beyond marker/token string matching; target content cannot register tools or alter policy |
| False positives / fabricated findings | marker- and token-attributed evidence required for failures; heuristic observations capped at `inconclusive`; findings start `pending_review`; passed checks carry no security claim |
| Destructive actions against targets | detection-only checks; synthetic tools; no real destructive operations; prompt-triggered-action checks detect execution markers rather than causing real effects |

### Web platform additions

| Threat | Controls |
| --- | --- |
| Exposed dashboard | local-only design: bind 127.0.0.1; optional shared token (`NULLTRACE_API_TOKEN`, `X-API-Token` header); no multi-user auth — public exposure is explicitly unsupported and documented |
| API key theft via web layer | keys never stored/returned/logged; only env-var names are handled; keys are registered with the redaction engine for the run |
| Unauthorized network runs via API | double gate: target-level `allow_network` flag AND per-run consent, enforced server-side |
| Path traversal in downloads / static files | reports generated from DB content only; SPA handler resolves paths and refuses anything outside the dist directory |
| Malicious input to API | pydantic validation with bounds; same strict base-URL validation as the CLI; parameterized SQL throughout |

## Residual risks (accepted or open)

- The assessor's own machine environment (shell history, report files)
  is outside NullTrace's control; reports may still contain sensitive
  target responses that pattern-based redaction missed.
- `validate_base_url` and the transport defend against configured-URL
  SSRF, but the transport has not had an external security review
  (Phase 8).
- Nondeterministic targets can produce unreproducible evidence; the
  framework records probes verbatim to mitigate.

## Limitations

A finite test suite cannot prove an AI system secure. Results depend on
coverage, configuration, model nondeterminism, and available
instrumentation.
