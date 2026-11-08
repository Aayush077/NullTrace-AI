# Report and finding schema (version 1.0)

Reports are JSON objects validated by
`nulltrace.reporting.render.validate_report` before writing and before
rendering.

## Top level

| Field | Type | Notes |
| --- | --- | --- |
| schema_version | string | `"1.0"` |
| project / project_version | string | producer identity |
| assessment_id | string | `NTA-<12 hex>` unique per run |
| target | string | adapter target name |
| mode | string | `mock` or `api` |
| scope | string | what was (and was not) assessed |
| profile | string | `quick` / `standard` / `full` / `custom` |
| modules_executed | string[] | module names in execution order |
| started_at / completed_at | string | ISO-8601 UTC |
| assessment_status | string | `completed` or `incomplete` (budget stop) |
| synthetic_target | bool | true for the bundled mock |
| requests_used / request_limit | int / int\|null | budget accounting |
| summary | object | `checks_executed`, `status_counts`, `findings_total`, `findings_by_severity` |
| results | CheckResult[] | one per executed/skipped check |
| findings | Finding[] | deduplicated, severity-sortable |
| notes | string[] | run-specific caveats |
| limitations | string[] | standing epistemic limits |
| config | object | modules, profile, request limit |

## CheckResult

`check_id`, `module`, `title`, `status`
(`pass|fail|inconclusive|error|skipped`), `details`, `evidence[]`,
`error` (redacted, only for `error` status), `executed_at`,
`finding_ids[]`.

## Finding

| Field | Notes |
| --- | --- |
| finding_id | `<assessment_id>-<check_id>-<NN>` |
| check_id / category | originating check and module |
| title / description | human-readable statement |
| affected_component | target name |
| severity | `critical` / `high` / `medium` / `low` / `informational` |
| confidence | `high` (marker/token-attributed) / `medium` / `low` |
| evidence[] | `{probe, response, note, synthetic}` — stored **after redaction**; `synthetic: true` marks fixture evidence |
| reproduction_steps[] | ordered steps |
| expected_behavior / actual_behavior | contrast backed by evidence |
| impact / remediation / references[] | triage support |
| assessment_id / timestamp | linkage |
| validation_status | `pending_review` (always, at creation) / `confirmed` / `rejected` / `needs_retesting` — changed only by a human reviewer |
| review_note | optional free-text note set during human review (web platform) |

## Severity and confidence policy

- `critical`/`high` are only assigned with marker- or token-attributed
  evidence (confidence `high`).
- Heuristic-only observations never produce findings above
  `informational`, and usually produce `inconclusive` check results with
  no finding at all.
- Deduplication key: `(check_id, title, sha256(actual_behavior)[:16])`.
