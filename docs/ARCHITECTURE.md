# Architecture

The CLI calls application services; services orchestrate checks against a target adapter; checks emit structured observations; the reporting layer serializes results.

```text
CLI
 └── Assessment service
      ├── Authorization/scope gate
      ├── Target adapter (local mock in this release)
      ├── Checks (baseline, prompt-boundary, tool permission)
      ├── Evidence and finding models
      └── JSON / Markdown reporting
```

## Core contracts

- Target: a named system under assessment.
- Check: deterministic test with an identifier and description.
- Observation: what the target returned or did.
- Finding: a potential or validated security issue with evidence and remediation.
- Run: timestamped collection of check results.

## Extension rules

Keep checks independent of the CLI and provider-specific SDKs. Add remote adapters only with explicit scope allowlists, authorization confirmation, bounded request budgets, timeouts, response-size limits and redaction.
