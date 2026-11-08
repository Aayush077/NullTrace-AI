# Examples

- `nulltrace demo` — runs the bundled synthetic local agent (hardened
  profile). No real customer data, no network requests.
- `reports/example-hardened.{json,md}` — full assessment of the hardened
  mock: 25 checks, all pass, zero findings.
- `reports/example-vulnerable.{json,md}` — full assessment of the
  deliberately vulnerable training fixture: 22 evidence-backed findings,
  all labeled synthetic and pending human review.

Regenerate them with:

```bash
uv run nulltrace assess --mode mock --profile full \
    -o reports/example-hardened.json -m reports/example-hardened.md
uv run nulltrace assess --mode mock --mock-profile vulnerable --profile full \
    -o reports/example-vulnerable.json -m reports/example-vulnerable.md
```
