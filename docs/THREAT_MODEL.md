# Initial threat model

## Assets
Target data, credentials, assessment evidence, reports, and local execution environment.

## Threats and controls
- Unauthorized target testing: local-only default; explicit authorization required before remote adapters.
- Excessive requests: bounded runs, timeouts and concurrency limits.
- Secret leakage: redact sensitive values; never commit credentials.
- Malicious target output: treat responses as untrusted data; limit parsing and storage.
- False positives: distinguish potential findings from validated findings.
- Analyzer prompt injection: target content must never grant tools or change system policy.

## Limitations
A finite test suite cannot prove an AI system secure. Results depend on coverage, configuration, model nondeterminism and available instrumentation.
