# Benchmark Results

**Benchmark type: INTERNAL SYNTHETIC.** These numbers measure NullTrace
AI against its own deterministic Demo Target Lab fixtures. They are a
regression and false-positive/false-negative control, **not** external
validation against third-party vulnerable applications, and **not** a
claim of real-world detection rate. No network calls are made.

Reproduce:

```bash
uv run nulltrace benchmark --profile comprehensive -o reports/benchmark-comprehensive.json
uv run nulltrace benchmark --profile standard      -o reports/benchmark-standard.json
```

## Methodology

- **Targets:** the 5 Demo Lab scenarios, each in its vulnerable profile
  (where applicable) and its secure control variant — 9 benchmark cases.
- **Ground truth:** derived independently from each scenario's declared
  `SimulationWeaknesses` flags via a fixed flag→check-ID mapping
  (`src/nulltrace/benchmark/ground_truth.py`), authored from check
  objectives — **not** read back from tool output.
- **Scoring:** per executed check — expected-FAIL that FAILs = TP;
  unexpected FAIL = FP; expected-FAIL that does not FAIL = FN; other
  executed checks = TN. SKIPPED checks (capability absent / not in
  profile) are excluded.
- **Metrics:** precision = TP/(TP+FP), recall = TP/(TP+FN),
  F1 = harmonic mean.

## Results (measured in this environment)

### Comprehensive profile (corpus v1.0, full families)

| Scope | TP | FP | FN | TN | Precision | Recall | F1 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| **overall** | 30 | 0 | 0 | 179 | 1.000 | 1.000 | 1.000 |
| prompt_injection | 8 | 0 | 0 | 46 | 1.000 | 1.000 | 1.000 |
| info_disclosure | 3 | 0 | 0 | 24 | 1.000 | 1.000 | 1.000 |
| authorization | 3 | 0 | 0 | 16 | 1.000 | 1.000 | 1.000 |
| tool_abuse | 4 | 0 | 0 | 20 | 1.000 | 1.000 | 1.000 |
| rag_security | 3 | 0 | 0 | 3 | 1.000 | 1.000 | 1.000 |
| agent_security | 7 | 0 | 0 | 27 | 1.000 | 1.000 | 1.000 |
| attack_chains | 2 | 0 | 0 | 16 | 1.000 | 1.000 | 1.000 |
| output_handling | 0 | 0 | 0 | 18 | 1.000 | 1.000 | 1.000 |
| baseline | 0 | 0 | 0 | 9 | 1.000 | 1.000 | 1.000 |

### Standard profile (depth 2)

| Scope | TP | FP | FN | TN | Precision | Recall | F1 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| **overall** | 18 | 0 | 0 | 133 | 1.000 | 1.000 | 1.000 |

(attack_chains and the deeper probe families are not part of the
standard profile, hence fewer true positives; this is coverage, not a
miss — no false negatives against the checks that ran.)

## Interpretation (honest)

- **What this proves:** on deterministic fixtures, the engine produces
  **zero false positives** on secure control variants and **zero false
  negatives** on seeded weaknesses, across depth profiles, with every
  finding attributable to a probe/marker. This is a strong regression
  guarantee and a genuine demonstration that detection is behavior-driven
  (secure variant of each scenario, receiving identical probes, yields no
  findings).
- **What this does NOT prove:** real-world precision/recall against
  production LLM applications. The fixtures are rule-based simulations,
  so a 1.0 score is expected and is a *control*, not a *field result*.
  Real targets are nondeterministic and adversarially harder; measuring
  there requires the deep profile's repeated sampling and authorized live
  access (see KNOWN_LIMITATIONS.md).

## External benchmarks — pending

Validation against independently maintained vulnerable LLM applications
(e.g. OWASP GenAI project resources) is **not performed here**: it
requires network access and explicit target authorization, which the
automated development process must not use. The harness accepts any
registered target, so such runs can be added as a separate, clearly
labeled "external benchmark" once an authorized environment is
available. No external numbers are claimed in this document.
