"""Internal synthetic benchmark harness.

Measures NullTrace AI's detection performance against the Demo Target
Lab, whose ground truth is *independently declared* here (not derived
from running the tool). This is an INTERNAL SYNTHETIC benchmark: it
measures the engine against its own deterministic fixtures. It is not
external validation against third-party vulnerable applications, and the
harness never makes network calls.
"""

from nulltrace.benchmark.harness import BenchmarkReport, run_benchmark

__all__ = ["BenchmarkReport", "run_benchmark"]
