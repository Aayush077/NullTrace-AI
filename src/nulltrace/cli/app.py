"""NullTrace AI command-line interface."""

import json
import os
from pathlib import Path
from typing import Any

import typer
from rich.console import Console
from rich.table import Table

from nulltrace import __version__
from nulltrace.adapters.openai_compatible import (
    AdapterError,
    OpenAICompatibleAdapter,
    validate_base_url,
)
from nulltrace.checks.registry import MODULES, PROFILES
from nulltrace.core.budget import RequestBudget
from nulltrace.core.models import AssessmentReport
from nulltrace.core.runner import run_assessment, run_local_assessment
from nulltrace.reporting.render import (
    ReportValidationError,
    to_markdown,
    validate_report,
)
from nulltrace.targets.registry import DEMO_TARGETS, get_definition

app = typer.Typer(
    no_args_is_help=True,
    help="NullTrace AI — evidence-first AI application security assessment.",
)
console = Console()

ASSESS_OUTPUT_OPTION = typer.Option(
    Path("reports/assessment-report.json"),
    "--output",
    "-o",
    help="Path for the JSON report.",
)

ASSESS_MARKDOWN_OPTION = typer.Option(
    None,
    "--markdown-output",
    "-m",
    help="Optional path for a rendered Markdown report.",
)

BENCHMARK_OUTPUT_OPTION = typer.Option(
    None,
    "--output",
    "-o",
    help="Optional path for the JSON benchmark report.",
)

USER_DB_OPTION = typer.Option(
    Path(os.getenv("NULLTRACE_DB_PATH", "data/nulltrace.db")),
    "--db",
    help="Web platform database path (defaults to $NULLTRACE_DB_PATH).",
)


def _parse_modules(modules: str) -> list[str] | None:
    names = [name.strip() for name in modules.split(",") if name.strip()]
    return names or None


def _write_report(
    report: AssessmentReport,
    output: Path,
    markdown_output: Path | None,
) -> None:
    data = report.to_dict()
    validate_report(data)

    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(data, indent=2), encoding="utf-8")
    console.print(f"[green]JSON report written to {output}[/green]")

    if markdown_output is not None:
        markdown_output.parent.mkdir(parents=True, exist_ok=True)
        markdown_output.write_text(to_markdown(data), encoding="utf-8")
        console.print(
            f"[green]Markdown report written to {markdown_output}[/green]"
        )


def _print_summary(report: AssessmentReport) -> None:
    counts = report.status_counts
    console.print(f"Assessment ID: {report.assessment_id}")
    console.print(f"Target: {report.target}")
    console.print(f"Assessment status: {report.assessment_status}")
    console.print(
        f"Checks: {len(report.results)} "
        f"(pass {counts['pass']}, fail {counts['fail']}, "
        f"inconclusive {counts['inconclusive']}, error {counts['error']}, "
        f"skipped {counts['skipped']})"
    )
    console.print(f"Findings: {len(report.findings)} (pending human review)")

    if report.request_limit is not None:
        console.print(
            f"Requests used: {report.requests_used} / {report.request_limit}"
        )


@app.command()
def version() -> None:
    """Show the installed NullTrace AI version."""

    console.print(f"NullTrace AI {__version__}")


@app.command()
def serve(
    host: str = typer.Option("127.0.0.1", "--host", help="Bind address."),
    port: int = typer.Option(8787, "--port", min=1, max=65535, help="Port."),
    reload: bool = typer.Option(
        False, "--reload", help="Auto-reload on code changes (development)."
    ),
) -> None:
    """Start the web dashboard (FastAPI backend + built frontend).

    This runs Uvicorn from the project's own environment, so it never
    falls back to a globally installed uvicorn on PATH. Bind to 127.0.0.1
    for local use; do not expose the dashboard to the public internet
    without the hardening described in docs/SECURITY_REVIEW.md.
    """

    try:
        import uvicorn
    except ImportError as exc:  # pragma: no cover - dependency is required
        raise typer.BadParameter(
            "uvicorn is not installed in this environment. Run "
            "'uv sync' (or 'pip install -e .') first."
        ) from exc

    console.print(
        f"[green]Starting NullTrace AI dashboard[/green] on "
        f"http://{host}:{port}  (landing: /, dashboard: /app, API docs: "
        "/api/docs)"
    )
    uvicorn.run(
        "nulltrace.web.main:app", host=host, port=port, reload=reload
    )


@app.command()
def doctor() -> None:
    """Check that the local environment can run assessments."""

    import sys

    ok = sys.version_info >= (3, 11)
    console.print(
        f"Python: {sys.version.split()[0]} "
        + ("[green]ok[/green]" if ok else "[red]3.11+ required[/red]")
    )
    console.print(f"Registered modules: {len(MODULES)} ({', '.join(MODULES)})")
    console.print(f"Profiles: {', '.join(PROFILES)}")
    console.print("Local mock mode: available offline, no credentials needed.")
    console.print(
        "Network mode: requires --mode api, --allow-network, and an API key "
        "environment variable."
    )

    if not ok:
        raise typer.Exit(code=1)


@app.command()
def modules() -> None:
    """List assessment modules and their checks."""

    table = Table(title="NullTrace AI assessment modules")
    table.add_column("Module")
    table.add_column("Check ID")
    table.add_column("Title")

    for module_name, checks in MODULES.items():
        for check_class in checks:
            table.add_row(module_name, check_class.check_id, check_class.title)

    console.print(table)
    console.print(
        "Profiles: "
        + "; ".join(
            f"{name} = {', '.join(members)}"
            for name, members in PROFILES.items()
        )
    )


@app.command()
def targets() -> None:
    """List the Demo Target Lab scenarios (all synthetic, all offline)."""

    table = Table(title="NullTrace AI — Demo Target Lab (synthetic)")
    table.add_column("ID")
    table.add_column("Name")
    table.add_column("Simulated model")
    table.add_column("Profile")
    table.add_column("Seeded weaknesses")

    for definition in DEMO_TARGETS.values():
        info = definition.info
        table.add_row(
            info.id,
            info.display_name,
            f"{info.provider_label} {info.model_label} (simulated)",
            info.security_profile,
            str(len(info.seeded_weaknesses)),
        )

    console.print(table)
    console.print(
        "Model names are display metadata for simulated configurations; "
        "no provider API is contacted."
    )


@app.command()
def benchmark(
    profile: str = typer.Option(
        "comprehensive",
        "--profile",
        help=f"Assessment profile: {', '.join(PROFILES)}.",
    ),
    output: Path | None = BENCHMARK_OUTPUT_OPTION,
) -> None:
    """Run the internal synthetic benchmark and print measured metrics.

    This measures detection against NullTrace AI's own Demo Target Lab
    fixtures (ground truth derived from declared weakness flags). It is
    NOT external validation against third-party vulnerable applications.
    """

    from nulltrace.benchmark import run_benchmark

    report = run_benchmark(profile=profile)
    data = report.to_dict()
    overall = data["overall"]

    console.print("[yellow]Internal synthetic benchmark[/yellow] "
                  "(not external validation; no network calls).")
    console.print(f"Profile: {profile} · corpus v{data['corpus_version']}")

    table = Table(title="Detection metrics")
    table.add_column("Scope")
    table.add_column("TP")
    table.add_column("FP")
    table.add_column("FN")
    table.add_column("TN")
    table.add_column("Precision")
    table.add_column("Recall")
    table.add_column("F1")

    table.add_row(
        "overall", str(overall["tp"]), str(overall["fp"]), str(overall["fn"]),
        str(overall["tn"]), f"{overall['precision']:.3f}",
        f"{overall['recall']:.3f}", f"{overall['f1']:.3f}",
    )
    for module, conf in data["per_module"].items():
        table.add_row(
            module, str(conf["tp"]), str(conf["fp"]), str(conf["fn"]),
            str(conf["tn"]), f"{conf['precision']:.3f}",
            f"{conf['recall']:.3f}", f"{conf['f1']:.3f}",
        )
    console.print(table)

    if output is not None:
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(json.dumps(data, indent=2), encoding="utf-8")
        console.print(f"[green]Benchmark report written to {output}[/green]")


@app.command()
def demo() -> None:
    """Run the offline synthetic demonstration (hardened mock target)."""

    report = run_local_assessment(profile="full")

    table = Table(title="NullTrace AI — local demo (synthetic target)")
    table.add_column("Check")
    table.add_column("Module")
    table.add_column("Status")

    for result in report.results:
        table.add_row(result.check_id, result.module, result.status.value)

    console.print(table)
    _print_summary(report)
    console.print(
        "Synthetic local target only. No external system was contacted."
    )


@app.command()
def assess(
    mode: str = typer.Option(
        "mock",
        "--mode",
        help="Assessment mode: mock, demo, or api.",
    ),
    mock_profile: str = typer.Option(
        "hardened",
        "--mock-profile",
        help="Mock target profile: hardened or vulnerable (mock mode only).",
    ),
    target: str = typer.Option(
        "",
        "--target",
        help="Demo Target Lab id (demo mode only); see 'nulltrace targets'.",
    ),
    secure_variant: bool = typer.Option(
        False,
        "--secure-variant",
        help="Run the secure control variant of the demo target.",
    ),
    profile: str = typer.Option(
        "standard",
        "--profile",
        help=f"Assessment profile: {', '.join(PROFILES)}.",
    ),
    modules: str = typer.Option(
        "",
        "--modules",
        help="Comma-separated module list (overrides --profile).",
    ),
    model: str = typer.Option(
        "",
        "--model",
        help="Model name for an OpenAI-compatible API.",
    ),
    base_url: str = typer.Option(
        "https://api.openai.com/v1",
        "--base-url",
        help="Base URL of the OpenAI-compatible API.",
    ),
    api_key_env: str = typer.Option(
        "OPENAI_API_KEY",
        "--api-key-env",
        help="Environment variable containing the API key.",
    ),
    allow_network: bool = typer.Option(
        False,
        "--allow-network",
        help="Explicitly authorize network requests in API mode.",
    ),
    max_requests: int = typer.Option(
        10,
        "--max-requests",
        min=1,
        help="Maximum outbound API requests for this assessment.",
    ),
    timeout: float = typer.Option(
        30.0,
        "--timeout",
        min=1.0,
        help="Per-request timeout in seconds (API mode).",
    ),
    output: Path = ASSESS_OUTPUT_OPTION,
    markdown_output: Path | None = ASSESS_MARKDOWN_OPTION,
) -> None:
    """Run a security assessment against the mock target or a configured API."""

    module_list = _parse_modules(modules)

    if mode == "mock":
        if mock_profile not in {"hardened", "vulnerable"}:
            raise typer.BadParameter(
                "--mock-profile must be 'hardened' or 'vulnerable'."
            )
        try:
            report = run_local_assessment(
                profile=profile,
                modules=module_list,
                mock_profile=mock_profile,
            )
        except ValueError as exc:
            raise typer.BadParameter(str(exc)) from exc

    elif mode == "demo":
        definition = get_definition(target)

        if definition is None:
            raise typer.BadParameter(
                "--target must name a demo target; run 'nulltrace targets'."
            )

        variant = "secure" if secure_variant else definition.default_profile

        try:
            report = run_assessment(
                definition.build(variant),
                modules=module_list,
                profile=profile,
                mode="mock",
            )
        except ValueError as exc:
            raise typer.BadParameter(str(exc)) from exc

        console.print(
            f"Demo target: {definition.info.display_name} "
            f"({variant}; simulated "
            f"{definition.info.provider_label} {definition.info.model_label})"
        )

    elif mode == "api":
        if not allow_network:
            raise typer.BadParameter(
                "API mode requires explicit network consent. "
                "Add --allow-network to proceed."
            )

        if not model.strip():
            raise typer.BadParameter(
                "--model is required when --mode api is selected."
            )

        try:
            budget = RequestBudget(max_requests=max_requests)

            console.print("[yellow]Network assessment authorized.[/yellow]")
            console.print(
                "Only synthetic assessment prompts will be sent. "
                f"Maximum outbound requests: {max_requests}."
            )

            adapter = OpenAICompatibleAdapter(
                model=model,
                base_url=base_url,
                api_key_env=api_key_env,
                timeout=timeout,
                request_budget=budget,
            )

            api_key = os.getenv(api_key_env) or ""

            report = run_assessment(
                adapter,
                request_budget=budget,
                modules=module_list,
                profile=profile,
                mode="api",
                known_secrets=(api_key,) if api_key else (),
            )

        except (AdapterError, ValueError) as exc:
            raise typer.BadParameter(str(exc)) from exc

    else:
        raise typer.BadParameter("--mode must be 'mock', 'demo', or 'api'.")

    _write_report(report, output, markdown_output)
    _print_summary(report)


@app.command()
def report(
    path: Path,
    output_format: str = typer.Option(
        "markdown",
        "--format",
        help="Output format: markdown or summary.",
    ),
) -> None:
    """Render a JSON report as Markdown or a short summary."""

    data = _load_report(path)

    if output_format == "markdown":
        console.print(to_markdown(data))
        return

    if output_format == "summary":
        summary = data["summary"]
        console.print(f"Assessment {data['assessment_id']} — {data['target']}")
        console.print(f"Status: {data['assessment_status']}")
        console.print(f"Checks executed: {summary['checks_executed']}")
        console.print(f"Status counts: {summary['status_counts']}")
        console.print(f"Findings: {summary['findings_total']}")
        console.print(f"By severity: {summary['findings_by_severity']}")
        return

    raise typer.BadParameter("--format must be 'markdown' or 'summary'.")


@app.command()
def findings(
    path: Path,
    severity: str = typer.Option(
        "",
        "--severity",
        help="Filter by severity (critical, high, medium, low, informational).",
    ),
) -> None:
    """List the findings recorded in a JSON report."""

    data = _load_report(path)
    items = data["findings"]

    if severity:
        items = [item for item in items if item["severity"] == severity]

    if not items:
        console.print("No findings match.")
        return

    table = Table(title=f"Findings — {data['assessment_id']}")
    table.add_column("ID")
    table.add_column("Severity")
    table.add_column("Confidence")
    table.add_column("Validation")
    table.add_column("Title")

    for item in items:
        table.add_row(
            item["finding_id"],
            item["severity"],
            item["confidence"],
            item["validation_status"],
            item["title"],
        )

    console.print(table)


@app.command("user-add")
def user_add(
    username: str = typer.Option(..., "--username", help="New user's name."),
    role: str = typer.Option(
        "admin", "--role", help="viewer, analyst, researcher, or admin."
    ),
    db_path: Path = USER_DB_OPTION,
    password: str = typer.Option(
        ...,
        "--password",
        prompt=True,
        hide_input=True,
        confirmation_prompt=True,
        help="Password (min 8 chars). Prompted securely if omitted.",
    ),
) -> None:
    """Create a web-platform user (use once to bootstrap the first admin).

    The password is never echoed or logged. Creating the first user
    closes the dashboard's open setup mode.
    """

    from nulltrace.web.service import AssessmentService, ServiceError

    service = AssessmentService(db_path)
    first = service.setup_mode()
    try:
        service.create_user(username, password, role)
    except ServiceError as exc:
        raise typer.BadParameter(str(exc)) from exc

    service.audit("cli", "user.create", f"username={username} role={role}")
    console.print(f"[green]Created user '{username}' with role '{role}'.[/green]")
    if first:
        console.print(
            "This was the first user — the dashboard now requires login."
        )


@app.command("validate-target")
def validate_target(
    base_url: str = typer.Option(
        ...,
        "--base-url",
        help="Base URL of the OpenAI-compatible API to validate.",
    ),
    api_key_env: str = typer.Option(
        "OPENAI_API_KEY",
        "--api-key-env",
        help="Environment variable expected to hold the API key.",
    ),
) -> None:
    """Validate target configuration without sending any request."""

    try:
        normalized = validate_base_url(base_url)
    except ValueError as exc:
        console.print(f"[red]Base URL rejected:[/red] {exc}")
        raise typer.Exit(code=1) from exc

    console.print(f"[green]Base URL accepted:[/green] {normalized}")

    if os.getenv(api_key_env):
        console.print(
            f"[green]API key environment variable '{api_key_env}' is set.[/green]"
        )
    else:
        console.print(
            f"[yellow]API key environment variable '{api_key_env}' is not "
            "set; API mode will fail until it is.[/yellow]"
        )

    console.print("No network request was made during validation.")


def _load_report(path: Path) -> dict[str, Any]:
    if not path.is_file():
        raise typer.BadParameter(f"Report file does not exist: {path}")

    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise typer.BadParameter(f"Invalid JSON report: {exc}") from exc

    if not isinstance(data, dict):
        raise typer.BadParameter("Report must be a JSON object.")

    try:
        validate_report(data)
    except ReportValidationError as exc:
        raise typer.BadParameter(f"Report failed validation: {exc}") from exc

    return data


if __name__ == "__main__":
    app()
