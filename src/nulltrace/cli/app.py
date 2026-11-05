import json
from pathlib import Path

import typer
from rich.console import Console
from rich.table import Table

from nulltrace import __version__
from nulltrace.adapters.openai_compatible import (
    AdapterError,
    OpenAICompatibleAdapter,
)
from nulltrace.core.budget import RequestBudget
from nulltrace.core.runner import run_assessment, run_local_assessment
from nulltrace.reporting.render import to_markdown

app = typer.Typer(
    no_args_is_help=True,
    help="NullTrace AI — local-first AI security assessment.",
)
console = Console()

ASSESS_OUTPUT_OPTION = typer.Option(
    Path("reports/demo-report.json"),
    "--output",
    "-o",
)


@app.command()
def version() -> None:
    console.print(f"NullTrace AI {__version__}")


@app.command()
def doctor() -> None:
    console.print("[green]Environment check passed.[/green]")
    console.print("Mode: local-only demo; no network access.")
    console.print("Python requirement: 3.11+.")
    console.print("Status: development MVP, not a production scanner.")


@app.command()
def demo() -> None:
    report = run_local_assessment().to_dict()

    table = Table(title="NullTrace AI — Local Demo")
    table.add_column("Check")
    table.add_column("Status")
    table.add_column("Severity")

    for finding in report["findings"]:
        table.add_row(
            finding["check_id"],
            finding["status"],
            finding["severity"],
        )

    console.print(table)
    console.print("Synthetic local target only. No external system was contacted.")


@app.command()
def assess(
    mode: str = typer.Option(
        "mock",
        "--mode",
        help="Assessment mode: mock or api.",
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
    output: Path = ASSESS_OUTPUT_OPTION,
) -> None:
    if mode == "mock":
        target_report = run_local_assessment()
        target_description = "local-mock-agent (offline synthetic demo)"

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

            console.print(
                "[yellow]Network assessment authorized.[/yellow]"
            )
            console.print(
                "Only synthetic assessment prompts will be sent. "
                f"Maximum outbound requests: {max_requests}."
            )

            adapter = OpenAICompatibleAdapter(
                model=model,
                base_url=base_url,
                api_key_env=api_key_env,
                request_budget=budget,
            )

            target_report = run_assessment(
                adapter,
                request_budget=budget,
            )
            target_description = adapter.target_name

        except (AdapterError, ValueError) as exc:
            raise typer.BadParameter(str(exc)) from exc

    else:
        raise typer.BadParameter("--mode must be either 'mock' or 'api'.")

    report_data = target_report.to_dict()

    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(
        json.dumps(report_data, indent=2),
        encoding="utf-8",
    )

    console.print(f"[green]Assessment report written to {output}[/green]")
    console.print(f"Target: {target_description}")
    console.print(f"Assessment status: {report_data['assessment_status']}")
    console.print(f"Requests used: {report_data['requests_used']}")

    if report_data["request_limit"] is not None:
        console.print(f"Request limit: {report_data['request_limit']}")


@app.command()
def report(path: Path) -> None:
    if not path.is_file():
        raise typer.BadParameter(f"Report file does not exist: {path}")

    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise typer.BadParameter(f"Invalid JSON report: {exc}") from exc

    console.print(to_markdown(data))


if __name__ == "__main__":
    app()
