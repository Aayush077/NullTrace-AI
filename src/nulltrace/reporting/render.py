from typing import Any


def to_markdown(data: dict[str, Any]) -> str:
    lines = [
        f"# {data['project']} assessment",
        "",
        f"- Target: `{data['target']}`",
        f"- Started: {data['started_at']}",
        f"- Completed: {data['completed_at']}",
        "",
        "## Findings",
        "",
    ]
    for item in data["findings"]:
        lines += [
            f"### {item['check_id']} — {item['title']}",
            f"- Severity: **{item['severity']}**",
            f"- Status: **{item['status']}**",
            f"- Description: {item['description']}",
            f"- Remediation: {item['remediation']}",
            "- Evidence:",
        ]
        lines.extend([f"  - {e}" for e in item["evidence"]])
        lines.append("")
    lines += ["## Notes", ""]
    lines.extend([f"- {note}" for note in data.get("notes", [])])
    return "\n".join(lines) + "\n"
