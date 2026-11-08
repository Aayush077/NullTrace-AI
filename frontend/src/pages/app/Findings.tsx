import { useState } from "react";
import { Link } from "react-router-dom";
import { Search } from "lucide-react";
import { api } from "../../lib/api";
import { useAsync } from "../../lib/useAsync";
import {
  Card,
  ConfidenceBadge,
  EmptyState,
  ErrorState,
  SeverityBadge,
  Spinner,
  ValidationBadge,
} from "../../components/ui";
import { timeAgo, titleCase } from "../../lib/format";

const SEVERITIES = ["", "critical", "high", "medium", "low", "informational"];
const CONFIDENCES = ["", "high", "medium", "low"];
const VALIDATIONS = ["", "pending_review", "confirmed", "rejected", "needs_retesting"];
const CATEGORIES = [
  "",
  "prompt_injection",
  "info_disclosure",
  "authorization",
  "tool_abuse",
  "output_handling",
  "rag_security",
  "agent_security",
];

export function Findings() {
  const [search, setSearch] = useState("");
  const [severity, setSeverity] = useState("");
  const [confidence, setConfidence] = useState("");
  const [validation, setValidation] = useState("");
  const [category, setCategory] = useState("");

  const findings = useAsync(
    () =>
      api.findings({
        search: search || undefined,
        severity: severity || undefined,
        confidence: confidence || undefined,
        validation_status: validation || undefined,
        category: category || undefined,
      }),
    [search, severity, confidence, validation, category],
  );

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-xl font-semibold tracking-tight">Findings</h1>
        <p className="mt-1 text-sm text-tx-3">
          Evidence-backed findings across all assessments. Automation never
          confirms a finding — review state is yours to set.
        </p>
      </div>

      <Card className="p-4">
        <div className="grid gap-3 lg:grid-cols-5">
          <div className="relative lg:col-span-2">
            <Search className="pointer-events-none absolute left-3 top-2.5 h-4 w-4 text-tx-3" aria-hidden />
            <input
              className="input pl-9"
              placeholder="Search title, finding ID, or check ID…"
              value={search}
              onChange={(event) => setSearch(event.target.value)}
            />
          </div>
          <FilterSelect label="Severity" value={severity} onChange={setSeverity} options={SEVERITIES} />
          <FilterSelect label="Confidence" value={confidence} onChange={setConfidence} options={CONFIDENCES} />
          <FilterSelect label="Review" value={validation} onChange={setValidation} options={VALIDATIONS} />
          <div className="lg:col-start-5">
            <FilterSelect label="Category" value={category} onChange={setCategory} options={CATEGORIES} />
          </div>
        </div>
      </Card>

      <Card>
        {findings.loading ? (
          <Spinner />
        ) : findings.error ? (
          <ErrorState message={findings.error} onRetry={findings.reload} />
        ) : !findings.data || findings.data.length === 0 ? (
          <EmptyState
            title="No findings match"
            detail="Adjust the filters, or run an assessment. Findings are only created when a check fails with attributable evidence."
          />
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full min-w-[840px] text-left text-sm">
              <thead>
                <tr className="border-b border-line text-[11px] uppercase tracking-wider text-tx-3">
                  <th className="px-5 py-3 font-medium">Finding</th>
                  <th className="px-5 py-3 font-medium">Category</th>
                  <th className="px-5 py-3 font-medium">Severity</th>
                  <th className="px-5 py-3 font-medium">Confidence</th>
                  <th className="px-5 py-3 font-medium">Review</th>
                  <th className="px-5 py-3 font-medium">When</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-line">
                {findings.data.map((finding) => (
                  <tr key={finding.finding_id} className="hover:bg-ink-800/50">
                    <td className="max-w-sm px-5 py-3">
                      <Link
                        to={`/app/findings/${finding.finding_id}`}
                        className="block"
                      >
                        <p className="truncate text-sm font-medium text-tx-1 hover:text-violet-300">
                          {finding.title}
                        </p>
                        <p className="mt-0.5 truncate font-mono text-[11px] text-tx-3">
                          {finding.finding_id}
                        </p>
                      </Link>
                    </td>
                    <td className="px-5 py-3 font-mono text-xs text-tx-3">
                      {finding.category}
                    </td>
                    <td className="px-5 py-3">
                      <SeverityBadge severity={finding.severity} />
                    </td>
                    <td className="px-5 py-3">
                      <ConfidenceBadge confidence={finding.confidence} />
                    </td>
                    <td className="px-5 py-3">
                      <ValidationBadge status={finding.validation_status} />
                    </td>
                    <td className="px-5 py-3 text-xs text-tx-3">
                      {timeAgo(finding.timestamp)}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Card>
    </div>
  );
}

function FilterSelect({
  label,
  value,
  onChange,
  options,
}: {
  label: string;
  value: string;
  onChange: (value: string) => void;
  options: string[];
}) {
  return (
    <select
      aria-label={label}
      className="input"
      value={value}
      onChange={(event) => onChange(event.target.value)}
    >
      {options.map((option) => (
        <option key={option || "all"} value={option}>
          {option ? titleCase(option) : `All ${label.toLowerCase()}`}
        </option>
      ))}
    </select>
  );
}
