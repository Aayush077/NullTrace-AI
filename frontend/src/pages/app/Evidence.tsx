import { useMemo, useState } from "react";
import { Link } from "react-router-dom";
import { api } from "../../lib/api";
import { useAsync } from "../../lib/useAsync";
import {
  Card,
  CardHeader,
  EmptyState,
  ErrorState,
  SeverityBadge,
  Spinner,
} from "../../components/ui";
import { EvidenceBlock } from "../../components/EvidenceBlock";
import { formatDateTime, titleCase } from "../../lib/format";

export function EvidenceExplorer() {
  const findings = useAsync(() => api.findings({ limit: "500" }), []);
  const [category, setCategory] = useState("");

  const entries = useMemo(() => {
    const list = findings.data ?? [];
    return list
      .filter((finding) => !category || finding.category === category)
      .flatMap((finding) =>
        finding.evidence.map((evidence, index) => ({
          key: `${finding.finding_id}-${index}`,
          finding,
          evidence,
        })),
      );
  }, [findings.data, category]);

  const categories = useMemo(() => {
    const set = new Set((findings.data ?? []).map((f) => f.category));
    return ["", ...Array.from(set).sort()];
  }, [findings.data]);

  return (
    <div className="space-y-6">
      <div className="flex flex-wrap items-end justify-between gap-3">
        <div>
          <h1 className="text-xl font-semibold tracking-tight">Evidence</h1>
          <p className="mt-1 text-sm text-tx-3">
            Every probe/response pair backing a finding. Evidence is stored
            after secret redaction; synthetic fixtures are labeled.
          </p>
        </div>
        <select
          aria-label="Filter by category"
          className="input w-56"
          value={category}
          onChange={(event) => setCategory(event.target.value)}
        >
          {categories.map((option) => (
            <option key={option || "all"} value={option}>
              {option ? titleCase(option) : "All categories"}
            </option>
          ))}
        </select>
      </div>

      {findings.loading ? (
        <Spinner />
      ) : findings.error ? (
        <ErrorState message={findings.error} onRetry={findings.reload} />
      ) : entries.length === 0 ? (
        <Card>
          <EmptyState
            title="No evidence recorded"
            detail="Evidence appears here once assessments produce findings."
          />
        </Card>
      ) : (
        <div className="space-y-4">
          {entries.map(({ key, finding, evidence }) => (
            <Card key={key}>
              <CardHeader
                title={finding.title}
                subtitle={`${finding.check_id} · recorded ${formatDateTime(finding.timestamp)}`}
                action={
                  <div className="flex items-center gap-2">
                    <SeverityBadge severity={finding.severity} />
                    <Link
                      to={`/app/findings/${finding.finding_id}`}
                      className="text-xs text-violet-300 hover:text-violet-200"
                    >
                      Open finding →
                    </Link>
                  </div>
                }
              />
              <div className="px-5 py-4">
                <EvidenceBlock evidence={evidence} />
              </div>
            </Card>
          ))}
        </div>
      )}
    </div>
  );
}
