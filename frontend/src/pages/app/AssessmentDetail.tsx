import { useEffect, useState } from "react";
import { Link, useParams } from "react-router-dom";
import {
  ArrowLeft,
  CheckCircle2,
  ChevronDown,
  ChevronRight,
  Download,
  FileText,
  RefreshCw,
} from "lucide-react";
import { EvidenceBlock } from "../../components/EvidenceBlock";
import { api } from "../../lib/api";
import { useAsync } from "../../lib/useAsync";
import {
  Card,
  CardHeader,
  CheckStatusBadge,
  EmptyState,
  ErrorState,
  RunStatusBadge,
  SeverityBadge,
  Spinner,
  ValidationBadge,
} from "../../components/ui";
import { SeverityDonut } from "../../components/charts";
import { formatDateTime } from "../../lib/format";

export function AssessmentDetail() {
  const { id = "" } = useParams();
  const assessment = useAsync(() => api.assessment(id), [id]);
  const [expandedCheck, setExpandedCheck] = useState<string | null>(null);

  // Poll while a background (API-mode) assessment is still running.
  useEffect(() => {
    if (assessment.data?.status === "running") {
      const timer = window.setTimeout(assessment.reload, 2500);
      return () => window.clearTimeout(timer);
    }
    return undefined;
  }, [assessment.data?.status, assessment.reload]);

  if (assessment.loading && !assessment.data) return <Spinner />;
  if (assessment.error)
    return <ErrorState message={assessment.error} onRetry={assessment.reload} />;

  const record = assessment.data;
  if (!record) return null;
  const report = record.report;

  return (
    <div className="space-y-6">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div>
          <Link
            to="/app/assessments"
            className="mb-2 inline-flex items-center gap-1 text-xs text-tx-3 hover:text-tx-1"
          >
            <ArrowLeft className="h-3.5 w-3.5" aria-hidden /> All assessments
          </Link>
          <h1 className="font-mono text-lg font-semibold tracking-tight">{record.id}</h1>
          <p className="mt-1 text-sm text-tx-3">
            {record.target_name} · profile <span className="font-mono">{record.profile}</span> ·{" "}
            {formatDateTime(record.created_at)}
          </p>
          {record.model_label ? (
            <div className="mt-2 flex flex-wrap gap-1.5">
              <span className="chip border-sky-500/40 bg-sky-500/10 text-sky-300">
                Simulated model configuration: {record.provider_label}{" "}
                {record.model_label}
              </span>
              {record.variant ? (
                <span
                  className={`chip ${
                    record.variant === "secure"
                      ? "border-emerald-500/40 bg-emerald-500/10 text-emerald-300"
                      : "border-amber-500/40 bg-amber-500/10 text-amber-300"
                  }`}
                >
                  {record.variant === "secure"
                    ? "secure control variant"
                    : "intentionally vulnerable profile"}
                </span>
              ) : null}
            </div>
          ) : null}
        </div>
        <div className="flex items-center gap-2">
          <RunStatusBadge status={record.status} />
          {report ? (
            <>
              <button
                type="button"
                className="btn-ghost"
                onClick={() => void api.downloadReport(record.id, "json")}
              >
                <Download className="h-4 w-4" aria-hidden /> JSON
              </button>
              <button
                type="button"
                className="btn-ghost"
                onClick={() => void api.downloadReport(record.id, "markdown")}
              >
                <FileText className="h-4 w-4" aria-hidden /> Markdown
              </button>
            </>
          ) : null}
        </div>
      </div>

      {record.status === "running" ? (
        <Card>
          <EmptyState
            icon={<RefreshCw className="h-6 w-6 animate-spin" aria-hidden />}
            title="Assessment running"
            detail="Network assessments run in the background under their request budget. This page refreshes automatically."
          />
        </Card>
      ) : null}

      {record.status === "failed" ? (
        <Card>
          <ErrorState message={record.error || "The assessment failed to execute."} />
        </Card>
      ) : null}

      {report ? (
        <>
          <div className="grid gap-4 xl:grid-cols-3">
            <Card className="xl:col-span-2">
              <CardHeader title="Run details" />
              <dl className="grid gap-x-8 gap-y-3 px-5 py-4 text-sm sm:grid-cols-2">
                {[
                  ["Mode", report.mode],
                  ["Scope", report.scope],
                  ["Modules", report.modules_executed.join(", ")],
                  ["Synthetic target", report.synthetic_target ? "yes — evidence labeled synthetic" : "no"],
                  [
                    "Requests used",
                    report.request_limit !== null
                      ? `${report.requests_used} / ${report.request_limit}`
                      : String(report.requests_used),
                  ],
                  ["Started", formatDateTime(report.started_at)],
                  ["Completed", formatDateTime(report.completed_at)],
                  ["Report schema", `v${report.schema_version}`],
                ].map(([key, value]) => (
                  <div key={key}>
                    <dt className="text-[11px] uppercase tracking-wider text-tx-3">{key}</dt>
                    <dd className="mt-0.5 break-words text-xs text-tx-1">{value}</dd>
                  </div>
                ))}
              </dl>
              {report.notes.length > 0 ? (
                <div className="border-t border-line px-5 py-4">
                  <p className="text-[11px] uppercase tracking-wider text-tx-3">Notes</p>
                  <ul className="mt-2 list-disc space-y-1 pl-4 text-xs text-tx-2">
                    {report.notes.map((note) => (
                      <li key={note}>{note}</li>
                    ))}
                  </ul>
                </div>
              ) : null}
            </Card>
            <Card>
              <CardHeader title="Findings by severity" />
              <div className="px-5 py-3">
                <SeverityDonut
                  data={report.summary.findings_by_severity}
                  centerLabel="findings"
                />
              </div>
            </Card>
          </div>

          <ExecutionTimeline
            startedAt={report.started_at}
            completedAt={report.completed_at}
            checksExecuted={report.summary.checks_executed}
            findingsTotal={report.summary.findings_total}
            skipped={report.summary.status_counts.skipped}
          />

          <Card>
            <CardHeader
              title="Check execution detail"
              subtitle="Expand a check to see its objective, the exact probe, the target's response, and the detection logic. A failed security check is not a failed test execution; skipped checks are never counted as passed."
            />
            <ul className="divide-y divide-line">
              {report.results.map((result) => {
                const expanded = expandedCheck === result.check_id;
                return (
                  <li key={result.check_id}>
                    <button
                      type="button"
                      className="flex w-full items-center justify-between gap-3 px-5 py-3 text-left hover:bg-ink-800/50"
                      onClick={() =>
                        setExpandedCheck(expanded ? null : result.check_id)
                      }
                      aria-expanded={expanded}
                    >
                      <span className="flex min-w-0 items-center gap-3">
                        {expanded ? (
                          <ChevronDown className="h-4 w-4 shrink-0 text-tx-3" aria-hidden />
                        ) : (
                          <ChevronRight className="h-4 w-4 shrink-0 text-tx-3" aria-hidden />
                        )}
                        <span className="font-mono text-xs text-tx-1">
                          {result.check_id}
                        </span>
                        <span className="truncate text-xs text-tx-2">
                          {result.title}
                        </span>
                      </span>
                      <span className="flex shrink-0 items-center gap-2">
                        <span className="hidden font-mono text-[11px] text-tx-3 sm:inline">
                          {result.module}
                        </span>
                        <CheckStatusBadge status={result.status} />
                      </span>
                    </button>
                    {expanded ? (
                      <div className="space-y-3 border-t border-line bg-ink-900/40 px-6 py-4 sm:px-12">
                        {result.objective ? (
                          <DetailRow label="Objective" text={result.objective} />
                        ) : null}
                        <DetailRow
                          label="Detection outcome"
                          text={result.details || "—"}
                        />
                        {result.error ? (
                          <DetailRow label="Execution error" text={result.error} mono />
                        ) : null}
                        {result.evidence.length > 0 ? (
                          <div>
                            <p className="mb-1.5 text-[11px] uppercase tracking-wider text-tx-3">
                              Probe → response evidence
                            </p>
                            <div className="space-y-3">
                              {result.evidence.map((item, index) => (
                                <EvidenceBlock key={index} evidence={item} />
                              ))}
                            </div>
                          </div>
                        ) : null}
                        {result.finding_ids.length > 0 ? (
                          <div>
                            <p className="mb-1.5 text-[11px] uppercase tracking-wider text-tx-3">
                              Associated findings
                            </p>
                            <div className="flex flex-wrap gap-2">
                              {result.finding_ids.map((findingId) => (
                                <Link
                                  key={findingId}
                                  to={`/app/findings/${findingId}`}
                                  className="chip border-violet-500/40 bg-violet-500/10 text-violet-300 hover:bg-violet-500/20"
                                >
                                  {findingId}
                                </Link>
                              ))}
                            </div>
                          </div>
                        ) : null}
                      </div>
                    ) : null}
                  </li>
                );
              })}
            </ul>
          </Card>

          <Card>
            <CardHeader
              title={`Findings (${report.findings.length})`}
              subtitle="All findings require human validation before being treated as confirmed vulnerabilities."
            />
            {report.findings.length === 0 ? (
              <EmptyState
                title="No findings"
                detail="The executed checks did not observe attributable insecure behavior. This does not establish that the target is secure."
              />
            ) : (
              <ul className="divide-y divide-line">
                {report.findings.map((finding) => (
                  <li key={finding.finding_id}>
                    <Link
                      to={`/app/findings/${finding.finding_id}`}
                      className="flex flex-wrap items-center justify-between gap-3 px-5 py-3.5 hover:bg-ink-800/50"
                    >
                      <div className="min-w-0">
                        <p className="text-sm font-medium text-tx-1">{finding.title}</p>
                        <p className="mt-0.5 font-mono text-[11px] text-tx-3">
                          {finding.finding_id}
                        </p>
                      </div>
                      <div className="flex shrink-0 items-center gap-2">
                        <SeverityBadge severity={finding.severity} />
                        <ValidationBadge status={finding.validation_status} />
                      </div>
                    </Link>
                  </li>
                ))}
              </ul>
            )}
          </Card>

          {report.limitations.length > 0 ? (
            <Card>
              <CardHeader title="Limitations" />
              <ul className="list-disc space-y-1.5 px-9 py-4 text-xs leading-relaxed text-tx-2">
                {report.limitations.map((item) => (
                  <li key={item}>{item}</li>
                ))}
              </ul>
            </Card>
          ) : null}
        </>
      ) : null}
    </div>
  );
}

function DetailRow({
  label,
  text,
  mono = false,
}: {
  label: string;
  text: string;
  mono?: boolean;
}) {
  return (
    <div>
      <p className="text-[11px] uppercase tracking-wider text-tx-3">{label}</p>
      <p
        className={`mt-0.5 text-xs leading-relaxed text-tx-2 ${
          mono ? "font-mono" : ""
        }`}
      >
        {text}
      </p>
    </div>
  );
}

function ExecutionTimeline({
  startedAt,
  completedAt,
  checksExecuted,
  findingsTotal,
  skipped,
}: {
  startedAt: string;
  completedAt: string;
  checksExecuted: number;
  findingsTotal: number;
  skipped: number;
}) {
  const steps = [
    { label: "Assessment initialized", detail: formatDateTime(startedAt) },
    {
      label: "Target capabilities identified",
      detail: `${skipped} incompatible check${skipped === 1 ? "" : "s"} skipped`,
    },
    {
      label: "Probes generated & executed",
      detail: `${checksExecuted} checks with per-assessment probe tokens`,
    },
    {
      label: "Evidence analyzed, boundaries evaluated",
      detail: "marker/token attribution; heuristics capped at inconclusive",
    },
    {
      label: "Findings generated (pending human review)",
      detail: `${findingsTotal} finding${findingsTotal === 1 ? "" : "s"}`,
    },
    { label: "Assessment completed", detail: formatDateTime(completedAt) },
  ];

  return (
    <Card>
      <CardHeader
        title="Execution timeline"
        subtitle="How this assessment ran, from initialization to report."
      />
      <ol className="grid gap-x-6 gap-y-4 px-5 py-4 sm:grid-cols-2 xl:grid-cols-3">
        {steps.map((step, index) => (
          <li key={step.label} className="flex items-start gap-2.5">
            <CheckCircle2
              className="mt-0.5 h-4 w-4 shrink-0 text-mint-300"
              aria-hidden
            />
            <div>
              <p className="text-xs font-medium text-tx-1">
                {index + 1}. {step.label}
              </p>
              <p className="mt-0.5 text-[11px] text-tx-3">{step.detail}</p>
            </div>
          </li>
        ))}
      </ol>
    </Card>
  );
}
