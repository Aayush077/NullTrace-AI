import { useState } from "react";
import { Link, useParams } from "react-router-dom";
import { ArrowLeft, ClipboardCheck } from "lucide-react";
import { api, ApiError } from "../../lib/api";
import { useAsync } from "../../lib/useAsync";
import type { ValidationStatus } from "../../lib/types";
import {
  Card,
  CardHeader,
  ConfidenceBadge,
  ErrorState,
  SeverityBadge,
  Spinner,
  ValidationBadge,
} from "../../components/ui";
import { formatDateTime, titleCase } from "../../lib/format";
import { EvidenceBlock } from "../../components/EvidenceBlock";

const REVIEW_OPTIONS: { value: ValidationStatus; label: string; hint: string }[] = [
  {
    value: "pending_review",
    label: "Pending review",
    hint: "Default state for machine-generated findings.",
  },
  {
    value: "confirmed",
    label: "Confirmed",
    hint: "A human reproduced the behavior and confirms the vulnerability.",
  },
  {
    value: "rejected",
    label: "Rejected",
    hint: "Reviewed and judged a false positive or acceptable behavior.",
  },
  {
    value: "needs_retesting",
    label: "Needs retesting",
    hint: "Remediation applied or behavior unclear — re-run the check.",
  },
];

export function FindingDetail() {
  const { id = "" } = useParams();
  const finding = useAsync(() => api.finding(id), [id]);
  const [note, setNote] = useState<string | null>(null);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);

  if (finding.loading) return <Spinner />;
  if (finding.error)
    return <ErrorState message={finding.error} onRetry={finding.reload} />;

  const data = finding.data;
  if (!data) return null;

  const review = async (status: ValidationStatus) => {
    setSaving(true);
    setError(null);
    try {
      await api.reviewFinding(data.finding_id, status, note ?? data.review_note ?? "");
      finding.reload();
    } catch (err) {
      setError(err instanceof ApiError ? err.message : String(err));
    } finally {
      setSaving(false);
    }
  };

  return (
    <div className="space-y-6">
      <div>
        <Link
          to="/app/findings"
          className="mb-2 inline-flex items-center gap-1 text-xs text-tx-3 hover:text-tx-1"
        >
          <ArrowLeft className="h-3.5 w-3.5" aria-hidden /> All findings
        </Link>
        <h1 className="text-xl font-semibold tracking-tight">{data.title}</h1>
        <div className="mt-2 flex flex-wrap items-center gap-2">
          <SeverityBadge severity={data.severity} />
          <ConfidenceBadge confidence={data.confidence} />
          <ValidationBadge status={data.validation_status} />
          <span className="font-mono text-[11px] text-tx-3">{data.finding_id}</span>
        </div>
      </div>

      <div className="grid gap-4 xl:grid-cols-3">
        <div className="space-y-4 xl:col-span-2">
          <Card>
            <CardHeader title="Description" />
            <p className="px-5 py-4 text-sm leading-relaxed text-tx-2">{data.description}</p>
            <dl className="grid gap-x-8 gap-y-3 border-t border-line px-5 py-4 text-sm sm:grid-cols-2">
              <Detail label="Category" value={titleCase(data.category)} />
              <Detail label="Originating check" value={data.check_id} mono />
              <Detail label="Affected component" value={data.affected_component} />
              <Detail label="Assessment" value={data.assessment_id} mono link={`/app/assessments/${data.assessment_id}`} />
              <Detail label="Recorded" value={formatDateTime(data.timestamp)} />
            </dl>
          </Card>

          <Card>
            <CardHeader title="Behavior" />
            <div className="space-y-4 px-5 py-4 text-sm">
              <div>
                <p className="text-[11px] uppercase tracking-wider text-tx-3">Expected</p>
                <p className="mt-1 leading-relaxed text-tx-2">{data.expected_behavior}</p>
              </div>
              <div>
                <p className="text-[11px] uppercase tracking-wider text-red-300/80">Actual</p>
                <p className="mt-1 leading-relaxed text-tx-1">{data.actual_behavior}</p>
              </div>
              <div>
                <p className="text-[11px] uppercase tracking-wider text-tx-3">Impact</p>
                <p className="mt-1 leading-relaxed text-tx-2">{data.impact}</p>
              </div>
              <div>
                <p className="text-[11px] uppercase tracking-wider text-mint-300/80">Remediation</p>
                <p className="mt-1 leading-relaxed text-tx-2">{data.remediation}</p>
              </div>
            </div>
          </Card>

          <Card>
            <CardHeader
              title="Evidence"
              subtitle="Stored after redaction; synthetic evidence is explicitly labeled."
            />
            <div className="space-y-4 px-5 py-4">
              {data.evidence.map((item, index) => (
                <EvidenceBlock key={index} evidence={item} />
              ))}
            </div>
          </Card>

          <Card>
            <CardHeader title="Reproduction steps" />
            <ol className="list-decimal space-y-1.5 px-10 py-4 text-sm text-tx-2">
              {data.reproduction_steps.map((step) => (
                <li key={step}>{step}</li>
              ))}
            </ol>
            {data.references.length > 0 ? (
              <div className="border-t border-line px-5 py-3">
                <p className="text-[11px] uppercase tracking-wider text-tx-3">References</p>
                <ul className="mt-1.5 space-y-1 text-xs text-tx-2">
                  {data.references.map((ref) => (
                    <li key={ref}>{ref}</li>
                  ))}
                </ul>
              </div>
            ) : null}
          </Card>
        </div>

        <div>
          <Card>
            <CardHeader
              title="Human review"
              subtitle="A potential vulnerability never becomes confirmed automatically."
            />
            <div className="space-y-3 px-5 py-4">
              {REVIEW_OPTIONS.map((option) => (
                <button
                  key={option.value}
                  type="button"
                  disabled={saving}
                  onClick={() => void review(option.value)}
                  className={`w-full rounded-xl border px-4 py-3 text-left transition-colors ${
                    data.validation_status === option.value
                      ? "border-violet-500/50 bg-violet-500/10"
                      : "border-line hover:border-line-strong hover:bg-ink-800"
                  }`}
                >
                  <p className="flex items-center gap-2 text-sm font-medium text-tx-1">
                    {data.validation_status === option.value ? (
                      <ClipboardCheck className="h-4 w-4 text-violet-300" aria-hidden />
                    ) : null}
                    {option.label}
                  </p>
                  <p className="mt-0.5 text-xs text-tx-3">{option.hint}</p>
                </button>
              ))}
              <div>
                <label className="label" htmlFor="review-note">Review note</label>
                <textarea
                  id="review-note"
                  className="input min-h-[90px] resize-y"
                  placeholder="How was this verified or rejected?"
                  value={note ?? data.review_note ?? ""}
                  onChange={(event) => setNote(event.target.value)}
                />
                <button
                  type="button"
                  className="btn-ghost mt-2 w-full"
                  disabled={saving}
                  onClick={() => void review(data.validation_status)}
                >
                  {saving ? "Saving…" : "Save note"}
                </button>
              </div>
              {error ? (
                <p className="rounded-lg border border-red-500/30 bg-red-500/10 px-3 py-2 text-xs text-red-300">
                  {error}
                </p>
              ) : null}
            </div>
          </Card>
        </div>
      </div>
    </div>
  );
}

function Detail({
  label,
  value,
  mono = false,
  link,
}: {
  label: string;
  value: string;
  mono?: boolean;
  link?: string;
}) {
  const content = link ? (
    <Link to={link} className="text-violet-300 hover:text-violet-200">
      {value}
    </Link>
  ) : (
    value
  );
  return (
    <div className="min-w-0">
      <dt className="text-[11px] uppercase tracking-wider text-tx-3">{label}</dt>
      <dd className={`mt-0.5 break-words text-xs text-tx-1 ${mono ? "font-mono" : ""}`}>
        {content}
      </dd>
    </div>
  );
}
