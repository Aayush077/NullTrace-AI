import { Link } from "react-router-dom";
import {
  Activity,
  ListChecks,
  ShieldAlert,
  ShieldX,
} from "lucide-react";
import { api } from "../../lib/api";
import { useAsync } from "../../lib/useAsync";
import {
  Card,
  CardHeader,
  EmptyState,
  ErrorState,
  RunStatusBadge,
  SeverityBadge,
  Spinner,
  StatCard,
  ValidationBadge,
} from "../../components/ui";
import { CategoryBars, HistoryChart, SeverityDonut } from "../../components/charts";
import { timeAgo } from "../../lib/format";

export function Overview() {
  const summary = useAsync(() => api.dashboardSummary(), []);
  const analytics = useAsync(() => api.dashboardAnalytics(), []);

  if (summary.loading) return <Spinner label="Loading workspace…" />;
  if (summary.error)
    return <ErrorState message={summary.error} onRetry={summary.reload} />;

  const data = summary.data;
  if (!data) return null;

  const severity = data.findings_by_severity;
  const checks = data.checks_by_status;

  if (data.assessments_total === 0) {
    return (
      <div className="space-y-6">
        <PageTitle />
        <Card>
          <EmptyState
            icon={<Activity className="h-7 w-7" aria-hidden />}
            title="No assessments yet"
            detail="Run your first assessment against the bundled offline mock target — no credentials or network access required."
            action={
              <Link to="/app/assessments" className="btn-primary">
                Create assessment
              </Link>
            }
          />
        </Card>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      <PageTitle />

      <div className="grid gap-4 sm:grid-cols-2 xl:grid-cols-4">
        <StatCard
          label="Assessments"
          value={data.assessments_total}
          hint={`${data.assessments_by_status["completed"] ?? 0} completed`}
          icon={<ListChecks className="h-4 w-4" aria-hidden />}
        />
        <StatCard
          label="Findings"
          value={data.findings_total}
          hint={`${data.findings_by_validation["pending_review"] ?? 0} pending review`}
          tone="violet"
          icon={<ShieldAlert className="h-4 w-4" aria-hidden />}
        />
        <StatCard
          label="Critical / High"
          value={`${severity["critical"] ?? 0} / ${severity["high"] ?? 0}`}
          hint="require prioritized review"
          tone="red"
          icon={<ShieldX className="h-4 w-4" aria-hidden />}
        />
        <StatCard
          label="Checks passed"
          value={checks.pass ?? 0}
          hint={`${checks.fail ?? 0} failed · ${checks.inconclusive ?? 0} inconclusive · ${checks.skipped ?? 0} skipped`}
          tone="mint"
          icon={<Activity className="h-4 w-4" aria-hidden />}
        />
      </div>

      <div className="grid gap-4 xl:grid-cols-3">
        <Card className="xl:col-span-2">
          <CardHeader
            title="Assessment history"
            subtitle="Checks executed and findings per assessment"
          />
          <div className="px-4 py-3">
            {analytics.data ? (
              <HistoryChart history={analytics.data.history} />
            ) : analytics.error ? (
              <ErrorState message={analytics.error} onRetry={analytics.reload} />
            ) : (
              <Spinner />
            )}
          </div>
        </Card>
        <Card>
          <CardHeader title="Findings by severity" />
          <div className="px-5 py-3">
            <SeverityDonut data={severity} centerLabel="findings" />
          </div>
        </Card>
      </div>

      <div className="grid gap-4 xl:grid-cols-3">
        <Card className="xl:col-span-2">
          <CardHeader
            title="Recent assessments"
            action={
              <Link to="/app/assessments" className="text-xs text-violet-300 hover:text-violet-200">
                View all →
              </Link>
            }
          />
          <ul className="divide-y divide-line">
            {data.recent_assessments.map((assessment) => (
              <li key={assessment.id}>
                <Link
                  to={`/app/assessments/${assessment.id}`}
                  className="flex items-center justify-between gap-4 px-5 py-3 hover:bg-ink-800/60"
                >
                  <div className="min-w-0">
                    <p className="truncate font-mono text-xs text-tx-1">{assessment.id}</p>
                    <p className="mt-0.5 truncate text-xs text-tx-3">
                      {assessment.target_name} · {assessment.profile}
                    </p>
                  </div>
                  <div className="flex shrink-0 items-center gap-3">
                    <span className="text-xs text-tx-3">{timeAgo(assessment.created_at)}</span>
                    <RunStatusBadge status={assessment.status} />
                  </div>
                </Link>
              </li>
            ))}
          </ul>
        </Card>
        <Card>
          <CardHeader
            title="Recent findings"
            action={
              <Link to="/app/findings" className="text-xs text-violet-300 hover:text-violet-200">
                View all →
              </Link>
            }
          />
          {data.recent_findings.length === 0 ? (
            <EmptyState title="No findings recorded" detail="Findings appear here after a check fails with attributable evidence." />
          ) : (
            <ul className="divide-y divide-line">
              {data.recent_findings.slice(0, 6).map((finding) => (
                <li key={finding.finding_id}>
                  <Link
                    to={`/app/findings/${finding.finding_id}`}
                    className="block px-5 py-3 hover:bg-ink-800/60"
                  >
                    <p className="truncate text-xs font-medium text-tx-1">{finding.title}</p>
                    <div className="mt-1.5 flex items-center gap-2">
                      <SeverityBadge severity={finding.severity} />
                      <ValidationBadge status={finding.validation_status} />
                    </div>
                  </Link>
                </li>
              ))}
            </ul>
          )}
        </Card>
      </div>

      {analytics.data ? (
        <div className="grid gap-4 xl:grid-cols-2">
          <Card>
            <CardHeader
              title="Module coverage"
              subtitle="How often each module has been executed"
            />
            <div className="px-4 py-3">
              <CategoryBars data={analytics.data.module_coverage} />
            </div>
          </Card>
          <Card>
            <CardHeader
              title="Findings by category"
              subtitle="Vulnerability category distribution"
            />
            <div className="px-4 py-3">
              <CategoryBars data={analytics.data.findings_by_category} />
            </div>
          </Card>
        </div>
      ) : null}
    </div>
  );
}

function PageTitle() {
  return (
    <div>
      <h1 className="text-xl font-semibold tracking-tight">Overview</h1>
      <p className="mt-1 text-sm text-tx-3">
        Live data from your local assessment workspace.
      </p>
    </div>
  );
}
