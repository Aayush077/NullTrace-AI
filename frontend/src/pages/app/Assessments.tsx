import { useMemo, useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import {
  GitCompareArrows,
  Play,
  Plus,
  RefreshCw,
  Trash2,
} from "lucide-react";
import { api, ApiError } from "../../lib/api";
import { useAsync } from "../../lib/useAsync";
import type { AssessmentRecord, ModuleInfo, Target } from "../../lib/types";
import {
  Card,
  EmptyState,
  ErrorState,
  Modal,
  RunStatusBadge,
  Spinner,
} from "../../components/ui";
import { formatDateTime } from "../../lib/format";
import { getDefaults } from "./Settings";

export function Assessments() {
  const assessments = useAsync(() => api.assessments(), []);
  const [showCreate, setShowCreate] = useState(false);
  const [selected, setSelected] = useState<string[]>([]);
  const [showCompare, setShowCompare] = useState(false);
  const [confirmDelete, setConfirmDelete] = useState<string[] | null>(null);
  const [deleting, setDeleting] = useState(false);
  const [notice, setNotice] = useState<
    { kind: "success" | "error"; text: string } | null
  >(null);

  const loaded = assessments.data ?? [];
  const loadedIds = loaded.map((item) => item.id);
  const allSelected =
    loadedIds.length > 0 && selected.length === loadedIds.length;
  const someSelected = selected.length > 0 && !allSelected;

  const toggleSelect = (id: string) => {
    setSelected((current) =>
      current.includes(id)
        ? current.filter((item) => item !== id)
        : [...current, id],
    );
  };

  const toggleSelectAll = () => {
    setSelected(allSelected ? [] : loadedIds);
  };

  const runDeletion = async (ids: string[]) => {
    setDeleting(true);
    setNotice(null);
    try {
      if (ids.length === 1) {
        await api.deleteAssessment(ids[0]);
        setNotice({
          kind: "success",
          text: `Deleted ${ids[0]} and its findings, evidence, and report.`,
        });
      } else {
        const result = await api.deleteAssessments(ids);
        const parts = [
          `Deleted ${result.deleted_count} assessment${
            result.deleted_count === 1 ? "" : "s"
          } with their findings, evidence, and reports.`,
        ];
        if (result.not_found.length > 0) {
          parts.push(`${result.not_found.length} no longer existed.`);
        }
        if (result.skipped_running.length > 0) {
          parts.push(
            `${result.skipped_running.length} still running and skipped.`,
          );
        }
        setNotice({ kind: "success", text: parts.join(" ") });
      }
      setSelected((current) => current.filter((id) => !ids.includes(id)));
      assessments.reload();
    } catch (err) {
      setNotice({
        kind: "error",
        text: err instanceof ApiError ? err.message : String(err),
      });
    } finally {
      setDeleting(false);
      setConfirmDelete(null);
    }
  };

  return (
    <div className="space-y-6">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div>
          <h1 className="text-xl font-semibold tracking-tight">Assessments</h1>
          <p className="mt-1 text-sm text-tx-3">
            Reproducible security runs against configured targets.
          </p>
        </div>
        <div className="flex flex-wrap gap-2">
          <button
            type="button"
            className="btn-danger"
            disabled={selected.length === 0 || deleting}
            onClick={() => setConfirmDelete(selected)}
          >
            <Trash2 className="h-4 w-4" aria-hidden /> Delete selected
            {selected.length > 0 ? ` (${selected.length})` : ""}
          </button>
          <button
            type="button"
            className="btn-ghost"
            disabled={selected.length !== 2}
            title="Select exactly two assessments to compare"
            onClick={() => setShowCompare(true)}
          >
            <GitCompareArrows className="h-4 w-4" aria-hidden /> Compare
            {selected.length > 0 ? ` (${Math.min(selected.length, 2)}/2)` : ""}
          </button>
          <button type="button" className="btn-ghost" onClick={assessments.reload}>
            <RefreshCw className="h-4 w-4" aria-hidden /> Refresh
          </button>
          <button type="button" className="btn-primary" onClick={() => setShowCreate(true)}>
            <Plus className="h-4 w-4" aria-hidden /> New assessment
          </button>
        </div>
      </div>

      {notice ? (
        <p
          role="status"
          className={`rounded-lg border px-3 py-2 text-xs ${
            notice.kind === "success"
              ? "border-emerald-500/30 bg-emerald-500/10 text-emerald-300"
              : "border-red-500/30 bg-red-500/10 text-red-300"
          }`}
        >
          {notice.text}
        </p>
      ) : null}

      {selected.length > 0 ? (
        <p className="text-xs text-tx-3">
          {selected.length} of {loadedIds.length} loaded assessments selected.
          “Select all” applies to the {loadedIds.length} loaded (most recent)
          records shown here, not to anything beyond this list.
        </p>
      ) : null}

      <Card>
        {assessments.loading ? (
          <Spinner />
        ) : assessments.error ? (
          <ErrorState message={assessments.error} onRetry={assessments.reload} />
        ) : !assessments.data || assessments.data.length === 0 ? (
          <EmptyState
            title="No assessments yet"
            detail="Start with the offline mock target — it needs no credentials and no network."
            action={
              <button type="button" className="btn-primary" onClick={() => setShowCreate(true)}>
                Create assessment
              </button>
            }
          />
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full min-w-[720px] text-left text-sm">
              <thead>
                <tr className="border-b border-line text-[11px] uppercase tracking-wider text-tx-3">
                  <th className="w-10 px-4 py-3 font-medium">
                    <input
                      type="checkbox"
                      aria-label={`Select all ${loadedIds.length} loaded assessments`}
                      checked={allSelected}
                      ref={(element) => {
                        if (element) element.indeterminate = someSelected;
                      }}
                      onChange={toggleSelectAll}
                      className="h-4 w-4 rounded border-line bg-ink-900 accent-violet-500"
                    />
                  </th>
                  <th className="px-5 py-3 font-medium">Assessment</th>
                  <th className="px-5 py-3 font-medium">Target</th>
                  <th className="px-5 py-3 font-medium">Profile</th>
                  <th className="px-5 py-3 font-medium">Checks</th>
                  <th className="px-5 py-3 font-medium">Findings</th>
                  <th className="px-5 py-3 font-medium">Created</th>
                  <th className="px-5 py-3 font-medium">Status</th>
                  <th className="px-5 py-3 font-medium">
                    <span className="sr-only">Actions</span>
                  </th>
                </tr>
              </thead>
              <tbody className="divide-y divide-line">
                {assessments.data.map((item) => (
                  <tr key={item.id} className="hover:bg-ink-800/50">
                    <td className="px-4 py-3">
                      <input
                        type="checkbox"
                        aria-label={`Select ${item.id}`}
                        checked={selected.includes(item.id)}
                        onChange={() => toggleSelect(item.id)}
                        className="h-4 w-4 rounded border-line bg-ink-900 accent-violet-500"
                      />
                    </td>
                    <td className="px-5 py-3">
                      <Link
                        to={`/app/assessments/${item.id}`}
                        className="font-mono text-xs text-violet-300 hover:text-violet-200"
                      >
                        {item.id}
                      </Link>
                    </td>
                    <td className="px-5 py-3 text-xs text-tx-2">{item.target_name}</td>
                    <td className="px-5 py-3 font-mono text-xs text-tx-3">{item.profile}</td>
                    <td className="px-5 py-3 font-mono text-xs text-tx-2">
                      {item.summary?.checks_executed ?? "—"}
                    </td>
                    <td className="px-5 py-3 font-mono text-xs text-tx-2">
                      {item.summary?.findings_total ?? "—"}
                    </td>
                    <td className="px-5 py-3 text-xs text-tx-3">
                      {formatDateTime(item.created_at)}
                    </td>
                    <td className="px-5 py-3">
                      <RunStatusBadge status={item.status} />
                    </td>
                    <td className="px-5 py-3 text-right">
                      <button
                        type="button"
                        aria-label={`Delete ${item.id}`}
                        title="Delete this assessment"
                        disabled={deleting}
                        className="rounded-md p-1.5 text-tx-3 transition-colors hover:bg-red-500/10 hover:text-red-300 disabled:opacity-50"
                        onClick={() => setConfirmDelete([item.id])}
                      >
                        <Trash2 className="h-4 w-4" aria-hidden />
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Card>

      {showCreate ? (
        <CreateAssessmentModal
          onClose={() => setShowCreate(false)}
          onCreated={() => {
            setShowCreate(false);
            assessments.reload();
          }}
        />
      ) : null}

      {showCompare && selected.length === 2 ? (
        <CompareModal
          records={loaded.filter((item) => selected.includes(item.id))}
          onClose={() => setShowCompare(false)}
        />
      ) : null}

      {confirmDelete ? (
        <ConfirmDeleteModal
          ids={confirmDelete}
          deleting={deleting}
          onCancel={() => setConfirmDelete(null)}
          onConfirm={() => void runDeletion(confirmDelete)}
        />
      ) : null}
    </div>
  );
}

function ConfirmDeleteModal({
  ids,
  deleting,
  onCancel,
  onConfirm,
}: {
  ids: string[];
  deleting: boolean;
  onCancel: () => void;
  onConfirm: () => void;
}) {
  const single = ids.length === 1;

  return (
    <Modal
      title={single ? "Delete assessment?" : `Delete ${ids.length} assessments?`}
      onClose={onCancel}
    >
      <div className="space-y-4 text-sm">
        <p className="text-tx-2">
          {single ? (
            <>
              This permanently deletes{" "}
              <span className="font-mono text-xs text-tx-1">{ids[0]}</span>{" "}
              together with its findings, evidence, and generated reports.
            </>
          ) : (
            <>
              This permanently deletes the {ids.length} selected assessments
              together with their findings, evidence, and generated reports.
            </>
          )}{" "}
          Targets and configuration are not affected. This cannot be undone.
        </p>
        {!single ? (
          <div className="max-h-36 overflow-y-auto rounded-lg border border-line bg-ink-900 px-3 py-2">
            <ul className="space-y-1 font-mono text-[11px] text-tx-3">
              {ids.map((id) => (
                <li key={id}>{id}</li>
              ))}
            </ul>
          </div>
        ) : null}
        <div className="flex justify-end gap-2">
          <button
            type="button"
            className="btn-ghost"
            onClick={onCancel}
            disabled={deleting}
          >
            Cancel
          </button>
          <button
            type="button"
            className="btn-danger"
            onClick={onConfirm}
            disabled={deleting}
          >
            <Trash2 className="h-4 w-4" aria-hidden />
            {deleting
              ? "Deleting…"
              : single
                ? "Delete assessment"
                : `Delete ${ids.length} assessments`}
          </button>
        </div>
      </div>
    </Modal>
  );
}

function CompareModal({
  records,
  onClose,
}: {
  records: AssessmentRecord[];
  onClose: () => void;
}) {
  const statusKeys = ["pass", "fail", "inconclusive", "error", "skipped"] as const;
  const severityKeys = [
    "critical",
    "high",
    "medium",
    "low",
    "informational",
  ] as const;

  return (
    <Modal title="Compare assessments" onClose={onClose} wide>
      <div className="overflow-x-auto">
        <table className="w-full min-w-[520px] text-left text-sm">
          <thead>
            <tr className="border-b border-line text-[11px] uppercase tracking-wider text-tx-3">
              <th className="py-2 pr-4 font-medium">Metric</th>
              {records.map((record) => (
                <th key={record.id} className="py-2 pr-4 font-medium">
                  <Link
                    to={`/app/assessments/${record.id}`}
                    className="font-mono text-xs text-violet-300"
                  >
                    {record.id}
                  </Link>
                </th>
              ))}
            </tr>
          </thead>
          <tbody className="divide-y divide-line text-xs">
            <CompareRow
              label="Target"
              values={records.map((record) => record.target_name)}
            />
            <CompareRow
              label="Variant"
              values={records.map((record) => record.variant || "—")}
            />
            <CompareRow
              label="Profile"
              values={records.map((record) => record.profile)}
            />
            <CompareRow
              label="Checks executed"
              values={records.map((record) =>
                String(record.summary?.checks_executed ?? "—"),
              )}
            />
            {statusKeys.map((key) => (
              <CompareRow
                key={key}
                label={`Checks ${key}`}
                values={records.map((record) =>
                  String(record.summary?.status_counts?.[key] ?? 0),
                )}
              />
            ))}
            <CompareRow
              label="Findings total"
              values={records.map((record) =>
                String(record.summary?.findings_total ?? 0),
              )}
              strong
            />
            {severityKeys.map((key) => (
              <CompareRow
                key={key}
                label={`Findings ${key}`}
                values={records.map((record) =>
                  String(record.summary?.findings_by_severity?.[key] ?? 0),
                )}
              />
            ))}
          </tbody>
        </table>
      </div>
      <p className="mt-3 text-[11px] text-tx-3">
        Both columns come from stored assessment results — compare a
        vulnerable demo profile against its secure control variant to see
        behavior-driven detection.
      </p>
    </Modal>
  );
}

function CompareRow({
  label,
  values,
  strong = false,
}: {
  label: string;
  values: string[];
  strong?: boolean;
}) {
  return (
    <tr>
      <td className="py-2 pr-4 text-tx-3">{label}</td>
      {values.map((value, index) => (
        <td
          key={index}
          className={`py-2 pr-4 ${strong ? "font-semibold text-tx-1" : "text-tx-2"}`}
        >
          {value}
        </td>
      ))}
    </tr>
  );
}

export function CreateAssessmentModal({
  onClose,
  onCreated,
  fixedTargetId,
  recommendedModules,
  allowSecureVariant = false,
}: {
  onClose: () => void;
  onCreated: () => void;
  fixedTargetId?: string;
  recommendedModules?: string[];
  allowSecureVariant?: boolean;
}) {
  const navigate = useNavigate();
  const targets = useAsync(() => api.targets(), []);
  const modules = useAsync(() => api.modules(), []);
  const defaults = getDefaults();

  const [targetId, setTargetId] = useState(
    fixedTargetId ?? "demo-secure-support",
  );
  const [profile, setProfile] = useState(defaults.profile);
  const [useCustomModules, setUseCustomModules] = useState(
    Boolean(recommendedModules?.length),
  );
  const [selectedModules, setSelectedModules] = useState<string[]>(
    recommendedModules ?? [],
  );
  const [secureVariant, setSecureVariant] = useState(false);
  const [maxRequests, setMaxRequests] = useState(defaults.maxRequests);
  const [timeout_, setTimeout_] = useState(defaults.timeout);
  const [allowNetwork, setAllowNetwork] = useState(false);
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const selectedTarget: Target | undefined = useMemo(
    () => targets.data?.find((t) => String(t.id) === targetId),
    [targets.data, targetId],
  );
  const isNetworkTarget = selectedTarget ? !selectedTarget.builtin : false;

  const toggleModule = (name: string) => {
    setSelectedModules((current) =>
      current.includes(name)
        ? current.filter((item) => item !== name)
        : [...current, name],
    );
  };

  const submit = async () => {
    setSubmitting(true);
    setError(null);
    try {
      const record = await api.createAssessment({
        target_id: targetId,
        profile,
        modules: useCustomModules && selectedModules.length > 0 ? selectedModules : null,
        max_requests: isNetworkTarget ? maxRequests : null,
        timeout: isNetworkTarget ? timeout_ : null,
        allow_network: isNetworkTarget ? allowNetwork : false,
        secure_variant: allowSecureVariant ? secureVariant : false,
      });
      onCreated();
      navigate(`/app/assessments/${record.id}`);
    } catch (err) {
      setError(err instanceof ApiError ? err.message : String(err));
      setSubmitting(false);
    }
  };

  return (
    <Modal title="New assessment" onClose={onClose} wide>
      {targets.loading || modules.loading ? (
        <Spinner />
      ) : (
        <div className="space-y-5">
          <div>
            <label className="label" htmlFor="target">Target</label>
            <select
              id="target"
              className="input"
              value={targetId}
              onChange={(event) => setTargetId(event.target.value)}
              disabled={Boolean(fixedTargetId)}
            >
              {(targets.data ?? []).map((target) => (
                <option key={String(target.id)} value={String(target.id)}>
                  {target.name}
                  {target.builtin ? " (offline synthetic)" : ` — ${target.model}`}
                </option>
              ))}
            </select>
            {selectedTarget ? (
              <p className="mt-1.5 text-xs text-tx-3">{selectedTarget.description}</p>
            ) : null}
          </div>

          <div className="grid gap-4 sm:grid-cols-2">
            <div>
              <label className="label" htmlFor="profile">Profile</label>
              <select
                id="profile"
                className="input"
                value={profile}
                onChange={(event) => setProfile(event.target.value)}
                disabled={useCustomModules}
              >
                <option value="quick">quick — baseline + prompt injection</option>
                <option value="standard">standard — core modules</option>
                <option value="full">full — all 8 modules</option>
              </select>
            </div>
            <div className="flex items-end pb-2">
              <label className="flex items-center gap-2 text-sm text-tx-2">
                <input
                  type="checkbox"
                  checked={useCustomModules}
                  onChange={(event) => setUseCustomModules(event.target.checked)}
                  className="h-4 w-4 rounded border-line bg-ink-900 accent-violet-500"
                />
                Select individual modules instead
              </label>
            </div>
          </div>

          {useCustomModules ? (
            <div className="grid gap-2 rounded-xl border border-line bg-ink-900/60 p-4 sm:grid-cols-2">
              {(modules.data ?? []).map((module: ModuleInfo) => (
                <label key={module.name} className="flex items-center gap-2 text-sm text-tx-2">
                  <input
                    type="checkbox"
                    checked={selectedModules.includes(module.name)}
                    onChange={() => toggleModule(module.name)}
                    className="h-4 w-4 rounded border-line bg-ink-900 accent-violet-500"
                  />
                  <span className="font-mono text-xs">{module.name}</span>
                  <span className="text-xs text-tx-3">({module.check_count})</span>
                </label>
              ))}
            </div>
          ) : null}

          {allowSecureVariant ? (
            <label className="flex items-start gap-2 rounded-xl border border-mint-400/20 bg-mint-400/5 p-4 text-sm text-tx-2">
              <input
                type="checkbox"
                checked={secureVariant}
                onChange={(event) => setSecureVariant(event.target.checked)}
                className="mt-0.5 h-4 w-4 rounded border-line bg-ink-900 accent-teal-400"
              />
              <span>
                Run the <strong>secure control variant</strong> of this
                scenario instead (same probes, hardened behavior) — useful
                for comparing against the intentionally vulnerable profile.
              </span>
            </label>
          ) : null}

          {isNetworkTarget ? (
            <div className="space-y-4 rounded-xl border border-amber-500/30 bg-amber-500/5 p-4">
              <div className="grid gap-4 sm:grid-cols-2">
                <div>
                  <label className="label" htmlFor="budget">Request budget</label>
                  <input
                    id="budget"
                    type="number"
                    min={1}
                    max={500}
                    className="input"
                    value={maxRequests}
                    onChange={(event) => setMaxRequests(Number(event.target.value))}
                  />
                </div>
                <div>
                  <label className="label" htmlFor="timeout">Timeout (seconds)</label>
                  <input
                    id="timeout"
                    type="number"
                    min={1}
                    max={300}
                    className="input"
                    value={timeout_}
                    onChange={(event) => setTimeout_(Number(event.target.value))}
                  />
                </div>
              </div>
              <label className="flex items-start gap-2 text-sm text-tx-2">
                <input
                  type="checkbox"
                  checked={allowNetwork}
                  onChange={(event) => setAllowNetwork(event.target.checked)}
                  className="mt-0.5 h-4 w-4 rounded border-line bg-ink-900 accent-amber-500"
                />
                <span>
                  I am explicitly authorized to assess this target and consent
                  to outbound network requests (bounded by the budget above).
                </span>
              </label>
            </div>
          ) : (
            <p className="rounded-xl border border-mint-400/20 bg-mint-400/5 px-4 py-3 text-xs text-tx-2">
              Offline synthetic target: the assessment runs locally and makes
              no network requests.
            </p>
          )}

          {error ? (
            <p className="rounded-lg border border-red-500/30 bg-red-500/10 px-3 py-2 text-xs text-red-300">
              {error}
            </p>
          ) : null}

          <div className="flex justify-end gap-2">
            <button type="button" className="btn-ghost" onClick={onClose}>
              Cancel
            </button>
            <button
              type="button"
              className="btn-primary"
              onClick={submit}
              disabled={submitting || (isNetworkTarget && !allowNetwork)}
            >
              <Play className="h-4 w-4" aria-hidden />
              {submitting ? "Running…" : "Run assessment"}
            </button>
          </div>
        </div>
      )}
    </Modal>
  );
}
