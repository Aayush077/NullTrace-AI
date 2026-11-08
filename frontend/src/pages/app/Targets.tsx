import { useState } from "react";
import { Globe, Play, Plus, ShieldCheck, Trash2 } from "lucide-react";
import { api, ApiError } from "../../lib/api";
import { useAsync } from "../../lib/useAsync";
import type { Target } from "../../lib/types";
import {
  Card,
  CardHeader,
  ErrorState,
  Modal,
  Spinner,
} from "../../components/ui";
import { CreateAssessmentModal } from "./Assessments";

export function Targets() {
  const targets = useAsync(() => api.targets(), []);
  const [showCreate, setShowCreate] = useState(false);
  const [assessTarget, setAssessTarget] = useState<string | null>(null);
  const [deleting, setDeleting] = useState<number | null>(null);
  const [error, setError] = useState<string | null>(null);

  const remove = async (target: Target) => {
    if (target.builtin) return;
    if (!window.confirm(`Delete target "${target.name}"? Past assessments are kept.`)) {
      return;
    }
    setDeleting(Number(target.id));
    setError(null);
    try {
      await api.deleteTarget(Number(target.id));
      targets.reload();
    } catch (err) {
      setError(err instanceof ApiError ? err.message : String(err));
    } finally {
      setDeleting(null);
    }
  };

  return (
    <div className="space-y-6">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div>
          <h1 className="text-xl font-semibold tracking-tight">Targets</h1>
          <p className="mt-1 text-sm text-tx-3">
            Systems under assessment. API keys are referenced by environment
            variable name only and never stored or displayed.
          </p>
        </div>
        <button type="button" className="btn-primary" onClick={() => setShowCreate(true)}>
          <Plus className="h-4 w-4" aria-hidden /> Add API target
        </button>
      </div>

      {error ? (
        <p className="rounded-lg border border-red-500/30 bg-red-500/10 px-3 py-2 text-xs text-red-300">
          {error}
        </p>
      ) : null}

      {targets.loading ? (
        <Spinner />
      ) : targets.error ? (
        <ErrorState message={targets.error} onRetry={targets.reload} />
      ) : (
        <div className="grid gap-4 lg:grid-cols-2">
          {(targets.data ?? []).map((target) => (
            <Card key={String(target.id)} className="flex flex-col">
              <CardHeader
                title={target.name}
                subtitle={target.description}
                action={
                  target.builtin ? (
                    <span className="chip border-mint-400/30 bg-mint-400/10 text-mint-300">
                      <ShieldCheck className="h-3 w-3" aria-hidden /> offline
                    </span>
                  ) : (
                    <span
                      className={`chip ${
                        target.allow_network
                          ? "border-amber-500/40 bg-amber-500/10 text-amber-300"
                          : "border-line-strong bg-ink-700 text-tx-3"
                      }`}
                    >
                      <Globe className="h-3 w-3" aria-hidden />
                      {target.allow_network ? "network authorized" : "network not authorized"}
                    </span>
                  )
                }
              />
              <dl className="grid flex-1 grid-cols-2 gap-x-6 gap-y-3 px-5 py-4 text-xs">
                <Item label="Type" value={target.type} mono />
                {target.builtin ? (
                  <>
                    <Item label="Credentials" value="none required" />
                    {target.provider_label ? (
                      <Item
                        label="Simulated model configuration"
                        value={`${target.provider_label} ${target.model ?? ""}`}
                      />
                    ) : null}
                    <Item
                      label="Environment"
                      value={target.environment ?? "Simulated"}
                    />
                  </>
                ) : (
                  <>
                    <Item label="Model" value={target.model ?? "—"} mono />
                    <Item label="Base URL" value={target.base_url ?? "—"} mono />
                    <Item label="API key env var" value={target.api_key_env ?? "—"} mono />
                    <Item label="Timeout" value={`${target.timeout ?? "—"}s`} />
                    <Item label="Request budget" value={String(target.max_requests ?? "—")} />
                  </>
                )}
              </dl>
              <div className="flex items-center justify-end gap-2 border-t border-line px-5 py-3">
                {!target.builtin ? (
                  <button
                    type="button"
                    className="btn-danger"
                    onClick={() => void remove(target)}
                    disabled={deleting === Number(target.id)}
                  >
                    <Trash2 className="h-4 w-4" aria-hidden />
                    {deleting === Number(target.id) ? "Deleting…" : "Delete"}
                  </button>
                ) : null}
                <button
                  type="button"
                  className="btn-primary"
                  onClick={() => setAssessTarget(String(target.id))}
                >
                  <Play className="h-4 w-4" aria-hidden /> Assess
                </button>
              </div>
            </Card>
          ))}
        </div>
      )}

      {showCreate ? (
        <CreateTargetModal
          onClose={() => setShowCreate(false)}
          onCreated={() => {
            setShowCreate(false);
            targets.reload();
          }}
        />
      ) : null}

      {assessTarget ? (
        <CreateAssessmentModal
          fixedTargetId={assessTarget}
          onClose={() => setAssessTarget(null)}
          onCreated={() => setAssessTarget(null)}
        />
      ) : null}
    </div>
  );
}

function Item({
  label,
  value,
  mono = false,
}: {
  label: string;
  value: string;
  mono?: boolean;
}) {
  return (
    <div className="min-w-0">
      <dt className="text-[10px] uppercase tracking-wider text-tx-3">{label}</dt>
      <dd className={`mt-0.5 truncate text-tx-1 ${mono ? "font-mono" : ""}`}>{value}</dd>
    </div>
  );
}

function CreateTargetModal({
  onClose,
  onCreated,
}: {
  onClose: () => void;
  onCreated: () => void;
}) {
  const [form, setForm] = useState({
    name: "",
    base_url: "https://",
    model: "",
    api_key_env: "OPENAI_API_KEY",
    timeout: 30,
    max_requests: 10,
    allow_network: false,
  });
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const submit = async () => {
    setSubmitting(true);
    setError(null);
    try {
      await api.createTarget(form);
      onCreated();
    } catch (err) {
      setError(err instanceof ApiError ? err.message : String(err));
      setSubmitting(false);
    }
  };

  const set = <K extends keyof typeof form>(key: K, value: (typeof form)[K]) =>
    setForm((current) => ({ ...current, [key]: value }));

  return (
    <Modal title="Add OpenAI-compatible API target" onClose={onClose} wide>
      <div className="space-y-4">
        <div className="grid gap-4 sm:grid-cols-2">
          <div>
            <label className="label" htmlFor="t-name">Target name</label>
            <input
              id="t-name"
              className="input"
              placeholder="staging-assistant"
              value={form.name}
              onChange={(event) => set("name", event.target.value)}
            />
          </div>
          <div>
            <label className="label" htmlFor="t-model">Model name</label>
            <input
              id="t-model"
              className="input"
              placeholder="gpt-4o-mini"
              value={form.model}
              onChange={(event) => set("model", event.target.value)}
            />
          </div>
        </div>
        <div>
          <label className="label" htmlFor="t-url">Base URL</label>
          <input
            id="t-url"
            className="input font-mono"
            placeholder="https://api.example.com/v1"
            value={form.base_url}
            onChange={(event) => set("base_url", event.target.value)}
          />
          <p className="mt-1.5 text-xs text-tx-3">
            HTTPS required (HTTP only for explicit localhost). Private and
            reserved addresses are rejected. Validation makes no network
            request.
          </p>
        </div>
        <div className="grid gap-4 sm:grid-cols-3">
          <div>
            <label className="label" htmlFor="t-env">API key env variable</label>
            <input
              id="t-env"
              className="input font-mono"
              value={form.api_key_env}
              onChange={(event) => set("api_key_env", event.target.value)}
            />
          </div>
          <div>
            <label className="label" htmlFor="t-timeout">Timeout (s)</label>
            <input
              id="t-timeout"
              type="number"
              min={1}
              max={300}
              className="input"
              value={form.timeout}
              onChange={(event) => set("timeout", Number(event.target.value))}
            />
          </div>
          <div>
            <label className="label" htmlFor="t-budget">Request budget</label>
            <input
              id="t-budget"
              type="number"
              min={1}
              max={500}
              className="input"
              value={form.max_requests}
              onChange={(event) => set("max_requests", Number(event.target.value))}
            />
          </div>
        </div>
        <label className="flex items-start gap-2 rounded-xl border border-amber-500/30 bg-amber-500/5 p-4 text-sm text-tx-2">
          <input
            type="checkbox"
            checked={form.allow_network}
            onChange={(event) => set("allow_network", event.target.checked)}
            className="mt-0.5 h-4 w-4 rounded border-line bg-ink-900 accent-amber-500"
          />
          <span>
            I own this system or hold explicit written authorization to assess
            it. (Each assessment run additionally requires per-run consent;
            configuring a target never triggers any request.)
          </span>
        </label>
        <p className="text-xs text-tx-3">
          The API key itself is read from the environment variable on the
          machine running the backend at assessment time. It is never sent by
          the browser, stored in the database, or included in reports.
        </p>

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
            disabled={submitting || !form.name || !form.model}
          >
            {submitting ? "Saving…" : "Save target"}
          </button>
        </div>
      </div>
    </Modal>
  );
}
