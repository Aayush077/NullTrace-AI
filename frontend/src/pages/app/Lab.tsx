import { useState } from "react";
import {
  Boxes,
  FlaskConical,
  Play,
  ShieldAlert,
  ShieldCheck,
} from "lucide-react";
import { api } from "../../lib/api";
import { useAsync } from "../../lib/useAsync";
import type { DemoTarget } from "../../lib/types";
import {
  Card,
  ErrorState,
  Modal,
  Spinner,
} from "../../components/ui";
import { CreateAssessmentModal } from "./Assessments";

function ProfileBadge({ target }: { target: DemoTarget }) {
  if (target.security_profile === "secure_baseline") {
    return (
      <span className="chip border-emerald-500/40 bg-emerald-500/10 text-emerald-300">
        <ShieldCheck className="h-3 w-3" aria-hidden /> Secure Baseline
      </span>
    );
  }
  return (
    <span className="chip border-amber-500/40 bg-amber-500/10 text-amber-300">
      <ShieldAlert className="h-3 w-3" aria-hidden /> Intentionally Vulnerable
    </span>
  );
}

function SimulatedBadge() {
  return (
    <span className="chip border-sky-500/40 bg-sky-500/10 text-sky-300">
      <FlaskConical className="h-3 w-3" aria-hidden /> Synthetic Environment
    </span>
  );
}

export function Lab() {
  const targets = useAsync(() => api.demoTargets(), []);
  const [details, setDetails] = useState<DemoTarget | null>(null);
  const [launch, setLaunch] = useState<DemoTarget | null>(null);

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-xl font-semibold tracking-tight">Demo Target Lab</h1>
        <p className="mt-1 max-w-3xl text-sm text-tx-3">
          Five synthetic AI application scenarios — one secure baseline and
          four with intentionally seeded weaknesses. Assessments execute
          real checks against the selected application; findings come from
          observed behavior, never from the target's label. Model names are
          simulated configuration metadata only: no provider API is ever
          contacted.
        </p>
      </div>

      {targets.loading ? (
        <Spinner />
      ) : targets.error ? (
        <ErrorState message={targets.error} onRetry={targets.reload} />
      ) : (
        <div className="grid gap-4 xl:grid-cols-2">
          {(targets.data ?? []).map((target) => (
            <Card key={target.id} className="flex flex-col">
              <div className="flex items-start justify-between gap-3 border-b border-line px-5 py-4">
                <div>
                  <h3 className="text-sm font-semibold">{target.display_name}</h3>
                  <p className="mt-0.5 text-xs text-tx-3">{target.category}</p>
                </div>
                <ProfileBadge target={target} />
              </div>
              <div className="flex-1 space-y-3 px-5 py-4">
                <p className="text-xs leading-relaxed text-tx-2">
                  {target.description}
                </p>
                <div className="flex flex-wrap gap-1.5">
                  <SimulatedBadge />
                  <span className="chip border-line-strong bg-ink-700 text-tx-2">
                    {target.provider_label} {target.model_label} · simulated
                  </span>
                  <span className="chip border-line-strong bg-ink-700 text-tx-3">
                    {target.supported_modules.length} modules
                  </span>
                  {target.seeded_weakness_count > 0 ? (
                    <span className="chip border-amber-500/40 bg-amber-500/10 text-amber-300">
                      {target.seeded_weakness_count} seeded weaknesses
                    </span>
                  ) : (
                    <span className="chip border-emerald-500/40 bg-emerald-500/10 text-emerald-300">
                      0 seeded weaknesses
                    </span>
                  )}
                </div>
                <div className="flex flex-wrap gap-1.5">
                  {target.capabilities.map((capability) => (
                    <span
                      key={capability}
                      className="chip border-violet-500/30 bg-violet-500/10 text-violet-300"
                    >
                      {capability}
                    </span>
                  ))}
                </div>
                <p className="text-[11px] text-tx-3">{target.complexity}</p>
              </div>
              <div className="flex items-center justify-end gap-2 border-t border-line px-5 py-3">
                <button
                  type="button"
                  className="btn-ghost"
                  onClick={() => setDetails(target)}
                >
                  <Boxes className="h-4 w-4" aria-hidden /> Details
                </button>
                <button
                  type="button"
                  className="btn-primary"
                  onClick={() => setLaunch(target)}
                >
                  <Play className="h-4 w-4" aria-hidden /> Run Security
                  Assessment
                </button>
              </div>
            </Card>
          ))}
        </div>
      )}

      {details ? (
        <Modal
          title={details.display_name}
          onClose={() => setDetails(null)}
          wide
        >
          <div className="space-y-4 text-sm">
            <div className="flex flex-wrap gap-1.5">
              <ProfileBadge target={details} />
              <SimulatedBadge />
              <span className="chip border-line-strong bg-ink-700 text-tx-2">
                Simulated model configuration: {details.provider_label}{" "}
                {details.model_label}
              </span>
            </div>

            <Section title="Architecture overview" body={details.architecture} />
            <Section title="Synthetic data" body={details.synthetic_data} />

            <div>
              <SectionTitle title="Assessment compatibility" />
              <div className="mt-1.5 flex flex-wrap gap-1.5">
                {details.supported_modules.map((module) => (
                  <span key={module} className="chip border-violet-500/30 bg-violet-500/10 text-violet-300">
                    {module}
                  </span>
                ))}
              </div>
            </div>

            {details.seeded_weaknesses.length > 0 ? (
              <div>
                <SectionTitle title="Intentionally seeded weaknesses" />
                <ul className="mt-1.5 list-disc space-y-1 pl-5 text-xs text-tx-2">
                  {details.seeded_weaknesses.map((weakness) => (
                    <li key={weakness}>{weakness}</li>
                  ))}
                </ul>
              </div>
            ) : (
              <p className="rounded-lg border border-emerald-500/30 bg-emerald-500/5 px-3 py-2 text-xs text-tx-2">
                Secure baseline: no weaknesses are seeded. Expected result —
                all applicable checks pass, incompatible checks are skipped,
                and no findings are generated.
              </p>
            )}

            <div>
              <SectionTitle title="Simulation limitations" />
              <ul className="mt-1.5 list-disc space-y-1 pl-5 text-xs text-tx-3">
                {details.limitations.map((limitation) => (
                  <li key={limitation}>{limitation}</li>
                ))}
              </ul>
            </div>

            <div className="flex justify-end gap-2 border-t border-line pt-4">
              <button type="button" className="btn-ghost" onClick={() => setDetails(null)}>
                Close
              </button>
              <button
                type="button"
                className="btn-primary"
                onClick={() => {
                  setLaunch(details);
                  setDetails(null);
                }}
              >
                <Play className="h-4 w-4" aria-hidden /> Run Security Assessment
              </button>
            </div>
          </div>
        </Modal>
      ) : null}

      {launch ? (
        <CreateAssessmentModal
          fixedTargetId={launch.id}
          recommendedModules={launch.supported_modules}
          allowSecureVariant={launch.security_profile === "intentionally_vulnerable"}
          onClose={() => setLaunch(null)}
          onCreated={() => setLaunch(null)}
        />
      ) : null}
    </div>
  );
}

function SectionTitle({ title }: { title: string }) {
  return (
    <p className="text-[11px] font-medium uppercase tracking-wider text-tx-3">
      {title}
    </p>
  );
}

function Section({ title, body }: { title: string; body: string }) {
  return (
    <div>
      <SectionTitle title={title} />
      <p className="mt-1.5 text-xs leading-relaxed text-tx-2">{body}</p>
    </div>
  );
}
