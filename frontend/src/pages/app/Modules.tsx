import { Boxes } from "lucide-react";
import { api } from "../../lib/api";
import { useAsync } from "../../lib/useAsync";
import {
  Card,
  CardHeader,
  ErrorState,
  Spinner,
} from "../../components/ui";
import { titleCase } from "../../lib/format";

const MODULE_NOTES: Record<string, string> = {
  baseline: "Connectivity sanity check before security probes run.",
  prompt_injection:
    "Probe-token and canary attributed injection checks, incl. multi-turn persistence (needs conversation support on the target).",
  info_disclosure:
    "Marker-attributed secret, cross-user, and unprompted leakage detection. Degrades to inconclusive without declared markers.",
  authorization:
    "Requires a tool-execution capability on the target; currently exercised by the synthetic tool layer.",
  tool_abuse:
    "Requires a tool-execution capability on the target; destructive tools are only ever probed, never executed for real.",
  output_handling:
    "Structured output validity plus informational markup passthrough observation.",
  rag_security:
    "Runs against the bundled synthetic document store. No external RAG adapter exists yet — the framework does not claim to assess one.",
  agent_security:
    "Synthetic agent probes plus OpenAI-format tool-call probing (attempted calls are parsed as evidence, never executed).",
};

export function Modules() {
  const modules = useAsync(() => api.modules(), []);

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-xl font-semibold tracking-tight">Security Modules</h1>
        <p className="mt-1 text-sm text-tx-3">
          The module registry as implemented — including each check's
          capability requirements and honest limitations.
        </p>
      </div>

      {modules.loading ? (
        <Spinner />
      ) : modules.error ? (
        <ErrorState message={modules.error} onRetry={modules.reload} />
      ) : (
        <div className="grid gap-4 xl:grid-cols-2">
          {(modules.data ?? []).map((module) => (
            <Card key={module.name}>
              <CardHeader
                title={titleCase(module.name)}
                subtitle={MODULE_NOTES[module.name]}
                action={
                  <div className="flex items-center gap-2">
                    <span className="chip border-violet-500/40 bg-violet-500/10 text-violet-300">
                      <Boxes className="h-3 w-3" aria-hidden />
                      {module.check_count} checks
                    </span>
                    <span className="chip border-emerald-500/40 bg-emerald-500/10 text-emerald-300">
                      implemented
                    </span>
                  </div>
                }
              />
              <ul className="divide-y divide-line">
                {module.checks.map((check) => (
                  <li key={check.check_id} className="px-5 py-3">
                    <div className="flex items-center justify-between gap-3">
                      <p className="font-mono text-xs font-medium text-tx-1">
                        {check.check_id}
                      </p>
                      {check.required_capability ? (
                        <span className="chip border-sky-500/40 bg-sky-500/10 text-sky-300">
                          needs {check.required_capability}
                        </span>
                      ) : null}
                    </div>
                    <p className="mt-1 text-xs font-medium text-tx-2">{check.title}</p>
                    {check.description ? (
                      <p className="mt-0.5 text-xs leading-relaxed text-tx-3">
                        {check.description}
                      </p>
                    ) : null}
                  </li>
                ))}
              </ul>
              <div className="border-t border-line px-5 py-3 text-xs text-tx-3">
                Profiles: {module.profiles.map((p) => (
                  <span key={p} className="mr-1.5 font-mono">{p}</span>
                ))}
              </div>
            </Card>
          ))}
        </div>
      )}
    </div>
  );
}
