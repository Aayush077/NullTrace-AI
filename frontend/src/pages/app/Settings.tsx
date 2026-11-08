import { useState } from "react";
import { Info, KeyRound, Save } from "lucide-react";
import { getSessionToken, setSessionToken } from "../../lib/api";
import { Card, CardHeader } from "../../components/ui";

export interface Defaults {
  profile: string;
  maxRequests: number;
  timeout: number;
}

const DEFAULTS_KEY = "nulltrace.defaults";
const FALLBACK: Defaults = { profile: "standard", maxRequests: 10, timeout: 30 };

// Assessment defaults are non-sensitive UI preferences; localStorage is the
// right place for them. Secrets never go to localStorage.
export function getDefaults(): Defaults {
  try {
    const raw = localStorage.getItem(DEFAULTS_KEY);
    if (!raw) return FALLBACK;
    const parsed = JSON.parse(raw) as Partial<Defaults>;
    return {
      profile: parsed.profile ?? FALLBACK.profile,
      maxRequests: parsed.maxRequests ?? FALLBACK.maxRequests,
      timeout: parsed.timeout ?? FALLBACK.timeout,
    };
  } catch {
    return FALLBACK;
  }
}

export function Settings() {
  const [defaults, setDefaults] = useState<Defaults>(getDefaults());
  const [token, setToken] = useState(getSessionToken());
  const [savedAt, setSavedAt] = useState<number | null>(null);

  const save = () => {
    try {
      localStorage.setItem(DEFAULTS_KEY, JSON.stringify(defaults));
    } catch {
      // Storage unavailable; defaults apply for this page load only.
    }
    setSessionToken(token.trim());
    setSavedAt(Date.now());
  };

  return (
    <div className="max-w-2xl space-y-6">
      <div>
        <h1 className="text-xl font-semibold tracking-tight">Settings</h1>
        <p className="mt-1 text-sm text-tx-3">
          Workspace preferences for this browser. Target API keys are
          configured as environment variables on the backend host — never
          here.
        </p>
      </div>

      <Card>
        <CardHeader
          title="Assessment defaults"
          subtitle="Pre-filled when creating a new assessment; always editable per run."
        />
        <div className="grid gap-4 px-5 py-4 sm:grid-cols-3">
          <div>
            <label className="label" htmlFor="s-profile">Default profile</label>
            <select
              id="s-profile"
              className="input"
              value={defaults.profile}
              onChange={(event) =>
                setDefaults({ ...defaults, profile: event.target.value })
              }
            >
              <option value="quick">quick</option>
              <option value="standard">standard</option>
              <option value="full">full</option>
            </select>
          </div>
          <div>
            <label className="label" htmlFor="s-budget">Request budget</label>
            <input
              id="s-budget"
              type="number"
              min={1}
              max={500}
              className="input"
              value={defaults.maxRequests}
              onChange={(event) =>
                setDefaults({ ...defaults, maxRequests: Number(event.target.value) })
              }
            />
          </div>
          <div>
            <label className="label" htmlFor="s-timeout">Timeout (s)</label>
            <input
              id="s-timeout"
              type="number"
              min={1}
              max={300}
              className="input"
              value={defaults.timeout}
              onChange={(event) =>
                setDefaults({ ...defaults, timeout: Number(event.target.value) })
              }
            />
          </div>
        </div>
      </Card>

      <Card>
        <CardHeader
          title="Dashboard session token"
          subtitle="Only needed when the backend sets NULLTRACE_API_TOKEN."
        />
        <div className="space-y-3 px-5 py-4">
          <div className="relative">
            <KeyRound className="pointer-events-none absolute left-3 top-2.5 h-4 w-4 text-tx-3" aria-hidden />
            <input
              type="password"
              className="input pl-9 font-mono"
              placeholder="X-API-Token value"
              value={token}
              onChange={(event) => setToken(event.target.value)}
              autoComplete="off"
            />
          </div>
          <p className="flex items-start gap-2 text-xs leading-relaxed text-tx-3">
            <Info className="mt-0.5 h-3.5 w-3.5 shrink-0" aria-hidden />
            Kept in sessionStorage only and cleared when this tab closes. This
            token guards the local dashboard API; it is unrelated to any AI
            provider API key.
          </p>
        </div>
      </Card>

      <Card>
        <CardHeader title="API target credentials" />
        <div className="space-y-2 px-5 py-4 text-xs leading-relaxed text-tx-2">
          <p>
            Provider API keys are read by the <em>backend</em> from the
            environment variable named on each target, at assessment time:
          </p>
          <pre className="overflow-x-auto rounded-lg border border-line bg-ink-900 px-3 py-2 font-mono text-[11px] text-tx-2">
            export OPENAI_API_KEY=…   # on the machine running the backend
          </pre>
          <p>
            Keys are never stored in the database, never sent to or from the
            browser, never logged, and redacted from all evidence and
            reports.
          </p>
        </div>
      </Card>

      <Card>
        <CardHeader title="Appearance" />
        <p className="px-5 py-4 text-xs leading-relaxed text-tx-3">
          NullTrace AI currently ships a single dark theme tuned for security
          work; a light theme is not implemented yet.
        </p>
      </Card>

      <div className="flex items-center gap-3">
        <button type="button" className="btn-primary" onClick={save}>
          <Save className="h-4 w-4" aria-hidden /> Save settings
        </button>
        {savedAt ? <span className="text-xs text-mint-300">Saved.</span> : null}
      </div>
    </div>
  );
}
