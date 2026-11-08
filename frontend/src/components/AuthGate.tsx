import {
  createContext,
  useCallback,
  useContext,
  useState,
  type ReactNode,
} from "react";
import { LogIn, ShieldCheck } from "lucide-react";
import { api, ApiError, type AuthStatus } from "../lib/api";
import { useAsync } from "../lib/useAsync";
import { Logo } from "./Logo";
import { Spinner } from "./ui";

interface AuthContextValue {
  status: AuthStatus;
  refresh: () => void;
}

const AuthContext = createContext<AuthContextValue | null>(null);

export function useAuth(): AuthContextValue {
  const value = useContext(AuthContext);
  if (!value) throw new Error("useAuth outside AuthGate");
  return value;
}

export function AuthGate({ children }: { children: ReactNode }) {
  const status = useAsync(() => api.authStatus(), []);

  if (status.loading) return <Spinner label="Checking session…" />;

  // If the status call itself fails (backend down), show the login form so
  // the user can retry rather than a blank screen.
  const data: AuthStatus = status.data ?? {
    setup_mode: false,
    authenticated: false,
    user: null,
  };

  const open = data.setup_mode || data.authenticated;

  if (!open) {
    return <LoginScreen onSuccess={status.reload} />;
  }

  return (
    <AuthContext.Provider value={{ status: data, refresh: status.reload }}>
      {children}
    </AuthContext.Provider>
  );
}

function LoginScreen({ onSuccess }: { onSuccess: () => void }) {
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const submit = useCallback(
    async (event: React.FormEvent) => {
      event.preventDefault();
      setBusy(true);
      setError(null);
      try {
        await api.login(username, password);
        onSuccess();
      } catch (err) {
        setError(err instanceof ApiError ? err.message : String(err));
        setBusy(false);
      }
    },
    [username, password, onSuccess],
  );

  return (
    <div className="flex min-h-screen items-center justify-center bg-ink-950 px-4">
      <div className="hero-glow absolute inset-0" aria-hidden />
      <div className="card relative w-full max-w-sm p-6">
        <div className="mb-6 flex flex-col items-center gap-3 text-center">
          <Logo to="/" />
          <div className="flex items-center gap-1.5 text-xs text-tx-3">
            <ShieldCheck className="h-3.5 w-3.5 text-mint-300" aria-hidden />
            Authenticated access
          </div>
        </div>
        <form onSubmit={submit} className="space-y-4">
          <div>
            <label className="label" htmlFor="username">
              Username
            </label>
            <input
              id="username"
              className="input"
              autoComplete="username"
              value={username}
              onChange={(event) => setUsername(event.target.value)}
              required
            />
          </div>
          <div>
            <label className="label" htmlFor="password">
              Password
            </label>
            <input
              id="password"
              type="password"
              className="input"
              autoComplete="current-password"
              value={password}
              onChange={(event) => setPassword(event.target.value)}
              required
            />
          </div>
          {error ? (
            <p className="rounded-lg border border-red-500/30 bg-red-500/10 px-3 py-2 text-xs text-red-300">
              {error}
            </p>
          ) : null}
          <button
            type="submit"
            className="btn-primary w-full"
            disabled={busy || !username || !password}
          >
            <LogIn className="h-4 w-4" aria-hidden />
            {busy ? "Signing in…" : "Sign in"}
          </button>
        </form>
        <p className="mt-4 text-center text-[11px] leading-relaxed text-tx-3">
          Local workspace. Contact your NullTrace administrator if you need
          an account.
        </p>
      </div>
    </div>
  );
}
