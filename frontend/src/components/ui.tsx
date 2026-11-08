import type { ReactNode } from "react";
import { AlertTriangle, Inbox, Loader2, ShieldCheck } from "lucide-react";
import type {
  CheckStatus,
  Confidence,
  Severity,
  ValidationStatus,
} from "../lib/types";
import { titleCase } from "../lib/format";

export function Card({
  children,
  className = "",
}: {
  children: ReactNode;
  className?: string;
}) {
  return <div className={`card ${className}`}>{children}</div>;
}

export function CardHeader({
  title,
  subtitle,
  action,
}: {
  title: string;
  subtitle?: string;
  action?: ReactNode;
}) {
  return (
    <div className="flex items-start justify-between gap-4 border-b border-line px-5 py-4">
      <div>
        <h3 className="text-sm font-semibold text-tx-1">{title}</h3>
        {subtitle ? <p className="mt-0.5 text-xs text-tx-3">{subtitle}</p> : null}
      </div>
      {action}
    </div>
  );
}

export function Spinner({ label = "Loading…" }: { label?: string }) {
  return (
    <div className="flex items-center justify-center gap-2 py-14 text-tx-3">
      <Loader2 className="h-4 w-4 animate-spin" aria-hidden />
      <span className="text-sm">{label}</span>
    </div>
  );
}

export function EmptyState({
  title,
  detail,
  icon,
  action,
}: {
  title: string;
  detail?: string;
  icon?: ReactNode;
  action?: ReactNode;
}) {
  return (
    <div className="flex flex-col items-center justify-center gap-2 px-6 py-14 text-center">
      <div className="text-tx-3">{icon ?? <Inbox className="h-7 w-7" aria-hidden />}</div>
      <p className="text-sm font-medium text-tx-2">{title}</p>
      {detail ? <p className="max-w-sm text-xs text-tx-3">{detail}</p> : null}
      {action ? <div className="mt-3">{action}</div> : null}
    </div>
  );
}

export function ErrorState({
  message,
  onRetry,
}: {
  message: string;
  onRetry?: () => void;
}) {
  return (
    <div className="flex flex-col items-center justify-center gap-2 px-6 py-12 text-center">
      <AlertTriangle className="h-6 w-6 text-amber-400" aria-hidden />
      <p className="text-sm text-tx-2">{message}</p>
      {onRetry ? (
        <button type="button" className="btn-ghost mt-2" onClick={onRetry}>
          Retry
        </button>
      ) : null}
    </div>
  );
}

export function SecureEmpty({ detail }: { detail: string }) {
  return (
    <EmptyState
      icon={<ShieldCheck className="h-7 w-7 text-mint-400" aria-hidden />}
      title="Nothing here yet"
      detail={detail}
    />
  );
}

const SEVERITY_STYLES: Record<Severity, string> = {
  critical: "border-red-500/40 bg-red-500/10 text-red-300",
  high: "border-orange-500/40 bg-orange-500/10 text-orange-300",
  medium: "border-amber-500/40 bg-amber-500/10 text-amber-300",
  low: "border-sky-500/40 bg-sky-500/10 text-sky-300",
  informational: "border-line-strong bg-ink-700 text-tx-2",
};

export function SeverityBadge({ severity }: { severity: Severity }) {
  return (
    <span className={`chip ${SEVERITY_STYLES[severity] ?? SEVERITY_STYLES.informational}`}>
      {severity}
    </span>
  );
}

const STATUS_STYLES: Record<CheckStatus, string> = {
  pass: "border-emerald-500/40 bg-emerald-500/10 text-emerald-300",
  fail: "border-red-500/40 bg-red-500/10 text-red-300",
  inconclusive: "border-amber-500/40 bg-amber-500/10 text-amber-300",
  error: "border-fuchsia-500/40 bg-fuchsia-500/10 text-fuchsia-300",
  skipped: "border-line-strong bg-ink-700 text-tx-3",
};

export function CheckStatusBadge({ status }: { status: CheckStatus }) {
  return <span className={`chip ${STATUS_STYLES[status]}`}>{status}</span>;
}

export function ConfidenceBadge({ confidence }: { confidence: Confidence }) {
  const styles: Record<Confidence, string> = {
    high: "border-violet-500/40 bg-violet-500/10 text-violet-300",
    medium: "border-sky-500/40 bg-sky-500/10 text-sky-300",
    low: "border-line-strong bg-ink-700 text-tx-3",
  };
  return <span className={`chip ${styles[confidence]}`}>{confidence} conf.</span>;
}

const VALIDATION_STYLES: Record<ValidationStatus, string> = {
  pending_review: "border-amber-500/40 bg-amber-500/10 text-amber-300",
  confirmed: "border-red-500/40 bg-red-500/10 text-red-300",
  rejected: "border-line-strong bg-ink-700 text-tx-3",
  needs_retesting: "border-sky-500/40 bg-sky-500/10 text-sky-300",
};

export function ValidationBadge({ status }: { status: ValidationStatus }) {
  return (
    <span className={`chip ${VALIDATION_STYLES[status]}`}>
      {titleCase(status)}
    </span>
  );
}

export function RunStatusBadge({ status }: { status: string }) {
  const styles: Record<string, string> = {
    completed: "border-emerald-500/40 bg-emerald-500/10 text-emerald-300",
    incomplete: "border-amber-500/40 bg-amber-500/10 text-amber-300",
    running: "border-violet-500/40 bg-violet-500/10 text-violet-300",
    failed: "border-red-500/40 bg-red-500/10 text-red-300",
  };
  return (
    <span className={`chip ${styles[status] ?? "border-line-strong bg-ink-700 text-tx-3"}`}>
      {status}
    </span>
  );
}

export function StatCard({
  label,
  value,
  hint,
  icon,
  tone = "default",
}: {
  label: string;
  value: ReactNode;
  hint?: string;
  icon?: ReactNode;
  tone?: "default" | "violet" | "mint" | "red";
}) {
  const tones: Record<string, string> = {
    default: "text-tx-1",
    violet: "text-violet-300",
    mint: "text-mint-300",
    red: "text-red-300",
  };
  return (
    <Card className="px-5 py-4">
      <div className="flex items-center justify-between">
        <p className="text-xs font-medium uppercase tracking-wider text-tx-3">
          {label}
        </p>
        {icon ? <span className="text-tx-3">{icon}</span> : null}
      </div>
      <p className={`mt-2 text-2xl font-semibold tabular-nums ${tones[tone]}`}>
        {value}
      </p>
      {hint ? <p className="mt-1 text-xs text-tx-3">{hint}</p> : null}
    </Card>
  );
}

export function Modal({
  title,
  onClose,
  children,
  wide = false,
}: {
  title: string;
  onClose: () => void;
  children: ReactNode;
  wide?: boolean;
}) {
  return (
    <div
      className="fixed inset-0 z-50 flex items-start justify-center overflow-y-auto bg-black/60 p-4 backdrop-blur-sm sm:p-8"
      role="dialog"
      aria-modal="true"
      aria-label={title}
      onMouseDown={(event) => {
        if (event.target === event.currentTarget) onClose();
      }}
    >
      <div
        className={`card w-full ${wide ? "max-w-3xl" : "max-w-lg"} bg-ink-850`}
      >
        <div className="flex items-center justify-between border-b border-line px-5 py-4">
          <h3 className="text-sm font-semibold">{title}</h3>
          <button
            type="button"
            className="rounded-md px-2 py-1 text-tx-3 hover:bg-ink-700 hover:text-tx-1"
            onClick={onClose}
          >
            ✕
          </button>
        </div>
        <div className="px-5 py-4">{children}</div>
      </div>
    </div>
  );
}
