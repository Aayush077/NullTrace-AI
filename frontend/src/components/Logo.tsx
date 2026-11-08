import { Link } from "react-router-dom";

export function Logo({ to = "/" }: { to?: string }) {
  return (
    <Link to={to} className="flex items-center gap-2.5">
      <span className="flex h-8 w-8 items-center justify-center rounded-lg border border-violet-500/40 bg-violet-500/10">
        <svg viewBox="0 0 20 20" className="h-4 w-4" aria-hidden>
          <path
            d="M4 16V4h2.1l6.4 8.3V4H15v12h-2.1L6.5 7.7V16H4z"
            fill="#9f7bff"
          />
        </svg>
      </span>
      <span className="text-[15px] font-semibold tracking-tight">
        NullTrace <span className="text-violet-400">AI</span>
      </span>
    </Link>
  );
}
