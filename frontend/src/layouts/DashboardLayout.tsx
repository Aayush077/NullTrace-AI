import { useState } from "react";
import { NavLink, Outlet } from "react-router-dom";
import {
  Boxes,
  Crosshair,
  FileText,
  FlaskConical,
  LayoutDashboard,
  ListChecks,
  LogOut,
  Menu,
  ScrollText,
  Settings,
  ShieldAlert,
  X,
} from "lucide-react";
import { Logo } from "../components/Logo";
import { useAuth } from "../components/AuthGate";
import { api } from "../lib/api";

const NAV = [
  { to: "/app", label: "Overview", icon: LayoutDashboard, end: true },
  { to: "/app/lab", label: "Demo Lab", icon: FlaskConical },
  { to: "/app/assessments", label: "Assessments", icon: ListChecks },
  { to: "/app/targets", label: "Targets", icon: Crosshair },
  { to: "/app/modules", label: "Security Modules", icon: Boxes },
  { to: "/app/findings", label: "Findings", icon: ShieldAlert },
  { to: "/app/evidence", label: "Evidence", icon: ScrollText },
  { to: "/app/reports", label: "Reports", icon: FileText },
  { to: "/app/settings", label: "Settings", icon: Settings },
];

function SessionControls() {
  const { status, refresh } = useAuth();

  if (status.setup_mode && !status.authenticated) {
    return (
      <span className="chip border-amber-400/30 bg-amber-400/10 text-amber-300">
        setup mode — no auth
      </span>
    );
  }

  if (!status.authenticated || !status.user) {
    return (
      <span className="chip border-mint-400/30 bg-mint-400/10 text-mint-300">
        local-only mode
      </span>
    );
  }

  const logout = async () => {
    await api.logout();
    refresh();
  };

  return (
    <div className="flex items-center gap-3">
      <span className="hidden text-right sm:block">
        <span className="block text-xs font-medium text-tx-1">
          {status.user.username}
        </span>
        <span className="block text-[10px] uppercase tracking-wider text-tx-3">
          {status.user.role}
        </span>
      </span>
      <button
        type="button"
        onClick={() => void logout()}
        className="rounded-md border border-line px-2.5 py-1.5 text-xs text-tx-2 hover:bg-ink-700 hover:text-tx-1"
      >
        <LogOut className="mr-1 inline h-3.5 w-3.5" aria-hidden />
        Sign out
      </button>
    </div>
  );
}

function SidebarNav({ onNavigate }: { onNavigate?: () => void }) {
  return (
    <nav className="flex-1 space-y-0.5 px-3 py-4">
      <p className="px-3 pb-2 text-[10px] font-semibold uppercase tracking-[0.14em] text-tx-3">
        Workspace
      </p>
      {NAV.map(({ to, label, icon: Icon, end }) => (
        <NavLink
          key={to}
          to={to}
          end={end}
          onClick={onNavigate}
          className={({ isActive }) =>
            `flex items-center gap-3 rounded-lg px-3 py-2 text-sm transition-colors ${
              isActive
                ? "bg-violet-500/15 font-medium text-violet-300"
                : "text-tx-2 hover:bg-ink-700 hover:text-tx-1"
            }`
          }
        >
          <Icon className="h-4 w-4" aria-hidden />
          {label}
        </NavLink>
      ))}
    </nav>
  );
}

export function DashboardLayout() {
  const [mobileOpen, setMobileOpen] = useState(false);

  return (
    <div className="flex min-h-full bg-ink-950">
      {/* Desktop sidebar */}
      <aside className="sticky top-0 hidden h-screen w-60 shrink-0 flex-col border-r border-line bg-ink-900/70 lg:flex">
        <div className="flex h-16 items-center border-b border-line px-5">
          <Logo to="/" />
        </div>
        <SidebarNav />
        <div className="border-t border-line px-5 py-4">
          <p className="text-[11px] leading-relaxed text-tx-3">
            Local workspace. Only assess systems you are authorized to test.
          </p>
        </div>
      </aside>

      {/* Mobile drawer */}
      {mobileOpen ? (
        <div className="fixed inset-0 z-40 lg:hidden">
          <div
            className="absolute inset-0 bg-black/60"
            onClick={() => setMobileOpen(false)}
          />
          <aside className="absolute inset-y-0 left-0 flex w-64 flex-col border-r border-line bg-ink-900">
            <div className="flex h-16 items-center justify-between border-b border-line px-5">
              <Logo to="/" />
              <button
                type="button"
                className="text-tx-3"
                onClick={() => setMobileOpen(false)}
                aria-label="Close navigation"
              >
                <X className="h-5 w-5" />
              </button>
            </div>
            <SidebarNav onNavigate={() => setMobileOpen(false)} />
          </aside>
        </div>
      ) : null}

      <div className="flex min-w-0 flex-1 flex-col">
        <header className="sticky top-0 z-30 flex h-16 items-center justify-between border-b border-line bg-ink-950/80 px-4 backdrop-blur sm:px-6">
          <div className="flex items-center gap-3">
            <button
              type="button"
              className="rounded-md border border-line p-2 text-tx-2 lg:hidden"
              onClick={() => setMobileOpen(true)}
              aria-label="Open navigation"
            >
              <Menu className="h-4 w-4" />
            </button>
            <span className="hidden text-sm text-tx-3 sm:block">
              AI Application Security Assessment
            </span>
          </div>
          <SessionControls />
        </header>
        <main className="mx-auto w-full max-w-7xl flex-1 px-4 py-6 sm:px-6 lg:px-8">
          <Outlet />
        </main>
      </div>
    </div>
  );
}
