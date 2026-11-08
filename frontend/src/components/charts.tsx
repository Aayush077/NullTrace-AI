import {
  Area,
  AreaChart,
  Bar,
  BarChart,
  CartesianGrid,
  Cell,
  Pie,
  PieChart,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";
import type { AnalyticsHistoryPoint } from "../lib/types";
import { titleCase } from "../lib/format";

const GRID = "rgba(148, 150, 200, 0.10)";
const TEXT = "#6e7090";

export const SEVERITY_COLORS: Record<string, string> = {
  critical: "#f87171",
  high: "#fb923c",
  medium: "#fbbf24",
  low: "#38bdf8",
  informational: "#6e7090",
};

const PALETTE = ["#7c5dfa", "#9f7bff", "#2dd4bf", "#f472b6", "#38bdf8", "#fbbf24", "#f87171", "#34d399"];

const tooltipStyle = {
  backgroundColor: "#101021",
  border: "1px solid rgba(148,150,200,0.25)",
  borderRadius: 10,
  fontSize: 12,
  color: "#f2f2f8",
};

export function SeverityDonut({
  data,
  centerLabel,
}: {
  data: Record<string, number>;
  centerLabel: string;
}) {
  const entries = Object.entries(data).filter(([, count]) => count > 0);
  const total = entries.reduce((sum, [, count]) => sum + count, 0);

  if (total === 0) {
    return (
      <p className="py-10 text-center text-xs text-tx-3">
        No findings recorded yet.
      </p>
    );
  }

  return (
    <div className="relative">
      <ResponsiveContainer width="100%" height={210}>
        <PieChart>
          <Pie
            data={entries.map(([name, value]) => ({ name, value }))}
            dataKey="value"
            nameKey="name"
            innerRadius={62}
            outerRadius={86}
            paddingAngle={3}
            strokeWidth={0}
          >
            {entries.map(([name], index) => (
              <Cell
                key={name}
                fill={SEVERITY_COLORS[name] ?? PALETTE[index % PALETTE.length]}
              />
            ))}
          </Pie>
          <Tooltip contentStyle={tooltipStyle} />
        </PieChart>
      </ResponsiveContainer>
      <div className="pointer-events-none absolute inset-0 flex flex-col items-center justify-center">
        <p className="text-2xl font-semibold tabular-nums">{total}</p>
        <p className="text-[11px] uppercase tracking-wider text-tx-3">
          {centerLabel}
        </p>
      </div>
      <ul className="mt-2 space-y-1.5">
        {entries.map(([name, value]) => (
          <li key={name} className="flex items-center justify-between text-xs">
            <span className="flex items-center gap-2 text-tx-2">
              <span
                className="h-2 w-2 rounded-full"
                style={{ background: SEVERITY_COLORS[name] ?? "#7c5dfa" }}
              />
              {titleCase(name)}
            </span>
            <span className="font-mono text-tx-3">{value}</span>
          </li>
        ))}
      </ul>
    </div>
  );
}

export function HistoryChart({ history }: { history: AnalyticsHistoryPoint[] }) {
  if (history.length === 0) {
    return (
      <p className="py-14 text-center text-xs text-tx-3">
        Run an assessment to populate history.
      </p>
    );
  }

  const data = history.map((point, index) => ({
    name: `#${index + 1}`,
    checks: point.checks_executed,
    findings: point.findings_total,
    id: point.assessment_id,
  }));

  return (
    <ResponsiveContainer width="100%" height={240}>
      <AreaChart data={data} margin={{ top: 10, right: 8, left: -18, bottom: 0 }}>
        <defs>
          <linearGradient id="gradChecks" x1="0" y1="0" x2="0" y2="1">
            <stop offset="0%" stopColor="#7c5dfa" stopOpacity={0.45} />
            <stop offset="100%" stopColor="#7c5dfa" stopOpacity={0.02} />
          </linearGradient>
          <linearGradient id="gradFindings" x1="0" y1="0" x2="0" y2="1">
            <stop offset="0%" stopColor="#2dd4bf" stopOpacity={0.4} />
            <stop offset="100%" stopColor="#2dd4bf" stopOpacity={0.02} />
          </linearGradient>
        </defs>
        <CartesianGrid stroke={GRID} vertical={false} />
        <XAxis dataKey="name" stroke={TEXT} fontSize={11} tickLine={false} axisLine={false} />
        <YAxis stroke={TEXT} fontSize={11} tickLine={false} axisLine={false} allowDecimals={false} />
        <Tooltip contentStyle={tooltipStyle} />
        <Area
          type="monotone"
          dataKey="checks"
          name="Checks executed"
          stroke="#9f7bff"
          strokeWidth={2}
          fill="url(#gradChecks)"
        />
        <Area
          type="monotone"
          dataKey="findings"
          name="Findings"
          stroke="#2dd4bf"
          strokeWidth={2}
          fill="url(#gradFindings)"
        />
      </AreaChart>
    </ResponsiveContainer>
  );
}

export function CategoryBars({ data }: { data: Record<string, number> }) {
  const entries = Object.entries(data)
    .sort((a, b) => b[1] - a[1])
    .map(([name, value]) => ({ name: titleCase(name), value }));

  if (entries.length === 0) {
    return (
      <p className="py-14 text-center text-xs text-tx-3">No data recorded yet.</p>
    );
  }

  return (
    <ResponsiveContainer width="100%" height={Math.max(180, entries.length * 36)}>
      <BarChart
        layout="vertical"
        data={entries}
        margin={{ top: 4, right: 12, left: 10, bottom: 0 }}
      >
        <CartesianGrid stroke={GRID} horizontal={false} />
        <XAxis type="number" stroke={TEXT} fontSize={11} tickLine={false} axisLine={false} allowDecimals={false} />
        <YAxis
          type="category"
          dataKey="name"
          stroke={TEXT}
          fontSize={11}
          width={130}
          tickLine={false}
          axisLine={false}
        />
        <Tooltip contentStyle={tooltipStyle} cursor={{ fill: "rgba(124,93,250,0.08)" }} />
        <Bar dataKey="value" radius={[0, 6, 6, 0]} maxBarSize={16}>
          {entries.map((entry, index) => (
            <Cell key={entry.name} fill={PALETTE[index % PALETTE.length]} />
          ))}
        </Bar>
      </BarChart>
    </ResponsiveContainer>
  );
}
