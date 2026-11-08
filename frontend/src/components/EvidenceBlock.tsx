import type { Evidence } from "../lib/types";

export function EvidenceBlock({ evidence }: { evidence: Evidence }) {
  return (
    <div className="overflow-hidden rounded-xl border border-line">
      <div className="flex items-center justify-between border-b border-line bg-ink-900 px-4 py-2">
        <span className="text-[11px] uppercase tracking-wider text-tx-3">
          Probe → Response
        </span>
        {evidence.synthetic ? (
          <span className="chip border-mint-400/30 bg-mint-400/10 text-mint-300">
            synthetic
          </span>
        ) : null}
      </div>
      <div className="divide-y divide-line">
        <pre className="overflow-x-auto whitespace-pre-wrap break-words bg-ink-900/50 px-4 py-3 font-mono text-[11px] leading-relaxed text-tx-2">
          {evidence.probe}
        </pre>
        <pre className="overflow-x-auto whitespace-pre-wrap break-words px-4 py-3 font-mono text-[11px] leading-relaxed text-tx-1">
          {evidence.response}
        </pre>
      </div>
      {evidence.note ? (
        <p className="border-t border-line bg-ink-900/40 px-4 py-2 text-[11px] text-tx-3">
          {evidence.note}
        </p>
      ) : null}
    </div>
  );
}
