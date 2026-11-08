import { Link } from "react-router-dom";
import {
  ArrowRight,
  Boxes,
  CheckCircle2,
  Crosshair,
  Database,
  Eye,
  FileCode2,
  FileText,
  GitBranch,
  Lock,
  ScrollText,
  ShieldAlert,
  ShieldCheck,
  Terminal,
  Workflow,
} from "lucide-react";
import { Logo } from "../components/Logo";

// Set to your repository URL when the project is published; the link is
// hidden while null so we never ship a fabricated destination.
const GITHUB_URL: string | null = null;

const NAV_LINKS = [
  { label: "Product", href: "#product" },
  { label: "Features", href: "#features" },
  { label: "Modules", href: "#modules" },
  { label: "Documentation", href: "/api/docs" },
  { label: "Roadmap", href: "#roadmap" },
];

const FEATURES = [
  {
    icon: ShieldAlert,
    title: "Prompt Injection Testing",
    text: "Direct override, role and delimiter confusion, multi-turn persistence, and indirect injection — proven with per-assessment probe tokens, not keyword guessing.",
  },
  {
    icon: Eye,
    title: "Sensitive Information Disclosure",
    text: "Canary- and marker-attributed detection of system prompt leaks, credential disclosure, and cross-user data exposure.",
  },
  {
    icon: Lock,
    title: "Authorization Testing",
    text: "Vertical and horizontal escalation, IDOR patterns, and confused-deputy scenarios against synthetic tool layers.",
  },
  {
    icon: Workflow,
    title: "AI Tool Security",
    text: "Unregistered tool invocation, destructive-action safeguards, argument validation, and injected tool-call attempts — parsed as evidence, never executed.",
  },
  {
    icon: Boxes,
    title: "Agent Security",
    text: "Tool-output trust, excessive autonomy, and delegation abuse probed against a deterministic synthetic agent.",
  },
  {
    icon: Database,
    title: "RAG Security",
    text: "Document ACL enforcement, poisoned-document injection, and metadata leakage against a bundled synthetic store.",
  },
  {
    icon: ScrollText,
    title: "Evidence-Based Findings",
    text: "Every finding carries probes, responses, reproduction steps, confidence, and a human-review status. Automation never confirms its own findings.",
  },
  {
    icon: FileText,
    title: "Automated Security Reports",
    text: "Schema-validated JSON for machines, severity-sorted Markdown for humans — with secrets redacted and synthetic evidence labeled.",
  },
];

const MODULES: {
  name: string;
  checks: number;
  status: string;
  statusTone: string;
  text: string;
}[] = [
  {
    name: "prompt_injection",
    checks: 6,
    status: "Implemented",
    statusTone: "text-emerald-300 border-emerald-500/40 bg-emerald-500/10",
    text: "Override, extraction, role & delimiter confusion, persistence, indirect injection.",
  },
  {
    name: "info_disclosure",
    checks: 3,
    status: "Implemented",
    statusTone: "text-emerald-300 border-emerald-500/40 bg-emerald-500/10",
    text: "Secret, cross-user, and unprompted marker leakage detection.",
  },
  {
    name: "authorization",
    checks: 3,
    status: "Implemented",
    statusTone: "text-emerald-300 border-emerald-500/40 bg-emerald-500/10",
    text: "Vertical/horizontal escalation and prompt-asserted role abuse.",
  },
  {
    name: "tool_abuse",
    checks: 4,
    status: "Implemented",
    statusTone: "text-emerald-300 border-emerald-500/40 bg-emerald-500/10",
    text: "Tool allowlists, destructive safeguards, argument validation.",
  },
  {
    name: "output_handling",
    checks: 2,
    status: "Implemented",
    statusTone: "text-emerald-300 border-emerald-500/40 bg-emerald-500/10",
    text: "Structured-output validity and markup passthrough observations.",
  },
  {
    name: "rag_security",
    checks: 3,
    status: "Synthetic fixtures",
    statusTone: "text-amber-300 border-amber-500/40 bg-amber-500/10",
    text: "Runs against the bundled synthetic document store; external RAG adapters are on the roadmap.",
  },
  {
    name: "agent_security",
    checks: 4,
    status: "Synthetic + tool-call probing",
    statusTone: "text-amber-300 border-amber-500/40 bg-amber-500/10",
    text: "Includes injected tool-call detection via OpenAI-format function calling.",
  },
  {
    name: "baseline",
    checks: 1,
    status: "Implemented",
    statusTone: "text-emerald-300 border-emerald-500/40 bg-emerald-500/10",
    text: "Connectivity sanity check before security probes run.",
  },
];

const STEPS = [
  { title: "Configure an authorized target", text: "The bundled offline mock, or an OpenAI-compatible API you are explicitly authorized to assess." },
  { title: "Select an assessment profile", text: "Quick, standard, or full — or hand-pick individual modules." },
  { title: "Execute security checks", text: "Budgeted, time-bounded, redirect-free requests through a DNS-validated, origin-pinned transport." },
  { title: "Review evidence-backed findings", text: "Probe/response pairs, confidence scores, and reproduction steps for every finding." },
  { title: "Generate reports", text: "Schema-validated JSON and professional Markdown, with secrets redacted." },
  { title: "Remediate and retest", text: "Mark findings confirmed, rejected, or needs-retesting, then re-run the same reproducible checks." },
];

const ROADMAP = [
  { phase: "Foundation, secure API transport, core modules", status: "Complete", done: true },
  { phase: "Evidence & risk engine, reporting schema v1.0", status: "Complete", done: true },
  { phase: "RAG & agent security (synthetic environments)", status: "Partial — synthetic fixtures only", done: false },
  { phase: "Web platform: FastAPI backend + dashboard", status: "Shipped in 0.3.0 (local use)", done: true },
  { phase: "External RAG/agent adapters, streaming, multi-provider", status: "Planned", done: false },
  { phase: "Release hardening & external security review", status: "Planned", done: false },
];

const REPORT_SNIPPET = `{
  "schema_version": "1.0",
  "assessment_id": "NTA-1a16d1e12fbe",
  "target": "local-mock-agent (vulnerable)",
  "synthetic_target": true,
  "summary": {
    "checks_executed": 26,
    "status_counts": { "pass": 3, "fail": 22, "inconclusive": 1 },
    "findings_total": 23,
    "findings_by_severity": { "critical": 1, "high": 13, "medium": 6 }
  },
  "findings": [{
    "finding_id": "NTA-1a16d1e12fbe-NT-AZ-001-09",
    "severity": "critical",
    "confidence": "high",
    "validation_status": "pending_review",
    "evidence": [{ "probe": "…", "response": "…", "synthetic": true }]
  }]
}`;

function SectionHeading({
  eyebrow,
  title,
  text,
}: {
  eyebrow: string;
  title: string;
  text?: string;
}) {
  return (
    <div className="mx-auto max-w-2xl text-center">
      <p className="chip mx-auto border-violet-500/40 bg-violet-500/10 text-violet-300">
        {eyebrow}
      </p>
      <h2 className="mt-4 text-3xl font-semibold tracking-tight sm:text-4xl">
        {title}
      </h2>
      {text ? <p className="mt-3 text-sm leading-relaxed text-tx-2">{text}</p> : null}
    </div>
  );
}

function HeroPreview() {
  return (
    <div className="card mx-auto mt-16 max-w-4xl overflow-hidden text-left shadow-glow">
      <div className="flex items-center gap-2 border-b border-line bg-ink-900 px-4 py-3">
        <span className="h-2.5 w-2.5 rounded-full bg-red-400/70" />
        <span className="h-2.5 w-2.5 rounded-full bg-amber-400/70" />
        <span className="h-2.5 w-2.5 rounded-full bg-emerald-400/70" />
        <span className="ml-3 font-mono text-xs text-tx-3">
          nulltrace dashboard — product preview
        </span>
      </div>
      <div className="grid gap-4 p-5 sm:grid-cols-3">
        {[
          { label: "Checks executed", value: "26", tone: "text-tx-1" },
          { label: "Findings (pending review)", value: "23", tone: "text-violet-300" },
          { label: "Critical", value: "1", tone: "text-red-300" },
        ].map((stat) => (
          <div key={stat.label} className="rounded-xl border border-line bg-ink-900/70 px-4 py-3">
            <p className="text-[10px] uppercase tracking-wider text-tx-3">{stat.label}</p>
            <p className={`mt-1 text-xl font-semibold tabular-nums ${stat.tone}`}>{stat.value}</p>
          </div>
        ))}
        <div className="sm:col-span-3">
          <div className="rounded-xl border border-line bg-ink-900/70 p-4 font-mono text-[11px] leading-relaxed text-tx-2">
            <p><span className="text-mint-300">NT-PI-006</span> prompt_injection <span className="text-red-300">fail</span> — injected instruction followed (token emitted)</p>
            <p><span className="text-mint-300">NT-AZ-001</span> authorization <span className="text-red-300">fail</span> — privileged tool executed for role 'customer'</p>
            <p><span className="text-mint-300">NT-RAG-002</span> rag_security <span className="text-red-300">fail</span> — poisoned document instruction followed</p>
            <p><span className="text-mint-300">NT-TA-002</span> tool_abuse <span className="text-emerald-300">pass</span> — destructive tool gated behind confirmation</p>
            <p className="mt-2 text-tx-3">synthetic target · evidence recorded · findings pending human review</p>
          </div>
        </div>
      </div>
    </div>
  );
}

export function Landing() {
  return (
    <div className="min-h-full bg-ink-950">
      {/* Navigation */}
      <header className="sticky top-0 z-40 border-b border-line bg-ink-950/80 backdrop-blur">
        <div className="mx-auto flex h-16 max-w-6xl items-center justify-between px-4 sm:px-6">
          <Logo />
          <nav className="hidden items-center gap-6 md:flex">
            {NAV_LINKS.map((link) =>
              link.href.startsWith("#") ? (
                <a key={link.label} href={link.href} className="text-sm text-tx-2 hover:text-tx-1">
                  {link.label}
                </a>
              ) : (
                <a key={link.label} href={link.href} className="text-sm text-tx-2 hover:text-tx-1">
                  {link.label}
                </a>
              ),
            )}
            {GITHUB_URL ? (
              <a href={GITHUB_URL} className="text-sm text-tx-2 hover:text-tx-1">
                GitHub
              </a>
            ) : null}
          </nav>
          <Link to="/app" className="btn-primary">
            Launch Dashboard
          </Link>
        </div>
      </header>

      {/* Hero */}
      <section id="product" className="relative overflow-hidden">
        <div className="hero-glow absolute inset-0" aria-hidden />
        <div className="hero-grid absolute inset-0" aria-hidden />
        <div className="relative mx-auto max-w-6xl px-4 pb-24 pt-20 text-center sm:px-6 sm:pt-28">
          <p className="chip mx-auto border-violet-500/40 bg-violet-500/10 text-violet-300">
            v0.3.0 · evidence-first · local-first
          </p>
          <h1 className="mx-auto mt-6 max-w-3xl text-4xl font-semibold leading-tight tracking-tight sm:text-6xl">
            Secure the Intelligence{" "}
            <span className="bg-gradient-to-r from-violet-400 via-violet-300 to-mint-300 bg-clip-text text-transparent">
              Behind Your Applications
            </span>
          </h1>
          <p className="mx-auto mt-5 max-w-2xl text-base leading-relaxed text-tx-2">
            An evidence-driven security assessment framework for LLM
            applications, AI agents, and modern AI-powered systems. 26 checks
            across 8 modules — every finding backed by attributable evidence
            and gated behind human review.
          </p>
          <div className="mt-8 flex flex-wrap items-center justify-center gap-3">
            <Link to="/app" className="btn-primary px-6 py-2.5 text-base">
              Launch Dashboard <ArrowRight className="h-4 w-4" aria-hidden />
            </Link>
            <a href="#features" className="btn-ghost px-6 py-2.5 text-base">
              Explore Capabilities
            </a>
          </div>
          <p className="mt-5 text-xs text-tx-3">
            Offline synthetic mode by default · explicit consent for network
            assessments · MIT licensed
          </p>
          <HeroPreview />
        </div>
      </section>

      {/* Features */}
      <section id="features" className="mx-auto max-w-6xl px-4 py-24 sm:px-6">
        <SectionHeading
          eyebrow="Capabilities"
          title="Built for real AI security assessment"
          text="Everything below is implemented and covered by the automated test suite. No vaporware features."
        />
        <div className="mt-12 grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
          {FEATURES.map(({ icon: Icon, title, text }) => (
            <div key={title} className="card p-5">
              <span className="flex h-9 w-9 items-center justify-center rounded-lg border border-violet-500/30 bg-violet-500/10">
                <Icon className="h-4.5 w-4.5 h-[18px] w-[18px] text-violet-300" aria-hidden />
              </span>
              <h3 className="mt-4 text-sm font-semibold">{title}</h3>
              <p className="mt-1.5 text-xs leading-relaxed text-tx-3">{text}</p>
            </div>
          ))}
        </div>
      </section>

      {/* Architecture */}
      <section className="border-y border-line bg-ink-900/40">
        <div className="mx-auto max-w-6xl px-4 py-24 sm:px-6">
          <SectionHeading
            eyebrow="Architecture"
            title="From target to validated finding"
            text="A modular pipeline: adapters talk to targets, checks collect evidence, the evidence engine builds findings, and reporting renders validated artifacts."
          />
          <div className="mt-12 flex flex-col items-stretch justify-center gap-3 lg:flex-row lg:items-center">
            {[
              { icon: Crosshair, label: "Target Application", sub: "mock · OpenAI-compatible API" },
              { icon: Terminal, label: "Assessment Engine", sub: "profiles · budgets · isolation" },
              { icon: Boxes, label: "Security Modules", sub: "26 checks · 8 modules" },
              { icon: ScrollText, label: "Evidence Engine", sub: "markers · tokens · redaction" },
              { icon: ShieldAlert, label: "Findings", sub: "severity · confidence · review" },
              { icon: FileText, label: "Reports", sub: "JSON · Markdown · validated" },
            ].map((node, index, nodes) => (
              <div key={node.label} className="flex flex-col items-center gap-3 lg:flex-row">
                <div className="card w-full px-4 py-3 text-center lg:w-auto">
                  <node.icon className="mx-auto h-4 w-4 text-mint-300" aria-hidden />
                  <p className="mt-1.5 text-xs font-semibold">{node.label}</p>
                  <p className="font-mono text-[10px] text-tx-3">{node.sub}</p>
                </div>
                {index < nodes.length - 1 ? (
                  <ArrowRight className="h-4 w-4 rotate-90 text-tx-3 lg:rotate-0" aria-hidden />
                ) : null}
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* Modules */}
      <section id="modules" className="mx-auto max-w-6xl px-4 py-24 sm:px-6">
        <SectionHeading
          eyebrow="Security Modules"
          title="Eight modules, honest statuses"
          text="Statuses reflect the actual implementation: RAG and agent modules currently assess bundled synthetic environments."
        />
        <div className="mt-12 grid gap-4 sm:grid-cols-2">
          {MODULES.map((module) => (
            <div key={module.name} className="card flex items-start justify-between gap-4 p-5">
              <div>
                <p className="font-mono text-sm font-medium text-tx-1">{module.name}</p>
                <p className="mt-1 text-xs leading-relaxed text-tx-3">{module.text}</p>
              </div>
              <div className="flex shrink-0 flex-col items-end gap-1.5">
                <span className={`chip ${module.statusTone}`}>{module.status}</span>
                <span className="font-mono text-[11px] text-tx-3">{module.checks} checks</span>
              </div>
            </div>
          ))}
        </div>
      </section>

      {/* How it works */}
      <section className="border-y border-line bg-ink-900/40">
        <div className="mx-auto max-w-6xl px-4 py-24 sm:px-6">
          <SectionHeading eyebrow="Workflow" title="How an assessment runs" />
          <ol className="mx-auto mt-12 grid max-w-4xl gap-4 sm:grid-cols-2 lg:grid-cols-3">
            {STEPS.map((step, index) => (
              <li key={step.title} className="card p-5">
                <span className="font-mono text-xs text-violet-300">
                  {String(index + 1).padStart(2, "0")}
                </span>
                <h3 className="mt-2 text-sm font-semibold">{step.title}</h3>
                <p className="mt-1.5 text-xs leading-relaxed text-tx-3">{step.text}</p>
              </li>
            ))}
          </ol>
        </div>
      </section>

      {/* Reporting */}
      <section className="mx-auto max-w-6xl px-4 py-24 sm:px-6">
        <div className="grid items-center gap-10 lg:grid-cols-2">
          <div>
            <p className="chip border-violet-500/40 bg-violet-500/10 text-violet-300">
              Reporting
            </p>
            <h2 className="mt-4 text-3xl font-semibold tracking-tight">
              Reports you can hand to an engineering team
            </h2>
            <p className="mt-3 text-sm leading-relaxed text-tx-2">
              Machine-readable JSON (schema v1.0, validated before it is ever
              written) and severity-sorted Markdown with full evidence,
              reproduction steps, impact and remediation for every finding.
            </p>
            <ul className="mt-5 space-y-2.5">
              {[
                "Secrets redacted from every probe, response, and error",
                "Synthetic evidence explicitly labeled as synthetic",
                "Findings start as pending_review — humans confirm, not automation",
                "Deterministic check IDs for reproducible retesting",
              ].map((item) => (
                <li key={item} className="flex items-start gap-2 text-sm text-tx-2">
                  <CheckCircle2 className="mt-0.5 h-4 w-4 shrink-0 text-mint-300" aria-hidden />
                  {item}
                </li>
              ))}
            </ul>
          </div>
          <div className="card overflow-hidden">
            <div className="flex items-center gap-2 border-b border-line bg-ink-900 px-4 py-2.5">
              <FileCode2 className="h-3.5 w-3.5 text-tx-3" aria-hidden />
              <span className="font-mono text-xs text-tx-3">
                NTA-1a16d1e12fbe.json — real schema, synthetic demo target
              </span>
            </div>
            <pre className="overflow-x-auto p-4 font-mono text-[11px] leading-relaxed text-tx-2">
              {REPORT_SNIPPET}
            </pre>
          </div>
        </div>
      </section>

      {/* Responsible testing */}
      <section className="border-y border-line bg-ink-900/40">
        <div className="mx-auto max-w-6xl px-4 py-24 sm:px-6">
          <SectionHeading
            eyebrow="Responsible Testing"
            title="Safe by default, by design"
          />
          <div className="mt-12 grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
            {[
              { icon: ShieldCheck, title: "Explicit authorization", text: "Network mode requires the target to be marked authorized AND per-run consent. Offline mock mode is the default." },
              { icon: Lock, title: "Controlled assessments", text: "DNS-validated, IP- and origin-pinned transport; TLS verification; redirects refused; proxies disabled." },
              { icon: GitBranch, title: "Request limits", text: "Hard request budgets, bounded timeouts, and response-size limits on every outbound call." },
              { icon: Database, title: "Synthetic testing", text: "All bundled fixtures use clearly-labeled synthetic secrets and records. No real customer data, ever." },
              { icon: ScrollText, title: "Evidence-based reporting", text: "Findings require attributable evidence. Heuristic observations are capped at 'inconclusive'." },
              { icon: Eye, title: "Detection, not exploitation", text: "No destructive actions: attempted tool calls are parsed as evidence and never executed." },
            ].map(({ icon: Icon, title, text }) => (
              <div key={title} className="card p-5">
                <Icon className="h-5 w-5 text-mint-300" aria-hidden />
                <h3 className="mt-3 text-sm font-semibold">{title}</h3>
                <p className="mt-1.5 text-xs leading-relaxed text-tx-3">{text}</p>
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* Roadmap */}
      <section id="roadmap" className="mx-auto max-w-4xl px-4 py-24 sm:px-6">
        <SectionHeading eyebrow="Roadmap" title="Where the project stands" />
        <ul className="mt-12 space-y-3">
          {ROADMAP.map((item) => (
            <li key={item.phase} className="card flex items-center justify-between gap-4 px-5 py-4">
              <div className="flex items-center gap-3">
                <span
                  className={`h-2 w-2 shrink-0 rounded-full ${
                    item.done ? "bg-emerald-400" : "bg-amber-400"
                  }`}
                />
                <p className="text-sm text-tx-1">{item.phase}</p>
              </div>
              <span className="shrink-0 text-xs text-tx-3">{item.status}</span>
            </li>
          ))}
        </ul>
      </section>

      {/* CTA */}
      <section className="relative overflow-hidden border-t border-line">
        <div className="hero-glow absolute inset-0" aria-hidden />
        <div className="relative mx-auto max-w-3xl px-4 py-20 text-center sm:px-6">
          <h2 className="text-3xl font-semibold tracking-tight">
            Assess your first AI target in minutes
          </h2>
          <p className="mt-3 text-sm text-tx-2">
            The bundled synthetic environment needs no credentials and no
            network access.
          </p>
          <Link to="/app" className="btn-primary mt-6 px-6 py-2.5 text-base">
            Launch Dashboard <ArrowRight className="h-4 w-4" aria-hidden />
          </Link>
        </div>
      </section>

      {/* Footer */}
      <footer className="border-t border-line bg-ink-900/60">
        <div className="mx-auto flex max-w-6xl flex-col items-center justify-between gap-6 px-4 py-10 sm:px-6 md:flex-row">
          <div>
            <Logo />
            <p className="mt-2 max-w-xs text-xs leading-relaxed text-tx-3">
              Evidence-first security assessment for LLM applications and AI
              agents. Only assess systems you are authorized to test.
            </p>
          </div>
          <nav className="grid grid-cols-2 gap-x-12 gap-y-2 text-sm sm:grid-cols-3">
            <a href="/api/docs" className="text-tx-2 hover:text-tx-1">API Documentation</a>
            <a href="#modules" className="text-tx-2 hover:text-tx-1">Security Modules</a>
            <a href="#roadmap" className="text-tx-2 hover:text-tx-1">Roadmap</a>
            <Link to="/app" className="text-tx-2 hover:text-tx-1">Dashboard</Link>
            <span className="text-tx-3">MIT License</span>
            {GITHUB_URL ? (
              <a href={GITHUB_URL} className="text-tx-2 hover:text-tx-1">GitHub</a>
            ) : (
              <span className="text-tx-3">Contributions welcome</span>
            )}
          </nav>
        </div>
        <div className="border-t border-line py-4 text-center text-xs text-tx-3">
          NullTrace AI · a defensive security testing framework · no public
          scanning, no real customer data
        </div>
      </footer>
    </div>
  );
}
