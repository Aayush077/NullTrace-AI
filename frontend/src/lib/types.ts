// API types mirroring the backend schema (schema_version 1.0).

export type Severity = "critical" | "high" | "medium" | "low" | "informational";
export type Confidence = "high" | "medium" | "low";
export type CheckStatus = "pass" | "fail" | "inconclusive" | "error" | "skipped";
export type ValidationStatus =
  | "pending_review"
  | "confirmed"
  | "rejected"
  | "needs_retesting";

export interface Evidence {
  probe: string;
  response: string;
  note: string;
  synthetic: boolean;
}

export interface Finding {
  finding_id: string;
  check_id: string;
  title: string;
  description: string;
  category: string;
  affected_component: string;
  severity: Severity;
  confidence: Confidence;
  evidence: Evidence[];
  reproduction_steps: string[];
  expected_behavior: string;
  actual_behavior: string;
  impact: string;
  remediation: string;
  references: string[];
  assessment_id: string;
  timestamp: string;
  validation_status: ValidationStatus;
  review_note?: string;
}

export interface CheckResult {
  check_id: string;
  module: string;
  title: string;
  status: CheckStatus;
  details: string;
  objective?: string;
  evidence: Evidence[];
  error: string;
  executed_at: string;
  finding_ids: string[];
}

export interface ReportSummary {
  checks_executed: number;
  status_counts: Record<CheckStatus, number>;
  findings_total: number;
  findings_by_severity: Record<Severity, number>;
}

export interface Report {
  schema_version: string;
  project: string;
  project_version: string;
  assessment_id: string;
  target: string;
  mode: string;
  scope: string;
  profile: string;
  modules_executed: string[];
  started_at: string;
  completed_at: string;
  assessment_status: string;
  synthetic_target: boolean;
  requests_used: number;
  request_limit: number | null;
  summary: ReportSummary;
  results: CheckResult[];
  findings: Finding[];
  notes: string[];
  limitations: string[];
  config: Record<string, unknown>;
}

export interface AssessmentRecord {
  id: string;
  target_ref: string;
  target_name: string;
  mode: string;
  profile: string;
  modules: string[];
  status: string;
  created_at: string;
  completed_at: string | null;
  error: string;
  provider_label?: string;
  model_label?: string;
  security_profile?: string;
  variant?: string;
  summary?: ReportSummary | null;
  report?: Report | null;
}

export interface Target {
  id: number | string;
  name: string;
  type: string;
  base_url: string | null;
  model: string | null;
  api_key_env: string | null;
  timeout: number | null;
  max_requests: number | null;
  allow_network: boolean;
  builtin: boolean;
  description: string;
  provider_label?: string;
  security_profile?: string;
  environment?: string;
}

export interface DemoTarget {
  id: string;
  display_name: string;
  category: string;
  description: string;
  provider_label: string;
  model_label: string;
  environment: string;
  security_profile: "secure_baseline" | "intentionally_vulnerable";
  capabilities: string[];
  supported_modules: string[];
  seeded_weaknesses: string[];
  seeded_weakness_count: number;
  complexity: string;
  architecture: string;
  synthetic_data: string;
  limitations: string[];
  simulated: boolean;
}

export interface ModuleCheckInfo {
  check_id: string;
  title: string;
  description: string;
  required_capability: string | null;
}

export interface ModuleInfo {
  name: string;
  check_count: number;
  implemented: boolean;
  checks: ModuleCheckInfo[];
  profiles: string[];
}

export interface DashboardSummary {
  assessments_total: number;
  assessments_by_status: Record<string, number>;
  findings_total: number;
  findings_by_severity: Record<string, number>;
  findings_by_validation: Record<string, number>;
  checks_by_status: Record<CheckStatus, number>;
  recent_assessments: AssessmentRecord[];
  recent_findings: Finding[];
}

export interface AnalyticsHistoryPoint {
  assessment_id: string;
  created_at: string;
  status: string;
  target_name: string;
  checks_executed: number;
  findings_total: number;
  status_counts: Partial<Record<CheckStatus, number>>;
}

export interface DashboardAnalytics {
  history: AnalyticsHistoryPoint[];
  module_coverage: Record<string, number>;
  findings_by_category: Record<string, number>;
  findings_by_confidence: Record<string, number>;
}
