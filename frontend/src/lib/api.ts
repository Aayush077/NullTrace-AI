import type {
  AssessmentRecord,
  DashboardAnalytics,
  DashboardSummary,
  DemoTarget,
  Finding,
  ModuleInfo,
  Target,
  ValidationStatus,
} from "./types";

// The optional legacy shared token (X-API-Token) and the per-user login
// session token (X-Session-Token) are both kept in sessionStorage only
// (cleared when the tab closes). Target API keys are never handled here.
const TOKEN_KEY = "nulltrace.session.token";
const USER_TOKEN_KEY = "nulltrace.user.token";

function readStore(key: string): string {
  try {
    return sessionStorage.getItem(key) ?? "";
  } catch {
    return "";
  }
}

function writeStore(key: string, value: string): void {
  try {
    if (value) sessionStorage.setItem(key, value);
    else sessionStorage.removeItem(key);
  } catch {
    // Session storage unavailable; token applies for this page load only.
  }
}

export function getSessionToken(): string {
  return readStore(TOKEN_KEY);
}

export function setSessionToken(token: string): void {
  writeStore(TOKEN_KEY, token);
}

export function getUserToken(): string {
  return readStore(USER_TOKEN_KEY);
}

export function setUserToken(token: string): void {
  writeStore(USER_TOKEN_KEY, token);
}

export interface AuthStatus {
  setup_mode: boolean;
  authenticated: boolean;
  user: { username: string; role: string } | null;
}

export class ApiError extends Error {
  status: number;

  constructor(status: number, message: string) {
    super(message);
    this.status = status;
  }
}

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const headers: Record<string, string> = {
    ...(init?.headers as Record<string, string> | undefined),
  };

  if (init?.body) headers["Content-Type"] = "application/json";

  const token = getSessionToken();
  if (token) headers["X-API-Token"] = token;

  const userToken = getUserToken();
  if (userToken) headers["X-Session-Token"] = userToken;

  const response = await fetch(path, { ...init, headers });

  if (!response.ok) {
    let detail = `Request failed (${response.status})`;
    try {
      const data = (await response.json()) as { detail?: unknown };
      if (typeof data.detail === "string") detail = data.detail;
    } catch {
      // Non-JSON error body; keep the generic message.
    }
    throw new ApiError(response.status, detail);
  }

  if (response.status === 204) return undefined as T;

  return (await response.json()) as T;
}

export const api = {
  health: () => request<{ status: string }>("/api/health"),
  version: () => request<{ project: string; version: string }>("/api/version"),

  authStatus: () => request<AuthStatus>("/api/auth/status"),
  login: async (username: string, password: string) => {
    const result = await request<{
      token: string;
      role: string;
      username: string;
    }>("/api/auth/login", {
      method: "POST",
      body: JSON.stringify({ username, password }),
    });
    setUserToken(result.token);
    return result;
  },
  logout: async () => {
    try {
      await request<void>("/api/auth/logout", { method: "POST" });
    } finally {
      setUserToken("");
    }
  },

  modules: () => request<ModuleInfo[]>("/api/modules"),

  demoTargets: () => request<DemoTarget[]>("/api/demo-targets"),

  targets: () => request<Target[]>("/api/targets"),
  createTarget: (payload: {
    name: string;
    base_url: string;
    model: string;
    api_key_env: string;
    timeout: number;
    max_requests: number;
    allow_network: boolean;
  }) =>
    request<{ id: number }>("/api/targets", {
      method: "POST",
      body: JSON.stringify(payload),
    }),
  deleteTarget: (id: number) =>
    request<void>(`/api/targets/${id}`, { method: "DELETE" }),

  assessments: () => request<AssessmentRecord[]>("/api/assessments"),
  assessment: (id: string) => request<AssessmentRecord>(`/api/assessments/${id}`),
  createAssessment: (payload: {
    target_id: string;
    profile: string;
    modules?: string[] | null;
    max_requests?: number | null;
    timeout?: number | null;
    allow_network?: boolean;
    secure_variant?: boolean;
  }) =>
    request<AssessmentRecord>("/api/assessments", {
      method: "POST",
      body: JSON.stringify(payload),
    }),
  assessmentFindings: (id: string) =>
    request<Finding[]>(`/api/assessments/${id}/findings`),
  deleteAssessment: (id: string) =>
    request<void>(`/api/assessments/${id}`, { method: "DELETE" }),
  deleteAssessments: (ids: string[]) =>
    request<{
      deleted: string[];
      deleted_count: number;
      not_found: string[];
      skipped_running: string[];
    }>("/api/assessments/delete-batch", {
      method: "POST",
      body: JSON.stringify({ ids }),
    }),

  findings: (filters: Record<string, string | undefined> = {}) => {
    const params = new URLSearchParams();
    for (const [key, value] of Object.entries(filters)) {
      if (value) params.set(key, value);
    }
    const query = params.toString();
    return request<Finding[]>(`/api/findings${query ? `?${query}` : ""}`);
  },
  finding: (id: string) => request<Finding>(`/api/findings/${id}`),
  reviewFinding: (id: string, validation_status: ValidationStatus, note: string) =>
    request<Finding>(`/api/findings/${id}/review`, {
      method: "PATCH",
      body: JSON.stringify({ validation_status, note }),
    }),

  reportUrl: (assessmentId: string, format: "json" | "markdown") =>
    `/api/assessments/${assessmentId}/report?format=${format}`,

  downloadReport: async (assessmentId: string, format: "json" | "markdown") => {
    const token = getSessionToken();
    const response = await fetch(api.reportUrl(assessmentId, format), {
      headers: token ? { "X-API-Token": token } : undefined,
    });
    if (!response.ok) throw new ApiError(response.status, "Download failed.");
    const blob = await response.blob();
    const url = URL.createObjectURL(blob);
    const anchor = document.createElement("a");
    anchor.href = url;
    anchor.download = `${assessmentId}.${format === "json" ? "json" : "md"}`;
    anchor.click();
    URL.revokeObjectURL(url);
  },

  dashboardSummary: () => request<DashboardSummary>("/api/dashboard/summary"),
  dashboardAnalytics: () =>
    request<DashboardAnalytics>("/api/dashboard/analytics"),
};
