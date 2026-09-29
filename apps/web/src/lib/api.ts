// Thin typed API client. Token handling is intentionally simple for slice 6 (kept in
// memory / localStorage); real login flow lands with the auth UI. Never puts the token in
// a URL — it always goes in the Authorization header.

import type {
  Finding,
  FindingsPage,
  FindingStatus,
  Program,
  ScanSnapshot,
} from "./types";

const BASE = process.env.NEXT_PUBLIC_API_BASE || "http://localhost:8000";

let authToken: string | null = null;
export function setToken(t: string | null) {
  authToken = t;
  if (typeof window !== "undefined") {
    try {
      if (t) window.localStorage.setItem("orvex_token", t);
      else window.localStorage.removeItem("orvex_token");
    } catch {
      /* storage may be unavailable; in-memory token still works */
    }
  }
}
export function getToken(): string | null {
  if (authToken) return authToken;
  if (typeof window !== "undefined") {
    try {
      authToken = window.localStorage.getItem("orvex_token");
    } catch {
      /* ignore */
    }
  }
  return authToken;
}

async function req<T>(path: string, init?: RequestInit): Promise<T> {
  const headers = new Headers(init?.headers);
  headers.set("content-type", "application/json");
  const token = getToken();
  if (token) headers.set("authorization", `Bearer ${token}`);
  const res = await fetch(`${BASE}${path}`, { ...init, headers });
  if (!res.ok) {
    const body = await res.text().catch(() => "");
    throw new Error(`${res.status} ${res.statusText}: ${body}`);
  }
  return (await res.json()) as T;
}

export interface ScopeRuleInput {
  kind: "domain" | "wildcard" | "ip" | "cidr" | "url";
  action: "include" | "exclude";
  value: string;
}

export interface CreateProgramRequest {
  name: string;
  platform?: string | null;
  program_url?: string | null;
  scope_rules?: ScopeRuleInput[];
  scope_text?: string;
  out_of_scope_text?: string;
  authorization?: {
    authorized_by: string;
    authorization_type?: string;
    expires_in_days?: number;
    allows_active_testing?: boolean;
    allows_automated_tools?: boolean;
  };
}

export interface ScanListItem {
  id: string;
  program?: string | null;
  status: string;
  aggressiveness: string;
  seeds: string[];
  created_at?: string | null;
  finished_at?: string | null;
  findings: number;
}

export interface AssetPage {
  kind: string;
  columns: string[];
  items: Record<string, unknown>[];
  total: number;
}

export interface CreateScanRequest {
  program_id: string;
  seeds: string[];
  aggressiveness: string;
  active_probes: boolean;
  fuzzing: boolean;
}

export interface CreateScanResponse {
  scan_id: string;
  status: string;
  scope_snapshot_hash: string;
}

export const api = {
  login: async (email: string, password: string) => {
    const res = await req<{ token: string; role: string; org_id: string }>("/auth/login", {
      method: "POST",
      body: JSON.stringify({ email, password }),
    });
    setToken(res.token);
    return res;
  },
  listPrograms: () => req<Program[]>("/programs"),
  createProgram: (p: CreateProgramRequest) =>
    req<Program>("/programs", { method: "POST", body: JSON.stringify(p) }),
  createScan: (body: CreateScanRequest) =>
    req<CreateScanResponse>("/scans", { method: "POST", body: JSON.stringify(body) }),
  scanState: (scanId: string) => req<ScanSnapshot>(`/scans/${scanId}/state`),
  listScans: () => req<{ items: ScanListItem[]; total: number }>("/scans"),
  listAssets: (scanId: string, kind: string, limit = 500) =>
    req<AssetPage>(`/scans/${scanId}/assets/${kind}?limit=${limit}`),
  listFindings: (scanId: string, filters: Record<string, string> = {}) => {
    const qs = new URLSearchParams(filters).toString();
    return req<FindingsPage>(`/scans/${scanId}/findings${qs ? `?${qs}` : ""}`);
  },
  triageFinding: (findingId: string, status: FindingStatus) =>
    req<Finding>(`/findings/${findingId}`, {
      method: "PATCH",
      body: JSON.stringify({ status }),
    }),
  getReport: (scanId: string) =>
    req<Record<string, unknown>>(`/scans/${scanId}/report`),
};

// Download an export (html/pdf/json) with the auth header, then save via a blob.
export async function downloadReport(scanId: string, fmt: "html" | "pdf" | "json") {
  const headers = new Headers();
  const token = getToken();
  if (token) headers.set("authorization", `Bearer ${token}`);
  const res = await fetch(`${BASE}/scans/${scanId}/report.${fmt}`, { headers });
  if (!res.ok) throw new Error(`${res.status} ${res.statusText}`);
  const blob = await res.blob();
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = `orvex-${scanId}.${fmt}`;
  document.body.appendChild(a);
  a.click();
  a.remove();
  URL.revokeObjectURL(url);
}

// WebSocket URL for live scan events (token passed via subprotocol, not the query string).
export function scanEventsUrl(scanId: string): string {
  return `${BASE.replace(/^http/, "ws")}/scans/${scanId}/events`;
}
