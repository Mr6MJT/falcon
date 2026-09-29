// Shapes mirrored from the backend (packages/core/models.py). Kept minimal for the UI.

export type Severity = "info" | "low" | "medium" | "high" | "critical";
export type Confidence = "informational" | "candidate" | "confirmed";
export type ScanStatus =
  | "pending"
  | "running"
  | "paused"
  | "cancelled"
  | "completed"
  | "failed";

export type FindingStatus =
  | "new"
  | "triaging"
  | "confirmed"
  | "false_positive"
  | "wont_fix"
  | "reported"
  | "resolved";

export interface Finding {
  id: string;
  type: string;
  title: string;
  severity: Severity;
  confidence: Confidence;
  status: FindingStatus;
  cvss?: number | null;
  cve_id?: string | null;
  cwe?: string | null;
  target?: string | null;
  evidence: Record<string, unknown>;
}

export interface FindingsPage {
  items: Finding[];
  total: number;
}

export interface Program {
  id: string;
  name: string;
  slug: string;
  platform?: string | null;
  program_url?: string | null;
  allows_active_testing?: boolean;
  scannable?: boolean;
  scope_rule_count?: number;
}

export type ScanEvent =
  | { type: "snapshot" }
  | { type: "stage.started"; stage: string }
  | { type: "stage.progress"; stage: string; done: number; total: number }
  | { type: "stage.done"; stage: string; stats?: Record<string, number> }
  | { type: "scan.status"; status: ScanStatus }
  | {
      type: "finding.created";
      finding_id: string;
      finding_type: string;
      severity: Severity;
      confidence: Confidence;
      title: string;
    }
  | { type: "ping" };

export interface StageState {
  name: string;
  status: string;
  done: number;
  total: number;
  error?: string | null;
}

export interface ScanSnapshot {
  type: "snapshot";
  scan_id: string;
  status: ScanStatus;
  aggressiveness: string;
  started_at?: string | null;
  finished_at?: string | null;
  stages: StageState[];
  counts: Record<string, number>;
  findings_by_severity: Record<string, number>;
}
