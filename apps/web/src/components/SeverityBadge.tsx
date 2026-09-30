import type { Severity } from "@/lib/types";

// The severity scale is the loudest color in the UI — findings must read at a glance.
const STYLES: Record<Severity, string> = {
  info: "bg-sev-info/15 text-sev-info ring-sev-info/30",
  low: "bg-sev-low/15 text-sev-low ring-sev-low/30",
  medium: "bg-sev-medium/15 text-sev-medium ring-sev-medium/30",
  high: "bg-sev-high/15 text-sev-high ring-sev-high/30",
  critical: "bg-sev-critical/20 text-sev-critical ring-sev-critical/40",
};

export function SeverityBadge({ severity }: { severity: Severity }) {
  return (
    <span
      className={
        "inline-flex items-center gap-1 rounded-md px-2 py-0.5 text-[11px] font-semibold uppercase tracking-wide ring-1 ring-inset " +
        (STYLES[severity] ?? STYLES.info)
      }
    >
      <span className="h-1.5 w-1.5 rounded-full bg-current" />
      {severity}
    </span>
  );
}

export function ConfidenceTag({ confidence }: { confidence: string }) {
  // Candidates are rendered visually distinct (dashed) from confirmed findings.
  const isCandidate = confidence === "candidate";
  return (
    <span
      className={
        "rounded px-1.5 py-0.5 text-[10px] uppercase tracking-wide " +
        (isCandidate
          ? "border border-dashed border-line-strong text-ink-muted"
          : "bg-emerald-500/15 text-emerald-300 ring-1 ring-inset ring-emerald-500/30")
      }
    >
      {confidence}
    </span>
  );
}
