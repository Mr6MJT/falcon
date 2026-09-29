import type { Severity } from "@/lib/types";

// The severity scale is the only strong color in the UI.
const STYLES: Record<Severity, string> = {
  info: "bg-sev-info/20 text-sev-info",
  low: "bg-sev-low/20 text-sev-low",
  medium: "bg-sev-medium/20 text-sev-medium",
  high: "bg-sev-high/20 text-sev-high",
  critical: "bg-sev-critical/25 text-sev-critical",
};

export function SeverityBadge({ severity }: { severity: Severity }) {
  return (
    <span
      className={
        "inline-block rounded px-2 py-0.5 text-xs font-semibold uppercase " +
        (STYLES[severity] ?? STYLES.info)
      }
    >
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
          ? "border border-dashed border-neutral-600 text-neutral-400"
          : "bg-neutral-800 text-neutral-300")
      }
    >
      {confidence}
    </span>
  );
}
