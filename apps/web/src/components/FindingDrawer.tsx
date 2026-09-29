"use client";

import { ConfidenceTag, SeverityBadge } from "@/components/SeverityBadge";
import { useI18n } from "@/i18n/I18nProvider";
import type { Finding, FindingStatus } from "@/lib/types";

const STATUSES: FindingStatus[] = [
  "new",
  "triaging",
  "confirmed",
  "false_positive",
  "wont_fix",
  "reported",
  "resolved",
];

function Evidence({ label, value }: { label: string; value: unknown }) {
  if (value == null || value === "") return null;
  const text = typeof value === "string" ? value : JSON.stringify(value, null, 2);
  return (
    <div>
      <div className="mb-1 text-xs font-medium text-neutral-400">{label}</div>
      <pre className="max-h-60 overflow-auto rounded-md border border-neutral-800 bg-neutral-950 p-3 text-xs">
        {text}
      </pre>
    </div>
  );
}

export function FindingDrawer({
  finding,
  onClose,
  onTriage,
}: {
  finding: Finding;
  onClose: () => void;
  onTriage: (status: FindingStatus) => void;
}) {
  const { t } = useI18n();
  const ev = finding.evidence || {};
  const isCandidate = finding.confidence === "candidate";
  return (
    <div className="fixed inset-0 z-50 flex" role="dialog" aria-modal="true">
      <button
        aria-label={t("common.close")}
        className="flex-1 bg-black/60"
        onClick={onClose}
      />
      <div className="flex h-full w-full max-w-xl flex-col gap-4 overflow-auto border-s border-neutral-800 bg-neutral-900 p-5">
        <div className="flex items-start justify-between gap-3">
          <div>
            <div className="flex items-center gap-2">
              <SeverityBadge severity={finding.severity} />
              <ConfidenceTag confidence={finding.confidence} />
            </div>
            <h2 className="mt-2 text-lg font-semibold">{finding.title}</h2>
            <div className="mt-1 font-mono text-xs text-neutral-500">{finding.type}</div>
          </div>
          <button
            onClick={onClose}
            className="rounded-md border border-neutral-700 px-3 py-1 text-sm"
          >
            {t("common.close")}
          </button>
        </div>

        {isCandidate && (
          <div className="rounded-md border border-dashed border-amber-700 bg-amber-950/40 p-2 text-xs text-amber-300">
            {t("findings.candidateNote")}
          </div>
        )}

        <div className="grid grid-cols-2 gap-2 text-sm">
          {finding.cve_id && (
            <div>
              <span className="text-neutral-500">CVE </span>
              {finding.cve_id}
            </div>
          )}
          {finding.cvss != null && (
            <div>
              <span className="text-neutral-500">CVSS </span>
              {finding.cvss}
            </div>
          )}
          {finding.cwe && (
            <div>
              <span className="text-neutral-500">CWE </span>
              {finding.cwe}
            </div>
          )}
        </div>

        {finding.target && <Evidence label={t("findings.target")} value={finding.target} />}

        <label className="text-sm">
          <span className="text-neutral-400">{t("findings.status")}</span>
          <select
            value={finding.status}
            onChange={(e) => onTriage(e.target.value as FindingStatus)}
            className="mt-1 w-full rounded-md border border-neutral-800 bg-neutral-950 px-3 py-2 text-sm"
          >
            {STATUSES.map((s) => (
              <option key={s} value={s}>
                {s}
              </option>
            ))}
          </select>
        </label>

        <div className="space-y-3">
          <div className="text-sm font-medium text-neutral-300">{t("findings.evidence")}</div>
          <Evidence label={t("findings.request")} value={ev["request"]} />
          <Evidence label={t("findings.response")} value={ev["response"]} />
          {/* Any remaining evidence keys */}
          <Evidence
            label="Detail"
            value={Object.fromEntries(
              Object.entries(ev).filter(([k]) => !["request", "response"].includes(k)),
            )}
          />
        </div>
      </div>
    </div>
  );
}
