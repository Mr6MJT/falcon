"use client";

import { useParams } from "next/navigation";
import { useEffect, useState } from "react";
import { useI18n } from "@/i18n/I18nProvider";
import { api, downloadReport } from "@/lib/api";

const SEV_ORDER = ["critical", "high", "medium", "low", "info"] as const;
const SEV_COLOR: Record<string, string> = {
  critical: "#dc2626", high: "#f97316", medium: "#f59e0b", low: "#0ea5e9", info: "#64748b",
};

type Report = {
  scan: { program?: string; status?: string; scope_snapshot_hash?: string };
  summary: {
    findings_total: number;
    by_severity: Record<string, number>;
    by_confidence: Record<string, number>;
    assets: Record<string, number>;
  };
};

export default function ReportPage() {
  const { t } = useI18n();
  const params = useParams<{ id: string }>();
  const scanId = params.id;
  const [rep, setRep] = useState<Report | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    api
      .getReport(scanId)
      .then((r) => setRep(r as unknown as Report))
      .catch((e: unknown) => setError(e instanceof Error ? e.message : String(e)));
  }, [scanId]);

  async function dl(fmt: "html" | "pdf" | "json") {
    try {
      await downloadReport(scanId, fmt);
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : String(e));
    }
  }

  return (
    <div className="mx-auto max-w-4xl space-y-6">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <h1 className="text-2xl font-semibold">{t("report.title")}</h1>
        <div className="flex gap-2">
          <button onClick={() => dl("pdf")} className="rounded-md bg-brand-gradient px-3 py-1.5 text-sm font-medium text-surface-sunken">
            PDF
          </button>
          <button onClick={() => dl("html")} className="rounded-md border border-line-strong px-3 py-1.5 text-sm">
            HTML
          </button>
          <button onClick={() => dl("json")} className="rounded-md border border-line-strong px-3 py-1.5 text-sm">
            JSON
          </button>
        </div>
      </div>

      {error && (
        <div className="rounded-md border border-amber-900 bg-amber-950 p-3 text-xs text-amber-300">
          {error}
        </div>
      )}

      {rep && (
        <>
          <div className="text-sm text-ink-muted">
            {rep.scan.program} · {rep.scan.status} ·{" "}
            <span className="font-mono text-xs">{rep.scan.scope_snapshot_hash?.slice(0, 16)}…</span>
          </div>

          <section>
            <h2 className="mb-2 text-sm font-medium text-ink">{t("report.bySeverity")}</h2>
            <div className="grid grid-cols-5 gap-2">
              {SEV_ORDER.map((s) => (
                <div key={s} className="rounded-lg border border-line p-3 text-center">
                  <div className="text-2xl font-semibold" style={{ color: SEV_COLOR[s] }}>
                    {rep.summary.by_severity[s] ?? 0}
                  </div>
                  <div className="text-xs uppercase text-ink-muted">{s}</div>
                </div>
              ))}
            </div>
          </section>

          <section>
            <h2 className="mb-2 text-sm font-medium text-ink">{t("report.byConfidence")}</h2>
            <div className="grid grid-cols-3 gap-2">
              {(["confirmed", "candidate", "informational"] as const).map((c) => (
                <div key={c} className="rounded-lg border border-line p-3 text-center">
                  <div className="text-2xl font-semibold tabular-nums">
                    {rep.summary.by_confidence[c] ?? 0}
                  </div>
                  <div className="text-xs uppercase text-ink-muted">{c}</div>
                </div>
              ))}
            </div>
          </section>

          <section>
            <h2 className="mb-2 text-sm font-medium text-ink">{t("report.assets")}</h2>
            <div className="grid grid-cols-3 gap-2 sm:grid-cols-4">
              {Object.entries(rep.summary.assets).map(([k, v]) => (
                <div key={k} className="rounded-lg border border-line p-3">
                  <div className="text-xl font-semibold tabular-nums">{v}</div>
                  <div className="text-xs capitalize text-ink-muted">{k.replace(/_/g, " ")}</div>
                </div>
              ))}
            </div>
          </section>
        </>
      )}
    </div>
  );
}
