"use client";

import Link from "next/link";
import { useParams } from "next/navigation";
import { ConfidenceTag, SeverityBadge } from "@/components/SeverityBadge";
import { useI18n } from "@/i18n/I18nProvider";
import type { StageState } from "@/lib/types";
import { useScanEvents } from "@/lib/useScanEvents";

const STATUS_COLOR: Record<string, string> = {
  running: "bg-sky-900 text-sky-300",
  completed: "bg-emerald-900 text-emerald-300",
  failed: "bg-rose-900 text-rose-300",
  cancelled: "bg-white/[0.05] text-ink-muted",
  pending: "bg-white/[0.05] text-ink-muted",
  paused: "bg-amber-900 text-amber-300",
};

function StageRow({ stage }: { stage: StageState }) {
  const pct = stage.total > 0 ? Math.round((stage.done / stage.total) * 100) : 0;
  const dot =
    stage.status === "done"
      ? "bg-emerald-400"
      : stage.status === "running"
        ? "bg-sky-400 animate-pulse"
        : stage.status === "failed"
          ? "bg-rose-400"
          : stage.status === "skipped"
            ? "bg-white/25"
            : "bg-white/15";
  return (
    <li className="flex items-center gap-3 py-2">
      <span className={"h-2.5 w-2.5 shrink-0 rounded-full " + dot} />
      <span className="w-32 shrink-0 text-sm">{stage.name}</span>
      <div className="h-1.5 flex-1 overflow-hidden rounded-full bg-white/[0.05]">
        <div
          className="h-full bg-brand-gradient transition-all"
          style={{ width: `${stage.status === "done" ? 100 : pct}%` }}
        />
      </div>
      <span className="w-24 shrink-0 text-end text-xs text-ink-muted">
        {stage.status === "running" || stage.done > 0
          ? `${stage.done}/${stage.total}`
          : stage.status}
      </span>
    </li>
  );
}

export default function LiveScanView() {
  const { t, locale } = useI18n();
  const params = useParams<{ id: string }>();
  const scanId = params.id;
  const { snapshot, findings, connected, error } = useScanEvents(scanId);

  return (
    <div className="mx-auto max-w-4xl space-y-6">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div>
          <h1 className="text-2xl font-semibold">{t("scan.title")}</h1>
          <p className="font-mono text-xs text-ink-muted">{scanId}</p>
        </div>
        <div className="flex items-center gap-2">
          {snapshot && (
            <span
              className={
                "rounded px-2 py-1 text-xs font-medium " +
                (STATUS_COLOR[snapshot.status] ?? "bg-white/[0.05] text-ink")
              }
            >
              {snapshot.status}
            </span>
          )}
          <span
            className={
              "flex items-center gap-1 text-xs " +
              (connected ? "text-emerald-400" : "text-amber-400")
            }
          >
            <span
              className={
                "h-2 w-2 rounded-full " + (connected ? "bg-emerald-400" : "bg-amber-400")
              }
            />
            {connected ? t("scan.live") : t("scan.reconnecting")}
          </span>
        </div>
      </div>

      {error && (
        <div className="rounded-md border border-amber-900 bg-amber-950 p-3 text-xs text-amber-300">
          {error}
        </div>
      )}

      {/* Counters */}
      {snapshot && (
        <div className="grid grid-cols-2 gap-3 sm:grid-cols-4">
          {Object.entries(snapshot.counts).map(([k, v]) => (
            <div key={k} className="rounded-lg border border-line p-3">
              <div className="text-2xl font-semibold tabular-nums">{v}</div>
              <div className="text-xs capitalize text-ink-muted">{k.replace(/_/g, " ")}</div>
            </div>
          ))}
        </div>
      )}

      <div className="grid gap-6 md:grid-cols-2">
        {/* Stage stepper */}
        <section className="rounded-lg border border-line p-4">
          <h2 className="mb-2 text-sm font-medium text-ink">{t("scan.stages")}</h2>
          <ul className="divide-y divide-line">
            {(snapshot?.stages ?? []).map((s) => (
              <StageRow key={s.name} stage={s} />
            ))}
          </ul>
        </section>

        {/* Findings feed */}
        <section className="rounded-lg border border-line p-4">
          <div className="mb-2 flex items-center justify-between">
            <h2 className="text-sm font-medium text-ink">{t("scan.findings")}</h2>
            <div className="flex gap-3">
              <Link
                href={`/${locale}/scans/${scanId}/findings`}
                className="text-xs text-ink-muted underline hover:text-ink"
              >
                {t("scan.viewFindings")}
              </Link>
              <Link
                href={`/${locale}/scans/${scanId}/report`}
                className="text-xs text-ink-muted underline hover:text-ink"
              >
                {t("scan.viewReport")}
              </Link>
            </div>
          </div>
          {findings.length === 0 ? (
            <p className="text-xs text-ink-muted">{t("scan.noFindings")}</p>
          ) : (
            <ul className="space-y-2">
              {findings.map((f) => (
                <li
                  key={f.id}
                  className="flex items-center gap-2 rounded-md border border-line p-2"
                >
                  <SeverityBadge severity={f.severity} />
                  <span className="flex-1 truncate text-sm">{f.title}</span>
                  <ConfidenceTag confidence={f.confidence} />
                </li>
              ))}
            </ul>
          )}
        </section>
      </div>
    </div>
  );
}
