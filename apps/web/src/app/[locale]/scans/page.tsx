"use client";

import Link from "next/link";
import { useEffect, useState } from "react";
import { useI18n } from "@/i18n/I18nProvider";
import { api, type ScanListItem } from "@/lib/api";

const STATUS_COLOR: Record<string, string> = {
  running: "bg-sky-900 text-sky-300",
  completed: "bg-emerald-900 text-emerald-300",
  failed: "bg-rose-900 text-rose-300",
  cancelled: "bg-white/[0.05] text-ink-muted",
  pending: "bg-white/[0.05] text-ink-muted",
  paused: "bg-amber-900 text-amber-300",
};

export default function ScansPage() {
  const { t, locale } = useI18n();
  const [scans, setScans] = useState<ScanListItem[]>([]);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    api
      .listScans()
      .then((p) => setScans(p.items))
      .catch((e: unknown) => setError(e instanceof Error ? e.message : String(e)));
  }, []);

  return (
    <div className="mx-auto max-w-4xl space-y-6">
      <h1 className="text-2xl font-semibold">{t("scans.title")}</h1>

      {error && (
        <div className="rounded-md border border-amber-900 bg-amber-950 p-3 text-xs text-amber-300">
          {error}
        </div>
      )}

      {scans.length === 0 ? (
        <p className="text-sm text-ink-muted">{t("scans.empty")}</p>
      ) : (
        <ul className="divide-y divide-line rounded-lg border border-line">
          {scans.map((sc) => (
            <li key={sc.id} className="flex items-center gap-3 p-3">
              <span
                className={
                  "shrink-0 rounded px-2 py-0.5 text-[10px] uppercase " +
                  (STATUS_COLOR[sc.status] ?? "bg-white/[0.05] text-ink")
                }
              >
                {sc.status}
              </span>
              <div className="min-w-0 flex-1">
                <div className="truncate text-sm font-medium">
                  {sc.program || "—"}{" "}
                  <span className="text-ink-muted">
                    · {sc.seeds.join(", ") || "no seeds"}
                  </span>
                </div>
                <div className="font-mono text-xs text-ink-faint">
                  {sc.id.slice(0, 8)} · {sc.aggressiveness}
                  {sc.created_at ? ` · ${sc.created_at.slice(0, 19).replace("T", " ")}` : ""}
                </div>
              </div>
              <span className="shrink-0 text-xs text-ink-muted">
                {sc.findings} {t("scans.findings")}
              </span>
              <div className="flex shrink-0 gap-2 text-xs">
                <Link href={`/${locale}/scans/${sc.id}`} className="text-ink-muted underline hover:text-ink">
                  {t("scans.view")}
                </Link>
                <Link href={`/${locale}/scans/${sc.id}/assets`} className="text-ink-muted underline hover:text-ink">
                  {t("assets.title")}
                </Link>
              </div>
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}
