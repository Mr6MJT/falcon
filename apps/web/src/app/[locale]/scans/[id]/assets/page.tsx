"use client";

import Link from "next/link";
import { useParams } from "next/navigation";
import { useCallback, useEffect, useState } from "react";
import { useI18n } from "@/i18n/I18nProvider";
import { api, type AssetPage } from "@/lib/api";

const KINDS = [
  "subdomains",
  "dns",
  "http_endpoints",
  "services",
  "tls",
  "technologies",
  "parameters",
  "secrets",
] as const;

type Kind = (typeof KINDS)[number];

export default function AssetsPage() {
  const { t, locale } = useI18n();
  const params = useParams<{ id: string }>();
  const scanId = params.id;
  const [kind, setKind] = useState<Kind>("subdomains");
  const [page, setPage] = useState<AssetPage | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);

  const load = useCallback((k: Kind) => {
    setLoading(true);
    setError(null);
    api
      .listAssets(scanId, k)
      .then(setPage)
      .catch((e: unknown) => setError(e instanceof Error ? e.message : String(e)))
      .finally(() => setLoading(false));
  }, [scanId]);

  useEffect(() => load(kind), [kind, load]);

  return (
    <div className="mx-auto max-w-5xl space-y-5">
      <div className="flex items-center justify-between">
        <h1 className="text-2xl font-semibold">{t("assets.title")}</h1>
        <Link href={`/${locale}/scans/${scanId}`} className="text-xs text-neutral-400 underline hover:text-neutral-200">
          ← {t("scan.title")}
        </Link>
      </div>

      <div className="flex flex-wrap gap-1.5">
        {KINDS.map((k) => (
          <button
            key={k}
            onClick={() => setKind(k)}
            className={
              "rounded-md px-3 py-1.5 text-xs " +
              (k === kind ? "bg-neutral-100 text-neutral-900" : "bg-neutral-900 text-neutral-400 hover:bg-neutral-800")
            }
          >
            {k.replace(/_/g, " ")}
          </button>
        ))}
      </div>

      {error && (
        <div className="rounded-md border border-amber-900 bg-amber-950 p-3 text-xs text-amber-300">
          {error}
        </div>
      )}

      {loading ? (
        <p className="text-sm text-neutral-500">…</p>
      ) : page && page.items.length > 0 ? (
        <div className="overflow-x-auto rounded-lg border border-neutral-800">
          <div className="border-b border-neutral-800 px-3 py-2 text-xs text-neutral-500">
            {page.total} {page.kind.replace(/_/g, " ")}
          </div>
          <table className="w-full text-sm">
            <thead>
              <tr className="text-start">
                {page.columns.map((c) => (
                  <th key={c} className="border-b border-neutral-900 px-3 py-2 text-start text-xs uppercase text-neutral-500">
                    {c.replace(/_/g, " ")}
                  </th>
                ))}
              </tr>
            </thead>
            <tbody>
              {page.items.map((row, i) => (
                <tr key={i} className="border-b border-neutral-900 hover:bg-neutral-900/50">
                  {page.columns.map((c) => (
                    <td key={c} className="px-3 py-1.5 font-mono text-xs">
                      {formatCell(row[c])}
                    </td>
                  ))}
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      ) : (
        <p className="text-sm text-neutral-500">{t("assets.empty")}</p>
      )}
    </div>
  );
}

function formatCell(v: unknown): string {
  if (v === null || v === undefined || v === "") return "—";
  if (typeof v === "boolean") return v ? "yes" : "no";
  return String(v);
}
