"use client";

import { useParams } from "next/navigation";
import { useCallback, useEffect, useMemo, useState } from "react";
import { FindingDrawer } from "@/components/FindingDrawer";
import { ConfidenceTag, SeverityBadge } from "@/components/SeverityBadge";
import { useI18n } from "@/i18n/I18nProvider";
import { api } from "@/lib/api";
import type { Finding, FindingStatus, Severity } from "@/lib/types";

const SEV_ORDER: Severity[] = ["critical", "high", "medium", "low", "info"];

export default function FindingsPage() {
  const { t } = useI18n();
  const params = useParams<{ id: string }>();
  const scanId = params.id;
  const [findings, setFindings] = useState<Finding[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [selected, setSelected] = useState<Finding | null>(null);
  const [confidenceFilter, setConfidenceFilter] = useState<string>("");

  const load = useCallback(() => {
    const filters: Record<string, string> = {};
    if (confidenceFilter) filters.confidence = confidenceFilter;
    api
      .listFindings(scanId, filters)
      .then((p) => setFindings(p.items))
      .catch((e: unknown) => setError(e instanceof Error ? e.message : String(e)));
  }, [scanId, confidenceFilter]);

  useEffect(() => load(), [load]);

  const grouped = useMemo(() => {
    const by: Record<string, Finding[]> = {};
    for (const f of findings) (by[f.severity] ??= []).push(f);
    return by;
  }, [findings]);

  async function triage(f: Finding, status: FindingStatus) {
    // optimistic update + persist
    setFindings((list) => list.map((x) => (x.id === f.id ? { ...x, status } : x)));
    setSelected((s) => (s && s.id === f.id ? { ...s, status } : s));
    try {
      await api.triageFinding(f.id, status);
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : String(e));
      load(); // reconcile on failure
    }
  }

  return (
    <div className="mx-auto max-w-4xl space-y-6">
      <div className="flex items-center justify-between">
        <h1 className="text-2xl font-semibold">{t("findings.title")}</h1>
        <select
          value={confidenceFilter}
          onChange={(e) => setConfidenceFilter(e.target.value)}
          className="rounded-md border border-line bg-white/[0.02] px-3 py-1.5 text-sm"
        >
          <option value="">{t("findings.all")}</option>
          <option value="confirmed">confirmed</option>
          <option value="candidate">candidate</option>
          <option value="informational">informational</option>
        </select>
      </div>

      {error && (
        <div className="rounded-md border border-amber-900 bg-amber-950 p-3 text-xs text-amber-300">
          {error}
        </div>
      )}

      {findings.length === 0 ? (
        <p className="text-sm text-ink-muted">{t("findings.empty")}</p>
      ) : (
        <div className="space-y-6">
          {SEV_ORDER.filter((s) => grouped[s]?.length).map((sev) => (
            <section key={sev}>
              <div className="mb-2 flex items-center gap-2">
                <SeverityBadge severity={sev} />
                <span className="text-xs text-ink-muted">{grouped[sev].length}</span>
              </div>
              <ul className="divide-y divide-line rounded-lg border border-line">
                {grouped[sev].map((f) => (
                  <li key={f.id}>
                    <button
                      onClick={() => setSelected(f)}
                      className="flex w-full items-center gap-3 p-3 text-start hover:bg-white/[0.04]"
                    >
                      <span className="flex-1 truncate text-sm">{f.title}</span>
                      {f.cve_id && (
                        <span className="font-mono text-xs text-ink-muted">{f.cve_id}</span>
                      )}
                      <ConfidenceTag confidence={f.confidence} />
                      <span className="w-24 shrink-0 text-end text-xs text-ink-muted">
                        {f.status}
                      </span>
                    </button>
                  </li>
                ))}
              </ul>
            </section>
          ))}
        </div>
      )}

      {selected && (
        <FindingDrawer
          finding={selected}
          onClose={() => setSelected(null)}
          onTriage={(status) => triage(selected, status)}
        />
      )}
    </div>
  );
}
