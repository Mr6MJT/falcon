"use client";

import { useEffect, useState } from "react";
import { useI18n } from "@/i18n/I18nProvider";
import { api } from "@/lib/api";
import type { Program } from "@/lib/types";

export default function ProgramsPage() {
  const { t } = useI18n();
  const [programs, setPrograms] = useState<Program[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [name, setName] = useState("");
  const [platform, setPlatform] = useState("");
  const [url, setUrl] = useState("");
  const [scopeText, setScopeText] = useState("");
  const [outScopeText, setOutScopeText] = useState("");
  const [authorizedBy, setAuthorizedBy] = useState("");
  const [allowActive, setAllowActive] = useState(true);
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    api
      .listPrograms()
      .then(setPrograms)
      .catch((e: unknown) => setError(e instanceof Error ? e.message : String(e)));
  }, []);

  // A name + at least one in-scope line is required. The server parses the scope syntax
  // (*.d / exact d / *end.api.d) and the out-of-scope list into rules it then enforces.
  const canCreate = Boolean(name.trim() && scopeText.trim());

  async function create(e: React.FormEvent) {
    e.preventDefault();
    if (!canCreate) return;
    setBusy(true);
    setError(null);
    try {
      const created = await api.createProgram({
        name,
        platform: platform || null,
        program_url: url || null,
        scope_text: scopeText,
        out_of_scope_text: outScopeText,
        authorization: {
          authorized_by: authorizedBy.trim() || "Operator (self-authorized)",
          authorization_type: "bug_bounty",
          expires_in_days: 90,
          allows_active_testing: allowActive,
          allows_automated_tools: true,
        },
      });
      setPrograms((p) => [created, ...p]);
      setName("");
      setPlatform("");
      setUrl("");
      setScopeText("");
      setOutScopeText("");
      setAuthorizedBy("");
      setAllowActive(true);
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(false);
    }
  }

  const field =
    "w-full rounded-md border border-neutral-800 bg-neutral-900 px-3 py-2 text-sm";

  return (
    <div className="mx-auto max-w-3xl space-y-6">
      <h1 className="text-2xl font-semibold">{t("programs.title")}</h1>

      <form onSubmit={create} className="space-y-3 rounded-lg border border-neutral-800 p-4">
        <div className="text-sm font-medium">{t("programs.new")}</div>
        <input value={name} onChange={(e) => setName(e.target.value)}
               placeholder={t("programs.name")} className={field} />
        <div className="grid gap-3 sm:grid-cols-2">
          <input value={platform} onChange={(e) => setPlatform(e.target.value)}
                 placeholder={t("programs.platform")} className={field} />
          <input value={url} onChange={(e) => setUrl(e.target.value)}
                 placeholder={t("programs.url")} className={field} />
        </div>

        <label className="block text-sm">
          <span className="text-neutral-300">{t("programs.scope")}</span>
          <textarea value={scopeText} onChange={(e) => setScopeText(e.target.value)} rows={4}
                    placeholder={"*.deriv.ae\nderiv.exchange\n*end.api.deriv.com"}
                    className={`${field} font-mono`} />
          <span className="text-xs text-neutral-500">{t("programs.scopeHint")}</span>
        </label>

        <label className="block text-sm">
          <span className="text-neutral-300">{t("programs.outScope")}</span>
          <textarea value={outScopeText} onChange={(e) => setOutScopeText(e.target.value)} rows={2}
                    placeholder={"admin.deriv.ae\ninternal.deriv.ae"}
                    className={`${field} font-mono`} />
        </label>

        <div className="rounded-md border border-neutral-800 p-3">
          <div className="text-xs font-medium text-neutral-300">{t("programs.authTitle")}</div>
          <input value={authorizedBy} onChange={(e) => setAuthorizedBy(e.target.value)}
                 placeholder={t("programs.authorizedBy")} className={`${field} mt-2`} />
          <label className="mt-2 flex items-center gap-2 text-sm">
            <input type="checkbox" checked={allowActive}
                   onChange={(e) => setAllowActive(e.target.checked)} />
            <span>{t("programs.allowActive")}</span>
          </label>
          <p className="mt-1 text-xs text-neutral-500">{t("programs.authHint")}</p>
        </div>

        <button type="submit" disabled={busy || !canCreate}
                className="rounded-md bg-neutral-100 px-4 py-2 text-sm font-medium text-neutral-900 disabled:opacity-40">
          {t("programs.create")}
        </button>
        {!canCreate && (
          <p className="text-xs text-amber-400">{t("programs.requiredHint")}</p>
        )}
      </form>

      {error && (
        <div className="rounded-md border border-amber-900 bg-amber-950 p-3 text-xs text-amber-300">
          {error}
        </div>
      )}

      {programs.length === 0 ? (
        <p className="text-sm text-neutral-500">{t("programs.empty")}</p>
      ) : (
        <ul className="divide-y divide-neutral-800 rounded-lg border border-neutral-800">
          {programs.map((p) => (
            <li key={p.id} className="flex items-center justify-between gap-3 p-3">
              <div className="min-w-0">
                <div className="text-sm font-medium">{p.name}</div>
                <div className="text-xs text-neutral-500">{p.platform || "—"}</div>
              </div>
              <span
                className={
                  "shrink-0 rounded px-2 py-0.5 text-[10px] uppercase " +
                  (p.allows_active_testing
                    ? "bg-emerald-950 text-emerald-300"
                    : "bg-neutral-800 text-neutral-400")
                }
              >
                {p.allows_active_testing ? t("programs.activeOn") : t("programs.activeOff")}
              </span>
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}
