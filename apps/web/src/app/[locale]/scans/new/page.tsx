"use client";

import { useRouter } from "next/navigation";
import { useEffect, useMemo, useState } from "react";
import { AuthorizationGate } from "@/components/AuthorizationGate";
import { useI18n } from "@/i18n/I18nProvider";
import { api } from "@/lib/api";
import {
  type WizardState,
  canStart,
  emptyAttestation,
  stepValid,
} from "@/lib/authorization";
import type { Program } from "@/lib/types";

const STEP_KEYS = [
  "wizard.step.domains",
  "wizard.step.scope",
  "wizard.step.aggressiveness",
  "wizard.step.authorization",
] as const;

export default function NewScanWizard() {
  const { t, locale } = useI18n();
  const router = useRouter();
  const [step, setStep] = useState(0);
  const [domainText, setDomainText] = useState("");
  const [programs, setPrograms] = useState<Program[]>([]);
  const [programId, setProgramId] = useState("");
  const [submitError, setSubmitError] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState(false);
  const [state, setState] = useState<WizardState>({
    domains: [],
    scopeRules: [],
    aggressiveness: "safe",
    activeProbes: false,
    fuzzing: false,
    attestation: emptyAttestation(),
    allowsActiveTesting: false, // comes from the selected program's authz record
  });

  // Load programs; selecting one sets whether active testing is permitted (backend still
  // enforces this — the UI just reflects it so sharp toggles aren't offered when disallowed).
  useEffect(() => {
    api
      .listPrograms()
      .then(setPrograms)
      .catch(() => setPrograms([]));
  }, []);

  const onSelectProgram = (id: string) => {
    setProgramId(id);
    const p = programs.find((x) => x.id === id);
    setState((s) => ({ ...s, allowsActiveTesting: Boolean(p?.allows_active_testing) }));
  };

  // Keep domains + a derived default scope (wildcard per root) in sync with the textarea.
  const onDomains = (text: string) => {
    setDomainText(text);
    const domains = text
      .split(/\s|,|;/)
      .map((d) => d.trim().toLowerCase())
      .filter(Boolean);
    const scopeRules = domains.flatMap((d) => [
      { kind: "domain" as const, action: "include" as const, value: d },
      { kind: "wildcard" as const, action: "include" as const, value: `*.${d}` },
    ]);
    setState((s) => ({ ...s, domains, scopeRules }));
  };

  const selectedProgram = useMemo(
    () => programs.find((p) => p.id === programId) || null,
    [programs, programId],
  );
  const programOk = Boolean(selectedProgram?.scannable);
  const stepOk = useMemo(
    () => stepValid(state, step) && (step !== 0 || programOk),
    [state, step, programOk],
  );
  const startReady = useMemo(
    () => canStart(state) && programOk,
    [state, programOk],
  );
  const isLast = step === STEP_KEYS.length - 1;

  async function onStart() {
    if (!startReady || submitting) return;
    setSubmitting(true);
    setSubmitError(null);
    try {
      const res = await api.createScan({
        program_id: programId,
        seeds: state.domains,
        aggressiveness: state.aggressiveness,
        active_probes: state.activeProbes,
        fuzzing: state.fuzzing,
      });
      router.push(`/${locale}/scans/${res.scan_id}`);
    } catch (e: unknown) {
      setSubmitError(e instanceof Error ? e.message : String(e));
      setSubmitting(false);
    }
  }

  return (
    <div className="mx-auto max-w-2xl space-y-6">
      <h1 className="text-2xl font-semibold">{t("wizard.title")}</h1>

      {/* Step indicator */}
      <ol className="flex flex-wrap gap-2 text-xs">
        {STEP_KEYS.map((k, i) => (
          <li
            key={k}
            className={
              "rounded-full px-3 py-1 " +
              (i === step
                ? "bg-brand-gradient text-surface-sunken"
                : i < step
                  ? "bg-white/[0.05] text-ink"
                  : "bg-white/[0.02] text-ink-faint")
            }
          >
            {i + 1}. {t(k)}
          </li>
        ))}
      </ol>

      <div className="rounded-lg border border-line p-5">
        {step === 0 && (
          <div className="space-y-4">
            <label className="block text-sm">
              <span className="text-ink">{t("wizard.program")}</span>
              {programs.length === 0 ? (
                <p className="mt-1 text-xs text-amber-400">{t("wizard.program.none")}</p>
              ) : (
                <select
                  value={programId}
                  onChange={(e) => onSelectProgram(e.target.value)}
                  className="mt-1 w-full rounded-md border border-line bg-white/[0.02] px-3 py-2 text-sm"
                >
                  <option value="">{t("wizard.program.select")}</option>
                  {programs.map((p) => (
                    <option key={p.id} value={p.id}>
                      {p.name}
                      {p.scannable
                        ? p.allows_active_testing
                          ? " — active OK"
                          : " — passive only"
                        : " — ⚠ not authorized"}
                    </option>
                  ))}
                </select>
              )}
              {selectedProgram && !selectedProgram.scannable && (
                <p className="mt-1 text-xs text-amber-400">{t("wizard.program.notAuthorized")}</p>
              )}
            </label>
            <label className="block text-sm">
              <span className="text-ink">{t("wizard.domains.label")}</span>
              <textarea
              value={domainText}
              onChange={(e) => onDomains(e.target.value)}
              rows={5}
              placeholder={"example.com\napi.example.com"}
              className="mt-1 w-full rounded-md border border-line bg-white/[0.02] px-3 py-2 font-mono text-sm"
            />
              <p className="mt-2 text-xs text-ink-muted">{t("wizard.domains.help")}</p>
            </label>
          </div>
        )}

        {step === 1 && (
          <div className="space-y-3 text-sm">
            <p className="text-xs text-ink-muted">{t("wizard.scope.help")}</p>
            <ul className="space-y-1">
              {state.scopeRules.map((r, i) => (
                <li
                  key={`${r.value}-${i}`}
                  className="flex items-center justify-between rounded-md border border-line px-3 py-2"
                >
                  <span className="font-mono text-xs">{r.value}</span>
                  <span
                    className={
                      "text-xs " +
                      (r.action === "include" ? "text-emerald-400" : "text-rose-400")
                    }
                  >
                    {r.action === "include" ? t("wizard.scope.include") : t("wizard.scope.exclude")}
                  </span>
                </li>
              ))}
              {state.scopeRules.length === 0 && (
                <li className="text-xs text-ink-muted">{t("wizard.domains.help")}</li>
              )}
            </ul>
          </div>
        )}

        {step === 2 && (
          <div className="space-y-4 text-sm">
            <div className="grid gap-2 sm:grid-cols-3">
              {(["safe", "normal", "aggressive"] as const).map((a) => (
                <button
                  key={a}
                  type="button"
                  onClick={() => setState((s) => ({ ...s, aggressiveness: a }))}
                  className={
                    "rounded-md border px-3 py-2 text-start text-xs " +
                    (state.aggressiveness === a
                      ? "border-brand/60 bg-brand/10"
                      : "border-line")
                  }
                >
                  {t(`wizard.aggr.${a}`)}
                </button>
              ))}
            </div>
            <label className="flex items-center gap-3">
              <input
                type="checkbox"
                checked={state.activeProbes}
                onChange={(e) => setState((s) => ({ ...s, activeProbes: e.target.checked }))}
              />
              <span>{t("wizard.aggr.active")}</span>
            </label>
            <label className="flex items-center gap-3">
              <input
                type="checkbox"
                checked={state.fuzzing}
                onChange={(e) => setState((s) => ({ ...s, fuzzing: e.target.checked }))}
              />
              <span>{t("wizard.aggr.fuzzing")}</span>
            </label>
            <p className="text-xs text-ink-muted">{t("wizard.aggr.help")}</p>
            {!stepOk && (
              <p className="text-xs text-amber-400">{t("wizard.aggr.help")}</p>
            )}
          </div>
        )}

        {step === 3 && (
          <AuthorizationGate
            value={state.attestation}
            onChange={(attestation) => setState((s) => ({ ...s, attestation }))}
          />
        )}
      </div>

      <div className="flex items-center justify-between">
        <button
          type="button"
          onClick={() => setStep((s) => Math.max(0, s - 1))}
          disabled={step === 0}
          className="rounded-md border border-line-strong px-4 py-2 text-sm disabled:opacity-40"
        >
          {t("common.back")}
        </button>

        {!isLast ? (
          <button
            type="button"
            onClick={() => setStep((s) => s + 1)}
            disabled={!stepOk}
            className="rounded-md bg-brand-gradient px-4 py-2 text-sm font-medium text-surface-sunken disabled:opacity-40"
          >
            {t("common.next")}
          </button>
        ) : (
          <button
            type="button"
            onClick={onStart}
            disabled={!startReady || submitting}
            title={startReady ? undefined : t("wizard.startDisabled")}
            className="rounded-md bg-emerald-500 px-4 py-2 text-sm font-semibold text-surface-sunken disabled:cursor-not-allowed disabled:bg-white/[0.05] disabled:text-ink-muted"
          >
            {t("wizard.start")}
          </button>
        )}
      </div>

      {submitError && (
        <div className="rounded-md border border-rose-900 bg-rose-950 p-3 text-xs text-rose-300">
          {submitError}
        </div>
      )}
    </div>
  );
}
