"use client";

import {
  type AttestationState,
  attestationComplete,
  REQUIRED_PHRASE,
} from "@/lib/authorization";
import { useI18n } from "@/i18n/I18nProvider";

function Check({
  checked,
  onChange,
  label,
}: {
  checked: boolean;
  onChange: (v: boolean) => void;
  label: string;
}) {
  return (
    <label className="flex cursor-pointer items-start gap-3 rounded-md border border-neutral-800 p-3 text-sm">
      <input
        type="checkbox"
        checked={checked}
        onChange={(e) => onChange(e.target.checked)}
        className="mt-0.5 h-4 w-4"
      />
      <span className="text-neutral-200">{label}</span>
    </label>
  );
}

export function AuthorizationGate({
  value,
  onChange,
}: {
  value: AttestationState;
  onChange: (next: AttestationState) => void;
}) {
  const { t } = useI18n();
  const set = <K extends keyof AttestationState>(k: K, v: AttestationState[K]) =>
    onChange({ ...value, [k]: v });
  const complete = attestationComplete(value);

  return (
    <div className="space-y-4">
      <div>
        <h2 className="text-lg font-semibold">{t("gate.title")}</h2>
        <p className="mt-1 text-sm text-neutral-400">{t("gate.intro")}</p>
      </div>

      <label className="block text-sm">
        <span className="text-neutral-300">{t("gate.authorizedBy")}</span>
        <input
          type="text"
          value={value.authorizedBy}
          onChange={(e) => set("authorizedBy", e.target.value)}
          className="mt-1 w-full rounded-md border border-neutral-800 bg-neutral-900 px-3 py-2 text-sm"
        />
      </label>

      <Check
        checked={value.programConfirmed}
        onChange={(v) => set("programConfirmed", v)}
        label={t("gate.program")}
      />
      <Check
        checked={value.scopeConfirmed}
        onChange={(v) => set("scopeConfirmed", v)}
        label={t("gate.scope")}
      />
      <Check
        checked={value.rulesConfirmed}
        onChange={(v) => set("rulesConfirmed", v)}
        label={t("gate.rules")}
      />

      <label className="block text-sm">
        <span className="text-neutral-300">{t("gate.typed")}</span>
        <p className="text-xs text-neutral-500">
          {t("gate.phrase", { phrase: REQUIRED_PHRASE })}
        </p>
        <input
          type="text"
          value={value.typedConfirmation}
          onChange={(e) => set("typedConfirmation", e.target.value)}
          aria-invalid={value.typedConfirmation.length > 0 && !complete}
          className="mt-1 w-full rounded-md border border-neutral-800 bg-neutral-900 px-3 py-2 text-sm"
        />
      </label>

      <div
        className={
          "rounded-md p-2 text-xs " +
          (complete ? "bg-emerald-950 text-emerald-300" : "bg-neutral-900 text-neutral-500")
        }
        data-testid="gate-status"
      >
        {complete ? "✓ authorized" : t("wizard.startDisabled")}
      </div>
    </div>
  );
}
