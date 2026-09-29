"use client";

import Link from "next/link";
import { useI18n } from "@/i18n/I18nProvider";

export default function Dashboard() {
  const { t, locale } = useI18n();
  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-semibold">{t("app.name")}</h1>
        <p className="text-neutral-400">{t("app.tagline")}</p>
      </div>
      <div className="grid gap-4 sm:grid-cols-2">
        <Link
          href={`/${locale}/programs`}
          className="rounded-lg border border-neutral-800 p-5 hover:border-neutral-600"
        >
          <div className="text-lg font-medium">{t("nav.programs")}</div>
          <p className="mt-1 text-sm text-neutral-400">{t("programs.empty")}</p>
        </Link>
        <Link
          href={`/${locale}/scans/new`}
          className="rounded-lg border border-neutral-800 p-5 hover:border-neutral-600"
        >
          <div className="text-lg font-medium">{t("nav.newScan")}</div>
          <p className="mt-1 text-sm text-neutral-400">{t("wizard.domains.help")}</p>
        </Link>
      </div>
    </div>
  );
}
