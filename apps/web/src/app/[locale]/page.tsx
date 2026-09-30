"use client";

import Link from "next/link";
import { useI18n } from "@/i18n/I18nProvider";

const CAPABILITIES = [
  { k: "Recon", d: "subfinder · dnsx · httpx · katana", icon: "M12 3a9 9 0 1 0 9 9M12 12l6-3.5" },
  { k: "Secrets", d: "hard-coded keys in JS bundles", icon: "M8 11V7a4 4 0 1 1 8 0v4M6 11h12v9H6z" },
  { k: "Takeover", d: "dangling-CNAME detection", icon: "M4 7h16M4 12h16M4 17h10" },
  { k: "CORS", d: "arbitrary-origin reflection", icon: "M12 3v18M3 12h18" },
];

function Arrow() {
  return (
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round"
      strokeLinejoin="round" className="h-4 w-4 transition-transform duration-200 group-hover:translate-x-0.5 rtl:group-hover:-translate-x-0.5 rtl:rotate-180">
      <path d="M5 12h14M13 6l6 6-6 6" />
    </svg>
  );
}

export default function Dashboard() {
  const { t, locale } = useI18n();
  return (
    <div className="space-y-8">
      {/* Hero */}
      <section className="card card-hover relative overflow-hidden !p-0">
        <div className="grid-overlay pointer-events-none absolute inset-0 opacity-40" />
        <div className="pointer-events-none absolute -end-24 -top-24 h-64 w-64 rounded-full bg-brand/20 blur-3xl" />
        <div className="relative p-7 md:p-9">
          <div className="chip mb-4">
            <span className="h-1.5 w-1.5 rounded-full bg-emerald-400" />
            Responsible by design
          </div>
          <h1 className="text-3xl font-semibold tracking-tight text-balance md:text-4xl">
            <span className="gradient-text">{t("app.name")}</span>
          </h1>
          <p className="mt-2 max-w-xl text-sm leading-relaxed text-ink-muted md:text-base">
            {t("app.tagline")}
          </p>
          <div className="mt-6 flex flex-wrap gap-3">
            <Link href={`/${locale}/scans/new`} className="btn-primary group">
              {t("nav.newScan")} <Arrow />
            </Link>
            <Link href={`/${locale}/programs`} className="btn-ghost">
              {t("nav.programs")}
            </Link>
          </div>
        </div>
      </section>

      {/* Capabilities */}
      <section>
        <h2 className="eyebrow mb-3 px-1">Detection surface</h2>
        <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
          {CAPABILITIES.map((c) => (
            <div key={c.k} className="card card-hover">
              <span className="grid h-10 w-10 place-items-center rounded-lg border border-line bg-white/[0.03] text-brand">
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.7"
                  strokeLinecap="round" strokeLinejoin="round" className="h-5 w-5">
                  <path d={c.icon} />
                </svg>
              </span>
              <div className="mt-4 text-base font-semibold text-ink">{c.k}</div>
              <div className="mt-1 text-xs text-ink-faint">{c.d}</div>
            </div>
          ))}
        </div>
      </section>

      {/* Primary actions */}
      <section className="grid gap-4 md:grid-cols-2">
        <Link href={`/${locale}/programs`} className="card card-hover group flex items-start justify-between">
          <div>
            <div className="text-lg font-semibold text-ink">{t("nav.programs")}</div>
            <p className="mt-1 max-w-xs text-sm text-ink-muted">{t("programs.empty")}</p>
          </div>
          <span className="text-ink-faint transition-colors group-hover:text-brand"><Arrow /></span>
        </Link>
        <Link href={`/${locale}/scans/new`} className="card card-hover group flex items-start justify-between">
          <div>
            <div className="text-lg font-semibold text-ink">{t("nav.newScan")}</div>
            <p className="mt-1 max-w-xs text-sm text-ink-muted">{t("wizard.domains.help")}</p>
          </div>
          <span className="text-ink-faint transition-colors group-hover:text-brand"><Arrow /></span>
        </Link>
      </section>
    </div>
  );
}
