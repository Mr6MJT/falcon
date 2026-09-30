"use client";

import Link from "next/link";
import { usePathname, useRouter } from "next/navigation";
import { type ReactNode, useEffect, useState } from "react";
import type { Locale } from "@/i18n/config";
import { locales } from "@/i18n/config";
import { useI18n } from "@/i18n/I18nProvider";
import { getToken, setToken } from "@/lib/api";

type IconProps = { className?: string };
const Icons = {
  dashboard: (p: IconProps) => (
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.7" className={p.className}>
      <rect x="3" y="3" width="7" height="9" rx="1.5" /><rect x="14" y="3" width="7" height="5" rx="1.5" />
      <rect x="14" y="12" width="7" height="9" rx="1.5" /><rect x="3" y="16" width="7" height="5" rx="1.5" />
    </svg>
  ),
  programs: (p: IconProps) => (
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.7" className={p.className}>
      <circle cx="12" cy="12" r="9" /><circle cx="12" cy="12" r="5" /><circle cx="12" cy="12" r="1.5" fill="currentColor" />
    </svg>
  ),
  scans: (p: IconProps) => (
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.7" className={p.className}>
      <path d="M12 3a9 9 0 1 0 9 9" /><path d="M12 12l6-3.5" strokeLinecap="round" /><circle cx="12" cy="12" r="1.5" fill="currentColor" stroke="none" />
    </svg>
  ),
  newScan: (p: IconProps) => (
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.7" strokeLinecap="round" className={p.className}>
      <path d="M12 5v14M5 12h14" />
    </svg>
  ),
};

function NavLink({
  href, label, active, icon,
}: { href: string; label: string; active: boolean; icon: ReactNode }) {
  return (
    <Link
      href={href}
      className={
        "group relative flex items-center gap-3 rounded-lg px-3 py-2.5 text-sm font-medium transition-all duration-150 " +
        (active
          ? "bg-white/[0.06] text-ink shadow-[inset_0_1px_0_rgba(255,255,255,0.05)]"
          : "text-ink-muted hover:bg-white/[0.035] hover:text-ink")
      }
    >
      {active && (
        <span className="absolute inset-y-1.5 start-0 w-0.5 rounded-full bg-brand-gradient shadow-[0_0_8px_rgba(34,211,238,0.7)]" />
      )}
      <span className={active ? "text-brand" : "text-ink-faint group-hover:text-ink-muted"}>{icon}</span>
      {label}
    </Link>
  );
}

function Logo() {
  return (
    <div className="flex items-center gap-2.5">
      <span className="relative grid h-9 w-9 place-items-center rounded-xl bg-brand-gradient shadow-glow">
        <svg viewBox="0 0 24 24" className="h-5 w-5 text-surface-sunken" fill="currentColor">
          <path d="M12 2l8 4.5v5c0 4.6-3.1 8.4-8 10-4.9-1.6-8-5.4-8-10v-5L12 2zm0 3.2L7 8v3.4c0 2.9 1.9 5.4 5 6.6 3.1-1.2 5-3.7 5-6.6V8l-5-2.8z" />
        </svg>
      </span>
      <div className="leading-tight">
        <div className="text-[15px] font-semibold tracking-tight text-ink">Falcon</div>
        <div className="text-[10px] uppercase tracking-[0.16em] text-ink-faint">Recon Platform</div>
      </div>
    </div>
  );
}

export function AppShell({ locale, children }: { locale: Locale; children: ReactNode }) {
  const { t } = useI18n();
  const pathname = usePathname();
  const router = useRouter();
  const base = `/${locale}`;
  const [signedIn, setSignedIn] = useState(false);
  useEffect(() => setSignedIn(Boolean(getToken())), [pathname]);

  const nav = [
    { href: base, label: t("nav.dashboard"), icon: <Icons.dashboard className="h-[18px] w-[18px]" /> },
    { href: `${base}/programs`, label: t("nav.programs"), icon: <Icons.programs className="h-[18px] w-[18px]" /> },
    { href: `${base}/scans`, label: t("nav.scans"), icon: <Icons.scans className="h-[18px] w-[18px]" /> },
    { href: `${base}/scans/new`, label: t("nav.newScan"), icon: <Icons.newScan className="h-[18px] w-[18px]" /> },
  ];

  const switchLocale = (target: Locale) => {
    const rest = pathname.replace(/^\/[a-z]{2}(?=\/|$)/, "");
    return `/${target}${rest || ""}`;
  };

  const authControls = (
    <div className="flex items-center gap-1.5">
      {locales.map((l) => (
        <Link
          key={l}
          href={switchLocale(l)}
          className={
            "rounded-md px-2 py-1 text-[11px] font-medium uppercase transition-colors " +
            (l === locale ? "bg-white/10 text-ink" : "text-ink-faint hover:text-ink-muted")
          }
        >
          {l}
        </Link>
      ))}
      <span className="mx-0.5 h-3.5 w-px bg-line" />
      {signedIn ? (
        <button
          onClick={() => {
            setToken(null);
            setSignedIn(false);
            router.push(`${base}/login`);
          }}
          className="rounded-md px-2 py-1 text-xs text-ink-muted transition-colors hover:text-ink"
        >
          {t("auth.signOut")}
        </button>
      ) : (
        <Link
          href={`${base}/login`}
          className="rounded-md px-2 py-1 text-xs font-medium text-brand transition-colors hover:text-brand-strong"
        >
          {t("nav.signIn")}
        </Link>
      )}
    </div>
  );

  return (
    <div className="min-h-screen md:grid md:grid-cols-[264px_1fr]">
      {/* Sidebar (desktop) */}
      <aside className="sticky top-0 hidden h-screen flex-col border-e border-line bg-white/[0.015] px-4 py-6 backdrop-blur-xl md:flex">
        <div className="px-1">
          <Logo />
        </div>
        <nav className="mt-8 flex flex-col gap-1">
          {nav.map((n) => (
            <NavLink key={n.href} href={n.href} label={n.label} active={pathname === n.href} icon={n.icon} />
          ))}
        </nav>
        <div className="mt-auto space-y-4 pt-6">
          <div className="flex items-center gap-2 rounded-lg border border-line bg-white/[0.02] px-3 py-2">
            <span className="h-1.5 w-1.5 animate-pulse-glow rounded-full bg-emerald-400 shadow-[0_0_6px_rgba(52,211,153,0.9)]" />
            <span className="text-[11px] text-ink-muted">{t("app.tagline")}</span>
          </div>
          {authControls}
        </div>
      </aside>

      {/* Top bar (mobile) */}
      <header className="sticky top-0 z-20 flex items-center justify-between border-b border-line bg-surface/80 px-4 py-3 backdrop-blur-xl md:hidden">
        <Logo />
        {authControls}
      </header>
      <nav className="flex gap-1.5 overflow-x-auto border-b border-line px-4 py-2 md:hidden">
        {nav.map((n) => (
          <Link
            key={n.href}
            href={n.href}
            className={
              "whitespace-nowrap rounded-lg px-3 py-1.5 text-sm transition-colors " +
              (pathname === n.href ? "bg-white/[0.07] text-ink" : "text-ink-muted")
            }
          >
            {n.label}
          </Link>
        ))}
      </nav>

      <main className="min-w-0 p-4 md:p-8 lg:p-10">
        <div className="mx-auto max-w-6xl animate-fade-up">{children}</div>
      </main>
    </div>
  );
}
