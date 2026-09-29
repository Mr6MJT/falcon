"use client";

import Link from "next/link";
import { usePathname, useRouter } from "next/navigation";
import { type ReactNode, useEffect, useState } from "react";
import type { Locale } from "@/i18n/config";
import { locales } from "@/i18n/config";
import { useI18n } from "@/i18n/I18nProvider";
import { getToken, setToken } from "@/lib/api";

function NavLink({ href, label, active }: { href: string; label: string; active: boolean }) {
  return (
    <Link
      href={href}
      className={
        "block rounded-md px-3 py-2 text-sm transition-colors " +
        (active ? "bg-neutral-800 text-white" : "text-neutral-400 hover:bg-neutral-900")
      }
    >
      {label}
    </Link>
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
    { href: base, label: t("nav.dashboard") },
    { href: `${base}/programs`, label: t("nav.programs") },
    { href: `${base}/scans`, label: t("nav.scans") },
    { href: `${base}/scans/new`, label: t("nav.newScan") },
  ];

  // Swap locale while keeping the rest of the path.
  const switchLocale = (target: Locale) => {
    const rest = pathname.replace(/^\/[a-z]{2}(?=\/|$)/, "");
    return `/${target}${rest || ""}`;
  };

  return (
    <div className="min-h-screen md:grid md:grid-cols-[240px_1fr]">
      <aside className="border-neutral-800 md:min-h-screen md:border-e md:p-4">
        <div className="flex items-center justify-between p-4 md:p-0">
          <div>
            <div className="text-base font-semibold">{t("app.name")}</div>
            <div className="text-xs text-neutral-500">{t("app.tagline")}</div>
          </div>
        </div>
        <nav className="hidden gap-1 px-2 md:mt-6 md:flex md:flex-col">
          {nav.map((n) => (
            <NavLink
              key={n.href}
              href={n.href}
              label={n.label}
              active={pathname === n.href}
            />
          ))}
        </nav>
        <div className="mt-4 flex items-center gap-2 px-4 md:mt-8 md:px-0">
          {locales.map((l) => (
            <Link
              key={l}
              href={switchLocale(l)}
              className={
                "rounded px-2 py-1 text-xs uppercase " +
                (l === locale ? "bg-neutral-700 text-white" : "text-neutral-500")
              }
            >
              {l}
            </Link>
          ))}
          <span className="mx-1 text-neutral-700">|</span>
          {signedIn ? (
            <button
              onClick={() => {
                setToken(null);
                setSignedIn(false);
                router.push(`${base}/login`);
              }}
              className="rounded px-2 py-1 text-xs text-neutral-400 hover:text-neutral-200"
            >
              {t("auth.signOut")}
            </button>
          ) : (
            <Link
              href={`${base}/login`}
              className="rounded px-2 py-1 text-xs text-emerald-400 hover:text-emerald-300"
            >
              {t("nav.signIn")}
            </Link>
          )}
        </div>
      </aside>
      <main className="p-4 md:p-8">{children}</main>
    </div>
  );
}
