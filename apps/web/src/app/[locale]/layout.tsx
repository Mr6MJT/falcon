import { notFound } from "next/navigation";
import { AppShell } from "@/components/AppShell";
import { isLocale, isRtl, locales, type Locale } from "@/i18n/config";
import { I18nProvider } from "@/i18n/I18nProvider";

export function generateStaticParams() {
  return locales.map((locale) => ({ locale }));
}

export default function LocaleLayout({
  children,
  params,
}: {
  children: React.ReactNode;
  params: { locale: string };
}) {
  if (!isLocale(params.locale)) notFound();
  const locale = params.locale as Locale;
  return (
    <div dir={isRtl(locale) ? "rtl" : "ltr"} lang={locale}>
      <I18nProvider locale={locale}>
        <AppShell locale={locale}>{children}</AppShell>
      </I18nProvider>
    </div>
  );
}
