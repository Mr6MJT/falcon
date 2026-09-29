export const locales = ["en", "ar", "fr"] as const;
export type Locale = (typeof locales)[number];
export const defaultLocale: Locale = "en";

const rtlLocales: readonly Locale[] = ["ar"];
export const isRtl = (l: Locale): boolean => rtlLocales.includes(l);
export const isLocale = (v: string): v is Locale => (locales as readonly string[]).includes(v);
