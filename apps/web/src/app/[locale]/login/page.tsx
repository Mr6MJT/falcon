"use client";

import { useRouter } from "next/navigation";
import { useState } from "react";
import { useI18n } from "@/i18n/I18nProvider";
import { api } from "@/lib/api";

export default function LoginPage() {
  const { t, locale } = useI18n();
  const router = useRouter();
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  async function signIn(e: React.FormEvent) {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      await api.login(email.trim(), password);
      router.push(`/${locale}`);
    } catch {
      setError(t("auth.error"));
      setBusy(false);
    }
  }

  return (
    <div className="mx-auto max-w-sm space-y-6 pt-10">
      <div>
        <h1 className="text-2xl font-semibold">{t("auth.title")}</h1>
        <p className="mt-1 text-sm text-neutral-400">{t("auth.tokenHint")}</p>
      </div>
      <form onSubmit={signIn} className="space-y-3 rounded-lg border border-neutral-800 p-5">
        <label className="block text-sm">
          <span className="text-neutral-300">{t("auth.email")}</span>
          <input
            type="email"
            value={email}
            onChange={(e) => setEmail(e.target.value)}
            autoFocus
            autoComplete="username"
            className="mt-1 w-full rounded-md border border-neutral-800 bg-neutral-900 px-3 py-2 text-sm"
          />
        </label>
        <label className="block text-sm">
          <span className="text-neutral-300">{t("auth.password")}</span>
          <input
            type="password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            autoComplete="current-password"
            className="mt-1 w-full rounded-md border border-neutral-800 bg-neutral-900 px-3 py-2 text-sm"
          />
        </label>
        {error && (
          <div className="rounded-md border border-rose-900 bg-rose-950 p-2 text-xs text-rose-300">
            {error}
          </div>
        )}
        <button
          type="submit"
          disabled={busy || !email.trim() || !password}
          className="w-full rounded-md bg-neutral-100 px-4 py-2 text-sm font-medium text-neutral-900 disabled:opacity-40"
        >
          {t("auth.signIn")}
        </button>
      </form>
    </div>
  );
}
