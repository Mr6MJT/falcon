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
    <div className="mx-auto max-w-sm pt-6 md:pt-16">
      <div className="mb-6 text-center">
        <span className="mx-auto mb-4 grid h-12 w-12 place-items-center rounded-2xl bg-brand-gradient shadow-glow">
          <svg viewBox="0 0 24 24" className="h-6 w-6 text-surface-sunken" fill="currentColor">
            <path d="M12 2l8 4.5v5c0 4.6-3.1 8.4-8 10-4.9-1.6-8-5.4-8-10v-5L12 2zm0 3.2L7 8v3.4c0 2.9 1.9 5.4 5 6.6 3.1-1.2 5-3.7 5-6.6V8l-5-2.8z" />
          </svg>
        </span>
        <h1 className="text-2xl font-semibold tracking-tight">{t("auth.title")}</h1>
        <p className="mt-1 text-sm text-ink-muted">{t("auth.tokenHint")}</p>
      </div>
      <form onSubmit={signIn} className="card space-y-4">
        <label className="block text-sm">
          <span className="text-ink-muted">{t("auth.email")}</span>
          <input
            type="email"
            value={email}
            onChange={(e) => setEmail(e.target.value)}
            autoFocus
            autoComplete="username"
            className="input mt-1.5"
          />
        </label>
        <label className="block text-sm">
          <span className="text-ink-muted">{t("auth.password")}</span>
          <input
            type="password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            autoComplete="current-password"
            className="input mt-1.5"
          />
        </label>
        {error && (
          <div className="rounded-lg border border-rose-500/30 bg-rose-500/10 p-2.5 text-xs text-rose-300">
            {error}
          </div>
        )}
        <button type="submit" disabled={busy || !email.trim() || !password} className="btn-primary w-full">
          {busy ? "…" : t("auth.signIn")}
        </button>
      </form>
    </div>
  );
}
