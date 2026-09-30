"use client";

import { useEffect, useRef, useState } from "react";

import { AnalyzeError, analyzeEmail, getHealth, loadAccessCode, saveAccessCode } from "@/lib/api";
import type { Health, Verdict } from "@/lib/types";

import { AccessCodeField } from "./AccessCodeField";
import { EmailInput } from "./EmailInput";
import { PrivacyNote } from "./PrivacyNote";
import { VerdictView } from "./VerdictView";

export function Analyzer() {
  const [verdict, setVerdict] = useState<Verdict | null>(null);
  const [error, setError] = useState<AnalyzeError | null>(null);
  const [busy, setBusy] = useState(false);
  const [health, setHealth] = useState<Health | null>(null);
  // The code field only renders after the health check, so reading storage here can't
  // cause a hydration mismatch.
  const [accessCode, setAccessCode] = useState(() => loadAccessCode());
  const results = useRef<HTMLDivElement>(null);

  useEffect(() => {
    getHealth().then(setHealth);
  }, []);

  async function run(source: string | ArrayBuffer) {
    setBusy(true);
    setError(null);
    setVerdict(null);
    try {
      setVerdict(await analyzeEmail(source, accessCode || undefined));
      if (accessCode) saveAccessCode(accessCode);
      // Move keyboard and screen-reader focus to the result.
      requestAnimationFrame(() => results.current?.focus());
    } catch (e) {
      setError(e instanceof AnalyzeError ? e : new AnalyzeError("Something went wrong. Please try again."));
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="space-y-8">
      {health?.access_code_required && (
        <AccessCodeField value={accessCode} onChange={setAccessCode} invalid={error?.status === 401} />
      )}
      <EmailInput busy={busy} onAnalyze={run} />
      <PrivacyNote health={health} />
      <div ref={results} tabIndex={-1} aria-live="polite" className="outline-none">
        {error && (
          <p role="alert" className="rounded-lg border border-red-300 bg-red-50 p-4 text-red-900 dark:border-red-800 dark:bg-red-950/50 dark:text-red-100">
            {error.message}
          </p>
        )}
        {verdict && <VerdictView verdict={verdict} />}
      </div>
    </div>
  );
}
