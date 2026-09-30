"use client";

import Link from "next/link";
import Script from "next/script";
import { useCallback, useEffect, useState } from "react";

import { AccessCodeField } from "@/components/AccessCodeField";
import { PrivacyNote } from "@/components/PrivacyNote";
import { VerdictView } from "@/components/VerdictView";
import { AnalyzeError, analyzeEmail, getHealth, loadAccessCode, saveAccessCode } from "@/lib/api";
import { currentMessageSource } from "@/lib/outlook";
import type { Health, Verdict } from "@/lib/types";

type State =
  | { kind: "loading" }
  | { kind: "outside-outlook" }
  | { kind: "checking" }
  | { kind: "done"; verdict: Verdict }
  | { kind: "error"; error: AnalyzeError };

/** Task pane shown inside Outlook by the PhishLens add-in (manifest at /outlook/manifest.xml). */
export default function OutlookPane() {
  const [state, setState] = useState<State>({ kind: "loading" });
  const [health, setHealth] = useState<Health | null>(null);
  const [accessCode, setAccessCode] = useState(() => loadAccessCode("local"));
  const [officeReady, setOfficeReady] = useState(false);

  const check = useCallback(async (code: string) => {
    setState({ kind: "checking" });
    try {
      const verdict = await analyzeEmail(await currentMessageSource(), code || undefined);
      if (code) saveAccessCode(code, "local");
      setState({ kind: "done", verdict });
    } catch (e) {
      const error = e instanceof AnalyzeError ? e : new AnalyzeError(e instanceof Error ? e.message : "Something went wrong.");
      setState({ kind: "error", error });
    }
  }, []);

  useEffect(() => {
    getHealth().then(setHealth);
  }, []);

  useEffect(() => {
    if (!officeReady) return;
    Office.onReady(({ host }) => {
      if (host !== Office.HostType.Outlook) {
        setState({ kind: "outside-outlook" });
        return;
      }
      const code = loadAccessCode("local");
      check(code);
      // Pinned task panes stay open while the user moves between emails.
      Office.context.mailbox.addHandlerAsync(Office.EventType.ItemChanged, () => {
        if (Office.context.mailbox.item) check(loadAccessCode("local"));
      });
    });
  }, [officeReady, check]);

  return (
    <main className="mx-auto w-full max-w-xl flex-1 space-y-4 px-3 py-4 text-sm">
      <Script src="https://appsforoffice.microsoft.com/lib/1/hosted/office.js" onLoad={() => setOfficeReady(true)} />
      <h1 className="text-lg font-bold">PhishLens</h1>

      {health?.access_code_required && state.kind !== "outside-outlook" && (
        <div className="space-y-2">
          <AccessCodeField value={accessCode} onChange={setAccessCode} invalid={state.kind === "error" && state.error.status === 401} />
          <button type="button" onClick={() => check(accessCode)} className="rounded-md bg-blue-700 px-3 py-1.5 font-semibold text-white">
            Check this email
          </button>
        </div>
      )}

      {state.kind === "loading" && <p className="text-zinc-500">Connecting to Outlook…</p>}
      {state.kind === "checking" && <p className="text-zinc-500">Checking this email…</p>}
      {state.kind === "outside-outlook" && (
        <p>
          This page runs inside Outlook. Install the add-in from <code>/outlook/manifest.xml</code>, or use the{" "}
          <Link href="/" className="text-blue-700 underline dark:text-blue-400">web checker</Link>.
        </p>
      )}
      {state.kind === "error" && (
        <div role="alert" className="space-y-2 rounded-lg border border-red-300 bg-red-50 p-3 text-red-900 dark:border-red-800 dark:bg-red-950/50 dark:text-red-100">
          <p>{state.error.message}</p>
          <button type="button" onClick={() => check(accessCode)} className="underline">Try again</button>
        </div>
      )}
      {state.kind === "done" && <VerdictView verdict={state.verdict} />}

      <PrivacyNote health={health} compact />
    </main>
  );
}
