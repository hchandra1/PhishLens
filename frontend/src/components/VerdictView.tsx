import type { AnalyzerReport, Evidence, Label, Severity, Signal, Verdict } from "@/lib/types";

const LABELS: Record<Label, { title: string; icon: string; tone: string; bar: string }> = {
  phishing: {
    title: "Likely phishing",
    icon: "⛔",
    tone: "border-red-300 bg-red-50 text-red-900 dark:border-red-800 dark:bg-red-950/50 dark:text-red-100",
    bar: "bg-red-600",
  },
  suspicious: {
    title: "Suspicious",
    icon: "⚠️",
    tone: "border-amber-300 bg-amber-50 text-amber-950 dark:border-amber-700 dark:bg-amber-950/40 dark:text-amber-100",
    bar: "bg-amber-500",
  },
  safe: {
    title: "No signs of phishing",
    icon: "✅",
    tone: "border-green-300 bg-green-50 text-green-950 dark:border-green-800 dark:bg-green-950/40 dark:text-green-100",
    bar: "bg-green-600",
  },
};

const SEVERITY: Record<Severity, { text: string; tone: string }> = {
  high: { text: "High risk", tone: "bg-red-100 text-red-800 dark:bg-red-900/60 dark:text-red-100" },
  medium: { text: "Medium risk", tone: "bg-amber-100 text-amber-900 dark:bg-amber-900/50 dark:text-amber-100" },
  low: { text: "Low risk", tone: "bg-zinc-200 text-zinc-800 dark:bg-zinc-700 dark:text-zinc-100" },
  info: { text: "Note", tone: "bg-zinc-100 text-zinc-700 dark:bg-zinc-800 dark:text-zinc-300" },
};

export const CHECK_NAMES: Record<string, string> = {
  auth: "Sender verification (SPF, DKIM, DMARC)",
  sender: "Sender identity",
  urls: "Links",
  attachments: "Attachments",
  content: "Hidden instructions",
  llm: "AI content check",
  domain_age: "Domain age",
  safe_browsing: "Google Safe Browsing",
  virustotal: "VirusTotal",
};

export function VerdictView({ verdict }: { verdict: Verdict }) {
  const look = LABELS[verdict.label];
  const warnings = verdict.signals.filter((s) => s.weight > 0 && s.severity !== "info");
  // Weight 0 = set aside by the scorer (e.g. a DMARC pass next to a look-alike domain).
  const notes = verdict.signals.filter((s) => s.weight >= 0 && s.severity === "info");
  const reassuring = verdict.signals.filter((s) => s.weight < 0);

  return (
    <div className="space-y-6">
      <section className={`rounded-xl border p-5 ${look.tone}`} aria-labelledby="verdict-title">
        <div className="flex flex-wrap items-center gap-x-4 gap-y-2">
          <h2 id="verdict-title" className="flex items-center gap-2 text-2xl font-bold">
            <span aria-hidden>{look.icon}</span>
            {look.title}
          </h2>
          <div className="ml-auto flex items-center gap-2 text-sm" aria-label={`Risk score ${verdict.score} out of 100`}>
            <span>Risk score</span>
            <span className="h-2 w-28 overflow-hidden rounded-full bg-black/10 dark:bg-white/15">
              <span className={`block h-full ${look.bar}`} style={{ width: `${verdict.score}%` }} />
            </span>
            <span className="font-semibold tabular-nums">{verdict.score}/100</span>
          </div>
        </div>
        <p className="mt-3 leading-relaxed">{verdict.summary}</p>
      </section>

      <EmailMeta verdict={verdict} />

      <section aria-labelledby="actions-title">
        <h3 id="actions-title" className="mb-2 text-lg font-semibold">What to do</h3>
        <ul className="space-y-1.5">
          {verdict.recommended_actions.map((action) => (
            <li key={action} className="flex gap-2">
              <span aria-hidden className="text-blue-700 dark:text-blue-400">→</span>
              <span>{action}</span>
            </li>
          ))}
        </ul>
      </section>

      {warnings.length > 0 && (
        <SignalGroup title="Why we flagged it" signals={warnings} />
      )}
      {reassuring.length > 0 && (
        <SignalGroup title="Reassuring signs" signals={reassuring} />
      )}
      {notes.length > 0 && <SignalGroup title="Minor notes" signals={notes} collapsed={warnings.length > 0} />}

      <ChecksRun reports={verdict.analyzers} />
    </div>
  );
}

function EmailMeta({ verdict }: { verdict: Verdict }) {
  const { email } = verdict;
  return (
    <section aria-label="Email details" className="rounded-lg border border-zinc-200 p-4 text-sm dark:border-zinc-800">
      <dl className="grid grid-cols-[auto_1fr] gap-x-4 gap-y-1">
        <dt className="text-zinc-500">From</dt>
        <dd className="break-all">
          {email.from_display && <span className="font-medium">{email.from_display} </span>}
          {email.from_address ? <span className="font-mono text-xs">&lt;{email.from_address}&gt;</span> : <span className="text-zinc-500">(no address)</span>}
        </dd>
        <dt className="text-zinc-500">Subject</dt>
        <dd>{email.subject || <span className="text-zinc-500">(none)</span>}</dd>
        <dt className="text-zinc-500">Contains</dt>
        <dd>
          {email.url_count} link{email.url_count === 1 ? "" : "s"}, {email.attachment_count} attachment
          {email.attachment_count === 1 ? "" : "s"}
        </dd>
      </dl>
      {email.warnings.length > 0 && (
        <ul className="mt-3 space-y-1 border-t border-zinc-200 pt-3 text-zinc-600 dark:border-zinc-800 dark:text-zinc-400">
          {email.warnings.map((w) => (
            <li key={w}>ⓘ {w}</li>
          ))}
        </ul>
      )}
    </section>
  );
}

function SignalGroup({ title, signals, collapsed = false }: { title: string; signals: Signal[]; collapsed?: boolean }) {
  const list = (
    <ul className="space-y-3">
      {signals.map((s) => (
        <SignalCard key={`${s.analyzer}-${s.id}`} signal={s} />
      ))}
    </ul>
  );
  if (collapsed) {
    return (
      <details>
        <summary className="cursor-pointer text-lg font-semibold">
          {title} ({signals.length})
        </summary>
        <div className="mt-3">{list}</div>
      </details>
    );
  }
  return (
    <section aria-label={title}>
      <h3 className="mb-3 text-lg font-semibold">{title}</h3>
      {list}
    </section>
  );
}

function SignalCard({ signal }: { signal: Signal }) {
  const severity = SEVERITY[signal.severity];
  return (
    <li className="rounded-lg border border-zinc-200 p-4 dark:border-zinc-800">
      <div className="flex items-start gap-3">
        <span className={`shrink-0 rounded px-2 py-0.5 text-xs font-semibold ${signal.weight < 0 ? "bg-green-100 text-green-800 dark:bg-green-900/50 dark:text-green-100" : severity.tone}`}>
          {signal.weight < 0 ? "Good sign" : severity.text}
        </span>
        <p className="leading-relaxed">{signal.explanation}</p>
      </div>
      {signal.evidence.length > 0 && <EvidenceList evidence={signal.evidence} />}
    </li>
  );
}

/** Evidence is attacker-controlled text: rendered as plain text, and links are never clickable. */
function EvidenceList({ evidence }: { evidence: Evidence[] }) {
  const rows: React.ReactNode[] = [];
  for (let i = 0; i < evidence.length; i++) {
    const item = evidence[i];
    const next = evidence[i + 1];
    if (item.label === "Link text" && next?.label === "Actually goes to") {
      rows.push(<LinkComparison key={i} shown={item.value} actual={next.value} />);
      i++;
      continue;
    }
    rows.push(
      <div key={i} className="grid grid-cols-1 gap-x-3 sm:grid-cols-[10rem_1fr]">
        <dt className="text-zinc-500">{item.label}</dt>
        <dd className="break-all font-mono text-xs leading-5">{item.value}</dd>
      </div>,
    );
  }
  return <dl className="mt-3 space-y-1.5 rounded-md bg-zinc-50 p-3 text-sm dark:bg-zinc-900">{rows}</dl>;
}

function LinkComparison({ shown, actual }: { shown: string; actual: string }) {
  return (
    <div className="grid gap-2 sm:grid-cols-2">
      <div className="rounded border border-zinc-200 bg-white p-2 dark:border-zinc-700 dark:bg-zinc-950">
        <dt className="text-xs font-semibold uppercase tracking-wide text-zinc-500">The link says</dt>
        <dd className="mt-1 break-all font-mono text-xs">{shown}</dd>
      </div>
      <div className="rounded border border-red-300 bg-red-50 p-2 dark:border-red-800 dark:bg-red-950/50">
        <dt className="text-xs font-semibold uppercase tracking-wide text-red-700 dark:text-red-300">It really goes to</dt>
        <dd className="mt-1 break-all font-mono text-xs font-semibold text-red-900 dark:text-red-100">{actual}</dd>
      </div>
    </div>
  );
}

function ChecksRun({ reports }: { reports: AnalyzerReport[] }) {
  return (
    <details className="text-sm">
      <summary className="cursor-pointer font-medium">Checks performed</summary>
      <ul className="mt-2 space-y-1">
        {reports.map((r) => (
          <li key={r.analyzer} className="flex flex-wrap gap-x-2">
            <span aria-hidden>{r.status === "ok" ? "✓" : "–"}</span>
            <span className={r.status === "ok" ? "" : "text-zinc-500"}>{CHECK_NAMES[r.analyzer] ?? r.analyzer}</span>
            {r.status !== "ok" && r.detail && <span className="text-zinc-500">({r.detail})</span>}
          </li>
        ))}
      </ul>
    </details>
  );
}
