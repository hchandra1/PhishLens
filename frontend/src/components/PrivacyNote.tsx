import type { Health } from "@/lib/types";

export function PrivacyNote({ health, compact = false }: { health: Health | null; compact?: boolean }) {
  const checks = health?.optional_checks ?? {};
  const external = [
    checks.llm && "the email's text goes to Anthropic's Claude API for the AI content check",
    checks.domain_age && "domain names go to public domain registries (RDAP)",
    checks.safe_browsing && "link addresses (without their personal query parts) go to Google Safe Browsing",
    checks.virustotal && "attachment fingerprints (never the files) go to VirusTotal",
  ].filter(Boolean);

  return (
    <aside className={`rounded-lg bg-zinc-100 text-zinc-700 dark:bg-zinc-900 dark:text-zinc-300 ${compact ? "p-3 text-xs" : "p-4 text-sm"}`}>
      <p>
        <strong>Private by design.</strong> Emails are analyzed in memory and never stored or logged.
        Links are never opened and attachments are never run.
      </p>
      {external.length > 0 ? (
        <p className="mt-1">With the extra checks your administrator turned on: {external.join("; ")}.</p>
      ) : (
        health && <p className="mt-1">No part of the email leaves the PhishLens server.</p>
      )}
    </aside>
  );
}
