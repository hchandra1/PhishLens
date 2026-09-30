import type { Health, Verdict } from "./types";

export class AnalyzeError extends Error {
  constructor(
    message: string,
    readonly status?: number,
  ) {
    super(message);
  }
}

export async function analyzeEmail(source: string | ArrayBuffer | Uint8Array, accessCode?: string): Promise<Verdict> {
  const headers: Record<string, string> = { "Content-Type": "message/rfc822" };
  if (accessCode) headers["X-Access-Code"] = accessCode;
  let response: Response;
  try {
    // Raw source as the body: the backend reads it in memory, nothing is stored.
    response = await fetch("/api/analyze", { method: "POST", headers, body: source as BodyInit });
  } catch {
    throw new AnalyzeError("Couldn't reach the analysis service. Check your connection and try again.");
  }
  if (!response.ok) {
    const detail = await response
      .json()
      .then((body) => (typeof body?.detail === "string" ? body.detail : null))
      .catch(() => null);
    throw new AnalyzeError(detail ?? `The analysis failed (HTTP ${response.status}).`, response.status);
  }
  return response.json();
}

export async function getHealth(): Promise<Health | null> {
  try {
    const response = await fetch("/api/health");
    return response.ok ? await response.json() : null;
  } catch {
    return null;
  }
}

// The access code is kept only for this browser session, never in the URL.
const CODE_KEY = "phishlens-access-code";

export function loadAccessCode(storage: "session" | "local" = "session"): string {
  if (typeof window === "undefined") return ""; // prerendering
  try {
    return (storage === "local" ? localStorage : sessionStorage).getItem(CODE_KEY) ?? "";
  } catch {
    return "";
  }
}

export function saveAccessCode(code: string, storage: "session" | "local" = "session"): void {
  try {
    (storage === "local" ? localStorage : sessionStorage).setItem(CODE_KEY, code);
  } catch {
    // Storage can be unavailable (private mode); the code then lasts until reload.
  }
}
