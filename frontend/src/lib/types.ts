// Mirrors backend/src/phishlens/models.py (the Verdict contract).

export type Label = "safe" | "suspicious" | "phishing";
export type Severity = "info" | "low" | "medium" | "high";
export type EvidenceKind = "header" | "sender" | "url" | "attachment" | "body";

export interface Evidence {
  kind: EvidenceKind;
  label: string;
  value: string;
}

export interface Signal {
  analyzer: string;
  id: string;
  severity: Severity;
  weight: number;
  evidence: Evidence[];
  explanation: string;
}

export interface AnalyzerReport {
  analyzer: string;
  status: "ok" | "unavailable" | "error";
  detail: string | null;
}

export interface EmailSummary {
  subject: string;
  from_display: string;
  from_address: string;
  url_count: number;
  attachment_count: number;
  warnings: string[];
}

export interface Verdict {
  label: Label;
  score: number;
  signals: Signal[];
  summary: string;
  recommended_actions: string[];
  override: string | null;
  analyzers: AnalyzerReport[];
  email: EmailSummary;
}

export interface Health {
  status: string;
  optional_checks: Record<string, boolean>;
  access_code_required: boolean;
}
