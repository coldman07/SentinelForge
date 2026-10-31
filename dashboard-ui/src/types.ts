export type Severity = "critical" | "high" | "medium" | "low" | "informational" | "unknown";
export type TriageState = "open" | "investigating" | "resolved";

export interface AlertSummary {
  event_id: string;
  timestamp: string;
  host_id: string;
  match_count: number;
  rule_ids: string[];
  rule_titles: string[];
  levels: string[];
}

export interface DetectionMatch {
  rule_id?: string | null;
  title: string;
  description?: string | null;
  level?: string | null;
  tags?: string[];
}

export interface AlertEvidence {
  event_id: string;
  event: Record<string, unknown>;
  matches: DetectionMatch[];
}

export interface TriageRecord {
  state: TriageState;
  note: string;
  updated_at: string;
}

export function getSeverity(alert: AlertSummary): Severity {
  const levels = (Array.isArray(alert.levels) ? alert.levels : []).map((level) =>
    String(level).toLowerCase(),
  );
  const order: Severity[] = ["critical", "high", "medium", "low", "informational"];
  return order.find((level) => levels.includes(level)) ?? "unknown";
}

export function asRecord(value: unknown): Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : {};
}

export function asText(value: unknown, fallback = "—"): string {
  if (typeof value === "string" && value.trim()) return value;
  if (typeof value === "number" || typeof value === "boolean") return String(value);
  return fallback;
}

export function readableTime(value: string): string {
  const date = new Date(value);
  return Number.isNaN(date.getTime())
    ? value
    : date.toLocaleString(undefined, { dateStyle: "medium", timeStyle: "short" });
}

export function relativeTime(value: string): string {
  const timestamp = new Date(value).getTime();
  if (Number.isNaN(timestamp)) return "time unavailable";
  const minutes = Math.max(0, Math.floor((Date.now() - timestamp) / 60_000));
  if (minutes < 1) return "just now";
  if (minutes < 60) return `${minutes}m ago`;
  const hours = Math.floor(minutes / 60);
  if (hours < 24) return `${hours}h ago`;
  return `${Math.floor(hours / 24)}d ago`;
}
