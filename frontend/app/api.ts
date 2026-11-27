export const API = process.env.NEXT_PUBLIC_API_URL ?? "http://localhost:8000";

export type Incident = {
  id: string; title: string; status: string; severity: string; risk_score: number | null; risk_tier: string | null;
  entity_type: string | null; entity_value: string | null; alert_count: number; summary: string | null;
  first_seen: string; last_seen: string;
};
export type Alert = {
  id: string; source: string; title: string; description: string; severity: string; event_time: string;
  src_ip: string | null; dst_ip: string | null; user: string | null; host: string | null;
  domain: string | null; file_hash: string | null; dup_count: number;
};
export type Enrichment = {
  alert_id: string;
  iocs: Record<string, string[]>;
  ip_classification: Record<string, { scope: string }>;
  threat_intel: { hits: { indicator: string; type: string; verdict: string; tags: string[]; source: string }[]; worst: string };
  asset_criticality: { assets: { type: string; name: string; level: string; reason: string }[]; max_level: string };
  mitre: { techniques: { id: string; name: string; tactic: string }[]; tactics: string[] };
};
export type Triage = {
  risk_score: number; risk_tier: string; triage_verdict: string; executive_summary: string;
  evidence_highlights: string[]; recommended_next_steps: string[]; provider: string; model: string | null; created_at: string;
};
export type IncidentDetail = Incident & { alerts: Alert[]; enrichments: Enrichment[]; triage: Triage | null };
export type Health = { status: string; database: string; llm_mode: string; redis_fallback: boolean };
export type IntelSource = {
  source: string; configured: boolean; ok: boolean; last_error: string | null; last_ok_at: string | null;
  cooldown_until: string | null; lookups: number; cache_entries: number;
};
export type Audit = {
  id: string; actor: string; action: string; target_type: string; target_id: string | null;
  note: string | null; detail: Record<string, unknown>; created_at: string;
};

export type Session = { access_token: string; username: string; role: "analyst" | "admin" };
const KEY = "hyperion.session";

export function getSession(): Session | null {
  if (typeof window === "undefined") return null;
  try { return JSON.parse(sessionStorage.getItem(KEY) ?? "null"); } catch { return null; }
}
export const setSession = (s: Session) => sessionStorage.setItem(KEY, JSON.stringify(s));
export function logout() {
  sessionStorage.removeItem(KEY);
  window.location.assign("/login");
}

export async function api<T>(path: string, init?: RequestInit): Promise<T> {
  const token = getSession()?.access_token;
  const res = await fetch(`${API}${path}`, {
    ...init,
    headers: { "content-type": "application/json", ...(token ? { authorization: `Bearer ${token}` } : {}), ...init?.headers },
    cache: "no-store",
  });
  if (res.status === 401 && !path.startsWith("/api/v1/auth/")) { logout(); throw new Error("Session expired"); }
  if (!res.ok) throw new Error(`${res.status} ${(await res.text()).slice(0, 200)}`);
  return res.json() as Promise<T>;
}

export const ACTIONS = [
  { id: "acknowledge", label: "Acknowledge" },
  { id: "escalate", label: "Escalate" },
  { id: "false_positive", label: "False Positive" },
  { id: "resolve", label: "Resolve" },
] as const;
