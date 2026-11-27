import { useEffect, useRef } from "react";

export const API = process.env.NEXT_PUBLIC_API_URL ?? "http://localhost:8000";

export type Sla = { ack_due: string; ack_state: string; resolve_due: string; resolve_state: string };
export type Incident = {
  id: string; title: string; status: string; severity: string; risk_score: number | null; risk_tier: string | null;
  entity_type: string | null; entity_value: string | null; alert_count: number; summary: string | null;
  first_seen: string; last_seen: string; created_at: string; assignee: string | null;
  acknowledged_at: string | null; resolved_at: string | null; sla: Sla;
};
export type Comment = { id: string; author: string; body: string; created_at: string };
export type PlaybookRun = {
  id: string; playbook: string; target: string; dry_run: boolean; status: string; result: Record<string, unknown>;
  actor: string; created_at: string;
};
export type Suggestion = {
  playbook: string; label: string; target: string; allowed: boolean; blocked_reason: string | null; reason: string;
};
export type UserRef = { username: string; role: string };
export type LiveEvent = {
  type: string; id: string; title: string; status: string; risk_score: number | null; risk_tier: string | null;
  assignee: string | null; new: boolean;
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
export type Similar = { id: string; title: string; status: string; risk_score: number | null; similarity: number; last_seen: string };
export type FeedbackRule = {
  rule_key: string; title: string; false_positive: number; escalated: number; resolved: number; verdict: string | null;
};
export type IncidentDetail = Incident & {
  alerts: Alert[]; enrichments: Enrichment[]; triage: Triage | null; similar: Similar[];
  comments: Comment[]; playbook_runs: PlaybookRun[]; playbooks: Suggestion[];
};
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

/** Download an authenticated file (the API needs the Bearer token, so a plain link will not work). */
export async function download(path: string, fallbackName: string) {
  const token = getSession()?.access_token;
  const res = await fetch(`${API}${path}`, { headers: token ? { authorization: `Bearer ${token}` } : {} });
  if (!res.ok) throw new Error(`${res.status} export failed`);
  const name = /filename="([^"]+)"/.exec(res.headers.get("content-disposition") ?? "")?.[1] ?? fallbackName;
  const url = URL.createObjectURL(await res.blob());
  const a = Object.assign(document.createElement("a"), { href: url, download: name });
  a.click();
  URL.revokeObjectURL(url);
}

/** Live incident updates via server-sent events (fetch streaming so the Authorization header can be sent). Reconnects with backoff. */
export function useEvents(onEvent: (e: LiveEvent) => void) {
  const handler = useRef(onEvent);
  handler.current = onEvent;
  useEffect(() => {
    const ctl = new AbortController();
    let since = new Date().toISOString();
    (async () => {
      let delay = 1000;
      while (!ctl.signal.aborted) {
        try {
          const token = getSession()?.access_token;
          const res = await fetch(`${API}/api/v1/events?since=${encodeURIComponent(since)}`, {
            headers: token ? { authorization: `Bearer ${token}` } : {}, signal: ctl.signal,
          });
          if (!res.ok || !res.body) throw new Error(String(res.status));
          delay = 1000;
          const reader = res.body.pipeThrough(new TextDecoderStream()).getReader();
          let buf = "";
          for (;;) {
            const { value, done } = await reader.read();
            if (done) break;
            buf += value;
            const frames = buf.split("\n\n");
            buf = frames.pop() ?? "";
            for (const f of frames) {
              const data = f.split("\n").find((l) => l.startsWith("data: "));
              if (!data) continue;
              try {
                const ev = JSON.parse(data.slice(6));
                if (ev.type === "incident_changed") { since = ev.updated_at; handler.current(ev as LiveEvent); }
              } catch { /* ignore malformed frame */ }
            }
          }
        } catch { /* fall through to retry */ }
        if (ctl.signal.aborted) return;
        await new Promise((r) => setTimeout(r, delay));
        delay = Math.min(delay * 2, 15000);
      }
    })();
    return () => ctl.abort();
  }, []);
}
