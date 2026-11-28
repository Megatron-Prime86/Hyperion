import type { ReactNode } from "react";
import { API } from "./api";

const ALIAS: Record<string, string> = {
  malicious: "critical", suspicious: "high", benign: "low", live: "low", mock: "medium", escalated: "critical",
  acknowledged: "info", ok: "low", met: "low", due_soon: "medium", overdue: "critical", missed: "high",
  resolved: "low", open: "neutral", false_positive: "neutral",
};
const KNOWN = new Set(["critical", "high", "medium", "low", "info", "neutral"]);

export function Badge({ tone = "", children, title }: { tone?: string; children: ReactNode; title?: string }) {
  const t = ALIAS[tone] ?? tone;
  return <span title={title} className={`badge badge-${KNOWN.has(t) ? t : "neutral"}`}>{children}</span>;
}

export const fmt = (iso: string) => new Date(iso).toLocaleString(undefined, { hour12: false });
export const label = (s: string) => s.replace(/_/g, " ");
export function ago(iso: string): string {
  const s = Math.max(0, (Date.now() - new Date(iso).getTime()) / 1000);
  return s < 90 ? "just now" : s < 5400 ? `${Math.round(s / 60)}m ago` : s < 129600 ? `${Math.round(s / 3600)}h ago` : `${Math.round(s / 86400)}d ago`;
}

export function Err({ msg, retry }: { msg: string; retry?: () => void }) {
  return (
    <div role="alert" className="card border-critical/40 text-sm">
      <p className="text-critical">{msg}</p>
      <p className="mt-1 text-muted">Is the API running at <code className="font-mono">{API}</code>?</p>
      {retry && <button className="btn mt-3" onClick={retry}>Retry</button>}
    </div>
  );
}

export function Skeleton({ className = "" }: { className?: string }) {
  return <div aria-hidden className={`skeleton ${className}`} />;
}

export function Loading({ rows = 4 }: { rows?: number }) {
  return (
    <div role="status" aria-live="polite" className="space-y-3">
      <span className="sr-only">Loading…</span>
      {Array.from({ length: rows }, (_, i) => <Skeleton key={i} className="h-12 w-full" />)}
    </div>
  );
}

export function Empty({ title, hint, children }: { title: string; hint?: string; children?: ReactNode }) {
  return (
    <div className="card flex flex-col items-center gap-2 py-10 text-center">
      <p className="font-medium">{title}</p>
      {hint && <p className="max-w-md text-sm text-muted">{hint}</p>}
      {children}
    </div>
  );
}

/** Semicircle risk gauge (0-100) coloured by tier. */
export function Gauge({ score, tier }: { score: number | null; tier: string | null }) {
  const s = Math.max(0, Math.min(100, score ?? 0));
  const color = tier ? `var(--t-${tier})` : "var(--muted)";
  return (
    <figure className="relative w-36 shrink-0" aria-label={`Risk score ${score ?? "not scored"} of 100, ${tier ?? "unknown"} tier`}>
      <svg viewBox="0 0 120 68" aria-hidden>
        <path d="M10 60 A50 50 0 0 1 110 60" fill="none" stroke="var(--line)" strokeWidth="10" strokeLinecap="round" pathLength={100} />
        {s > 0 && <path d="M10 60 A50 50 0 0 1 110 60" fill="none" stroke={color} strokeWidth="10" strokeLinecap="round" pathLength={100} strokeDasharray={`${s} 100`} />}
      </svg>
      <figcaption className="absolute inset-x-0 bottom-0 text-center leading-tight">
        <span className="block font-mono text-3xl font-bold">{score ?? "–"}</span>
        <span className="block text-xs font-medium uppercase tracking-wide" style={{ color }}>{tier ?? "unscored"}</span>
      </figcaption>
    </figure>
  );
}
