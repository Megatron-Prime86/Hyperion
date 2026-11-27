import type { ReactNode } from "react";

const TONES: Record<string, string> = {
  critical: "border-red-500/40 bg-red-500/15 text-red-300",
  high: "border-orange-500/40 bg-orange-500/15 text-orange-300",
  medium: "border-yellow-500/40 bg-yellow-500/15 text-yellow-300",
  low: "border-emerald-500/40 bg-emerald-500/15 text-emerald-300",
  info: "border-sky-500/40 bg-sky-500/15 text-sky-300",
  malicious: "border-red-500/40 bg-red-500/15 text-red-300",
  suspicious: "border-orange-500/40 bg-orange-500/15 text-orange-300",
  benign: "border-emerald-500/40 bg-emerald-500/15 text-emerald-300",
  live: "border-emerald-500/40 bg-emerald-500/15 text-emerald-300",
  mock: "border-yellow-500/40 bg-yellow-500/15 text-yellow-300",
  escalated: "border-red-500/40 bg-red-500/15 text-red-300",
  acknowledged: "border-sky-500/40 bg-sky-500/15 text-sky-300",
};

export function Badge({ tone = "", children }: { tone?: string; children: ReactNode }) {
  const cls = TONES[tone] ?? "border-zinc-700 bg-zinc-800/60 text-zinc-300";
  return <span className={`inline-block rounded border px-1.5 py-0.5 font-mono text-xs ${cls}`}>{children}</span>;
}

export const fmt = (iso: string) => new Date(iso).toLocaleString(undefined, { hour12: false });
export const label = (s: string) => s.replace(/_/g, " ");

export function Err({ msg }: { msg: string }) {
  return (
    <div className="card border-red-500/40 text-sm text-red-300">
      {msg}. Is the API running at <code>{process.env.NEXT_PUBLIC_API_URL ?? "http://localhost:8000"}</code>?
    </div>
  );
}
