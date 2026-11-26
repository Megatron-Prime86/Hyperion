"use client";
import Link from "next/link";
import { useEffect, useState } from "react";
import { api, type Audit, type Health } from "../api";
import { Badge, Err, fmt } from "../ui";

export default function System() {
  const [h, setH] = useState<Health | null>(null);
  const [logs, setLogs] = useState<Audit[]>([]);
  const [error, setError] = useState("");

  useEffect(() => {
    const load = () => {
      Promise.all([api<Health>("/api/v1/health"), api<Audit[]>("/api/v1/audit?limit=100")])
        .then(([a, b]) => { setH(a); setLogs(b); setError(""); })
        .catch((e) => setError(String(e.message)));
    };
    load();
    const t = setInterval(load, 10000);
    return () => clearInterval(t);
  }, []);

  const cards: [string, string, string][] = h ? [
    ["API", h.status, "live"],
    ["Database", h.database, "live"],
    ["LLM", h.llm_mode === "mock" ? "mock (deterministic)" : `live · ${h.llm_mode}`, h.llm_mode === "mock" ? "mock" : "live"],
    ["Task queue", h.redis_fallback ? "inline / eager" : "Celery + Redis", h.redis_fallback ? "mock" : "live"],
  ] : [];

  return (
    <div className="space-y-5">
      <h1 className="text-xl font-semibold">System health &amp; audit</h1>
      {error && <Err msg={error} />}
      <div className="grid grid-cols-2 gap-3 md:grid-cols-4">
        {cards.map(([k, v, tone]) => (
          <div key={k} className="card">
            <div className="text-xs uppercase tracking-wide text-zinc-500">{k}</div>
            <div className="mt-2"><Badge tone={tone}>{v}</Badge></div>
          </div>
        ))}
      </div>
      <div className="card overflow-x-auto p-0">
        <table className="w-full">
          <thead className="border-b border-zinc-800">
            <tr>{["Time", "Actor", "Action", "Target", "Note"].map((x) => <th key={x} className="th">{x}</th>)}</tr>
          </thead>
          <tbody className="divide-y divide-zinc-800/70">
            {logs.map((l) => (
              <tr key={l.id}>
                <td className="td whitespace-nowrap text-zinc-400">{fmt(l.created_at)}</td>
                <td className="td font-mono text-xs">{l.actor}</td>
                <td className="td"><Badge>{l.action}</Badge></td>
                <td className="td font-mono text-xs">
                  {l.target_type === "incident" && l.target_id ? <Link className="text-emerald-300 hover:underline" href={`/incidents/${l.target_id}`}>{l.target_id.slice(0, 8)}</Link> : l.target_type}
                </td>
                <td className="td text-zinc-400">{l.note}</td>
              </tr>
            ))}
            {!logs.length && <tr><td colSpan={5} className="td text-center text-zinc-500">No audit entries yet.</td></tr>}
          </tbody>
        </table>
      </div>
    </div>
  );
}
