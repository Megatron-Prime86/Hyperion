"use client";
import Link from "next/link";
import { useCallback, useEffect, useMemo, useState } from "react";
import { api, getSession, type Incident } from "./api";
import { Badge, Err, fmt, label } from "./ui";

const CLOSED = ["resolved", "false_positive"];

export default function Queue() {
  const [rows, setRows] = useState<Incident[]>([]);
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  const [status, setStatus] = useState("");
  const [tier, setTier] = useState("");
  const [q, setQ] = useState("");
  const [role, setRole] = useState("");
  const [pack, setPack] = useState("builtin");
  useEffect(() => setRole(getSession()?.role ?? ""), []);

  const load = useCallback(() => {
    api<Incident[]>("/api/v1/incidents?limit=500").then((d) => { setRows(d); setError(""); }).catch((e) => setError(String(e.message)));
  }, []);
  useEffect(() => {
    load();
    const t = setInterval(load, 10000);
    return () => clearInterval(t);
  }, [load]);

  async function simulate() {
    setBusy(true);
    try { await api(`/api/v1/simulator/replay?pack=${pack}`, { method: "POST" }); load(); }
    catch (e) { setError(String((e as Error).message)); }
    finally { setBusy(false); }
  }

  const open = rows.filter((r) => !CLOSED.includes(r.status));
  const kpis = [
    ["Open incidents", open.length],
    ["Critical / High", open.filter((r) => r.risk_tier === "critical" || r.risk_tier === "high").length],
    ["Escalated", rows.filter((r) => r.status === "escalated").length],
    ["Avg risk (open)", open.length ? Math.round(open.reduce((s, r) => s + (r.risk_score ?? 0), 0) / open.length) : 0],
    ["Alerts correlated", rows.reduce((s, r) => s + r.alert_count, 0)],
  ];
  const shown = useMemo(
    () => rows.filter((r) => (!status || r.status === status) && (!tier || r.risk_tier === tier) &&
      (!q || `${r.title} ${r.entity_value}`.toLowerCase().includes(q.toLowerCase()))),
    [rows, status, tier, q],
  );

  return (
    <div className="space-y-5">
      <div className="flex items-center justify-between">
        <h1 className="text-xl font-semibold">Incident queue</h1>
        {role === "admin" && (
          <div className="flex gap-2">
            <select className="input" value={pack} onChange={(e) => setPack(e.target.value)} aria-label="Sample pack">
              <option value="builtin">Built-in scenarios</option>
              <option value="wazuh">Wazuh sample pack</option>
              <option value="cloudtrail">CloudTrail sample pack</option>
            </select>
            <button className="btn border-emerald-600 text-emerald-300" onClick={simulate} disabled={busy}>
              {busy ? "Running…" : "Run Simulation"}
            </button>
          </div>
        )}
      </div>
      {error && <Err msg={error} />}
      <div className="grid grid-cols-2 gap-3 md:grid-cols-5">
        {kpis.map(([k, v]) => (
          <div key={k} className="card">
            <div className="text-xs uppercase tracking-wide text-zinc-500">{k}</div>
            <div className="mt-1 font-mono text-3xl text-zinc-100">{v}</div>
          </div>
        ))}
      </div>
      <div className="flex flex-wrap gap-2">
        <input className="input w-64" placeholder="Search title or entity…" value={q} onChange={(e) => setQ(e.target.value)} />
        <select className="input" value={tier} onChange={(e) => setTier(e.target.value)}>
          <option value="">All tiers</option>
          {["critical", "high", "medium", "low"].map((t) => <option key={t}>{t}</option>)}
        </select>
        <select className="input" value={status} onChange={(e) => setStatus(e.target.value)}>
          <option value="">All statuses</option>
          {["open", "acknowledged", "escalated", "false_positive", "resolved"].map((s) => <option key={s} value={s}>{label(s)}</option>)}
        </select>
      </div>
      <div className="card overflow-x-auto p-0">
        <table className="w-full">
          <thead className="border-b border-zinc-800">
            <tr>{["Risk", "Incident", "Entity", "Alerts", "Status", "Last seen"].map((h) => <th key={h} className="th">{h}</th>)}</tr>
          </thead>
          <tbody className="divide-y divide-zinc-800/70">
            {shown.map((r) => (
              <tr key={r.id} className="hover:bg-zinc-800/40">
                <td className="td whitespace-nowrap"><Badge tone={r.risk_tier ?? ""}>{r.risk_score ?? "–"} {r.risk_tier}</Badge></td>
                <td className="td"><Link href={`/incidents/${r.id}`} className="text-emerald-300 hover:underline">{r.title}</Link></td>
                <td className="td font-mono text-xs text-zinc-400">{r.entity_type}={r.entity_value}</td>
                <td className="td font-mono">{r.alert_count}</td>
                <td className="td"><Badge tone={r.status}>{label(r.status)}</Badge></td>
                <td className="td whitespace-nowrap text-zinc-400">{fmt(r.last_seen)}</td>
              </tr>
            ))}
            {!shown.length && <tr><td colSpan={6} className="td text-center text-zinc-500">No incidents. Ask an admin to run the simulation, or ingest alerts with the API key.</td></tr>}
          </tbody>
        </table>
      </div>
    </div>
  );
}
