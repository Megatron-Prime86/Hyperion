"use client";
import Link from "next/link";
import { useCallback, useEffect, useMemo, useState } from "react";
import { api, getSession, useEvents, type Incident } from "./api";
import { Badge, Err, fmt, label } from "./ui";

const CLOSED = ["resolved", "false_positive"];

function slaBadge(r: Incident) {
  if (CLOSED.includes(r.status)) return <span className="text-zinc-600">—</span>;
  const s = [r.sla.ack_state, r.sla.resolve_state];
  if (s.includes("overdue")) return <Badge tone="critical">overdue</Badge>;
  if (s.includes("due_soon")) return <Badge tone="medium">due soon</Badge>;
  return <Badge tone="low">ok</Badge>;
}

export default function Queue() {
  const [rows, setRows] = useState<Incident[]>([]);
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  const [status, setStatus] = useState("");
  const [tier, setTier] = useState("");
  const [q, setQ] = useState("");
  const [role, setRole] = useState("");
  const [pack, setPack] = useState("builtin");
  const [me, setMe] = useState("");
  const [mine, setMine] = useState(false);
  const [flash, setFlash] = useState("");
  useEffect(() => { setRole(getSession()?.role ?? ""); setMe(getSession()?.username ?? ""); }, []);

  const load = useCallback(() => {
    api<Incident[]>("/api/v1/incidents?limit=500").then((d) => { setRows(d); setError(""); }).catch((e) => setError(String(e.message)));
  }, []);
  useEffect(() => {
    load();
    const t = setInterval(load, 60000); // safety net; live updates arrive over SSE
    return () => clearInterval(t);
  }, [load]);
  useEvents((e) => {
    load();
    if (e.new && e.risk_tier === "critical") setFlash(`New critical incident: ${e.title}`);
  });

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
    () => rows.filter((r) => (!status || r.status === status) && (!tier || r.risk_tier === tier) && (!mine || r.assignee === me) &&
      (!q || `${r.title} ${r.entity_value}`.toLowerCase().includes(q.toLowerCase()))),
    [rows, status, tier, q, mine, me],
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
      {flash && (
        <div role="alert" className="card flex items-center justify-between border-red-500/40 text-sm text-red-300">
          <span>{flash}</span>
          <button className="btn" onClick={() => setFlash("")}>Dismiss</button>
        </div>
      )}
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
        <label className="flex items-center gap-2 text-sm text-zinc-400">
          <input type="checkbox" checked={mine} onChange={(e) => setMine(e.target.checked)} /> Assigned to me
        </label>
      </div>
      <div className="card overflow-x-auto p-0">
        <table className="w-full">
          <thead className="border-b border-zinc-800">
            <tr>{["Risk", "Incident", "Entity", "Alerts", "Status", "Assignee", "SLA", "Last seen"].map((h) => <th key={h} className="th">{h}</th>)}</tr>
          </thead>
          <tbody className="divide-y divide-zinc-800/70">
            {shown.map((r) => (
              <tr key={r.id} className="hover:bg-zinc-800/40">
                <td className="td whitespace-nowrap"><Badge tone={r.risk_tier ?? ""}>{r.risk_score ?? "–"} {r.risk_tier}</Badge></td>
                <td className="td"><Link href={`/incidents/${r.id}`} className="text-emerald-300 hover:underline">{r.title}</Link></td>
                <td className="td font-mono text-xs text-zinc-400">{r.entity_type}={r.entity_value}</td>
                <td className="td font-mono">{r.alert_count}</td>
                <td className="td"><Badge tone={r.status}>{label(r.status)}</Badge></td>
                <td className="td font-mono text-xs text-zinc-400">{r.assignee ?? "—"}</td>
                <td className="td">{slaBadge(r)}</td>
                <td className="td whitespace-nowrap text-zinc-400">{fmt(r.last_seen)}</td>
              </tr>
            ))}
            {!shown.length && <tr><td colSpan={8} className="td text-center text-zinc-500">No incidents. Ask an admin to run the simulation, or ingest alerts with the API key.</td></tr>}
          </tbody>
        </table>
      </div>
    </div>
  );
}
