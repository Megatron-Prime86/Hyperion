"use client";
import Link from "next/link";
import { usePathname, useRouter, useSearchParams } from "next/navigation";
import { Suspense, useEffect, useMemo, useState } from "react";
import { CLOSED, api, getSession, useIncidents, type Incident } from "../api";
import { Badge, Empty, Err, Loading, fmt, label } from "../ui";

const STATUSES = ["active", "open", "acknowledged", "escalated", "false_positive", "resolved"];
const TIER_OPTIONS: [string, string][] = [["", "All tiers"], ["critical", "Critical"], ["high", "High"], ["critical,high", "Critical + High"], ["medium", "Medium"], ["low", "Low"]];

function slaBadge(r: Incident) {
  if (CLOSED.includes(r.status)) return <span className="text-muted">—</span>;
  const s = [r.sla.ack_state, r.sla.resolve_state];
  if (s.includes("overdue")) return <Badge tone="overdue">overdue</Badge>;
  if (s.includes("due_soon")) return <Badge tone="due_soon">due soon</Badge>;
  return <Badge tone="ok">ok</Badge>;
}

function QueueInner() {
  const sp = useSearchParams();
  const router = useRouter();
  const pathname = usePathname();
  const { rows, error, reload } = useIncidents();
  const [role, setRole] = useState("");
  const [me, setMe] = useState("");
  const [pack, setPack] = useState("builtin");
  const [busy, setBusy] = useState(false);
  const [simError, setSimError] = useState("");
  const urlQ = sp.get("q") ?? "";
  const [q, setQ] = useState(urlQ);
  const tier = sp.get("tier") ?? "", status = sp.get("status") ?? "", assignee = sp.get("assignee") ?? "", sla = sp.get("sla") ?? "";

  useEffect(() => { setRole(getSession()?.role ?? ""); setMe(getSession()?.username ?? ""); }, []);
  useEffect(() => setQ(urlQ), [urlQ]); // header search and links update the box
  const set = (key: string, value: string) => {
    const p = new URLSearchParams(sp.toString());
    if (value) p.set(key, value); else p.delete(key);
    router.replace(`${pathname}${p.size ? `?${p}` : ""}`, { scroll: false });
  };
  useEffect(() => { // debounce typing into the URL
    if (q === urlQ) return;
    const t = setTimeout(() => set("q", q), 250);
    return () => clearTimeout(t);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [q]);

  async function simulate() {
    setBusy(true); setSimError("");
    try { await api(`/api/v1/simulator/replay?pack=${pack}`, { method: "POST" }); reload(); }
    catch (e) { setSimError(String((e as Error).message)); }
    finally { setBusy(false); }
  }

  const tiers = tier ? tier.split(",") : [];
  const shown = useMemo(() => (rows ?? []).filter((r) =>
    (!status || (status === "active" ? !CLOSED.includes(r.status) : r.status === status)) &&
    (!tiers.length || tiers.includes(r.risk_tier ?? "")) &&
    (!assignee || (assignee === "me" ? r.assignee === me : !r.assignee)) &&
    (!sla || r.sla.ack_state === sla || r.sla.resolve_state === sla) &&
    (!urlQ || `${r.title} ${r.entity_value} ${r.assignee ?? ""}`.toLowerCase().includes(urlQ.toLowerCase())),
  // eslint-disable-next-line react-hooks/exhaustive-deps
  ), [rows, status, tier, assignee, sla, urlQ, me]);
  const filtered = !!(status || tier || assignee || sla || urlQ);

  return (
    <div className="space-y-5">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <h1>Incident queue</h1>
        {role === "admin" && (
          <div className="flex gap-2">
            <select className="input" value={pack} onChange={(e) => setPack(e.target.value)} aria-label="Sample pack">
              <option value="builtin">Built-in scenarios</option>
              <option value="wazuh">Wazuh sample pack</option>
              <option value="cloudtrail">CloudTrail sample pack</option>
            </select>
            <button className="btn btn-primary" onClick={simulate} disabled={busy}>{busy ? "Running…" : "Run Simulation"}</button>
          </div>
        )}
      </div>
      {simError && <Err msg={simError} />}

      <div className="flex flex-wrap items-center gap-2" role="group" aria-label="Filters">
        <input className="input w-full sm:w-64" type="search" placeholder="Search title, entity, assignee…" aria-label="Search incidents" value={q} onChange={(e) => setQ(e.target.value)} />
        <select className="input" aria-label="Risk tier" value={tier} onChange={(e) => set("tier", e.target.value)}>
          {TIER_OPTIONS.map(([v, l]) => <option key={v} value={v}>{l}</option>)}
          {tier && !TIER_OPTIONS.some(([v]) => v === tier) && <option value={tier}>{tier}</option>}
        </select>
        <select className="input" aria-label="Status" value={status} onChange={(e) => set("status", e.target.value)}>
          <option value="">All statuses</option>
          {STATUSES.map((s) => <option key={s} value={s}>{s === "active" ? "Active (not closed)" : label(s)}</option>)}
        </select>
        <select className="input" aria-label="Assignee" value={assignee} onChange={(e) => set("assignee", e.target.value)}>
          <option value="">Anyone</option><option value="me">Assigned to me</option><option value="none">Unassigned</option>
        </select>
        <select className="input" aria-label="SLA" value={sla} onChange={(e) => set("sla", e.target.value)}>
          <option value="">Any SLA</option><option value="overdue">Overdue</option><option value="due_soon">Due soon</option>
        </select>
        {filtered && <button className="btn" onClick={() => { setQ(""); router.replace(pathname, { scroll: false }); }}>Clear filters</button>}
        {rows && <span className="ml-auto text-sm text-muted" aria-live="polite">{shown.length} of {rows.length}</span>}
      </div>

      {error && !rows ? <Err msg={error} retry={reload} /> : !rows ? <Loading rows={6} /> : !shown.length ? (
        <Empty title={rows.length ? "No incidents match these filters" : "No incidents yet"}
          hint={rows.length ? "Try clearing a filter." : "Ingest alerts, or ask an admin to run a simulation or sample pack."} />
      ) : (
        <div className="card overflow-x-auto p-0">
          <table className="w-full">
            <caption className="sr-only">Incidents, highest risk first</caption>
            <thead className="border-b border-line bg-panel2">
              <tr>
                <th scope="col" className="th">Risk</th><th scope="col" className="th">Incident</th>
                <th scope="col" className="th hidden md:table-cell">Entity</th><th scope="col" className="th hidden sm:table-cell">Alerts</th>
                <th scope="col" className="th">Status</th><th scope="col" className="th hidden lg:table-cell">Assignee</th>
                <th scope="col" className="th">SLA</th><th scope="col" className="th hidden xl:table-cell">Last seen</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-line">
              {shown.map((r) => (
                <tr key={r.id} className="hover:bg-panel2">
                  <td className="td whitespace-nowrap"><Badge tone={r.risk_tier ?? ""}>{r.risk_score ?? "–"} {r.risk_tier}</Badge></td>
                  <td className="td"><Link href={`/incidents/${r.id}`} className="link">{r.title}</Link></td>
                  <td className="td hidden font-mono text-xs text-muted md:table-cell">{r.entity_type}={r.entity_value}</td>
                  <td className="td hidden font-mono sm:table-cell">{r.alert_count}</td>
                  <td className="td"><Badge tone={r.status}>{label(r.status)}</Badge></td>
                  <td className="td hidden font-mono text-xs text-muted lg:table-cell">{r.assignee ?? "—"}</td>
                  <td className="td">{slaBadge(r)}</td>
                  <td className="td hidden whitespace-nowrap text-muted xl:table-cell">{fmt(r.last_seen)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}

export default function Queue() {
  return <Suspense fallback={<Loading rows={6} />}><QueueInner /></Suspense>;
}
