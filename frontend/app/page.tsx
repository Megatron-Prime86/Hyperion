"use client";
import Link from "next/link";
import { useMemo, useState } from "react";
import { CLOSED, TIERS, useIncidents, type Incident } from "./api";
import { TierBar, TimeBars, TopEntities, type Tier } from "./charts";
import { Badge, Empty, Err, Loading, Skeleton, ago } from "./ui";

const overdue = (r: Incident) => r.sla.ack_state === "overdue" || r.sla.resolve_state === "overdue";

export default function Dashboard() {
  const { rows, error, reload } = useIncidents();
  const [range, setRange] = useState<"24h" | "7d">("24h");

  const open = useMemo(() => (rows ?? []).filter((r) => !CLOSED.includes(r.status)), [rows]);
  const buckets = useMemo(() => {
    const hourly = range === "24h";
    const size = hourly ? 3600e3 : 86400e3;
    const n = hourly ? 24 : 7;
    const end = Math.ceil(Date.now() / size) * size;
    const out = Array.from({ length: n }, (_, i) => {
      const start = end - (n - i) * size;
      const d = new Date(start);
      return { start, label: hourly ? `${String(d.getHours()).padStart(2, "0")}:00` : d.toLocaleDateString(undefined, { weekday: "short" }),
        counts: { critical: 0, high: 0, medium: 0, low: 0 } as Record<Tier, number> };
    });
    for (const r of rows ?? []) {
      const b = out[Math.floor((new Date(r.first_seen).getTime() - (end - n * size)) / size)];
      if (b && r.risk_tier && (TIERS as readonly string[]).includes(r.risk_tier)) b.counts[r.risk_tier as Tier]++;
    }
    return out;
  }, [rows, range]);
  const tiers = useMemo(() => {
    const c: Record<Tier, number> = { critical: 0, high: 0, medium: 0, low: 0 };
    for (const r of open) if (r.risk_tier && r.risk_tier in c) c[r.risk_tier as Tier]++;
    return c;
  }, [open]);
  const entities = useMemo(() => {
    const m = new Map<string, { entity: string; incidents: number; alerts: number; risk: number }>();
    for (const r of open) {
      if (!r.entity_value) continue;
      const e = m.get(r.entity_value) ?? { entity: r.entity_value, incidents: 0, alerts: 0, risk: 0 };
      e.incidents++; e.alerts += r.alert_count; e.risk = Math.max(e.risk, r.risk_score ?? 0);
      m.set(r.entity_value, e);
    }
    return [...m.values()].sort((a, b) => b.incidents - a.incidents || b.risk - a.risk).slice(0, 6);
  }, [open]);
  const attention = useMemo(
    () => [...open].sort((a, b) => Number(overdue(b)) - Number(overdue(a)) || (b.risk_score ?? 0) - (a.risk_score ?? 0)).slice(0, 6),
    [open],
  );

  if (error && !rows) return <Err msg={error} retry={reload} />;
  if (!rows) return (
    <div className="space-y-5"><h1>Dashboard</h1>
      <div className="grid grid-cols-2 gap-3 lg:grid-cols-5">{Array.from({ length: 5 }, (_, i) => <Skeleton key={i} className="h-24" />)}</div>
      <Loading rows={3} /></div>
  );
  if (!rows.length) return (
    <div className="space-y-5"><h1>Dashboard</h1>
      <Empty title="No incidents yet" hint="Send alerts to the ingest API, or ask an admin to run a simulation or a sample pack from the queue.">
        <Link href="/queue" className="btn btn-primary mt-2">Go to queue</Link>
      </Empty></div>
  );

  const critHigh = open.filter((r) => r.risk_tier === "critical" || r.risk_tier === "high").length;
  const kpis = [
    { k: "Open incidents", v: open.length, href: "/queue?status=active" },
    { k: "Critical / High", v: critHigh, href: "/queue?status=active&tier=critical,high", tone: critHigh ? "text-critical" : "" },
    { k: "SLA overdue", v: open.filter(overdue).length, href: "/queue?status=active&sla=overdue", tone: open.some(overdue) ? "text-critical" : "" },
    { k: "Unassigned", v: open.filter((r) => !r.assignee).length, href: "/queue?status=active&assignee=none" },
    { k: "Avg risk (open)", v: open.length ? Math.round(open.reduce((s, r) => s + (r.risk_score ?? 0), 0) / open.length) : 0, href: "/queue?status=active" },
  ];

  return (
    <div className="space-y-5">
      <h1>Dashboard</h1>
      <div className="grid grid-cols-2 gap-3 lg:grid-cols-5">
        {kpis.map((c) => (
          <Link key={c.k} href={c.href} className="card block transition hover:border-accent">
            <div className="kicker">{c.k}</div>
            <div className={`mt-1 font-mono text-3xl ${c.tone ?? ""}`}>{c.v}</div>
          </Link>
        ))}
      </div>

      <div className="grid grid-cols-1 gap-5 lg:grid-cols-3">
        <section className="card lg:col-span-2" aria-labelledby="over-time">
          <div className="mb-2 flex items-center justify-between">
            <h2 id="over-time">Incidents over time</h2>
            <div className="flex gap-1" role="group" aria-label="Time range">
              {(["24h", "7d"] as const).map((r) => (
                <button key={r} className={`btn ${range === r ? "btn-primary" : ""}`} aria-pressed={range === r} onClick={() => setRange(r)}>{r}</button>
              ))}
            </div>
          </div>
          <TimeBars buckets={buckets} />
        </section>
        <section className="card" aria-labelledby="risk-dist">
          <h2 id="risk-dist" className="mb-3">Open risk distribution</h2>
          {open.length ? <TierBar counts={tiers} /> : <p className="text-sm text-muted">No open incidents.</p>}
        </section>
      </div>

      <div className="grid grid-cols-1 gap-5 lg:grid-cols-2">
        <section className="card" aria-labelledby="attention">
          <h2 id="attention" className="mb-3">Needs attention</h2>
          <ul className="divide-y divide-line">
            {attention.map((r) => (
              <li key={r.id} className="flex items-center gap-3 py-2">
                <Badge tone={r.risk_tier ?? ""}>{r.risk_score ?? "–"}</Badge>
                <div className="min-w-0 flex-1">
                  <Link href={`/incidents/${r.id}`} className="link block truncate">{r.title}</Link>
                  <span className="text-xs text-muted">{r.assignee ?? "unassigned"} · {ago(r.last_seen)}</span>
                </div>
                {overdue(r) && <Badge tone="overdue">SLA overdue</Badge>}
              </li>
            ))}
            {!attention.length && <li className="py-2 text-sm text-muted">Nothing open. Nice.</li>}
          </ul>
        </section>
        <section className="card" aria-labelledby="top-ent">
          <h2 id="top-ent" className="mb-3">Top entities (open)</h2>
          {entities.length ? <TopEntities rows={entities} /> : <p className="text-sm text-muted">No open incidents.</p>}
        </section>
      </div>
      <p className="text-xs text-muted">Charts and counts update live.</p>
    </div>
  );
}
