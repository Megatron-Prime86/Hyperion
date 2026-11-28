"use client";
import Link from "next/link";
import { useCallback, useEffect, useState } from "react";
import { api, useLive, type Audit, type FeedbackRule, type Health, type IntelSource } from "../api";
import { Badge, Empty, Err, Loading, fmt } from "../ui";

export default function System() {
  const [h, setH] = useState<Health | null>(null);
  const [logs, setLogs] = useState<Audit[] | null>(null);
  const [intel, setIntel] = useState<IntelSource[]>([]);
  const [rules, setRules] = useState<FeedbackRule[]>([]);
  const [error, setError] = useState("");

  const load = useCallback(() => {
    Promise.all([api<Health>("/api/v1/health"), api<Audit[]>("/api/v1/audit?limit=100"), api<IntelSource[]>("/api/v1/intel/status"), api<FeedbackRule[]>("/api/v1/feedback/rules")])
      .then(([a, b, c, r]) => { setH(a); setLogs(b); setIntel(c); setRules(r); setError(""); })
      .catch((e) => setError(String(e.message)));
  }, []);
  useEffect(() => { load(); const t = setInterval(load, 30000); return () => clearInterval(t); }, [load]);
  useLive(load);

  if (error && !h) return <Err msg={error} retry={load} />;
  if (!h || !logs) return <Loading rows={5} />;

  const cooling = (i: IntelSource) => !!i.cooldown_until && new Date(i.cooldown_until) > new Date();
  const cards: [string, string, string][] = [
    ["API", h.status, "live"],
    ["Database", h.database, "live"],
    ["LLM", h.llm_mode === "mock" ? "mock (deterministic)" : `live · ${h.llm_mode}`, h.llm_mode === "mock" ? "mock" : "live"],
    ["Task queue", h.redis_fallback ? "inline / eager" : "Celery + Redis", h.redis_fallback ? "mock" : "live"],
  ];

  return (
    <div className="space-y-6">
      <h1>System health &amp; audit</h1>
      {error && <Err msg={error} />}
      <section aria-label="Pipeline status" className="grid grid-cols-2 gap-3 md:grid-cols-4">
        {cards.map(([k, v, tone]) => (
          <div key={k} className="card"><div className="kicker">{k}</div><div className="mt-2"><Badge tone={tone}>{v}</Badge></div></div>
        ))}
      </section>

      <section aria-labelledby="intel"><h2 id="intel" className="mb-3">Threat intel sources</h2>
        <div className="grid grid-cols-2 gap-3 md:grid-cols-5">
          {intel.map((i) => (
            <div key={i.source} className="card space-y-1">
              <div className="font-mono text-sm">{i.source}</div>
              <Badge tone={!i.configured ? "neutral" : cooling(i) || !i.ok ? "high" : "low"}>{!i.configured ? "no key" : cooling(i) ? "cooling down" : i.ok ? "ok" : "error"}</Badge>
              <div className="text-xs text-muted">{i.lookups} lookups · {i.cache_entries} cached</div>
              {i.last_error && <div className="truncate text-xs text-critical" title={i.last_error}>{i.last_error}</div>}
            </div>
          ))}
        </div>
      </section>

      <section aria-labelledby="fb"><h2 id="fb" className="mb-3">Analyst feedback by alert pattern</h2>
        {rules.length ? (
          <div className="card overflow-x-auto p-0">
            <table className="w-full">
              <caption className="sr-only">Decisions per alert pattern</caption>
              <thead className="border-b border-line bg-panel2"><tr>{["Pattern", "False positive", "Escalated", "Resolved", "Effect on scoring"].map((x) => <th key={x} scope="col" className="th">{x}</th>)}</tr></thead>
              <tbody className="divide-y divide-line">
                {rules.map((r) => (
                  <tr key={r.rule_key}>
                    <td className="td">{r.title}</td><td className="td font-mono">{r.false_positive}</td><td className="td font-mono">{r.escalated}</td><td className="td font-mono">{r.resolved}</td>
                    <td className="td">{r.verdict ? <Badge tone={r.verdict === "likely_false_positive" ? "low" : "high"}>{r.verdict.replace(/_/g, " ")}</Badge> : <span className="text-muted">none yet</span>}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : <Empty title="No analyst decisions yet" hint="Mark incidents False Positive or Escalate to teach the scorer." />}
      </section>

      <section aria-labelledby="audit"><h2 id="audit" className="mb-3">Audit log</h2>
        {logs.length ? (
          <div className="card overflow-x-auto p-0">
            <table className="w-full">
              <caption className="sr-only">Most recent audit entries</caption>
              <thead className="border-b border-line bg-panel2"><tr>{["Time", "Actor", "Action", "Target", "Note"].map((x) => <th key={x} scope="col" className="th">{x}</th>)}</tr></thead>
              <tbody className="divide-y divide-line">
                {logs.map((l) => (
                  <tr key={l.id}>
                    <td className="td whitespace-nowrap text-muted">{fmt(l.created_at)}</td>
                    <td className="td font-mono text-xs">{l.actor}</td>
                    <td className="td"><Badge>{l.action}</Badge></td>
                    <td className="td font-mono text-xs">{l.target_type === "incident" && l.target_id ? <Link className="link" href={`/incidents/${l.target_id}`}>{l.target_id.slice(0, 8)}</Link> : l.target_type}</td>
                    <td className="td text-muted">{l.note}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : <Empty title="No audit entries yet" />}
      </section>
    </div>
  );
}
