"use client";
import Link from "next/link";
import { useParams } from "next/navigation";
import { useCallback, useEffect, useState } from "react";
import { ACTIONS, api, type Enrichment, type IncidentDetail } from "../../api";
import { Badge, Err, fmt, label } from "../../ui";

function IocBadges({ e }: { e?: Enrichment }) {
  if (!e) return null;
  const verdict = (ind: string) => e.threat_intel.hits.find((h) => h.indicator === ind)?.verdict ?? "";
  const items = [
    ...e.iocs.ips.map((v) => ({ v, k: "ip", extra: e.ip_classification[v]?.scope })),
    ...e.iocs.domains.map((v) => ({ v, k: "domain", extra: "" })),
    ...e.iocs.hashes.map((v) => ({ v: v.slice(0, 12) + "…", full: v, k: "hash", extra: "" })),
    ...e.iocs.users.map((v) => ({ v, k: "user", extra: "" })),
    ...e.iocs.hosts.map((v) => ({ v, k: "host", extra: "" })),
  ];
  return (
    <div className="mt-2 flex flex-wrap gap-1.5">
      {items.map((i, n) => (
        <Badge key={n} tone={verdict((i as { full?: string }).full ?? i.v)}>
          {i.k}:{i.v}{i.extra ? ` (${i.extra})` : ""}
        </Badge>
      ))}
      {e.mitre.techniques.map((t) => <Badge key={t.id} tone="info">{t.id} {t.name}</Badge>)}
    </div>
  );
}

export default function IncidentPage() {
  const { id } = useParams<{ id: string }>();
  const [d, setD] = useState<IncidentDetail | null>(null);
  const [error, setError] = useState("");
  const [note, setNote] = useState("");
  const [busy, setBusy] = useState(false);
  const [done, setDone] = useState("");

  const load = useCallback(() => {
    api<IncidentDetail>(`/api/v1/incidents/${id}`).then(setD).catch((e) => setError(String(e.message)));
  }, [id]);
  useEffect(load, [load]);

  async function act(action: string) {
    setBusy(true); setDone("");
    try {
      await api(`/api/v1/incidents/${id}/action`, { method: "POST", body: JSON.stringify({ action, note: note || null }) });
      setNote(""); setDone(`Recorded: ${label(action)}`); load();
    } catch (e) { setError(String((e as Error).message)); }
    finally { setBusy(false); }
  }

  if (error) return <Err msg={error} />;
  if (!d) return <p className="text-zinc-500">Loading…</p>;
  const enr = new Map(d.enrichments.map((e) => [e.alert_id, e]));
  const t = d.triage;
  const tactics = [...new Set(d.enrichments.flatMap((e) => e.mitre.tactics))];

  return (
    <div className="space-y-5">
      <Link href="/" className="text-sm text-zinc-400 hover:text-zinc-100">← Queue</Link>
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div>
          <h1 className="text-xl font-semibold">{d.title}</h1>
          <p className="mt-1 font-mono text-xs text-zinc-500">{d.entity_type}={d.entity_value} · {d.alert_count} alerts · {fmt(d.first_seen)} → {fmt(d.last_seen)}</p>
        </div>
        <div className="flex gap-2">
          <Badge tone={d.risk_tier ?? ""}>{d.risk_score ?? "–"}/100 {d.risk_tier}</Badge>
          <Badge tone={d.status}>{label(d.status)}</Badge>
        </div>
      </div>

      <div className="grid gap-5 lg:grid-cols-3">
        <div className="space-y-5 lg:col-span-2">
          <section className="card">
            <div className="mb-2 flex items-center gap-2">
              <h2 className="font-semibold">AI triage</h2>
              {t && <Badge tone={t.triage_verdict === "true_positive" ? "critical" : t.triage_verdict === "false_positive" ? "low" : "medium"}>{label(t.triage_verdict)}</Badge>}
              {t && <Badge tone={t.provider === "mock" || t.provider === "fallback" ? "mock" : "live"}>{t.provider}{t.model ? ` · ${t.model}` : ""}</Badge>}
            </div>
            {t ? (
              <>
                <p className="text-sm leading-relaxed">{t.executive_summary}</p>
                <h3 className="mt-3 text-xs uppercase tracking-wide text-zinc-500">Evidence</h3>
                <ul className="mt-1 list-disc space-y-1 pl-5 text-sm">{t.evidence_highlights.map((x, i) => <li key={i}>{x}</li>)}</ul>
                <h3 className="mt-3 text-xs uppercase tracking-wide text-zinc-500">Recommended next steps</h3>
                <ol className="mt-1 list-decimal space-y-1 pl-5 text-sm">{t.recommended_next_steps.map((x, i) => <li key={i}>{x}</li>)}</ol>
              </>
            ) : <p className="text-sm text-zinc-500">No triage report yet.</p>}
            {!!tactics.length && <div className="mt-3 flex flex-wrap gap-1.5">{tactics.map((x) => <Badge key={x} tone="info">{x}</Badge>)}</div>}
          </section>

          <section className="card">
            <h2 className="mb-3 font-semibold">Alert timeline</h2>
            <ol className="space-y-4 border-l border-zinc-700 pl-4">
              {d.alerts.map((a) => (
                <li key={a.id} className="relative">
                  <span className="absolute -left-[21px] top-1.5 h-2.5 w-2.5 rounded-full bg-emerald-500" />
                  <div className="flex flex-wrap items-center gap-2 text-sm">
                    <span className="font-mono text-xs text-zinc-500">{fmt(a.event_time)}</span>
                    <Badge tone={a.severity}>{a.severity}</Badge>
                    <Badge>{a.source}</Badge>
                    {a.dup_count > 1 && <Badge tone="medium">×{a.dup_count}</Badge>}
                    <span className="font-medium">{a.title}</span>
                  </div>
                  <p className="mt-1 text-sm text-zinc-400">{a.description}</p>
                  <IocBadges e={enr.get(a.id)} />
                </li>
              ))}
            </ol>
          </section>
        </div>

        <section className="card h-fit space-y-3">
          <h2 className="font-semibold">Analyst actions</h2>
          <textarea className="input h-28 w-full" placeholder="Override / decision note (saved to audit log)" maxLength={2000} value={note} onChange={(e) => setNote(e.target.value)} />
          <div className="grid grid-cols-2 gap-2">
            {ACTIONS.map((a) => (
              <button key={a.id} className={`btn ${a.id === "escalate" ? "border-red-500/60 text-red-300" : ""}`} disabled={busy} onClick={() => act(a.id)}>{a.label}</button>
            ))}
          </div>
          {done && <p className="text-sm text-emerald-400">{done}</p>}
        </section>
      </div>
    </div>
  );
}
