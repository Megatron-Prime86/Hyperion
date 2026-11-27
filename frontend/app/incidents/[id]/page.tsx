"use client";
import Link from "next/link";
import { useParams } from "next/navigation";
import { useCallback, useEffect, useState } from "react";
import { ACTIONS, api, download, getSession, useEvents, type Enrichment, type IncidentDetail, type PlaybookRun, type UserRef } from "../../api";
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
  const [users, setUsers] = useState<UserRef[]>([]);
  const [comment, setComment] = useState("");
  const [pbMsg, setPbMsg] = useState("");
  const session = getSession();

  const load = useCallback(() => {
    api<IncidentDetail>(`/api/v1/incidents/${id}`).then(setD).catch((e) => setError(String(e.message)));
  }, [id]);
  useEffect(load, [load]);
  useEffect(() => { api<UserRef[]>("/api/v1/users").then(setUsers).catch(() => setUsers([])); }, []);
  useEvents((e) => { if (e.id === id) load(); });

  async function call(fn: () => Promise<unknown>, ok?: string) {
    setBusy(true); setPbMsg("");
    try { await fn(); if (ok) setDone(ok); load(); }
    catch (e) { setError(String((e as Error).message)); }
    finally { setBusy(false); }
  }
  const assign = (assignee: string | null) => call(() => api(`/api/v1/incidents/${id}/assign`, { method: "POST", body: JSON.stringify({ assignee }) }));
  const addComment = () => call(async () => {
    await api(`/api/v1/incidents/${id}/comments`, { method: "POST", body: JSON.stringify({ body: comment }) });
    setComment("");
  });
  const runPlaybook = (playbook: string, target: string, dry_run: boolean) =>
    call(async () => {
      const r = await api<PlaybookRun>(`/api/v1/incidents/${id}/playbooks/${playbook}`, { method: "POST", body: JSON.stringify({ target, dry_run }) });
      setPbMsg(`${label(playbook)} on ${target}: ${r.status.replace("_", " ")}`);
    });

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

      <div className="card flex flex-wrap items-center gap-3 text-sm">
        <label className="flex items-center gap-2 text-zinc-400">
          Assignee
          <select className="input" value={d.assignee ?? ""} disabled={busy} onChange={(e) => assign(e.target.value || null)}>
            <option value="">Unassigned</option>
            {users.map((u) => <option key={u.username} value={u.username}>{u.username}</option>)}
          </select>
        </label>
        {session && d.assignee !== session.username && <button className="btn" disabled={busy} onClick={() => assign(session.username)}>Assign to me</button>}
        <span className="text-zinc-500">SLA</span>
        <Badge tone={{ ok: "low", met: "low", due_soon: "medium", overdue: "critical", missed: "high" }[d.sla.ack_state]}>acknowledge {d.sla.ack_state.replace("_", " ")}</Badge>
        <Badge tone={{ ok: "low", met: "low", due_soon: "medium", overdue: "critical", missed: "high" }[d.sla.resolve_state]}>resolve {d.sla.resolve_state.replace("_", " ")}</Badge>
        <span className="font-mono text-xs text-zinc-500">due {fmt(d.sla.ack_due)} / {fmt(d.sla.resolve_due)}</span>
        <button className="btn ml-auto" onClick={() => download(`/api/v1/incidents/${id}/export`, "incident.md").catch((e) => setError(String(e.message)))}>Export Markdown</button>
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

          {!!d.similar.length && (
            <section className="card">
              <h2 className="mb-2 font-semibold">Similar past incidents</h2>
              <ul className="space-y-1.5 text-sm">
                {d.similar.map((s) => (
                  <li key={s.id} className="flex flex-wrap items-center gap-2">
                    <Badge tone={s.status}>{label(s.status)}</Badge>
                    <Link href={`/incidents/${s.id}`} className="text-emerald-300 hover:underline">{s.title}</Link>
                    <span className="font-mono text-xs text-zinc-500">{Math.round(s.similarity * 100)}% match</span>
                  </li>
                ))}
              </ul>
            </section>
          )}

          <section className="card">
            <h2 className="mb-1 font-semibold">Response playbooks</h2>
            <p className="mb-3 text-xs text-zinc-500">Dry run shows what would happen and is audited. Executing is admin-only and disabled unless the server enables it.</p>
            <ul className="space-y-2 text-sm">
              {d.playbooks.map((p) => (
                <li key={`${p.playbook}:${p.target}`} className="flex flex-wrap items-center gap-2">
                  <span className="w-28 font-medium">{p.label}</span>
                  <span className="font-mono text-xs">{p.target}</span>
                  <span className="text-xs text-zinc-500">{p.allowed ? p.reason : p.blocked_reason}</span>
                  {p.allowed && (
                    <span className="ml-auto flex gap-2">
                      <button className="btn" disabled={busy} onClick={() => runPlaybook(p.playbook, p.target, true)}>Dry run</button>
                      {session?.role === "admin" && (
                        <button className="btn border-red-500/60 text-red-300" disabled={busy}
                          onClick={() => window.confirm(`Execute ${p.label} on ${p.target}?`) && runPlaybook(p.playbook, p.target, false)}>Execute</button>
                      )}
                    </span>
                  )}
                </li>
              ))}
              {!d.playbooks.length && <li className="text-zinc-500">No actionable entities in this incident.</li>}
            </ul>
            {pbMsg && <p className="mt-2 text-sm text-emerald-400">{pbMsg}</p>}
            {!!d.playbook_runs.length && (
              <div className="mt-3 space-y-1.5 border-t border-zinc-800 pt-3 text-xs">
                {d.playbook_runs.map((r) => (
                  <div key={r.id} className="flex flex-wrap items-center gap-2">
                    <Badge tone={r.status === "executed" ? "high" : r.status === "failed" ? "critical" : r.status === "blocked" ? "medium" : ""}>{r.status.replace("_", " ")}</Badge>
                    <span className="font-mono">{r.playbook} {r.target}</span>
                    <span className="text-zinc-500">{r.actor} · {fmt(r.created_at)}</span>
                    <span className="text-zinc-400">{String(r.result.would ?? r.result.reason ?? r.result.note ?? r.result.error ?? "")}</span>
                  </div>
                ))}
              </div>
            )}
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
          <section className="card">
            <h2 className="mb-3 font-semibold">Analyst notes</h2>
            <ul className="mb-3 space-y-2 text-sm">
              {d.comments.map((c) => (
                <li key={c.id}><span className="font-mono text-xs text-zinc-500">{c.author} · {fmt(c.created_at)}</span><p className="whitespace-pre-wrap">{c.body}</p></li>
              ))}
              {!d.comments.length && <li className="text-zinc-500">No notes yet.</li>}
            </ul>
            <textarea className="input h-20 w-full" placeholder="Add a note for the next analyst" maxLength={4000} value={comment} onChange={(e) => setComment(e.target.value)} />
            <button className="btn mt-2" disabled={busy || !comment.trim()} onClick={addComment}>Add note</button>
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
