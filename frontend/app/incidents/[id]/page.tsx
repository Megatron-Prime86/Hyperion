"use client";
import Link from "next/link";
import { useParams } from "next/navigation";
import { useCallback, useEffect, useState } from "react";
import { ACTIONS, api, download, getSession, useLive, type Enrichment, type IncidentDetail, type PlaybookRun, type UserRef } from "../../api";
import { KillChain } from "../../charts";
import { Badge, Err, Gauge, Loading, fmt, label } from "../../ui";

const SEV = ["info", "low", "medium", "high", "critical"];
const uniq = <T,>(items: T[], key: (t: T) => string) => [...new Map(items.map((i) => [key(i), i])).values()];

function IocBadges({ e }: { e?: Enrichment }) {
  if (!e) return null;
  const verdict = (ind: string) => e.threat_intel.hits.find((h) => h.indicator === ind)?.verdict ?? "";
  const items = [
    ...e.iocs.ips.map((v) => ({ v, full: v, k: "ip", extra: e.ip_classification[v]?.scope })),
    ...e.iocs.domains.map((v) => ({ v, full: v, k: "domain", extra: "" })),
    ...e.iocs.hashes.map((v) => ({ v: v.slice(0, 12) + "…", full: v, k: "hash", extra: "" })),
    ...e.iocs.users.map((v) => ({ v, full: v, k: "user", extra: "" })),
    ...e.iocs.hosts.map((v) => ({ v, full: v, k: "host", extra: "" })),
  ];
  return (
    <div className="mt-2 flex flex-wrap gap-1.5">
      {items.map((i, n) => (
        <Badge key={n} tone={verdict(i.full)} title={verdict(i.full) ? `Threat intel: ${verdict(i.full)}` : i.full}>
          {i.k}:{i.v}{i.extra ? ` (${i.extra})` : ""}
        </Badge>
      ))}
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
    api<IncidentDetail>(`/api/v1/incidents/${id}`).then((x) => { setD(x); setError(""); }).catch((e) => setError(String(e.message)));
  }, [id]);
  useEffect(load, [load]);
  useEffect(() => { api<UserRef[]>("/api/v1/users").then(setUsers).catch(() => setUsers([])); }, []);
  useLive((e) => { if (e.id === id) load(); });

  async function call(fn: () => Promise<unknown>, ok?: string) {
    setBusy(true); setPbMsg(""); setDone("");
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
  const act = (action: string) => call(async () => {
    await api(`/api/v1/incidents/${id}/action`, { method: "POST", body: JSON.stringify({ action, note: note || null }) });
    setNote("");
  }, `Recorded: ${label(action)}`);

  if (error && !d) return <Err msg={error} retry={load} />;
  if (!d) return <Loading rows={5} />;

  const enr = new Map(d.enrichments.map((e) => [e.alert_id, e]));
  const t = d.triage;
  const tactics = [...new Set(d.enrichments.flatMap((e) => e.mitre.tactics))];
  const peak = d.alerts.reduce((m, a) => (SEV.indexOf(a.severity) > SEV.indexOf(m) ? a.severity : m), "info");
  const hits = uniq(d.enrichments.flatMap((e) => e.threat_intel.hits).filter((h) => h.verdict !== "benign"), (h) => h.indicator);
  const assets = uniq(d.enrichments.flatMap((e) => e.asset_criticality.assets).filter((a) => a.level === "high" || a.level === "critical"), (a) => a.name);
  const repeats = d.alerts.reduce((s, a) => s + (a.dup_count - 1), 0);
  const slaTone = (s: string) => s;

  return (
    <div className="space-y-5">
      <Link href="/queue" className="link text-sm">← Back to queue</Link>
      {error && <Err msg={error} />}

      <header className="flex flex-wrap items-start justify-between gap-4">
        <div className="min-w-0 flex-1">
          <h1 className="break-words">{d.title}</h1>
          <p className="mt-1 font-mono text-xs text-muted">{d.entity_type}={d.entity_value} · {d.alert_count} alerts · {fmt(d.first_seen)} → {fmt(d.last_seen)}</p>
          <div className="mt-2 flex flex-wrap gap-2"><Badge tone={d.status}>{label(d.status)}</Badge>{t && <Badge tone={t.triage_verdict === "true_positive" ? "critical" : t.triage_verdict === "false_positive" ? "low" : "medium"}>{label(t.triage_verdict)}</Badge>}</div>
        </div>
        <Gauge score={d.risk_score} tier={d.risk_tier} />
      </header>

      <div className="card flex flex-wrap items-center gap-3 text-sm">
        <label className="flex items-center gap-2 text-muted">Assignee
          <select className="input text-fg" value={d.assignee ?? ""} disabled={busy} onChange={(e) => assign(e.target.value || null)}>
            <option value="">Unassigned</option>
            {users.map((u) => <option key={u.username} value={u.username}>{u.username}</option>)}
          </select>
        </label>
        {session && d.assignee !== session.username && <button className="btn" disabled={busy} onClick={() => assign(session.username)}>Assign to me</button>}
        <Badge tone={slaTone(d.sla.ack_state)}>acknowledge {d.sla.ack_state.replace("_", " ")}</Badge>
        <Badge tone={slaTone(d.sla.resolve_state)}>resolve {d.sla.resolve_state.replace("_", " ")}</Badge>
        <span className="font-mono text-xs text-muted">due {fmt(d.sla.ack_due)} / {fmt(d.sla.resolve_due)}</span>
        <button className="btn ml-auto" onClick={() => download(`/api/v1/incidents/${id}/export`, "incident.md").catch((e) => setError(String(e.message)))}>Export Markdown</button>
      </div>

      {!!tactics.length && (
        <section className="card" aria-labelledby="chain"><h2 id="chain" className="mb-3">Attack stages observed</h2><KillChain observed={tactics} /></section>
      )}

      <div className="grid grid-cols-1 gap-5 lg:grid-cols-[minmax(0,1fr)_20rem]">
        <div className="min-w-0 space-y-5">
          <section className="card" aria-labelledby="triage">
            <div className="mb-3 flex flex-wrap items-center gap-2">
              <h2 id="triage">AI triage</h2>
              {t && <Badge tone={t.provider === "mock" || t.provider === "fallback" ? "mock" : "live"}>{t.provider}{t.model ? ` · ${t.model}` : ""}</Badge>}
            </div>
            {t ? (
              <div className="grid grid-cols-1 gap-5 md:grid-cols-5">
                <div className="min-w-0 [overflow-wrap:anywhere] md:col-span-3">
                  <p className="text-sm leading-relaxed">{t.executive_summary}</p>
                  <h3 className="kicker mt-4">Evidence</h3>
                  <ul className="mt-1 list-disc space-y-1 pl-5 text-sm">{t.evidence_highlights.map((x, i) => <li key={i}>{x}</li>)}</ul>
                  <h3 className="kicker mt-4">Recommended next steps</h3>
                  <ol className="mt-1 list-decimal space-y-1 pl-5 text-sm">{t.recommended_next_steps.map((x, i) => <li key={i}>{x}</li>)}</ol>
                </div>
                <aside className="min-w-0 rounded-lg bg-panel2 p-3 text-sm [overflow-wrap:anywhere] md:col-span-2" aria-label="Risk factors">
                  <h3 className="kicker mb-2">Risk factors</h3>
                  <dl className="space-y-2">
                    <div><dt className="text-muted">Peak alert severity</dt><dd><Badge tone={peak}>{peak}</Badge></dd></div>
                    <div><dt className="text-muted">Correlated alerts</dt><dd className="font-mono">{d.alert_count}{repeats ? ` (+${repeats} repeats folded)` : ""}</dd></div>
                    <div><dt className="text-muted">Threat intel</dt><dd className="flex flex-wrap gap-1">{hits.length ? hits.map((h) => <Badge key={h.indicator} tone={h.verdict} title={h.tags.join(", ")}>{h.indicator.slice(0, 18)}</Badge>) : <span>No known-bad indicators</span>}</dd></div>
                    <div><dt className="text-muted">High-value assets</dt><dd className="flex flex-wrap gap-1">{assets.length ? assets.map((a) => <Badge key={a.name} tone={a.level} title={a.reason}>{a.name}</Badge>) : <span>None</span>}</dd></div>
                    <div><dt className="text-muted">ATT&amp;CK tactics</dt><dd className="font-mono">{tactics.length}</dd></div>
                  </dl>
                </aside>
              </div>
            ) : <p className="text-sm text-muted">No triage report yet.</p>}
          </section>

          {!!d.similar.length && (
            <section className="card" aria-labelledby="similar">
              <h2 id="similar" className="mb-2">Similar past incidents</h2>
              <ul className="space-y-1.5 text-sm">
                {d.similar.map((s) => (
                  <li key={s.id} className="flex flex-wrap items-center gap-2">
                    <Badge tone={s.status}>{label(s.status)}</Badge>
                    <Link href={`/incidents/${s.id}`} className="link">{s.title}</Link>
                    <span className="font-mono text-xs text-muted">{Math.round(s.similarity * 100)}% match</span>
                  </li>
                ))}
              </ul>
            </section>
          )}

          <section className="card" aria-labelledby="playbooks">
            <h2 id="playbooks" className="mb-1">Response playbooks</h2>
            <p className="mb-3 text-xs text-muted">Dry run shows what would happen and is audited. Executing is admin-only and disabled unless the server enables it.</p>
            <ul className="space-y-2 text-sm">
              {d.playbooks.map((p) => (
                <li key={`${p.playbook}:${p.target}`} className="flex flex-wrap items-center gap-2">
                  <span className="w-28 font-medium">{p.label}</span>
                  <span className="font-mono text-xs">{p.target}</span>
                  <span className="text-xs text-muted">{p.allowed ? p.reason : p.blocked_reason}</span>
                  {p.allowed && (
                    <span className="ml-auto flex gap-2">
                      <button className="btn" disabled={busy} onClick={() => runPlaybook(p.playbook, p.target, true)}>Dry run</button>
                      {session?.role === "admin" && (
                        <button className="btn btn-danger" disabled={busy}
                          onClick={() => window.confirm(`Execute ${p.label} on ${p.target}?`) && runPlaybook(p.playbook, p.target, false)}>Execute</button>
                      )}
                    </span>
                  )}
                </li>
              ))}
              {!d.playbooks.length && <li className="text-muted">No actionable entities in this incident.</li>}
            </ul>
            {pbMsg && <p role="status" className="mt-2 text-sm text-accent">{pbMsg}</p>}
            {!!d.playbook_runs.length && (
              <div className="mt-3 space-y-1.5 border-t border-line pt-3 text-xs">
                {d.playbook_runs.map((r) => (
                  <div key={r.id} className="flex flex-wrap items-center gap-2">
                    <Badge tone={r.status === "executed" ? "high" : r.status === "failed" ? "critical" : r.status === "blocked" ? "medium" : "info"}>{r.status.replace("_", " ")}</Badge>
                    <span className="font-mono">{r.playbook} {r.target}</span>
                    <span className="text-muted">{r.actor} · {fmt(r.created_at)}</span>
                    <span>{String(r.result.would ?? r.result.reason ?? r.result.note ?? r.result.error ?? "")}</span>
                  </div>
                ))}
              </div>
            )}
          </section>

          <section className="card" aria-labelledby="timeline">
            <h2 id="timeline" className="mb-3">Alert timeline</h2>
            <ol className="space-y-5 border-l border-line pl-5">
              {d.alerts.map((a) => (
                <li key={a.id} className="relative">
                  <span aria-hidden className="absolute -left-[26px] top-1.5 h-3 w-3 rounded-full border-2 border-app" style={{ background: `var(--t-${a.severity === "info" ? "info" : a.severity})` }} />
                  <div className="flex flex-wrap items-center gap-2 text-sm">
                    <time className="font-mono text-xs text-muted" dateTime={a.event_time}>{fmt(a.event_time)}</time>
                    <Badge tone={a.severity}>{a.severity}</Badge>
                    <Badge>{a.source}</Badge>
                    {a.dup_count > 1 && <Badge tone="medium">×{a.dup_count}</Badge>}
                    {enr.get(a.id)?.mitre.tactics.map((x) => <Badge key={x} tone="info">{x}</Badge>)}
                    <span className="font-medium">{a.title}</span>
                  </div>
                  <p className="mt-1 text-sm text-muted">{a.description}</p>
                  <IocBadges e={enr.get(a.id)} />
                  {!!enr.get(a.id)?.mitre.techniques.length && (
                    <p className="mt-1 text-xs text-muted">{enr.get(a.id)!.mitre.techniques.map((x) => `${x.id} ${x.name}`).join(" · ")}</p>
                  )}
                </li>
              ))}
            </ol>
          </section>

          <section className="card" aria-labelledby="notes">
            <h2 id="notes" className="mb-3">Analyst notes</h2>
            <ul className="mb-3 space-y-2 text-sm">
              {d.comments.map((c) => (
                <li key={c.id}><span className="font-mono text-xs text-muted">{c.author} · {fmt(c.created_at)}</span><p className="whitespace-pre-wrap">{c.body}</p></li>
              ))}
              {!d.comments.length && <li className="text-muted">No notes yet.</li>}
            </ul>
            <label htmlFor="new-note" className="sr-only">New note</label>
            <textarea id="new-note" className="input h-20 w-full" placeholder="Add a note for the next analyst" maxLength={4000} value={comment} onChange={(e) => setComment(e.target.value)} />
            <button className="btn mt-2" disabled={busy || !comment.trim()} onClick={addComment}>Add note</button>
          </section>
        </div>

        <aside className="card h-fit space-y-3 lg:sticky lg:top-20" aria-labelledby="actions">
          <h2 id="actions">Analyst actions</h2>
          <label htmlFor="override" className="sr-only">Override or decision note</label>
          <textarea id="override" className="input h-28 w-full" placeholder="Override / decision note (saved to audit log)" maxLength={2000} value={note} onChange={(e) => setNote(e.target.value)} />
          <div className="grid grid-cols-2 gap-2">
            {ACTIONS.map((a) => (
              <button key={a.id} className={`btn ${a.id === "escalate" ? "btn-danger" : ""}`} disabled={busy} onClick={() => act(a.id)}>{a.label}</button>
            ))}
          </div>
          {done && <p role="status" className="text-sm text-accent">{done}</p>}
        </aside>
      </div>
    </div>
  );
}
