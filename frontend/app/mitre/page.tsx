"use client";
import Link from "next/link";
import { useEffect, useMemo, useState } from "react";
import { TACTICS, api, type MitreStat } from "../api";
import { Empty, Err, Loading } from "../ui";

export default function Mitre() {
  const [days, setDays] = useState(30);
  const [stats, setStats] = useState<MitreStat[] | null>(null);
  const [error, setError] = useState("");
  const [picked, setPicked] = useState<string | null>(null);

  useEffect(() => {
    setStats(null);
    api<MitreStat[]>(`/api/v1/stats/mitre?days=${days}`).then((d) => { setStats(d); setError(""); }).catch((e) => setError(String(e.message)));
  }, [days]);

  const { columns, max } = useMemo(() => {
    const by = new Map<string, MitreStat[]>();
    for (const s of stats ?? []) by.set(s.tactic, [...(by.get(s.tactic) ?? []), s]);
    const names = [...TACTICS.filter((t) => by.has(t)), ...[...by.keys()].filter((t) => !TACTICS.includes(t))];
    return { columns: names.map((t) => ({ tactic: t, items: by.get(t) ?? [] })), max: Math.max(1, ...(stats ?? []).map((s) => s.incidents)) };
  }, [stats]);
  const sel = stats?.find((s) => s.id === picked);

  return (
    <div className="space-y-5">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <h1>MITRE ATT&amp;CK coverage</h1>
        <div className="flex items-center gap-2 text-sm">
          <label htmlFor="range" className="text-muted">Incidents active in the last</label>
          <select id="range" className="input" value={days} onChange={(e) => { setDays(Number(e.target.value)); setPicked(null); }}>
            {[7, 30, 90].map((d) => <option key={d} value={d}>{d} days</option>)}
          </select>
        </div>
      </div>
      <p className="text-sm text-muted">Techniques your incidents hit, grouped by tactic in kill-chain order. Darker cells appeared in more incidents. Select one to see which.</p>

      {error ? <Err msg={error} /> : !stats ? <Loading rows={4} /> : !stats.length ? (
        <Empty title="No techniques observed" hint="Techniques appear once incidents contain alerts that map to MITRE ATT&CK. Try a longer range or run a sample pack." />
      ) : (
        <>
          <div className="overflow-x-auto pb-2">
            <div className="grid min-w-max auto-cols-[11rem] grid-flow-col gap-3">
              {columns.map((c) => (
                <section key={c.tactic} aria-label={c.tactic} className="space-y-2">
                  <h2 className="kicker !text-xs">{c.tactic}</h2>
                  {c.items.map((s) => {
                    const strength = 10 + Math.round((s.incidents / max) * 30); // capped so text keeps AA contrast
                    return (
                      <button key={s.id} aria-pressed={picked === s.id} onClick={() => setPicked(picked === s.id ? null : s.id)}
                        style={{ background: `color-mix(in srgb, var(--accent) ${strength}%, var(--surface))` }}
                        className={`w-full rounded-lg border p-2 text-left text-xs transition ${picked === s.id ? "border-accent ring-2 ring-accent" : "border-line"}`}>
                        <span className="block font-mono font-semibold">{s.id}</span>
                        <span className="block leading-snug">{s.name}</span>
                        <span className="mt-1 block font-mono">{s.incidents} incident{s.incidents === 1 ? "" : "s"} · {s.alerts} alert{s.alerts === 1 ? "" : "s"}</span>
                      </button>
                    );
                  })}
                </section>
              ))}
            </div>
          </div>
          {sel && (
            <section className="card" aria-live="polite">
              <h2 className="mb-2">{sel.id} {sel.name} <span className="font-normal text-muted">({sel.tactic})</span></h2>
              <ul className="space-y-1 text-sm">
                {sel.incident_ids.map((id) => <li key={id}><Link href={`/incidents/${id}`} className="link font-mono">{id}</Link></li>)}
              </ul>
              {sel.incidents > sel.incident_ids.length && <p className="mt-2 text-xs text-muted">Showing {sel.incident_ids.length} of {sel.incidents} incidents.</p>}
            </section>
          )}
        </>
      )}
    </div>
  );
}
