import Link from "next/link";
import { TACTICS, TIERS } from "./api";

export type Tier = (typeof TIERS)[number];
const STACK: Tier[] = ["low", "medium", "high", "critical"]; // bottom to top

/** Stacked bars of incidents per time bucket, coloured by risk tier. Includes a screen-reader table. */
export function TimeBars({ buckets }: { buckets: { label: string; counts: Record<Tier, number> }[] }) {
  const W = 640, H = 176, L = 28, B = 24, T = 8, plot = H - B - T;
  const total = (b: { counts: Record<Tier, number> }) => TIERS.reduce((s, t) => s + b.counts[t], 0);
  const max = Math.max(1, ...buckets.map(total));
  const bw = (W - L) / buckets.length;
  const step = Math.ceil(buckets.length / 8);
  return (
    <div>
      <svg viewBox={`0 0 ${W} ${H}`} className="h-44 w-full" role="img" aria-label="Incidents over time, stacked by risk tier">
        {[0, max].map((v) => {
          const y = T + plot - (v / max) * plot;
          return (
            <g key={v}>
              <line x1={L} x2={W} y1={y} y2={y} stroke="var(--line)" strokeDasharray={v ? "3 3" : undefined} />
              <text x={L - 6} y={y + 4} textAnchor="end" fontSize="11" fill="var(--muted)">{v}</text>
            </g>
          );
        })}
        {buckets.map((b, i) => {
          let y = T + plot;
          return (
            <g key={i}>
              {STACK.map((t) => {
                const h = (b.counts[t] / max) * plot;
                y -= h;
                return h > 0 ? <rect key={t} x={L + i * bw + bw * 0.15} y={y} width={bw * 0.7} height={h} rx={2} fill={`var(--t-${t})`} /> : null;
              })}
              {i % step === 0 && <text x={L + i * bw + bw / 2} y={H - 6} textAnchor="middle" fontSize="11" fill="var(--muted)">{b.label}</text>}
            </g>
          );
        })}
      </svg>
      <table className="sr-only">
        <caption>Incidents per period by risk tier</caption>
        <thead><tr><th>Period</th>{TIERS.map((t) => <th key={t}>{t}</th>)}</tr></thead>
        <tbody>{buckets.map((b, i) => <tr key={i}><td>{b.label}</td>{TIERS.map((t) => <td key={t}>{b.counts[t]}</td>)}</tr>)}</tbody>
      </table>
    </div>
  );
}

/** Open incidents split by tier; each legend entry links to the filtered queue. */
export function TierBar({ counts }: { counts: Record<Tier, number> }) {
  const total = TIERS.reduce((s, t) => s + counts[t], 0);
  return (
    <div>
      <div className="flex h-3 overflow-hidden rounded-full bg-panel2" role="img" aria-label={TIERS.map((t) => `${counts[t]} ${t}`).join(", ")}>
        {TIERS.map((t) => counts[t] > 0 && <div key={t} style={{ width: `${(counts[t] / total) * 100}%`, background: `var(--t-${t})` }} />)}
      </div>
      <ul className="mt-3 grid grid-cols-2 gap-2 text-sm">
        {TIERS.map((t) => (
          <li key={t}>
            <Link href={`/queue?status=active&tier=${t}`} className="flex items-center gap-2 rounded-md px-1 py-0.5 hover:bg-panel2">
              <span aria-hidden className="h-2.5 w-2.5 rounded-full" style={{ background: `var(--t-${t})` }} />
              <span className="capitalize">{t}</span>
              <span className="ml-auto font-mono">{counts[t]}</span>
            </Link>
          </li>
        ))}
      </ul>
    </div>
  );
}

export function TopEntities({ rows }: { rows: { entity: string; incidents: number; alerts: number; risk: number }[] }) {
  const max = Math.max(1, ...rows.map((r) => r.incidents));
  return (
    <ul className="space-y-2">
      {rows.map((r) => (
        <li key={r.entity}>
          <Link href={`/queue?q=${encodeURIComponent(r.entity)}`} className="block rounded-md px-1 py-1 hover:bg-panel2">
            <div className="flex items-baseline justify-between gap-2 text-sm">
              <span className="truncate font-mono">{r.entity}</span>
              <span className="shrink-0 text-xs text-muted">{r.incidents} inc · {r.alerts} alerts · max risk {r.risk}</span>
            </div>
            <div className="mt-1 h-1.5 rounded-full bg-panel2"><div className="h-full rounded-full bg-accent" style={{ width: `${(r.incidents / max) * 100}%` }} /></div>
          </Link>
        </li>
      ))}
    </ul>
  );
}

/** ATT&CK tactics in kill-chain order; observed ones are highlighted. */
export function KillChain({ observed }: { observed: string[] }) {
  const seen = new Set(observed);
  const extra = observed.filter((t) => !TACTICS.includes(t));
  return (
    <ol className="flex flex-wrap gap-1.5" aria-label="ATT&CK tactics observed in this incident">
      {[...TACTICS, ...extra].map((t, i) => (
        <li key={t} className={`flex items-center gap-1.5 rounded-md border px-2 py-1 text-xs ${seen.has(t) ? "border-accent bg-accent/10 font-medium text-fg" : "border-line text-muted"}`}>
          <span aria-hidden className="font-mono text-[10px]">{i + 1}</span>
          {t}
          {seen.has(t) && <span className="sr-only"> (observed)</span>}
        </li>
      ))}
    </ol>
  );
}
