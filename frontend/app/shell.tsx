"use client";
import Link from "next/link";
import { usePathname, useRouter } from "next/navigation";
import { useEffect, useRef, useState, type ReactNode, type SyntheticEvent } from "react";
import { getSession, logout, useEvents, useLive, type LiveEvent, type Session } from "./api";

const Icon = ({ d }: { d: string }) => (
  <svg viewBox="0 0 24 24" width="18" height="18" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round" aria-hidden><path d={d} /></svg>
);
const NAV = [
  { href: "/", label: "Dashboard", d: "M3 3h7v9H3zM14 3h7v5h-7zM14 12h7v9h-7zM3 16h7v5H3z" },
  { href: "/queue", label: "Queue", d: "M4 6h16M4 12h16M4 18h10" },
  { href: "/mitre", label: "ATT&CK", d: "M3 3h6v6H3zM15 3h6v6h-6zM3 15h6v6H3zM15 15h6v6h-6z" },
  { href: "/system", label: "System & Audit", d: "M12 8a4 4 0 1 0 0 8 4 4 0 0 0 0-8zM12 2v3M12 19v3M2 12h3M19 12h3M4.9 4.9l2.1 2.1M17 17l2.1 2.1M19.1 4.9 17 7M7 17l-2.1 2.1" },
];
const SUN = "M12 7a5 5 0 1 0 0 10 5 5 0 0 0 0-10zM12 1v2M12 21v2M1 12h2M21 12h2M4.2 4.2l1.4 1.4M18.4 18.4l1.4 1.4M19.8 4.2l-1.4 1.4M5.6 18.4l-1.4 1.4";
const MOON = "M21 12.8A9 9 0 1 1 11.2 3a7 7 0 0 0 9.8 9.8z";

export default function Shell({ children }: { children: ReactNode }) {
  const path = usePathname();
  const router = useRouter();
  const [me, setMe] = useState<Session | null>(null);
  const [menu, setMenu] = useState(false);
  const [theme, setTheme] = useState("dark");
  const [alert, setAlert] = useState<LiveEvent | null>(null);
  const search = useRef<HTMLInputElement>(null);
  const onLogin = path === "/login";

  useEffect(() => {
    const s = getSession();
    setMe(s);
    if (!s && !onLogin) router.replace("/login");
  }, [path, router, onLogin]);
  useEffect(() => setTheme(document.documentElement.dataset.theme ?? "dark"), []);
  useEffect(() => setMenu(false), [path]);
  useEvents(!!me);
  useLive((e) => { if (e.new && e.risk_tier === "critical") setAlert(e); });
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      const t = e.target as HTMLElement;
      const typing = /INPUT|TEXTAREA|SELECT/.test(t.tagName) || t.isContentEditable;
      if (e.key === "/" && !typing) { e.preventDefault(); search.current?.focus(); }
      if (e.key === "Escape") setMenu(false);
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, []);

  function toggleTheme() {
    const next = theme === "dark" ? "light" : "dark";
    document.documentElement.dataset.theme = next;
    try { localStorage.setItem("hyperion.theme", next); } catch { /* storage unavailable */ }
    setTheme(next);
  }
  function submit(e: SyntheticEvent<HTMLFormElement>) {
    e.preventDefault();
    const q = String(new FormData(e.currentTarget).get("q") ?? "").trim();
    router.push(q ? `/queue?q=${encodeURIComponent(q)}` : "/queue");
  }

  if (onLogin) return <>{children}</>;
  return (
    <>
      <a href="#main" className="skip">Skip to content</a>
      <div className="min-h-dvh lg:grid lg:grid-cols-[14.5rem_minmax(0,1fr)]">
        <aside aria-label="Primary" className={`${menu ? "fixed" : "hidden"} inset-y-0 left-0 z-40 w-60 flex-col gap-1 border-r border-line bg-panel p-3 lg:sticky lg:top-0 lg:flex lg:h-dvh`}>
          <Link href="/" className="mb-3 px-2 py-2 font-mono text-lg font-bold tracking-widest text-accent">HYPERION</Link>
          <nav className="flex flex-col gap-1">
            {NAV.map((n) => {
              const active = n.href === "/" ? path === "/" : path.startsWith(n.href);
              return (
                <Link key={n.href} href={n.href} aria-current={active ? "page" : undefined}
                  className={`flex items-center gap-3 rounded-md px-3 py-2 text-sm font-medium ${active ? "bg-accent/15 text-accent" : "text-muted hover:bg-panel2 hover:text-fg"}`}>
                  <Icon d={n.d} />{n.label}
                </Link>
              );
            })}
          </nav>
          {me && (
            <div className="mt-auto border-t border-line pt-3 text-sm">
              <p className="px-2 font-mono text-xs text-muted">{me.username} · {me.role}</p>
              <button className="btn mt-2 w-full" onClick={logout}>Log out</button>
            </div>
          )}
        </aside>
        {menu && <button className="fixed inset-0 z-30 bg-black/50 lg:hidden" aria-label="Close menu" onClick={() => setMenu(false)} />}

        <div className="min-w-0">
          <header className="sticky top-0 z-20 flex items-center gap-3 border-b border-line bg-app/90 px-4 py-2.5 backdrop-blur">
            <button className="btn lg:hidden" aria-label="Open menu" aria-expanded={menu} onClick={() => setMenu(true)}><Icon d="M4 6h16M4 12h16M4 18h16" /></button>
            <form role="search" onSubmit={submit} className="max-w-md flex-1">
              <label htmlFor="global-search" className="sr-only">Search incidents</label>
              <input id="global-search" ref={search} name="q" className="input w-full" placeholder="Search incidents  ( / )" autoComplete="off" />
            </form>
            <button className="btn ml-auto" onClick={toggleTheme} aria-label={`Switch to ${theme === "dark" ? "light" : "dark"} mode`}>
              <Icon d={theme === "dark" ? SUN : MOON} /><span className="hidden sm:inline">{theme === "dark" ? "Light" : "Dark"}</span>
            </button>
          </header>
          {alert && (
            <div role="alert" className="mx-4 mt-4 flex items-center justify-between gap-3 rounded-lg border border-critical/40 bg-critical/10 px-4 py-2.5 text-sm sm:mx-6">
              <span><strong className="text-critical">New critical incident:</strong> {alert.title}</span>
              <span className="flex shrink-0 gap-2">
                <Link href={`/incidents/${alert.id}`} className="btn" onClick={() => setAlert(null)}>View</Link>
                <button className="btn" onClick={() => setAlert(null)}>Dismiss</button>
              </span>
            </div>
          )}
          <main id="main" tabIndex={-1} className="mx-auto max-w-7xl p-4 outline-none sm:p-6">{children}</main>
        </div>
      </div>
    </>
  );
}
