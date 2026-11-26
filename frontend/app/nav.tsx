"use client";
import Link from "next/link";
import { usePathname, useRouter } from "next/navigation";
import { useEffect, useState } from "react";
import { getSession, logout, type Session } from "./api";

export default function Nav() {
  const path = usePathname();
  const router = useRouter();
  const [me, setMe] = useState<Session | null>(null);

  useEffect(() => {
    const s = getSession();
    setMe(s);
    if (!s && path !== "/login") router.replace("/login");
  }, [path, router]);

  if (path === "/login") return null;
  return (
    <header className="border-b border-zinc-800 bg-zinc-900/80">
      <nav className="mx-auto flex max-w-7xl items-center gap-6 px-6 py-3">
        <Link href="/" className="font-mono text-lg font-bold tracking-widest text-emerald-400">HYPERION</Link>
        <Link href="/" className="text-sm text-zinc-400 hover:text-zinc-100">Queue</Link>
        <Link href="/system" className="text-sm text-zinc-400 hover:text-zinc-100">System &amp; Audit</Link>
        {me && (
          <div className="ml-auto flex items-center gap-3 text-sm text-zinc-400">
            <span className="font-mono">{me.username} · {me.role}</span>
            <button className="btn" onClick={logout}>Log out</button>
          </div>
        )}
      </nav>
    </header>
  );
}
