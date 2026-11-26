import type { Metadata } from "next";
import Link from "next/link";
import type { ReactNode } from "react";
import "./globals.css";

export const metadata: Metadata = { title: "Hyperion | SOC Triage", description: "AI-powered alert triage & enrichment" };

export default function RootLayout({ children }: { children: ReactNode }) {
  return (
    <html lang="en">
      <body>
        <header className="border-b border-zinc-800 bg-zinc-900/80">
          <nav className="mx-auto flex max-w-7xl items-center gap-6 px-6 py-3">
            <Link href="/" className="font-mono text-lg font-bold tracking-widest text-emerald-400">HYPERION</Link>
            <Link href="/" className="text-sm text-zinc-400 hover:text-zinc-100">Queue</Link>
            <Link href="/system" className="text-sm text-zinc-400 hover:text-zinc-100">System &amp; Audit</Link>
          </nav>
        </header>
        <main className="mx-auto max-w-7xl p-6">{children}</main>
      </body>
    </html>
  );
}
