import type { Metadata } from "next";
import Nav from "./nav";
import type { ReactNode } from "react";
import "./globals.css";

export const metadata: Metadata = { title: "Hyperion | SOC Triage", description: "AI-powered alert triage & enrichment" };

export default function RootLayout({ children }: { children: ReactNode }) {
  return (
    <html lang="en">
      <body>
        <Nav />
        <main className="mx-auto max-w-7xl p-6">{children}</main>
      </body>
    </html>
  );
}
