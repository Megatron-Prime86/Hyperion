import type { Metadata } from "next";
import type { ReactNode } from "react";
import Shell from "./shell";
import "./globals.css";

export const metadata: Metadata = { title: "Hyperion | SOC Triage", description: "AI-powered alert triage & enrichment" };

// Runs before first paint so the saved (or system) theme is applied without a flash.
const THEME_INIT = `(function(){try{var t=localStorage.getItem("hyperion.theme");if(!t){t=matchMedia("(prefers-color-scheme: light)").matches?"light":"dark"}document.documentElement.dataset.theme=t}catch(e){document.documentElement.dataset.theme="dark"}})()`;

export default function RootLayout({ children }: { children: ReactNode }) {
  return (
    <html lang="en" data-theme="dark" suppressHydrationWarning>
      <head><script dangerouslySetInnerHTML={{ __html: THEME_INIT }} /></head>
      <body><Shell>{children}</Shell></body>
    </html>
  );
}
