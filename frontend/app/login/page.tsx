"use client";
import { useRouter } from "next/navigation";
import { useState, type SyntheticEvent } from "react";
import { api, setSession, type Session } from "../api";

export default function Login() {
  const router = useRouter();
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);

  async function submit(e: SyntheticEvent) {
    e.preventDefault();
    setBusy(true); setError("");
    try {
      setSession(await api<Session>("/api/v1/auth/login", { method: "POST", body: JSON.stringify({ username, password }) }));
      router.replace("/");
    } catch (err) {
      setError(/^429/.test((err as Error).message) ? "Too many attempts. Wait a minute." : "Invalid username or password.");
    } finally { setBusy(false); }
  }

  return (
    <main className="grid min-h-dvh place-items-center p-4">
      <form onSubmit={submit} className="card w-full max-w-sm space-y-4">
        <div>
          <h1 className="font-mono text-xl font-bold tracking-widest text-accent">HYPERION</h1>
          <p className="mt-1 text-sm text-muted">Sign in to the SOC console.</p>
        </div>
        <div><label htmlFor="u" className="kicker">Username</label>
          <input id="u" className="input mt-1 w-full" autoComplete="username" value={username} onChange={(e) => setUsername(e.target.value)} required /></div>
        <div><label htmlFor="p" className="kicker">Password</label>
          <input id="p" className="input mt-1 w-full" type="password" autoComplete="current-password" value={password} onChange={(e) => setPassword(e.target.value)} required /></div>
        {error && <p role="alert" className="text-sm text-critical">{error}</p>}
        <button className="btn btn-primary w-full" disabled={busy}>{busy ? "Signing in…" : "Sign in"}</button>
      </form>
    </main>
  );
}
