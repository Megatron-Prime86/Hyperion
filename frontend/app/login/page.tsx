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
    <form onSubmit={submit} className="card mx-auto mt-24 w-full max-w-sm space-y-4">
      <h1 className="font-mono text-xl font-bold tracking-widest text-emerald-400">HYPERION</h1>
      <p className="text-sm text-zinc-400">Sign in to the SOC console.</p>
      <input className="input w-full" placeholder="Username" autoComplete="username" value={username} onChange={(e) => setUsername(e.target.value)} required />
      <input className="input w-full" type="password" placeholder="Password" autoComplete="current-password" value={password} onChange={(e) => setPassword(e.target.value)} required />
      {error && <p className="text-sm text-red-300">{error}</p>}
      <button className="btn w-full border-emerald-600 text-emerald-300" disabled={busy}>{busy ? "Signing in…" : "Sign in"}</button>
    </form>
  );
}
