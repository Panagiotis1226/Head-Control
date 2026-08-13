import { useState, type FormEvent } from "react";
import { post } from "../api/client";
import { Button, Input } from "../components/ui";

export function LoginPage({ onLoggedIn }: { onLoggedIn: (csrf: string) => void }) {
  const [password, setPassword] = useState("");
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    setBusy(true);
    setError("");
    try {
      const res = await post<{ csrfToken: string }>("/api/auth/login", { password });
      onLoggedIn(res.csrfToken);
    } catch (err) {
      setError(err instanceof Error ? err.message : "login failed");
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="flex min-h-screen items-center justify-center bg-slate-50 px-4 dark:bg-slate-950">
      <div className="w-full max-w-sm">
        <div className="mb-6 text-center">
          <h1 className="text-2xl font-bold tracking-tight text-slate-900 dark:text-slate-100">
            Head-<span className="text-indigo-600 dark:text-indigo-400">Control</span>
          </h1>
          <p className="mt-1 text-sm text-slate-500 dark:text-slate-400">headscale admin console</p>
        </div>
        <form
          onSubmit={submit}
          className="space-y-4 rounded-lg border border-slate-200 bg-white p-6 shadow-sm dark:border-slate-700 dark:bg-slate-900"
        >
          <label className="block space-y-1">
            <span className="text-sm font-medium text-slate-700 dark:text-slate-200">Admin password</span>
            <Input
              type="password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              autoFocus
              autoComplete="current-password"
            />
          </label>
          {error && <p className="text-sm text-red-600 dark:text-red-400">{error}</p>}
          <Button type="submit" variant="primary" className="w-full justify-center" loading={busy}>
            Sign in
          </Button>
        </form>
        <p className="mt-4 text-center text-xs text-slate-400">
          The password is set via <code>ADMIN_PASSWORD</code> / <code>ADMIN_PASSWORD_HASH</code> on the server.
        </p>
      </div>
    </div>
  );
}
