// App shell: sidebar navigation, top bar with health dot + version chip +
// dark-mode toggle, and the degraded-headscale status banner.

import { useEffect, useState, type ReactNode } from "react";
import { NavLink, useNavigate } from "react-router-dom";
import { useMeta } from "../api/queries";
import { post } from "../api/client";
import { Badge, cn } from "./ui";

const NAV: Array<{ to: string; label: string; icon: string; hideOnMobile?: boolean }> = [
  { to: "/", label: "Dashboard", icon: "▦" },
  { to: "/machines", label: "Machines", icon: "🖥" },
  { to: "/users", label: "Users", icon: "👤" },
  { to: "/acl", label: "Access Controls", icon: "🛡" },
  // Structured ACL editor; reachable from Access Controls on small screens.
  { to: "/acls-beta", label: "ACLs Beta", icon: "🧪", hideOnMobile: true },
  { to: "/routes", label: "Routes", icon: "⇄" },
  { to: "/keys", label: "Keys", icon: "🔑" },
  { to: "/dns", label: "DNS", icon: "◎" },
  { to: "/registrations", label: "Registrations", icon: "📥" },
  { to: "/settings", label: "Settings", icon: "⚙" },
];

function useDarkMode() {
  const [dark, setDark] = useState(
    () =>
      localStorage.getItem("hc-theme") === "dark" ||
      (localStorage.getItem("hc-theme") === null &&
        window.matchMedia("(prefers-color-scheme: dark)").matches),
  );
  useEffect(() => {
    document.documentElement.classList.toggle("dark", dark);
    localStorage.setItem("hc-theme", dark ? "dark" : "light");
  }, [dark]);
  return { dark, toggle: () => setDark((d) => !d) };
}

function StatusBanner() {
  const { data: meta } = useMeta();
  if (!meta) return null;
  const hs = meta.headscale;

  let tone: "red" | "yellow" | null = null;
  let text = "";
  if (!hs.reachable) {
    tone = "red";
    text = `Headscale is unreachable at ${meta.headscaleUrl}${hs.lastError ? ` — ${hs.lastError}` : ""}`;
  } else if (!hs.apiKeyValid) {
    tone = "red";
    text =
      "Headscale rejected this server's API key. Create a new one with `headscale apikeys create`, update HEADSCALE_API_KEY, and restart Head-Control.";
  } else if (!hs.databaseOk) {
    tone = "red";
    text = "Headscale reports its database is unreachable.";
  } else if (!hs.supported && hs.supportNote) {
    tone = "yellow";
    text = hs.supportNote;
  }
  if (!tone) return null;
  return (
    <div
      className={cn(
        "px-4 py-2 text-sm font-medium",
        tone === "red"
          ? "bg-red-600 text-white"
          : "bg-amber-400 text-amber-950",
      )}
    >
      {text}
    </div>
  );
}

export function Layout({ children }: { children: ReactNode }) {
  const { dark, toggle } = useDarkMode();
  const { data: meta } = useMeta();
  const navigate = useNavigate();
  const hs = meta?.headscale;
  const healthy = !!hs && hs.reachable && hs.apiKeyValid && hs.databaseOk;

  const logout = async () => {
    try {
      await post("/api/auth/logout");
    } finally {
      navigate("/login");
      // Full reload clears query cache + CSRF state.
      window.location.reload();
    }
  };

  return (
    <div className="flex min-h-screen bg-slate-50 text-slate-900 dark:bg-slate-950 dark:text-slate-100">
      {/* Sidebar */}
      <aside className="fixed inset-y-0 left-0 z-40 hidden w-56 flex-col border-r border-slate-200 bg-white dark:border-slate-800 dark:bg-slate-900 md:flex">
        <div className="flex items-center gap-2 px-5 py-4">
          <span className="text-lg font-bold tracking-tight">
            Head-<span className="text-indigo-600 dark:text-indigo-400">Control</span>
          </span>
        </div>
        <nav className="flex-1 space-y-0.5 px-3">
          {NAV.map((item) => (
            <NavLink
              key={item.to}
              to={item.to}
              end={item.to === "/"}
              className={({ isActive }) =>
                cn(
                  "flex items-center gap-2.5 rounded-md px-3 py-2 text-sm font-medium",
                  isActive
                    ? "bg-indigo-50 text-indigo-700 dark:bg-indigo-950/60 dark:text-indigo-300"
                    : "text-slate-600 hover:bg-slate-100 dark:text-slate-400 dark:hover:bg-slate-800",
                )
              }
            >
              <span className="w-5 text-center">{item.icon}</span>
              {item.label}
            </NavLink>
          ))}
        </nav>
        <div className="space-y-1 px-5 py-4 text-xs text-slate-400">
          <p>Head-Control {meta?.version ?? ""}</p>
          {hs?.version && <p>headscale v{hs.version}</p>}
        </div>
      </aside>

      {/* Main column */}
      <div className="flex min-w-0 flex-1 flex-col md:pl-56">
        {/* Top bar */}
        <header className="sticky top-0 z-30 flex items-center justify-between gap-3 border-b border-slate-200 bg-white/90 px-4 py-2.5 backdrop-blur dark:border-slate-800 dark:bg-slate-900/90">
          <div className="flex items-center gap-3 md:hidden">
            <span className="font-bold">Head-Control</span>
          </div>
          <div className="flex flex-1 items-center justify-end gap-3">
            <span className="flex items-center gap-1.5 text-xs text-slate-500 dark:text-slate-400">
              <span
                className={cn(
                  "inline-block h-2.5 w-2.5 rounded-full",
                  !hs ? "bg-slate-300" : healthy ? "bg-emerald-500" : "bg-red-500",
                )}
              />
              {!hs ? "checking…" : healthy ? "connected" : "degraded"}
            </span>
            {hs?.version && (
              <Badge tone={hs.supported ? "gray" : "yellow"} title={hs.supportNote}>
                headscale v{hs.version}
              </Badge>
            )}
            <button
              onClick={toggle}
              title="Toggle dark mode"
              className="rounded-md p-1.5 text-slate-500 hover:bg-slate-100 dark:text-slate-400 dark:hover:bg-slate-800"
            >
              {dark ? "☀" : "☾"}
            </button>
            <button
              onClick={logout}
              className="rounded-md px-2 py-1 text-sm text-slate-500 hover:bg-slate-100 dark:text-slate-400 dark:hover:bg-slate-800"
            >
              Log out
            </button>
          </div>
        </header>

        <StatusBanner />

        <main className="mx-auto w-full max-w-6xl flex-1 px-4 py-6">{children}</main>

        {/* Mobile bottom nav */}
        <nav className="sticky bottom-0 z-30 flex justify-around border-t border-slate-200 bg-white py-1.5 dark:border-slate-800 dark:bg-slate-900 md:hidden">
          {NAV.filter((item) => !item.hideOnMobile)
            .slice(0, 5)
            .map((item) => (
            <NavLink
              key={item.to}
              to={item.to}
              end={item.to === "/"}
              className={({ isActive }) =>
                cn(
                  "flex flex-col items-center rounded px-2 py-1 text-[10px]",
                  isActive ? "text-indigo-600 dark:text-indigo-400" : "text-slate-500",
                )
              }
            >
              <span className="text-base leading-tight">{item.icon}</span>
              {item.label}
            </NavLink>
          ))}
        </nav>
      </div>
    </div>
  );
}

export function PageHeader({ title, subtitle, actions }: { title: ReactNode; subtitle?: ReactNode; actions?: ReactNode }) {
  return (
    <div className="mb-5 flex flex-wrap items-start justify-between gap-3">
      <div>
        <h1 className="text-xl font-semibold tracking-tight">{title}</h1>
        {subtitle && <p className="mt-1 text-sm text-slate-500 dark:text-slate-400">{subtitle}</p>}
      </div>
      {actions && <div className="flex items-center gap-2">{actions}</div>}
    </div>
  );
}
