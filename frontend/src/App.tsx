import { useEffect, useState } from "react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { BrowserRouter, Navigate, Route, Routes } from "react-router-dom";
import { get, onSessionExpired, setCsrfToken } from "./api/client";
import { Layout } from "./components/Layout";
import { ToastProvider } from "./components/ui";
import { AclPage } from "./pages/AclPage";
import { DashboardPage } from "./pages/DashboardPage";
import { DnsPage } from "./pages/DnsPage";
import { KeysPage } from "./pages/KeysPage";
import { LoginPage } from "./pages/LoginPage";
import { MachinesPage } from "./pages/MachinesPage";
import { RegistrationsPage } from "./pages/RegistrationsPage";
import { RoutesPage } from "./pages/RoutesPage";
import { SettingsPage } from "./pages/SettingsPage";
import { UsersPage } from "./pages/UsersPage";

const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      retry: 1,
      refetchOnWindowFocus: true,
    },
  },
});

// Router basename comes from <base href>, which the backend rewrites per
// BASE_PATH at startup.
const basename = new URL(".", document.baseURI).pathname.replace(/\/$/, "");

type AuthState = "checking" | "in" | "out";

export default function App() {
  const [authState, setAuthState] = useState<AuthState>("checking");

  useEffect(() => {
    onSessionExpired(() => setAuthState("out"));
    get<{ authenticated: boolean; csrfToken?: string }>("/api/auth/session")
      .then((s) => {
        if (s.authenticated && s.csrfToken) {
          setCsrfToken(s.csrfToken);
          setAuthState("in");
        } else {
          setAuthState("out");
        }
      })
      .catch(() => setAuthState("out"));
  }, []);

  if (authState === "checking") {
    return (
      <div className="flex min-h-screen items-center justify-center bg-slate-50 dark:bg-slate-950">
        <span className="h-6 w-6 animate-spin rounded-full border-2 border-indigo-500 border-t-transparent" />
      </div>
    );
  }

  return (
    <QueryClientProvider client={queryClient}>
      <ToastProvider>
        <BrowserRouter basename={basename}>
          {authState === "out" ? (
            <Routes>
              <Route
                path="*"
                element={
                  <LoginPage
                    onLoggedIn={(csrf) => {
                      setCsrfToken(csrf);
                      setAuthState("in");
                    }}
                  />
                }
              />
            </Routes>
          ) : (
            <Layout>
              <Routes>
                <Route path="/" element={<DashboardPage />} />
                <Route path="/machines" element={<MachinesPage />} />
                <Route path="/machines/:id" element={<MachinesPage />} />
                <Route path="/users" element={<UsersPage />} />
                <Route path="/acl" element={<AclPage />} />
                <Route path="/routes" element={<RoutesPage />} />
                <Route path="/keys" element={<KeysPage />} />
                <Route path="/dns" element={<DnsPage />} />
                <Route path="/registrations" element={<RegistrationsPage />} />
                <Route path="/settings" element={<SettingsPage />} />
                <Route path="/login" element={<Navigate to="/" replace />} />
                <Route path="*" element={<Navigate to="/" replace />} />
              </Routes>
            </Layout>
          )}
        </BrowserRouter>
      </ToastProvider>
    </QueryClientProvider>
  );
}
