// Formatting helpers shared across pages.

export function relativeTime(iso: string | undefined): string {
  if (!iso) return "never";
  const then = new Date(iso).getTime();
  if (Number.isNaN(then)) return iso;
  const diff = Date.now() - then;
  const abs = Math.abs(diff);
  const suffix = diff >= 0 ? "ago" : "from now";
  const mins = Math.round(abs / 60_000);
  if (mins < 1) return diff >= 0 ? "just now" : "in <1 min";
  if (mins < 60) return `${mins} min ${suffix}`;
  const hours = Math.round(mins / 60);
  if (hours < 48) return `${hours} h ${suffix}`;
  const days = Math.round(hours / 24);
  if (days < 60) return `${days} d ${suffix}`;
  return new Date(iso).toLocaleDateString();
}

export function absoluteTime(iso: string | undefined): string {
  if (!iso) return "—";
  const d = new Date(iso);
  return Number.isNaN(d.getTime()) ? iso : d.toLocaleString();
}

export function isExpired(iso: string | undefined): boolean {
  return !!iso && new Date(iso).getTime() < Date.now();
}

export function expiresWithin(iso: string | undefined, ms: number): boolean {
  if (!iso) return false;
  const t = new Date(iso).getTime();
  return t > Date.now() && t < Date.now() + ms;
}

export const DAY = 24 * 60 * 60 * 1000;

/** Display name for a user, handling blank names from OIDC providers. */
export function userLabel(u: { name?: string; displayName?: string; email?: string; providerId?: string } | undefined): string {
  if (!u) return "—";
  return u.name || u.displayName || u.email || u.providerId || "unnamed";
}

export const EXIT_ROUTES = ["0.0.0.0/0", "::/0"];

export function isExitRoute(r: string): boolean {
  return EXIT_ROUTES.includes(r);
}

export function nodeIsExitNode(n: { approvedRoutes?: string[] }): boolean {
  return (n.approvedRoutes ?? []).some(isExitRoute);
}

export function nodeAdvertisesExit(n: { availableRoutes?: string[] }): boolean {
  return (n.availableRoutes ?? []).some(isExitRoute);
}

export function subnetRoutesOf(n: { availableRoutes?: string[]; approvedRoutes?: string[] }): {
  advertised: string[];
  approved: string[];
  pending: string[];
  stale: string[];
} {
  const advertised = (n.availableRoutes ?? []).filter((r) => !isExitRoute(r));
  const approved = (n.approvedRoutes ?? []).filter((r) => !isExitRoute(r));
  const advertisedSet = new Set(advertised);
  const approvedSet = new Set(approved);
  return {
    advertised,
    approved,
    pending: advertised.filter((r) => !approvedSet.has(r)),
    stale: approved.filter((r) => !advertisedSet.has(r)),
  };
}
