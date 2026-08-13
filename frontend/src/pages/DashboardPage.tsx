// Dashboard: stat tiles linking into each section, "needs attention"
// warnings derived from node/route state, and the recent audit feed.

import { type ReactNode } from "react";
import { Link } from "react-router-dom";
import { useMeta, useNodes, useOverview } from "../api/queries";
import type { Node } from "../api/types";
import { PageHeader } from "../components/Layout";
import { Code } from "../components/common";
import { Badge, Card, EmptyState, cn } from "../components/ui";
import { relativeTime, subnetRoutesOf } from "../lib/format";

export function DashboardPage() {
  const { data: overview, isLoading } = useOverview();
  const { data: nodes } = useNodes();
  const { data: meta } = useMeta();

  const attention = attentionItems(nodes ?? []);

  return (
    <>
      <PageHeader
        title="Dashboard"
        subtitle={meta ? `headscale at ${meta.publicServerUrl}` : undefined}
      />

      {isLoading || !overview ? (
        <p className="text-sm text-slate-500">Loading dashboard…</p>
      ) : (
        <div className="space-y-5">
          <div className="grid grid-cols-2 gap-3 sm:grid-cols-3 xl:grid-cols-4">
            <StatTile
              to="/machines"
              value={`${overview.nodes.online} / ${overview.nodes.total}`}
              label="Machines online"
            />
            <StatTile to="/users" value={overview.users} label="Users" />
            <StatTile
              to="/keys"
              value={overview.preAuthKeys.active}
              label="Active pre-auth keys"
              badge={
                overview.preAuthKeys.expiringSoon > 0 ? (
                  <Badge tone="yellow">
                    {overview.preAuthKeys.expiringSoon} expiring ≤14d
                  </Badge>
                ) : undefined
              }
            />
            <StatTile
              to="/keys"
              value={overview.apiKeys.total}
              label="API keys"
              badge={
                overview.apiKeys.uiKeyExpiring ? (
                  <Badge
                    tone="red"
                    title={`The API key this UI uses (${meta?.uiApiKeyPrefix ?? "…"}) expires soon — rotate it before Head-Control is locked out.`}
                  >
                    UI key expiring soon
                  </Badge>
                ) : undefined
              }
            />
            <StatTile
              to="/routes"
              value={overview.pendingRouteApprovals}
              label="Pending route approvals"
              tone={overview.pendingRouteApprovals > 0 ? "yellow" : "default"}
            />
            <StatTile
              to="/machines"
              value={overview.nodes.expiringSoon}
              label="Nodes expiring ≤7d"
              tone={overview.nodes.expiringSoon > 0 ? "yellow" : "default"}
            />
            <StatTile
              to="/machines"
              value={overview.nodes.expired}
              label="Expired nodes"
              tone={overview.nodes.expired > 0 ? "red" : "default"}
            />
          </div>

          {attention.length > 0 && (
            <Card title="Needs attention">
              <ul className="space-y-2">
                {attention.map((item) => (
                  <li key={item.key} className="flex items-start gap-2 text-sm">
                    <Badge tone={item.tone}>{item.badge}</Badge>
                    <span className="min-w-0 text-slate-700 dark:text-slate-300">
                      {item.content}
                    </span>
                  </li>
                ))}
              </ul>
            </Card>
          )}

          <Card title="Recent activity">
            {(overview.recentAudit ?? []).length === 0 ? (
              <EmptyState title="No activity yet" />
            ) : (
              <ul className="divide-y divide-slate-100 dark:divide-slate-800">
                {(overview.recentAudit ?? []).map((entry) => (
                  <li
                    key={entry.id}
                    className="flex items-center gap-3 py-2 text-sm first:pt-0 last:pb-0"
                  >
                    <Code>{entry.action}</Code>
                    <span className="min-w-0 flex-1 truncate text-slate-700 dark:text-slate-300">
                      {entry.targetName ?? entry.summary ?? ""}
                    </span>
                    {entry.outcome === "error" && (
                      <Badge tone="red" title={entry.error}>
                        error
                      </Badge>
                    )}
                    <span className="shrink-0 text-xs text-slate-400">
                      {relativeTime(entry.time)}
                    </span>
                  </li>
                ))}
              </ul>
            )}
          </Card>
        </div>
      )}
    </>
  );
}

// ---- stat tiles ----

function StatTile({
  to,
  value,
  label,
  badge,
  tone = "default",
}: {
  to: string;
  value: ReactNode;
  label: ReactNode;
  badge?: ReactNode;
  tone?: "default" | "yellow" | "red";
}) {
  return (
    <Link
      to={to}
      className="block rounded-lg focus:outline-none focus-visible:ring-2 focus-visible:ring-indigo-500"
    >
      <Card className="h-full transition-colors hover:border-indigo-300 dark:hover:border-indigo-600">
        <p
          className={cn(
            "text-2xl font-semibold tracking-tight",
            tone === "default" && "text-slate-900 dark:text-slate-100",
            tone === "yellow" && "text-amber-600 dark:text-amber-400",
            tone === "red" && "text-red-600 dark:text-red-400",
          )}
        >
          {value}
        </p>
        <p className="mt-1 text-xs font-medium text-slate-500 dark:text-slate-400">
          {label}
        </p>
        {badge && <div className="mt-2">{badge}</div>}
      </Card>
    </Link>
  );
}

// ---- needs-attention analysis ----

interface AttentionItem {
  key: string;
  tone: "yellow" | "red";
  badge: string;
  content: ReactNode;
}

function NodeLink({ node }: { node: Node }) {
  return (
    <Link
      to={`/machines/${node.id}`}
      className="font-medium text-slate-900 hover:underline dark:text-slate-100"
    >
      {node.givenName || node.name || node.id}
    </Link>
  );
}

function attentionItems(nodes: Node[]): AttentionItem[] {
  const items: AttentionItem[] = [];

  // Subnet prefixes whose only advertised+approved router is offline.
  const routersByPrefix = new Map<string, Node[]>();
  for (const n of nodes) {
    const routes = subnetRoutesOf(n);
    // Only routes both approved and still advertised count as routable.
    const active = routes.approved.filter((r) => routes.advertised.includes(r));
    for (const prefix of active) {
      routersByPrefix.set(prefix, [...(routersByPrefix.get(prefix) ?? []), n]);
    }
  }
  for (const [prefix, routers] of routersByPrefix) {
    if (routers.length === 1 && !routers[0].online) {
      const n = routers[0];
      items.push({
        key: `sole-router:${prefix}`,
        tone: "red",
        badge: "router offline",
        content: (
          <>
            The only approved router for <Code>{prefix}</Code>,{" "}
            <NodeLink node={n} />, is offline — clients using this route have
            lost connectivity.
          </>
        ),
      });
    }
  }

  // Stale approvals: approved routes the node no longer advertises.
  for (const n of nodes) {
    const stale = subnetRoutesOf(n).stale;
    if (stale.length > 0) {
      items.push({
        key: `stale:${n.id}`,
        tone: "yellow",
        badge: "stale approval",
        content: (
          <>
            <NodeLink node={n} /> has stale route approvals:{" "}
            <Code>{stale.join(", ")}</Code> — approved but no longer advertised
            by the node.
          </>
        ),
      });
    }
  }

  return items;
}
