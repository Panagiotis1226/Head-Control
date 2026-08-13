// Routes: tailnet-wide view of exit nodes and subnet routes. Headscale
// removed the standalone routes API in 0.26, so route state is aggregated
// client-side from every node's available/approved/serving route lists.

import { useMemo, useState } from "react";
import { Link } from "react-router-dom";
import { ApiError } from "../api/client";
import { useNodes, usePolicy, useSetRoutes } from "../api/queries";
import type { Node } from "../api/types";
import { PageHeader } from "../components/Layout";
import { CapabilityNotice, CliHint, Code, errorText } from "../components/common";
import {
  Badge,
  Button,
  Card,
  EmptyState,
  OnlineDot,
  cn,
  useToast,
} from "../components/ui";
import {
  EXIT_ROUTES,
  nodeAdvertisesExit,
  nodeIsExitNode,
  subnetRoutesOf,
  userLabel,
} from "../lib/format";
import { RoutesModal } from "./MachinesPage";

const HA_HINT =
  "Automatic failover; headscale actively health-probes HA subnet routers (node.routes.ha.* config)";

function nodeName(n: Node): string {
  return n.givenName || n.name || `node ${n.id}`;
}

// ---- autoApprovers cross-reference (tolerant HuJSON parse) ----

interface AutoApprovers {
  routes: Record<string, string[]>;
  exitNode: string[];
}

function parseAutoApprovers(policyText: string | undefined): AutoApprovers | null {
  if (!policyText) return null;
  try {
    const stripped = policyText
      .replace(/\/\*[\s\S]*?\*\//g, "")
      .replace(/\/\/.*$/gm, "")
      .replace(/,\s*([\]}])/g, "$1");
    const doc = JSON.parse(stripped) as {
      autoApprovers?: { routes?: Record<string, unknown>; exitNode?: unknown };
    };
    const aa = doc.autoApprovers;
    if (!aa || typeof aa !== "object") return null;
    const routes: Record<string, string[]> = {};
    for (const [prefix, owners] of Object.entries(aa.routes ?? {})) {
      routes[prefix] = Array.isArray(owners) ? owners.map(String) : [String(owners)];
    }
    return {
      routes,
      exitNode: Array.isArray(aa.exitNode) ? aa.exitNode.map(String) : [],
    };
  } catch {
    return null; // unparseable policy — silently skip the cross-reference
  }
}

// ---- shared approve/revoke mutation plumbing ----

function useRouteAction(
  node: Node,
  action: "approve" | "revoke",
  routes: string[],
  label?: string,
) {
  const setRoutes = useSetRoutes();
  const toast = useToast();
  const run = () =>
    setRoutes.mutate(
      {
        id: node.id,
        approve: action === "approve" ? routes : [],
        revoke: action === "revoke" ? routes : [],
        expectedApproved: node.approvedRoutes ?? [],
      },
      {
        onSuccess: () =>
          toast.success(
            `${action === "approve" ? "Approved" : "Revoked"} ${label ?? routes.join(", ")} on ${nodeName(node)}`,
          ),
        onError: (e) => {
          if (e instanceof ApiError && e.status === 409) {
            toast.error("Routes changed elsewhere — refresh and retry");
            return;
          }
          toast.error("Route update failed", errorText(e));
        },
      },
    );
  return { run, pending: setRoutes.isPending };
}

function ExitActionButton({ node }: { node: Node }) {
  const approved = nodeIsExitNode(node);
  const { run, pending } = useRouteAction(
    node,
    approved ? "revoke" : "approve",
    [...EXIT_ROUTES],
    "exit node (0.0.0.0/0 + ::/0)",
  );
  return (
    <Button variant={approved ? "secondary" : "primary"} loading={pending} onClick={run}>
      {approved ? "Revoke" : "Approve"}
    </Button>
  );
}

function SmallRouteAction({
  node,
  prefix,
  approved,
}: {
  node: Node;
  prefix: string;
  approved: boolean;
}) {
  const { run, pending } = useRouteAction(node, approved ? "revoke" : "approve", [prefix]);
  return (
    <button
      type="button"
      disabled={pending}
      onClick={run}
      title={approved ? `Revoke approval of ${prefix}` : `Approve ${prefix}`}
      className={cn(
        "rounded px-1.5 py-0.5 text-[11px] font-medium disabled:cursor-not-allowed disabled:opacity-50",
        approved
          ? "text-red-600 hover:bg-red-50 dark:text-red-400 dark:hover:bg-red-900/30"
          : "text-emerald-700 hover:bg-emerald-50 dark:text-emerald-400 dark:hover:bg-emerald-900/30",
      )}
    >
      {approved ? "revoke" : "approve"}
    </button>
  );
}

function Owner({ n }: { n: Node }) {
  const tags = n.tags ?? [];
  if (tags.length > 0) {
    return (
      <span className="flex flex-wrap gap-1">
        {tags.map((t) => (
          <Badge key={t} tone="purple">
            {t}
          </Badge>
        ))}
      </span>
    );
  }
  return <span className="text-xs text-slate-500 dark:text-slate-400">{userLabel(n.user)}</span>;
}

// ---- page ----

interface AttentionItem {
  key: string;
  node: Node;
  tone: "yellow" | "red";
  label: string;
  text: string;
}

interface Advertiser {
  node: Node;
  advertised: boolean;
  approved: boolean;
  serving: boolean;
}

export function RoutesPage() {
  const { data: nodes, isLoading } = useNodes();
  const { data: policy } = usePolicy();
  const [reviewNode, setReviewNode] = useState<Node | null>(null);

  const auto = useMemo(() => parseAutoApprovers(policy?.policy), [policy?.policy]);

  const attention = useMemo<AttentionItem[]>(() => {
    const items: AttentionItem[] = [];
    for (const n of nodes ?? []) {
      const r = subnetRoutesOf(n);
      const exitPending = nodeAdvertisesExit(n) && !nodeIsExitNode(n);
      const pending = [...r.pending, ...(exitPending ? ["exit node"] : [])];
      if (pending.length > 0) {
        items.push({
          key: `${n.id}:pending`,
          node: n,
          tone: "yellow",
          label: "pending",
          text: `${nodeName(n)} — awaiting approval: ${pending.join(", ")}`,
        });
      }
      const exitStale = nodeIsExitNode(n) && !nodeAdvertisesExit(n);
      const stale = [...r.stale, ...(exitStale ? ["exit node"] : [])];
      if (stale.length > 0) {
        items.push({
          key: `${n.id}:stale`,
          node: n,
          tone: "red",
          label: "stale",
          text: `${nodeName(n)} — approved but no longer advertised: ${stale.join(", ")}`,
        });
      }
      if (!n.online && (n.subnetRoutes ?? []).length > 0) {
        items.push({
          key: `${n.id}:offline`,
          node: n,
          tone: "red",
          label: "offline",
          text: `${nodeName(n)} is offline but approved to serve ${(n.subnetRoutes ?? []).join(", ")} — clients using these routes lose connectivity`,
        });
      }
    }
    return items;
  }, [nodes]);

  const exitNodes = useMemo(
    () => (nodes ?? []).filter((n) => nodeAdvertisesExit(n) || nodeIsExitNode(n)),
    [nodes],
  );

  const prefixRows = useMemo(() => {
    const map = new Map<string, Advertiser[]>();
    for (const n of nodes ?? []) {
      const r = subnetRoutesOf(n);
      // Advertisers plus stale approvals (approved routes no longer advertised).
      const prefixes = new Set([...r.advertised, ...r.approved]);
      for (const p of prefixes) {
        const entry: Advertiser = {
          node: n,
          advertised: r.advertised.includes(p),
          approved: r.approved.includes(p),
          serving: (n.subnetRoutes ?? []).includes(p),
        };
        const list = map.get(p);
        if (list) list.push(entry);
        else map.set(p, [entry]);
      }
    }
    return [...map.entries()].sort(([a], [b]) => a.localeCompare(b));
  }, [nodes]);

  return (
    <>
      <PageHeader
        title="Routes"
        subtitle={
          nodes
            ? `${prefixRows.length} subnet route${prefixRows.length === 1 ? "" : "s"} · ${exitNodes.length} exit node${exitNodes.length === 1 ? "" : "s"}`
            : undefined
        }
      />

      <div className="mb-4">
        <CapabilityNotice level="impossible">
          The standalone routes API was removed in headscale 0.26; route state lives on each node
          and is aggregated here client-side.
        </CapabilityNotice>
      </div>

      {isLoading ? (
        <p className="text-sm text-slate-500">Loading routes…</p>
      ) : (
        <div className="space-y-4">
          {attention.length > 0 && (
            <Card title={`Needs attention (${attention.length})`}>
              <ul className="divide-y divide-slate-100 dark:divide-slate-800">
                {attention.map((item) => (
                  <li key={item.key} className="flex items-center justify-between gap-3 py-2 first:pt-0 last:pb-0">
                    <span className="flex min-w-0 items-center gap-2 text-sm text-slate-700 dark:text-slate-300">
                      <Badge tone={item.tone}>{item.label}</Badge>
                      <span className="min-w-0 break-words">{item.text}</span>
                    </span>
                    <Button onClick={() => setReviewNode(item.node)}>Review</Button>
                  </li>
                ))}
              </ul>
            </Card>
          )}

          <Card title="Exit nodes">
            {exitNodes.length === 0 ? (
              <EmptyState title="No nodes advertise exit-node capability.">
                <p>
                  On a device: <Code>tailscale set --advertise-exit-node</Code>
                </p>
              </EmptyState>
            ) : (
              <>
                <ul className="divide-y divide-slate-100 dark:divide-slate-800">
                  {exitNodes.map((n) => {
                    const approved = nodeIsExitNode(n);
                    const advertised = nodeAdvertisesExit(n);
                    return (
                      <li key={n.id} className="flex flex-wrap items-center justify-between gap-3 py-2 first:pt-0 last:pb-0">
                        <span className="flex min-w-0 items-center gap-2">
                          <OnlineDot online={n.online} />
                          <span className="text-sm font-medium text-slate-900 dark:text-slate-100">
                            {nodeName(n)}
                          </span>
                          <Owner n={n} />
                        </span>
                        <span className="flex items-center gap-2">
                          {approved && advertised && <Badge tone="green">active</Badge>}
                          {!approved && advertised && <Badge tone="yellow">awaiting approval</Badge>}
                          {approved && !advertised && (
                            <Badge tone="red" title="Approved but the node no longer advertises exit-node capability">
                              stale
                            </Badge>
                          )}
                          {auto && auto.exitNode.length > 0 && (
                            <Badge tone="blue" title={`Owners: ${auto.exitNode.join(", ")}`}>
                              auto-approved by policy
                            </Badge>
                          )}
                          <ExitActionButton node={n} />
                        </span>
                      </li>
                    );
                  })}
                </ul>
                <CliHint command="headscale nodes approve-routes --identifier <node-id> --routes <existing-routes>,0.0.0.0/0,::/0" />
              </>
            )}
          </Card>

          <Card
            title="Subnet routes"
            actions={
              <Link
                to="/acl"
                className="text-xs text-indigo-600 hover:underline dark:text-indigo-400"
              >
                Edit autoApprovers in Access Controls
              </Link>
            }
          >
            {prefixRows.length === 0 ? (
              <EmptyState title="No subnet routes advertised.">
                <p>
                  On a device: <Code>tailscale set --advertise-routes=10.0.0.0/24</Code>
                </p>
              </EmptyState>
            ) : (
              <>
                <ul className="space-y-2">
                  {prefixRows.map(([prefix, advertisers]) => {
                    const haCount = advertisers.filter((a) => a.advertised).length;
                    const owners = auto?.routes[prefix];
                    return (
                      <li
                        key={prefix}
                        className="rounded-md border border-slate-200 px-3 py-2 dark:border-slate-700"
                      >
                        <div className="flex flex-wrap items-center gap-2">
                          <span className="font-mono text-sm text-slate-900 dark:text-slate-100">
                            {prefix}
                          </span>
                          {haCount >= 2 && (
                            <Badge tone="blue" title={HA_HINT}>
                              HA ×{haCount}
                            </Badge>
                          )}
                          {owners && (
                            <Badge tone="blue" title={`Owners: ${owners.join(", ")}`}>
                              auto-approved by policy
                            </Badge>
                          )}
                        </div>
                        <div className="mt-2 flex flex-wrap gap-2">
                          {advertisers.map((a) => (
                            <span
                              key={a.node.id}
                              className="inline-flex items-center gap-1.5 rounded-full border border-slate-200 py-1 pl-2.5 pr-1.5 text-xs text-slate-700 dark:border-slate-700 dark:text-slate-300"
                            >
                              <OnlineDot online={a.node.online} />
                              <span className="font-medium">{nodeName(a.node)}</span>
                              {a.serving ? (
                                <Badge tone="green">serving</Badge>
                              ) : a.approved && a.advertised ? (
                                <Badge tone="blue">approved</Badge>
                              ) : a.advertised ? (
                                <Badge tone="yellow">pending</Badge>
                              ) : (
                                <Badge tone="red" title="Approved but the node no longer advertises this route">
                                  stale
                                </Badge>
                              )}
                              <SmallRouteAction node={a.node} prefix={prefix} approved={a.approved} />
                            </span>
                          ))}
                        </div>
                      </li>
                    );
                  })}
                </ul>
                <CliHint command="headscale nodes approve-routes --identifier <node-id> --routes <full-approved-list>" />
              </>
            )}
          </Card>
        </div>
      )}

      {reviewNode && <RoutesModal node={reviewNode} onClose={() => setReviewNode(null)} />}
    </>
  );
}
