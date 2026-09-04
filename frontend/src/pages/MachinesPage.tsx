// Machines: table with search + filters, rename / tags / routes / expire /
// delete flows, node detail drawer, and the Add-device wizard.

import { useMemo, useState } from "react";
import { useNavigate, useParams } from "react-router-dom";
import { ApiError } from "../api/client";
import {
  useCreatePreAuthKey,
  useDeleteNode,
  useExpireNode,
  useMeta,
  useNodes,
  useRegisterDevice,
  useRenameNode,
  useSetRoutes,
  useSetTags,
  useUsers,
} from "../api/queries";
import type { Node } from "../api/types";
import { PageHeader } from "../components/Layout";
import {
  CapabilityNotice,
  CliHint,
  Code,
  ConfirmDialog,
  CopyButton,
  SecretModal,
  errorText,
} from "../components/common";
import { Badge, Button, Checkbox, EmptyState, Field, Input, Modal, OnlineDot, RowMenu, Select, Table, Td, Th, useToast } from "../components/ui";
import {
  DAY,
  expiresWithin,
  isExpired,
  nodeAdvertisesExit,
  nodeIsExitNode,
  relativeTime,
  subnetRoutesOf,
  userLabel,
} from "../lib/format";

const HOSTNAME_RE = /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])$/;

type Filter =
  | { kind: "state"; value: "online" | "offline" | "expired" | "expires-soon" }
  | { kind: "user"; value: string }
  | { kind: "tag"; value: string }
  | { kind: "is"; value: string }
  | { kind: "registered"; value: string };

function nodeMatches(n: Node, search: string, filters: Filter[]): boolean {
  if (search) {
    const hay = [
      n.givenName,
      n.name,
      ...(n.ipAddresses ?? []),
      userLabel(n.user),
      ...(n.tags ?? []),
    ]
      .join(" ")
      .toLowerCase();
    if (!hay.includes(search.toLowerCase())) return false;
  }
  // AND across kinds, OR within one kind.
  const kinds = new Map<string, Filter[]>();
  for (const f of filters) {
    const k = f.kind + (f.kind === "is" ? ":" + f.value : "");
    kinds.set(k, [...(kinds.get(k) ?? []), f]);
  }
  for (const group of kinds.values()) {
    const ok = group.some((f) => {
      switch (f.kind) {
        case "state":
          if (f.value === "online") return n.online;
          if (f.value === "offline") return !n.online;
          if (f.value === "expired") return isExpired(n.expiry);
          return expiresWithin(n.expiry, 7 * DAY);
        case "user":
          return userLabel(n.user) === f.value;
        case "tag":
          return (n.tags ?? []).includes(f.value);
        case "registered":
          return (n.registerMethod ?? "").toLowerCase().includes(f.value);
        case "is":
          switch (f.value) {
            case "exit-node":
              return nodeIsExitNode(n);
            case "subnet-router":
              return subnetRoutesOf(n).advertised.length > 0;
            case "ephemeral":
              return !!n.preAuthKey?.ephemeral;
            case "tagged":
              return (n.tags ?? []).length > 0;
            case "pending-routes":
              return subnetRoutesOf(n).pending.length > 0 ||
                (nodeAdvertisesExit(n) && !nodeIsExitNode(n));
            case "never-expires":
              return !n.expiry;
            default:
              return true;
          }
      }
    });
    if (!ok) return false;
  }
  return true;
}

export function MachinesPage() {
  const { data: nodes, isLoading } = useNodes();
  const { data: meta } = useMeta();
  const { id: detailId } = useParams();
  const navigate = useNavigate();
  const [search, setSearch] = useState("");
  const [filters, setFilters] = useState<Filter[]>([]);
  const [modal, setModal] = useState<
    | { kind: "rename"; node: Node }
    | { kind: "tags"; node: Node }
    | { kind: "routes"; node: Node }
    | { kind: "expire"; node: Node }
    | { kind: "delete"; node: Node }
    | { kind: "add" }
    | null
  >(null);

  const filtered = useMemo(
    () => (nodes ?? []).filter((n) => nodeMatches(n, search, filters)),
    [nodes, search, filters],
  );
  const detailNode = (nodes ?? []).find((n) => n.id === detailId);

  const addFilter = (f: Filter) => {
    setFilters((fs) =>
      fs.some((x) => x.kind === f.kind && x.value === f.value) ? fs : [...fs, f],
    );
  };

  return (
    <>
      <PageHeader
        title="Machines"
        subtitle={
          nodes
            ? `${nodes.filter((n) => n.online).length} online of ${nodes.length}`
            : undefined
        }
        actions={
          <Button variant="primary" onClick={() => setModal({ kind: "add" })}>
            + Add device
          </Button>
        }
      />

      <div className="mb-4 flex flex-wrap items-center gap-2">
        <Input
          placeholder="Search name, IP, user, tag…"
          value={search}
          onChange={(e) => setSearch(e.target.value)}
          className="max-w-xs"
        />
        <FilterPicker onAdd={addFilter} nodes={nodes ?? []} />
        {filters.map((f, i) => (
          <Badge key={i} tone="blue">
            {f.kind}:{f.value}
            <button
              className="ml-1 opacity-70 hover:opacity-100"
              onClick={() => setFilters((fs) => fs.filter((_, j) => j !== i))}
            >
              ✕
            </button>
          </Badge>
        ))}
      </div>

      {isLoading ? (
        <p className="text-sm text-slate-500">Loading machines…</p>
      ) : (nodes ?? []).length === 0 ? (
        <EmptyState title="No machines yet">
          <p>Connect your first device to headscale:</p>
          <div className="mx-auto mt-2 max-w-md text-left">
            <Code block>{`tailscale up --login-server ${meta?.publicServerUrl ?? "<your-headscale-url>"}`}</Code>
          </div>
          <p className="mt-2">
            …then register it here via <strong>Add device</strong>.
          </p>
        </EmptyState>
      ) : (
        <Table
          head={
            <>
              <Th>Machine</Th>
              <Th>Owner</Th>
              <Th>Address</Th>
              <Th>Status</Th>
              <Th>Expiry</Th>
              <Th className="w-10" />
            </>
          }
        >
          {filtered.map((n) => (
            <NodeRow
              key={n.id}
              node={n}
              onOpen={() => navigate(`/machines/${n.id}`)}
              onAction={(kind) => setModal({ kind, node: n } as any)}
              onFilterUser={(u) => addFilter({ kind: "user", value: u })}
              onFilterTag={(t) => addFilter({ kind: "tag", value: t })}
            />
          ))}
        </Table>
      )}

      {modal?.kind === "rename" && <RenameModal node={modal.node} onClose={() => setModal(null)} />}
      {modal?.kind === "tags" && <TagsModal node={modal.node} onClose={() => setModal(null)} />}
      {modal?.kind === "routes" && <RoutesModal node={modal.node} onClose={() => setModal(null)} />}
      {modal?.kind === "expire" && <ExpireModal node={modal.node} onClose={() => setModal(null)} />}
      {modal?.kind === "delete" && <DeleteModal node={modal.node} onClose={() => setModal(null)} />}
      {modal?.kind === "add" && (
        <AddDeviceWizard publicServerUrl={meta?.publicServerUrl ?? ""} onClose={() => setModal(null)} />
      )}
      {detailNode && (
        <NodeDetail
          node={detailNode}
          onClose={() => navigate("/machines")}
          onAction={(kind) => setModal({ kind, node: detailNode } as any)}
        />
      )}
    </>
  );
}

function FilterPicker({ onAdd, nodes }: { onAdd: (f: Filter) => void; nodes: Node[] }) {
  const users = [...new Set(nodes.map((n) => userLabel(n.user)))].filter((u) => u !== "—");
  const tags = [...new Set(nodes.flatMap((n) => n.tags ?? []))];
  return (
    <Select
      value=""
      onChange={(e) => {
        const v = e.target.value;
        if (!v) return;
        const [kind, ...rest] = v.split(":");
        onAdd({ kind, value: rest.join(":") } as Filter);
        e.target.value = "";
      }}
    >
      <option value="">+ Filter</option>
      <optgroup label="State">
        <option value="state:online">online</option>
        <option value="state:offline">offline</option>
        <option value="state:expired">expired</option>
        <option value="state:expires-soon">expires soon</option>
      </optgroup>
      <optgroup label="Properties">
        <option value="is:exit-node">exit node</option>
        <option value="is:subnet-router">subnet router</option>
        <option value="is:pending-routes">routes pending approval</option>
        <option value="is:ephemeral">ephemeral</option>
        <option value="is:tagged">tagged</option>
        <option value="is:never-expires">never expires</option>
      </optgroup>
      <optgroup label="Registered via">
        <option value="registered:auth_key">auth key</option>
        <option value="registered:cli">interactive</option>
        <option value="registered:oidc">OIDC</option>
      </optgroup>
      {users.length > 0 && (
        <optgroup label="User">
          {users.map((u) => (
            <option key={u} value={`user:${u}`}>
              {u}
            </option>
          ))}
        </optgroup>
      )}
      {tags.length > 0 && (
        <optgroup label="Tag">
          {tags.map((t) => (
            <option key={t} value={`tag:${t}`}>
              {t}
            </option>
          ))}
        </optgroup>
      )}
    </Select>
  );
}

function NodeBadges({ n }: { n: Node }) {
  const routes = subnetRoutesOf(n);
  return (
    <span className="flex flex-wrap gap-1">
      {isExpired(n.expiry) && <Badge tone="red">Expired</Badge>}
      {!isExpired(n.expiry) && expiresWithin(n.expiry, 7 * DAY) && (
        <Badge tone="yellow">Expires soon</Badge>
      )}
      {n.preAuthKey?.ephemeral && <Badge tone="purple">Ephemeral</Badge>}
      {nodeIsExitNode(n) && <Badge tone="blue">Exit node</Badge>}
      {routes.advertised.length > 0 && <Badge tone="blue">Subnet router</Badge>}
      {(routes.pending.length > 0 || (nodeAdvertisesExit(n) && !nodeIsExitNode(n))) && (
        <Badge tone="yellow">Routes pending</Badge>
      )}
    </span>
  );
}

function NodeRow({
  node: n,
  onOpen,
  onAction,
  onFilterUser,
  onFilterTag,
}: {
  node: Node;
  onOpen: () => void;
  onAction: (kind: "rename" | "tags" | "routes" | "expire" | "delete") => void;
  onFilterUser: (user: string) => void;
  onFilterTag: (tag: string) => void;
}) {
  const tagged = (n.tags ?? []).length > 0;
  return (
    <tr className="hover:bg-slate-50 dark:hover:bg-slate-800/50">
      <Td>
        <button onClick={onOpen} className="text-left">
          <span className="font-medium text-slate-900 hover:underline dark:text-slate-100">
            {n.givenName || n.name}
          </span>
          {n.name && n.name !== n.givenName && (
            <span className="ml-1.5 text-xs text-slate-400">({n.name})</span>
          )}
        </button>
        <div className="mt-1">
          <NodeBadges n={n} />
        </div>
      </Td>
      <Td>
        {tagged ? (
          <span className="flex flex-wrap gap-1">
            {(n.tags ?? []).map((t) => (
              <button key={t} onClick={() => onFilterTag(t)}>
                <Badge tone="purple">{t}</Badge>
              </button>
            ))}
          </span>
        ) : (
          <button
            className="text-slate-700 hover:underline dark:text-slate-300"
            onClick={() => onFilterUser(userLabel(n.user))}
          >
            {userLabel(n.user)}
          </button>
        )}
      </Td>
      <Td>
        <span className="flex items-center gap-1 font-mono text-xs">
          {n.ipAddresses?.[0] ?? "—"}
          {n.ipAddresses?.[0] && <CopyButton text={n.ipAddresses[0]} />}
        </span>
      </Td>
      <Td>
        <span className="flex items-center gap-1.5">
          <OnlineDot online={n.online} />
          <span className="text-xs text-slate-500">
            {n.online ? "online" : relativeTime(n.lastSeen)}
          </span>
        </span>
      </Td>
      <Td>
        <span className="text-xs text-slate-500">
          {n.expiry ? relativeTime(n.expiry) : "never"}
        </span>
      </Td>
      <Td>
        <RowMenu
          width="w-44"
          items={
            [
              ["rename", "Rename"],
              ["tags", "Edit tags"],
              ["routes", "Edit route settings"],
              ["expire", "Expiry…"],
              ["delete", "Delete…"],
            ] as const
          }
          onSelect={onAction}
        />
      </Td>
    </tr>
  );
}

// ---- modals ----

function RenameModal({ node, onClose }: { node: Node; onClose: () => void }) {
  const [name, setName] = useState(node.givenName ?? "");
  const rename = useRenameNode();
  const toast = useToast();
  const valid = HOSTNAME_RE.test(name);
  return (
    <Modal title={`Rename ${node.givenName}`} onClose={onClose}>
      <div className="space-y-3">
        <Field
          label="New name"
          hint="2–63 lowercase letters, digits or hyphens; becomes the MagicDNS name. Headscale appends a numeric suffix on collisions."
        >
          <Input
            value={name}
            onChange={(e) => setName(e.target.value.toLowerCase())}
            autoFocus
          />
        </Field>
        {!valid && name.length > 0 && (
          <p className="text-xs text-red-600">Invalid hostname format.</p>
        )}
        <div className="flex justify-end gap-2">
          <Button onClick={onClose}>Cancel</Button>
          <Button
            variant="primary"
            disabled={!valid || name === node.givenName}
            loading={rename.isPending}
            onClick={() =>
              rename.mutate(
                { id: node.id, newName: name },
                {
                  onSuccess: () => {
                    toast.success(`Renamed to ${name}`);
                    onClose();
                  },
                  onError: (e) => toast.error("Rename failed", errorText(e)),
                },
              )
            }
          >
            Rename
          </Button>
        </div>
        <CliHint command={`headscale nodes rename --identifier ${node.id} ${name || "<new-name>"}`} />
      </div>
    </Modal>
  );
}

function TagsModal({ node, onClose }: { node: Node; onClose: () => void }) {
  const [tags, setTags] = useState<string[]>(node.tags ?? []);
  const [draft, setDraft] = useState("");
  const setTagsMut = useSetTags();
  const toast = useToast();
  const wasUserOwned = (node.tags ?? []).length === 0;

  const addDraft = () => {
    let t = draft.trim().toLowerCase();
    if (!t) return;
    if (!t.startsWith("tag:")) t = "tag:" + t;
    if (!tags.includes(t)) setTags([...tags, t]);
    setDraft("");
  };

  return (
    <Modal title={`Tags for ${node.givenName}`} onClose={onClose}>
      <div className="space-y-3">
        {wasUserOwned && tags.length > 0 && (
          <CapabilityNotice level="impossible">
            Adding tags converts this node to <strong>tag ownership</strong>. Since headscale 0.28,
            tagged nodes never expire and cannot be returned to user ownership.
          </CapabilityNotice>
        )}
        <div className="flex flex-wrap gap-1.5">
          {tags.map((t) => (
            <Badge key={t} tone="purple">
              {t}
              <button className="ml-1 opacity-70 hover:opacity-100" onClick={() => setTags(tags.filter((x) => x !== t))}>
                ✕
              </button>
            </Badge>
          ))}
          {tags.length === 0 && <span className="text-xs text-slate-400">no tags</span>}
        </div>
        <div className="flex gap-2">
          <Input
            placeholder="tag:server"
            value={draft}
            onChange={(e) => setDraft(e.target.value)}
            onKeyDown={(e) => {
              if (e.key === "Enter") {
                e.preventDefault();
                addDraft();
              }
            }}
          />
          <Button onClick={addDraft}>Add</Button>
        </div>
        <p className="text-xs text-slate-500">
          Tags must be owned in the policy's <Code>tagOwners</Code> section to be usable in ACLs.
        </p>
        <div className="flex justify-end gap-2">
          <Button onClick={onClose}>Cancel</Button>
          <Button
            variant="primary"
            loading={setTagsMut.isPending}
            onClick={() =>
              setTagsMut.mutate(
                { id: node.id, tags },
                {
                  onSuccess: () => {
                    toast.success("Tags updated");
                    onClose();
                  },
                  onError: (e) => toast.error("Tag update failed", errorText(e)),
                },
              )
            }
          >
            Save tags
          </Button>
        </div>
        <CliHint command={`headscale nodes tag --identifier ${node.id} --tags ${tags.join(",") || "<tags>"}`} />
      </div>
    </Modal>
  );
}

export function RoutesModal({ node, onClose }: { node: Node; onClose: () => void }) {
  const routes = subnetRoutesOf(node);
  const advertisesExit = nodeAdvertisesExit(node);
  const initialExit = nodeIsExitNode(node);
  const allSubnet = [...new Set([...routes.advertised, ...routes.approved])].sort();
  const [approved, setApproved] = useState<Set<string>>(new Set(routes.approved));
  const [exit, setExit] = useState(initialExit);
  const setRoutesMut = useSetRoutes();
  const toast = useToast();

  const approve: string[] = [];
  const revoke: string[] = [];
  for (const r of allSubnet) {
    const was = routes.approved.includes(r);
    const is = approved.has(r);
    if (!was && is) approve.push(r);
    if (was && !is) revoke.push(r);
  }
  if (!initialExit && exit) approve.push("0.0.0.0/0", "::/0");
  if (initialExit && !exit) revoke.push("0.0.0.0/0", "::/0");
  const dirty = approve.length > 0 || revoke.length > 0;

  const submit = () =>
    setRoutesMut.mutate(
      {
        id: node.id,
        approve,
        revoke,
        expectedApproved: node.approvedRoutes ?? [],
      },
      {
        onSuccess: () => {
          toast.success("Routes updated");
          onClose();
        },
        onError: (e) => {
          if (e instanceof ApiError && e.status === 409) {
            toast.error(
              "Routes changed elsewhere",
              "This node's approved routes were modified concurrently (another admin or an autoApprover). Reopen the panel to see the fresh state.",
            );
            onClose();
            return;
          }
          toast.error("Route update failed", errorText(e));
        },
      },
    );

  return (
    <Modal title={`Route settings — ${node.givenName}`} onClose={onClose} wide>
      <div className="space-y-4">
        <section>
          <h3 className="mb-2 text-sm font-semibold">Subnet routes</h3>
          {allSubnet.length === 0 ? (
            <p className="text-sm text-slate-500">
              This node advertises no subnet routes. On the device:{" "}
              <Code>tailscale set --advertise-routes=10.0.0.0/24</Code>
            </p>
          ) : (
            <ul className="space-y-1.5">
              {allSubnet.map((r) => {
                const advertised = routes.advertised.includes(r);
                const serving = (node.subnetRoutes ?? []).includes(r);
                return (
                  <li key={r} className="flex items-center justify-between gap-2 rounded-md border border-slate-200 px-3 py-2 dark:border-slate-700">
                    <Checkbox
                      checked={approved.has(r)}
                      onChange={(e) => {
                        const next = new Set(approved);
                        e.target.checked ? next.add(r) : next.delete(r);
                        setApproved(next);
                      }}
                      label={<span className="font-mono text-xs">{r}</span>}
                    />
                    <span className="flex gap-1">
                      {serving && <Badge tone="green">serving</Badge>}
                      {advertised && !approved.has(r) && <Badge tone="yellow">awaiting approval</Badge>}
                      {!advertised && <Badge tone="red" title="Approved but the node no longer advertises this route">stale approval</Badge>}
                    </span>
                  </li>
                );
              })}
            </ul>
          )}
        </section>

        <section>
          <h3 className="mb-2 text-sm font-semibold">Exit node</h3>
          {advertisesExit || initialExit ? (
            <Checkbox
              checked={exit}
              onChange={(e) => setExit(e.target.checked)}
              label={
                <>
                  Use as exit node{" "}
                  <span className="text-xs text-slate-400">
                    (approves 0.0.0.0/0 and ::/0 together — headscale pairs them)
                  </span>
                </>
              }
            />
          ) : (
            <p className="text-sm text-slate-500">
              Not advertised by this node. On the device: <Code>tailscale set --advertise-exit-node</Code>
            </p>
          )}
        </section>

        {dirty && (
          <div className="rounded-md border border-slate-200 px-3 py-2 text-xs dark:border-slate-700">
            {approve.length > 0 && (
              <p className="text-emerald-700 dark:text-emerald-400">+ approve: {approve.join(", ")}</p>
            )}
            {revoke.length > 0 && (
              <p className="text-red-700 dark:text-red-400">− revoke: {revoke.join(", ")}</p>
            )}
          </div>
        )}

        <div className="flex justify-end gap-2">
          <Button onClick={onClose}>Cancel</Button>
          <Button variant="primary" disabled={!dirty} loading={setRoutesMut.isPending} onClick={submit}>
            Apply changes
          </Button>
        </div>
        <CliHint command={`headscale nodes approve-routes --identifier ${node.id} --routes <full-list>`} />
      </div>
    </Modal>
  );
}

function ExpireModal({ node, onClose }: { node: Node; onClose: () => void }) {
  const [mode, setMode] = useState<"now" | "at" | "never">("now");
  const [at, setAt] = useState("");
  const expire = useExpireNode();
  const toast = useToast();
  const tagged = (node.tags ?? []).length > 0;

  return (
    <Modal title={`Key expiry — ${node.givenName}`} onClose={onClose}>
      <div className="space-y-3 text-sm">
        {tagged && (
          <CapabilityNotice level="impossible">
            Tagged nodes never expire in headscale — expiry settings have no effect on this node.
          </CapabilityNotice>
        )}
        {(
          [
            ["now", "Expire now", "forces the device to re-authenticate"],
            ["at", "Expire at…", "schedule a future expiry"],
            ["never", "Never expire", "disables key expiry (recommended for servers)"],
          ] as const
        ).map(([value, label, hint]) => (
          <label key={value} className="flex cursor-pointer items-start gap-2">
            <input
              type="radio"
              name="expire-mode"
              checked={mode === value}
              onChange={() => setMode(value)}
              className="mt-0.5"
            />
            <span>
              <span className="font-medium">{label}</span>
              <span className="ml-1.5 text-xs text-slate-500">{hint}</span>
            </span>
          </label>
        ))}
        {mode === "at" && (
          <Input
            type="datetime-local"
            value={at}
            onChange={(e) => setAt(e.target.value)}
            min={new Date(Date.now() + 60_000).toISOString().slice(0, 16)}
          />
        )}
        <div className="flex justify-end gap-2">
          <Button onClick={onClose}>Cancel</Button>
          <Button
            variant={mode === "now" ? "danger" : "primary"}
            loading={expire.isPending}
            disabled={mode === "at" && !at}
            onClick={() =>
              expire.mutate(
                {
                  id: node.id,
                  mode,
                  expiry: mode === "at" ? new Date(at).toISOString() : undefined,
                },
                {
                  onSuccess: () => {
                    toast.success("Expiry updated");
                    onClose();
                  },
                  onError: (e) => toast.error("Expiry update failed", errorText(e)),
                },
              )
            }
          >
            Apply
          </Button>
        </div>
        <CliHint
          command={
            mode === "never"
              ? `headscale nodes expire --identifier ${node.id} --disable-expiry`
              : mode === "at"
                ? `headscale nodes expire --identifier ${node.id} --expiry <RFC3339>`
                : `headscale nodes expire --identifier ${node.id}`
          }
        />
      </div>
    </Modal>
  );
}

function DeleteModal({ node, onClose }: { node: Node; onClose: () => void }) {
  const deleteNode = useDeleteNode();
  const toast = useToast();
  const serving = (node.subnetRoutes ?? []).length > 0;
  return (
    <ConfirmDialog
      title={`Delete ${node.givenName}?`}
      danger
      typeToConfirm={node.givenName}
      confirmLabel="Delete machine"
      busy={deleteNode.isPending}
      cli={`headscale nodes delete --identifier ${node.id}`}
      message={
        <div className="space-y-2">
          <p>The machine is removed from the tailnet and must re-register to return.</p>
          {serving && (
            <p className="font-medium text-red-600 dark:text-red-400">
              This node is currently serving routes ({(node.subnetRoutes ?? []).join(", ")}) — clients
              using them will lose connectivity.
            </p>
          )}
        </div>
      }
      onCancel={onClose}
      onConfirm={() =>
        deleteNode.mutate(
          { id: node.id },
          {
            onSuccess: () => {
              toast.success(`Deleted ${node.givenName}`);
              onClose();
            },
            onError: (e) => toast.error("Delete failed", errorText(e)),
          },
        )
      }
    />
  );
}

// ---- node detail drawer ----

function NodeDetail({
  node: n,
  onClose,
  onAction,
}: {
  node: Node;
  onClose: () => void;
  onAction: (kind: "rename" | "tags" | "routes" | "expire" | "delete") => void;
}) {
  const registerLabel: Record<string, string> = {
    REGISTER_METHOD_AUTH_KEY: "auth key",
    REGISTER_METHOD_CLI: "interactive",
    REGISTER_METHOD_OIDC: "OIDC",
  };
  return (
    <div className="fixed inset-0 z-40 flex justify-end bg-black/30" onClick={onClose}>
      <div
        className="h-full w-full max-w-lg overflow-y-auto bg-white p-5 shadow-xl dark:bg-slate-900"
        onClick={(e) => e.stopPropagation()}
      >
        <div className="mb-4 flex items-start justify-between">
          <div>
            <h2 className="flex items-center gap-2 text-lg font-semibold">
              <OnlineDot online={n.online} /> {n.givenName}
            </h2>
            <p className="text-xs text-slate-500">{n.name}</p>
            <div className="mt-2">
              <NodeBadges n={n} />
            </div>
          </div>
          <button onClick={onClose} className="rounded p-1 text-slate-400 hover:bg-slate-100 dark:hover:bg-slate-800">
            ✕
          </button>
        </div>

        <div className="mb-4 flex flex-wrap gap-2">
          <Button onClick={() => onAction("rename")}>Rename</Button>
          <Button onClick={() => onAction("tags")}>Tags</Button>
          <Button onClick={() => onAction("routes")}>Routes</Button>
          <Button onClick={() => onAction("expire")}>Expiry</Button>
          <Button variant="danger" onClick={() => onAction("delete")}>
            Delete
          </Button>
        </div>

        <dl className="space-y-3 text-sm">
          <DetailRow label="Owner">
            {(n.tags ?? []).length > 0 ? (
              <span className="flex flex-wrap gap-1">
                {(n.tags ?? []).map((t) => (
                  <Badge key={t} tone="purple">
                    {t}
                  </Badge>
                ))}
              </span>
            ) : (
              userLabel(n.user)
            )}
            <p className="mt-1 text-xs text-slate-400">
              Nodes are permanently bound to their user or tags at registration (headscale ≥0.28 — no
              move-node).
            </p>
          </DetailRow>
          <DetailRow label="Addresses">
            <ul className="space-y-0.5">
              {(n.ipAddresses ?? []).map((ip) => (
                <li key={ip} className="flex items-center gap-1 font-mono text-xs">
                  {ip} <CopyButton text={ip} />
                </li>
              ))}
            </ul>
          </DetailRow>
          <DetailRow label="Registered">
            {registerLabel[n.registerMethod ?? ""] ?? "unknown"} · {relativeTime(n.createdAt)}
          </DetailRow>
          {n.preAuthKey && (
            <DetailRow label="Pre-auth key">
              <span className="font-mono text-xs">{n.preAuthKey.key || n.preAuthKey.id}</span>
              {n.preAuthKey.ephemeral && (
                <Badge tone="purple">ephemeral</Badge>
              )}
            </DetailRow>
          )}
          <DetailRow label="Last seen">{n.online ? "online now" : relativeTime(n.lastSeen)}</DetailRow>
          <DetailRow label="Expiry">{n.expiry ? relativeTime(n.expiry) : "never"}</DetailRow>
          <DetailRow label="Machine key">
            <span className="break-all font-mono text-xs">{n.machineKey}</span>
          </DetailRow>
          <DetailRow label="Node key">
            <span className="break-all font-mono text-xs">{n.nodeKey}</span>
          </DetailRow>
          <DetailRow label="Routes">
            <RouteSummary n={n} />
          </DetailRow>
        </dl>

        <div className="mt-5">
          <CapabilityNotice level="impossible">
            Headscale does not report client OS, version, endpoints, or netcheck data — those columns
            from the Tailscale console cannot exist here.
          </CapabilityNotice>
        </div>
      </div>
    </div>
  );
}

function DetailRow({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div>
      <dt className="text-xs font-medium uppercase tracking-wide text-slate-400">{label}</dt>
      <dd className="mt-0.5">{children}</dd>
    </div>
  );
}

function RouteSummary({ n }: { n: Node }) {
  const routes = subnetRoutesOf(n);
  if (routes.advertised.length === 0 && !nodeAdvertisesExit(n) && routes.approved.length === 0) {
    return <span className="text-slate-400">none advertised</span>;
  }
  return (
    <ul className="space-y-1 text-xs">
      {[...new Set([...routes.advertised, ...routes.approved])].sort().map((r) => (
        <li key={r} className="flex items-center gap-2 font-mono">
          {r}
          {(n.subnetRoutes ?? []).includes(r) ? (
            <Badge tone="green">serving</Badge>
          ) : routes.approved.includes(r) ? (
            <Badge tone="blue">approved</Badge>
          ) : (
            <Badge tone="yellow">pending</Badge>
          )}
        </li>
      ))}
      {nodeAdvertisesExit(n) && (
        <li className="flex items-center gap-2 font-mono">
          exit node{" "}
          {nodeIsExitNode(n) ? <Badge tone="green">approved</Badge> : <Badge tone="yellow">pending</Badge>}
        </li>
      )}
    </ul>
  );
}

// ---- add device wizard ----

function AddDeviceWizard({ publicServerUrl, onClose }: { publicServerUrl: string; onClose: () => void }) {
  const [tab, setTab] = useState<"key" | "interactive">("key");
  return (
    <Modal title="Add device" onClose={onClose} wide>
      <div className="mb-4 flex gap-1 rounded-md bg-slate-100 p-1 dark:bg-slate-800">
        {(
          [
            ["key", "Pre-auth key (unattended)"],
            ["interactive", "Interactive login"],
          ] as const
        ).map(([value, label]) => (
          <button
            key={value}
            onClick={() => setTab(value)}
            className={`flex-1 rounded px-3 py-1.5 text-sm font-medium ${
              tab === value
                ? "bg-white text-slate-900 shadow dark:bg-slate-700 dark:text-slate-100"
                : "text-slate-500"
            }`}
          >
            {label}
          </button>
        ))}
      </div>
      {tab === "key" ? (
        <PreAuthKeyFlow publicServerUrl={publicServerUrl} onClose={onClose} />
      ) : (
        <InteractiveFlow publicServerUrl={publicServerUrl} onClose={onClose} />
      )}
    </Modal>
  );
}

function PreAuthKeyFlow({ publicServerUrl, onClose }: { publicServerUrl: string; onClose: () => void }) {
  const { data: users } = useUsers();
  const [userId, setUserId] = useState("");
  const [reusable, setReusable] = useState(false);
  const [ephemeral, setEphemeral] = useState(false);
  const [hours, setHours] = useState(1);
  const [tags, setTags] = useState("");
  const [secret, setSecret] = useState("");
  const create = useCreatePreAuthKey();
  const toast = useToast();

  if (secret) {
    return (
      <SecretModal
        title="Pre-auth key created"
        secret={secret}
        extraCommand={{
          label: "Run on the device:",
          command: `tailscale up --login-server ${publicServerUrl} --authkey ${secret}`,
        }}
        onClose={onClose}
      />
    );
  }

  return (
    <div className="space-y-3">
      <Field label="User">
        <Select value={userId} onChange={(e) => setUserId(e.target.value)}>
          <option value="">Select a user…</option>
          {(users ?? []).map((u) => (
            <option key={u.id} value={u.id}>
              {userLabel(u)}
            </option>
          ))}
        </Select>
      </Field>
      <div className="flex flex-wrap gap-4">
        <Checkbox checked={reusable} onChange={(e) => setReusable(e.target.checked)} label="Reusable" />
        <Checkbox
          checked={ephemeral}
          onChange={(e) => setEphemeral(e.target.checked)}
          label={
            <>
              Ephemeral <span className="text-xs text-slate-400">(node auto-removed when offline)</span>
            </>
          }
        />
      </div>
      <Field label="Expires in">
        <Select value={hours} onChange={(e) => setHours(Number(e.target.value))}>
          <option value={1}>1 hour (headscale default)</option>
          <option value={8}>8 hours</option>
          <option value={24}>24 hours</option>
          <option value={24 * 7}>7 days</option>
          <option value={24 * 90}>90 days</option>
        </Select>
      </Field>
      <Field
        label="ACL tags (optional)"
        hint="Comma-separated, e.g. tag:server,tag:ci — the node registers as tag-owned and never expires."
      >
        <Input value={tags} onChange={(e) => setTags(e.target.value)} placeholder="tag:server" />
      </Field>
      <div className="flex justify-end gap-2">
        <Button onClick={onClose}>Cancel</Button>
        <Button
          variant="primary"
          disabled={!userId}
          loading={create.isPending}
          onClick={() =>
            create.mutate(
              {
                user: userId,
                reusable,
                ephemeral,
                expiration: new Date(Date.now() + hours * 3600_000).toISOString(),
                aclTags: tags
                  .split(",")
                  .map((t) => t.trim())
                  .filter(Boolean),
              },
              {
                onSuccess: (res) => setSecret(res.preAuthKey.key ?? ""),
                onError: (e) => toast.error("Key creation failed", errorText(e)),
              },
            )
          }
        >
          Create key
        </Button>
      </div>
      <CliHint command={`headscale preauthkeys create --user ${userId || "<user-id>"}${reusable ? " --reusable" : ""}${ephemeral ? " --ephemeral" : ""}`} />
    </div>
  );
}

function InteractiveFlow({ publicServerUrl, onClose }: { publicServerUrl: string; onClose: () => void }) {
  const { data: users } = useUsers();
  const [userName, setUserName] = useState("");
  const [authId, setAuthId] = useState("");
  const register = useRegisterDevice();
  const toast = useToast();

  return (
    <div className="space-y-3">
      <ol className="list-decimal space-y-1.5 pl-5 text-sm text-slate-600 dark:text-slate-300">
        <li>
          On the device, run <Code>{`tailscale up --login-server ${publicServerUrl}`}</Code>
        </li>
        <li>The device shows a registration page with a code — paste the code or the whole URL below.</li>
      </ol>
      <Field label="Registration code or URL">
        <Input
          value={authId}
          onChange={(e) => setAuthId(e.target.value)}
          placeholder="hskey-authreq-… or https://…/register/hskey-authreq-…"
        />
      </Field>
      <Field label="Register to user">
        <Select value={userName} onChange={(e) => setUserName(e.target.value)}>
          <option value="">Select a user…</option>
          {(users ?? []).map((u) => (
            <option key={u.id} value={u.name}>
              {userLabel(u)}
            </option>
          ))}
        </Select>
      </Field>
      <div className="flex justify-end gap-2">
        <Button onClick={onClose}>Cancel</Button>
        <Button
          variant="primary"
          disabled={!userName || !authId}
          loading={register.isPending}
          onClick={() =>
            register.mutate(
              { user: userName, authId },
              {
                onSuccess: (res) => {
                  toast.success(`Registered ${res.node.givenName ?? "device"}`);
                  onClose();
                },
                onError: (e) =>
                  toast.error(
                    "Registration failed",
                    errorText(e) +
                      " — the code may have expired; ask the user to re-run tailscale up.",
                  ),
              },
            )
          }
        >
          Register device
        </Button>
      </div>
      <CliHint command={`headscale auth register --user ${userName || "<user>"} --auth-id ${authId || "<auth-id>"}`} />
    </div>
  );
}
