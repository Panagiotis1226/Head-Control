// Settings: server status + integrations, audit log with export, and the
// advanced tools (backfill IPs, debug node, legacy-register toggle, purge).

import { useState, type ReactNode } from "react";
import {
  useAudit,
  useBackfillIps,
  useDebugCreateNode,
  useMeta,
  usePurgeAudit,
  useUsers,
} from "../api/queries";
import type { AuditEntry } from "../api/types";
import { PageHeader } from "../components/Layout";
import {
  CapabilityNotice,
  CliHint,
  Code,
  ConfirmDialog,
  CopyButton,
  errorText,
} from "../components/common";
import {
  Badge,
  Button,
  Card,
  Checkbox,
  EmptyState,
  Field,
  Input,
  Select,
  Table,
  Td,
  Th,
  useToast,
} from "../components/ui";
import { absoluteTime, relativeTime, userLabel } from "../lib/format";

type Tab = "server" | "audit" | "advanced";

export function SettingsPage() {
  const [tab, setTab] = useState<Tab>("server");
  return (
    <>
      <PageHeader title="Settings" />
      <div className="mb-4 flex max-w-md gap-1 rounded-md bg-slate-100 p-1 dark:bg-slate-800">
        {(
          [
            ["server", "Server"],
            ["audit", "Audit log"],
            ["advanced", "Advanced"],
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
      {tab === "server" && <ServerTab />}
      {tab === "audit" && <AuditTab />}
      {tab === "advanced" && <AdvancedTab />}
    </>
  );
}

function Row({ label, hint, children }: { label: string; hint?: string; children: ReactNode }) {
  return (
    <div className="flex flex-wrap items-baseline justify-between gap-2 border-b border-slate-100 py-2 last:border-0 dark:border-slate-800">
      <div>
        <p className="text-sm font-medium text-slate-700 dark:text-slate-200">{label}</p>
        {hint && <p className="font-mono text-[11px] text-slate-400">{hint}</p>}
      </div>
      <div className="text-sm text-slate-600 dark:text-slate-300">{children}</div>
    </div>
  );
}

function ServerTab() {
  const { data: m } = useMeta();
  if (!m) return <p className="text-sm text-slate-500">Loading…</p>;
  const hs = m.headscale;
  return (
    <div className="space-y-4">
      <Card title="Headscale connection">
        <Row label="Status">
          {hs.reachable && hs.apiKeyValid && hs.databaseOk ? (
            <Badge tone="green">connected</Badge>
          ) : (
            <Badge tone="red">degraded</Badge>
          )}
        </Row>
        <Row label="Headscale URL" hint="HEADSCALE_URL">
          <Code>{m.headscaleUrl}</Code>
        </Row>
        <Row label="Public server URL" hint="PUBLIC_SERVER_URL — used in copyable tailscale up commands">
          <Code>{m.publicServerUrl}</Code>
        </Row>
        <Row label="Headscale version">
          {hs.version ? (
            <span className="flex items-center gap-2">
              v{hs.version}{" "}
              {hs.supported ? (
                <Badge tone="green">supported</Badge>
              ) : (
                <Badge tone="yellow" title={hs.supportNote}>
                  unsupported
                </Badge>
              )}
            </span>
          ) : (
            "unknown"
          )}
        </Row>
        <Row label="Database connectivity">{hs.databaseOk ? "ok" : <Badge tone="red">failing</Badge>}</Row>
        <Row label="API key">
          {hs.apiKeyValid ? "valid" : <Badge tone="red">rejected</Badge>}
          {m.uiApiKeyPrefix && (
            <span className="ml-2 font-mono text-xs text-slate-400">prefix {m.uiApiKeyPrefix}</span>
          )}
        </Row>
        <Row label="API latency">{hs.latencyMs} ms</Row>
        <Row label="Last checked">{relativeTime(hs.checkedAt)}</Row>
        {hs.lastError && (
          <p className="mt-2 text-xs text-red-600 dark:text-red-400">{hs.lastError}</p>
        )}
      </Card>

      <Card title="Integrations">
        <Row label="Policy file mount" hint="POLICY_FILE_PATH — file-mode ACL editing">
          <Badge tone={m.capabilities.policyFileMounted ? "green" : "gray"}>
            {m.capabilities.policyFileMounted ? "mounted" : "not configured"}
          </Badge>
        </Row>
        <Row label="DNS extra records" hint="EXTRA_RECORDS_PATH — editable, hot-reloaded">
          <Badge tone={m.capabilities.extraRecordsWritable ? "green" : "gray"}>
            {m.capabilities.extraRecordsWritable
              ? "editable"
              : m.capabilities.extraRecords
                ? "read-only"
                : "not configured"}
          </Badge>
        </Row>
        <Row label="Config display" hint="HEADSCALE_CONFIG_PATH — read-only config.yaml mount">
          <Badge tone={m.capabilities.configView ? "green" : "gray"}>
            {m.capabilities.configView ? "mounted" : "not configured"}
          </Badge>
        </Row>
        <Row label="Docker reload" hint="DOCKER_SOCK — SIGHUP after file-mode policy saves">
          {m.capabilities.docker ? (
            m.docker?.reachable ? (
              <Badge tone="green">connected → {m.docker.containerName}</Badge>
            ) : (
              <Badge tone="red" title={m.docker?.error}>
                configured, unreachable
              </Badge>
            )
          ) : (
            <Badge tone="gray">not configured</Badge>
          )}
        </Row>
      </Card>

      <Card title="About">
        <Row label="Head-Control version">{m.version}</Row>
        <Row label="Base path">{m.basePath || "/"}</Row>
        <p className="mt-2 text-xs text-slate-400">
          Targets headscale v0.29.x (tested against v0.29.3). Headscale 0.30 changes the API (gRPC
          removal, new error format) and will need the next Head-Control release.
        </p>
      </Card>
    </div>
  );
}

function AuditTab() {
  const [action, setAction] = useState("");
  const [outcome, setOutcome] = useState("");
  const [sinceHours, setSinceHours] = useState<number | undefined>(168);
  const { data: entries } = useAudit({ action: action || undefined, outcome: outcome || undefined, sinceHours });
  const purge = usePurgeAudit();
  const toast = useToast();
  const [purging, setPurging] = useState(false);

  const download = (filename: string, mime: string, content: string) => {
    const url = URL.createObjectURL(new Blob([content], { type: mime }));
    const a = document.createElement("a");
    a.href = url;
    a.download = filename;
    a.click();
    URL.revokeObjectURL(url);
  };
  const exportJSON = () => download("head-control-audit.json", "application/json", JSON.stringify(entries ?? [], null, 2));
  const exportCSV = () => {
    const esc = (s: string) => `"${(s ?? "").replaceAll('"', '""')}"`;
    const rows = (entries ?? []).map((e: AuditEntry) =>
      [e.time, e.action, e.targetType ?? "", e.targetName || e.targetId || "", e.summary ?? "", e.outcome, e.error ?? "", e.cli ?? ""].map(esc).join(","),
    );
    download("head-control-audit.csv", "text/csv", ["time,action,targetType,target,summary,outcome,error,cli", ...rows].join("\n"));
  };

  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-center gap-2">
        <Select value={action} onChange={(e) => setAction(e.target.value)}>
          <option value="">All actions</option>
          {["user.", "node.", "preauthkey.", "apikey.", "policy.", "dns.", "auth."].map((p) => (
            <option key={p} value={p}>
              {p}*
            </option>
          ))}
        </Select>
        <Select value={outcome} onChange={(e) => setOutcome(e.target.value)}>
          <option value="">All outcomes</option>
          <option value="ok">ok</option>
          <option value="error">error</option>
        </Select>
        <Select
          value={sinceHours ?? ""}
          onChange={(e) => setSinceHours(e.target.value ? Number(e.target.value) : undefined)}
        >
          <option value={24}>Last 24 h</option>
          <option value={168}>Last 7 days</option>
          <option value={720}>Last 30 days</option>
          <option value="">All time</option>
        </Select>
        <span className="flex-1" />
        <Button onClick={exportJSON}>Export JSON</Button>
        <Button onClick={exportCSV}>Export CSV</Button>
      </div>

      {(entries ?? []).length === 0 ? (
        <EmptyState title="No audit entries match" />
      ) : (
        <Table
          head={
            <>
              <Th>Time</Th>
              <Th>Action</Th>
              <Th>Target</Th>
              <Th>Summary</Th>
              <Th>Outcome</Th>
              <Th>CLI</Th>
            </>
          }
        >
          {(entries ?? []).map((e) => (
            <tr key={e.id}>
              <Td>
                <span title={absoluteTime(e.time)} className="whitespace-nowrap text-xs">
                  {relativeTime(e.time)}
                </span>
              </Td>
              <Td>
                <Code>{e.action}</Code>
              </Td>
              <Td>{e.targetName || e.targetId || "—"}</Td>
              <Td className="max-w-[16rem] truncate" >
                <span title={e.summary}>{e.summary || "—"}</span>
              </Td>
              <Td>
                <Badge tone={e.outcome === "ok" ? "green" : "red"} title={e.error}>
                  {e.outcome}
                </Badge>
              </Td>
              <Td>{e.cli ? <CopyButton text={e.cli} label="copy cmd" /> : "—"}</Td>
            </tr>
          ))}
        </Table>
      )}

      <p className="text-xs text-slate-400">
        Only actions performed through this UI are recorded — CLI/API changes made elsewhere are not.
        (ACL history captures external edits via snapshots.) Entries are pruned after 90 days.
      </p>

      <div>
        <Button variant="danger" onClick={() => setPurging(true)}>
          Purge audit log…
        </Button>
        {purging && (
          <ConfirmDialog
            title="Purge the audit log?"
            danger
            confirmLabel="Purge everything"
            message="All audit entries are permanently deleted. This cannot be undone."
            busy={purge.isPending}
            onCancel={() => setPurging(false)}
            onConfirm={() =>
              purge.mutate(undefined, {
                onSuccess: () => {
                  setPurging(false);
                  toast.success("Audit log purged");
                },
                onError: (e) => toast.error("Purge failed", errorText(e)),
              })
            }
          />
        )}
      </div>
    </div>
  );
}

function AdvancedTab() {
  const backfill = useBackfillIps();
  const debugCreate = useDebugCreateNode();
  const { data: users } = useUsers();
  const toast = useToast();

  const [dryRunChanges, setDryRunChanges] = useState<string[] | null>(null);
  const [debug, setDebug] = useState({ user: "", key: "", name: "", routes: "" });
  const [legacyRegister, setLegacyRegister] = useState(
    () => localStorage.getItem("hc-legacy-register") === "true",
  );

  return (
    <div className="space-y-4">
      <Card title="Backfill IP addresses">
        <p className="mb-3 text-sm text-slate-600 dark:text-slate-300">
          Assigns missing IPv4/IPv6 addresses to nodes after you enable an additional address family
          in headscale's <Code>prefixes</Code> config. Always dry-run first.
        </p>
        <div className="flex gap-2">
          <Button
            loading={backfill.isPending && !backfill.variables?.confirmed}
            onClick={() =>
              backfill.mutate(
                { confirmed: false },
                {
                  onSuccess: (res) => setDryRunChanges(res.changes ?? []),
                  onError: (e) => toast.error("Dry run failed", errorText(e)),
                },
              )
            }
          >
            Dry run
          </Button>
          <Button
            variant="danger"
            disabled={dryRunChanges === null}
            loading={backfill.isPending && backfill.variables?.confirmed}
            onClick={() =>
              backfill.mutate(
                { confirmed: true },
                {
                  onSuccess: (res) => {
                    setDryRunChanges(res.changes ?? []);
                    toast.success("Backfill applied");
                  },
                  onError: (e) => toast.error("Backfill failed", errorText(e)),
                },
              )
            }
          >
            Apply
          </Button>
        </div>
        {dryRunChanges !== null && (
          <ul className="mt-3 max-h-48 space-y-0.5 overflow-y-auto rounded bg-slate-50 p-2 font-mono text-xs dark:bg-slate-800">
            {dryRunChanges.length === 0 ? <li>no changes needed</li> : dryRunChanges.map((c, i) => <li key={i}>{c}</li>)}
          </ul>
        )}
        <CliHint command="headscale nodes backfillips [--confirmed]" />
      </Card>

      <Card title="Create debug node">
        <div className="mb-3 rounded-md border border-amber-300 bg-amber-50 px-3 py-2 text-xs text-amber-900 dark:border-amber-700 dark:bg-amber-950/40 dark:text-amber-200">
          Testing only — creates a node record without a real client connecting.
        </div>
        <div className="grid gap-3 sm:grid-cols-2">
          <Field label="User">
            <Select value={debug.user} onChange={(e) => setDebug({ ...debug, user: e.target.value })}>
              <option value="">Select…</option>
              {(users ?? []).map((u) => (
                <option key={u.id} value={u.name}>
                  {userLabel(u)}
                </option>
              ))}
            </Select>
          </Field>
          <Field label="Node name">
            <Input value={debug.name} onChange={(e) => setDebug({ ...debug, name: e.target.value })} placeholder="test-node" />
          </Field>
          <Field label="Registration key">
            <Input value={debug.key} onChange={(e) => setDebug({ ...debug, key: e.target.value })} placeholder="hskey-authreq-… (a pending registration id)" />
          </Field>
          <Field label="Advertised routes (optional)">
            <Input value={debug.routes} onChange={(e) => setDebug({ ...debug, routes: e.target.value })} placeholder="10.0.0.0/24,192.168.1.0/24" />
          </Field>
        </div>
        <div className="mt-3">
          <Button
            variant="primary"
            disabled={!debug.user || !debug.name || !debug.key}
            loading={debugCreate.isPending}
            onClick={() =>
              debugCreate.mutate(
                {
                  user: debug.user,
                  key: debug.key,
                  name: debug.name,
                  routes: debug.routes.split(",").map((r) => r.trim()).filter(Boolean),
                },
                {
                  onSuccess: (res) => toast.success(`Debug node ${res.node.givenName} created`),
                  onError: (e) => toast.error("Creation failed", errorText(e)),
                },
              )
            }
          >
            Create debug node
          </Button>
        </div>
        <CliHint command={`headscale debug create-node --user ${debug.user || "<user>"} --key ${debug.key || "<key>"} --name ${debug.name || "<name>"}`} />
      </Card>

      <Card title="Legacy registration endpoint">
        <p className="mb-2 text-sm text-slate-600 dark:text-slate-300">
          Headscale 0.29 deprecates <Code>POST /api/v1/node/register</Code> in favor of the new{" "}
          <Code>/api/v1/auth/register</Code>. If registrations fail through the normal path, this
          fallback switches the Registrations page to the legacy endpoint.
        </p>
        <Checkbox
          checked={legacyRegister}
          onChange={(e) => {
            setLegacyRegister(e.target.checked);
            localStorage.setItem("hc-legacy-register", String(e.target.checked));
          }}
          label="Use the deprecated legacy register endpoint (troubleshooting only)"
        />
      </Card>

      <CapabilityNotice level="ui-local">
        Everything on this page except backfill/debug-node lives in Head-Control's own database —
        purging it never touches headscale state.
      </CapabilityNotice>
    </div>
  );
}
