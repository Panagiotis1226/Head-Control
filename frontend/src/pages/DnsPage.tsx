// DNS: read-only config display (from the optional config.yaml mount) and
// the editable extra-records file (headscale hot-reloads it — no restart).

import { useEffect, useState, type ReactNode } from "react";
import { useQueryClient } from "@tanstack/react-query";
import { ApiError } from "../api/client";
import { useDns, useNodes, useSaveDnsRecords } from "../api/queries";
import type { DnsRecord } from "../api/types";
import { PageHeader } from "../components/Layout";
import { CapabilityNotice, Code, errorText } from "../components/common";
import {
  Badge,
  Button,
  Card,
  EmptyState,
  Input,
  Modal,
  Select,
  useToast,
} from "../components/ui";

const IPV4_RE = /^(\d{1,3}\.){3}\d{1,3}$/;
const NAME_RE = /^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$/;

function validateRecord(r: DnsRecord): string | null {
  if (!r.name || !NAME_RE.test(r.name)) return `"${r.name || "(empty)"}" is not a valid DNS name`;
  if (r.type === "A" && !IPV4_RE.test(r.value)) return `"${r.value}" is not a valid IPv4 address`;
  if (r.type === "AAAA" && !r.value.includes(":")) return `"${r.value}" is not a valid IPv6 address`;
  return null;
}

export function DnsPage() {
  const { data, isLoading } = useDns();

  return (
    <>
      <PageHeader title="DNS" subtitle="MagicDNS, nameservers and extra records" />

      <div className="mb-4">
        <CapabilityNotice level="config-only">
          Headscale v0.29 has no DNS API. Settings below are read from the mounted{" "}
          <Code>config.yaml</Code> (if provided); extra records are editable when{" "}
          <Code>dns.extra_records_path</Code> is mounted — headscale hot-reloads that file, no
          restart needed.
        </CapabilityNotice>
      </div>

      {isLoading ? (
        <p className="text-sm text-slate-500">Loading…</p>
      ) : (
        <div className="space-y-4">
          <ConfigCard data={data} />
          <RecordsCard data={data} />
        </div>
      )}
    </>
  );
}

function ConfigRow({ label, keyName, children }: { label: string; keyName: string; children: ReactNode }) {
  return (
    <div className="flex flex-wrap items-baseline justify-between gap-2 border-b border-slate-100 py-2 last:border-0 dark:border-slate-800">
      <div>
        <p className="text-sm font-medium text-slate-700 dark:text-slate-200">{label}</p>
        <p className="font-mono text-[11px] text-slate-400">{keyName}</p>
      </div>
      <div className="text-sm text-slate-600 dark:text-slate-300">{children}</div>
    </div>
  );
}

function ConfigCard({ data }: { data: ReturnType<typeof useDns>["data"] }) {
  if (!data?.configMounted) {
    return (
      <Card title="DNS configuration">
        <EmptyState title="Config not mounted">
          <p>
            Mount headscale's <Code>config.yaml</Code> read-only into the Head-Control container and
            set <Code>HEADSCALE_CONFIG_PATH</Code> to display MagicDNS, base domain and nameserver
            settings here.
          </p>
          <p className="mt-2">
            Relevant keys: <Code>dns.magic_dns</Code>, <Code>dns.base_domain</Code>,{" "}
            <Code>dns.nameservers.global</Code>, <Code>dns.nameservers.split</Code>,{" "}
            <Code>dns.search_domains</Code>, <Code>dns.override_local_dns</Code>,{" "}
            <Code>dns.extra_records</Code>, <Code>dns.extra_records_path</Code>
          </p>
        </EmptyState>
      </Card>
    );
  }
  if (data.configError) {
    return (
      <Card title="DNS configuration">
        <p className="text-sm text-red-600 dark:text-red-400">{data.configError}</p>
      </Card>
    );
  }
  const cfg = data.config ?? {};
  return (
    <Card title="DNS configuration (read-only)">
      <ConfigRow label="MagicDNS" keyName="dns.magic_dns">
        {cfg.magicDns === undefined ? "—" : cfg.magicDns ? <Badge tone="green">enabled</Badge> : <Badge tone="gray">disabled</Badge>}
      </ConfigRow>
      <ConfigRow label="Base domain" keyName="dns.base_domain">
        {cfg.baseDomain ? <Code>{cfg.baseDomain}</Code> : "—"}
      </ConfigRow>
      <ConfigRow label="Override local DNS" keyName="dns.override_local_dns">
        {cfg.overrideLocalDns === undefined ? "—" : cfg.overrideLocalDns ? "yes" : "no"}
      </ConfigRow>
      <ConfigRow label="Global nameservers" keyName="dns.nameservers.global">
        {(cfg.nameservers?.global ?? []).length ? (cfg.nameservers!.global!).join(", ") : "—"}
      </ConfigRow>
      <ConfigRow label="Split DNS" keyName="dns.nameservers.split">
        {cfg.nameservers?.split && Object.keys(cfg.nameservers.split).length ? (
          <ul className="space-y-0.5 text-right">
            {Object.entries(cfg.nameservers.split).map(([domain, servers]) => (
              <li key={domain} className="font-mono text-xs">
                {domain} → {servers.join(", ")}
              </li>
            ))}
          </ul>
        ) : (
          "—"
        )}
      </ConfigRow>
      <ConfigRow label="Search domains" keyName="dns.search_domains">
        {(cfg.searchDomains ?? []).length ? cfg.searchDomains!.join(", ") : "—"}
      </ConfigRow>
      {(cfg.extraRecords ?? []).length > 0 && (
        <ConfigRow label="Static extra records" keyName="dns.extra_records">
          <span className="flex items-center gap-2">
            {cfg.extraRecords!.length} record{cfg.extraRecords!.length === 1 ? "" : "s"}{" "}
            <Badge tone="yellow" title="Static records in config.yaml require a headscale restart to change">
              requires restart
            </Badge>
          </span>
        </ConfigRow>
      )}
      {(cfg.extraRecords ?? []).length > 0 && data.recordsEnabled && (
        <p className="mt-2 text-xs text-amber-700 dark:text-amber-300">
          ⚠ Both static <Code>extra_records</Code> and the editable{" "}
          <Code>extra_records_path</Code> file are in use — records come from two sources, which is
          easy to misread. Prefer the file.
        </p>
      )}
    </Card>
  );
}

function RecordsCard({ data }: { data: ReturnType<typeof useDns>["data"] }) {
  const { data: nodes } = useNodes();
  const save = useSaveDnsRecords();
  const toast = useToast();
  const qc = useQueryClient();

  const [draft, setDraft] = useState<DnsRecord[]>([]);
  const [dirty, setDirty] = useState(false);
  const [conflict, setConflict] = useState(false);

  // Sync draft from server while not editing.
  useEffect(() => {
    if (!dirty && data?.records) setDraft(data.records);
  }, [data?.records, dirty]);

  if (!data?.recordsEnabled) {
    return (
      <Card title="Extra records">
        <EmptyState title="Extra-records editing is not configured">
          <p>
            Point headscale's <Code>dns.extra_records_path</Code> at a JSON file, mount that file
            into the Head-Control container, and set <Code>EXTRA_RECORDS_PATH</Code>. Headscale
            watches the file and applies changes instantly — no restart.
          </p>
        </EmptyState>
      </Card>
    );
  }

  const errors = draft.map(validateRecord);
  const firstError = errors.find((e) => e !== null) ?? null;
  const dupes = new Set<string>();
  const seen = new Set<string>();
  for (const r of draft) {
    const k = `${r.name}/${r.type}`;
    if (seen.has(k)) dupes.add(k);
    seen.add(k);
  }

  const tailnetIps = [...new Set((nodes ?? []).flatMap((n) => n.ipAddresses ?? []))];

  const doSave = (force = false) =>
    save.mutate(
      { records: draft, expectedHash: data.recordsHash ?? "", force },
      {
        onSuccess: () => {
          setDirty(false);
          setConflict(false);
          toast.success(
            "Records saved — headscale hot-reloads this file (verify with: dig <name> @100.100.100.100 from a tailnet device)",
          );
        },
        onError: (e) => {
          if (e instanceof ApiError && e.status === 409) {
            setConflict(true);
            return;
          }
          toast.error("Save failed", errorText(e));
        },
      },
    );

  return (
    <Card
      title="Extra records"
      actions={
        <span className="flex items-center gap-2">
          {!data.recordsWritable && <Badge tone="yellow">file mounted read-only</Badge>}
          <Button
            onClick={() => {
              setDraft([...draft, { name: "", type: "A", value: "" }]);
              setDirty(true);
            }}
            disabled={!data.recordsWritable}
          >
            + Add record
          </Button>
          <Button
            variant="primary"
            disabled={!dirty || !!firstError || dupes.size > 0 || !data.recordsWritable}
            loading={save.isPending}
            onClick={() => doSave(false)}
          >
            Save
          </Button>
        </span>
      }
    >
      {draft.length === 0 ? (
        <EmptyState title="No extra records">
          <p>
            Add A/AAAA records that resolve inside your tailnet — e.g.{" "}
            <Code>grafana.example.com → 100.64.0.3</Code>
          </p>
        </EmptyState>
      ) : (
        <div className="space-y-2">
          {draft.map((r, i) => (
            <div key={i} className="flex flex-wrap items-center gap-2">
              <Input
                placeholder="grafana.example.com"
                value={r.name}
                disabled={!data.recordsWritable}
                onChange={(e) => {
                  const next = [...draft];
                  next[i] = { ...r, name: e.target.value };
                  setDraft(next);
                  setDirty(true);
                }}
                className="max-w-xs flex-1"
              />
              <Select
                value={r.type}
                disabled={!data.recordsWritable}
                onChange={(e) => {
                  const next = [...draft];
                  next[i] = { ...r, type: e.target.value as DnsRecord["type"] };
                  setDraft(next);
                  setDirty(true);
                }}
              >
                <option value="A">A</option>
                <option value="AAAA">AAAA</option>
              </Select>
              <Input
                placeholder={r.type === "A" ? "100.64.0.3" : "fd7a:115c:a1e0::3"}
                value={r.value}
                list="tailnet-ips"
                disabled={!data.recordsWritable}
                onChange={(e) => {
                  const next = [...draft];
                  next[i] = { ...r, value: e.target.value };
                  setDraft(next);
                  setDirty(true);
                }}
                className="max-w-xs flex-1 font-mono"
              />
              <button
                onClick={() => {
                  setDraft(draft.filter((_, j) => j !== i));
                  setDirty(true);
                }}
                disabled={!data.recordsWritable}
                className="rounded p-1.5 text-slate-400 hover:bg-red-50 hover:text-red-600 dark:hover:bg-red-950"
                aria-label="Delete record"
              >
                ✕
              </button>
              {errors[i] && <p className="w-full text-xs text-red-600 dark:text-red-400">{errors[i]}</p>}
            </div>
          ))}
          <datalist id="tailnet-ips">
            {tailnetIps.map((ip) => (
              <option key={ip} value={ip} />
            ))}
          </datalist>
          {dupes.size > 0 && (
            <p className="text-xs text-red-600 dark:text-red-400">
              Duplicate records: {[...dupes].join(", ")}
            </p>
          )}
        </div>
      )}
      <p className="mt-3 text-xs text-slate-400">
        Only A and AAAA records — the only types Tailscale clients process. Values usually point at
        tailnet IPs (100.64.0.0/10).
      </p>

      {conflict && (
        <Modal title="File changed outside this UI" onClose={() => setConflict(false)}>
          <div className="space-y-3 text-sm">
            <p>
              The extra-records file was modified since you loaded it (another admin, or an external
              tool). Reload to discard your edits, or overwrite the file with yours.
            </p>
            <div className="flex justify-end gap-2">
              <Button
                onClick={() => {
                  setConflict(false);
                  setDirty(false);
                  qc.invalidateQueries({ queryKey: ["dns"] });
                }}
              >
                Reload (discard my edits)
              </Button>
              <Button variant="danger" loading={save.isPending} onClick={() => doSave(true)}>
                Overwrite
              </Button>
            </div>
          </div>
        </Modal>
      )}
    </Card>
  );
}
