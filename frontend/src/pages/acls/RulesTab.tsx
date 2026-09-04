// Rules tab: one card per ACL rule (enabled switch, sources → destinations,
// protocol, ports) and the rule editor modal.

import { useMemo, useState, type Dispatch } from "react";
import type { PolicyModel } from "../../api/types";
import { CliHint, ConfirmDialog } from "../../components/common";
import { Badge, Button, Checkbox, EmptyState, Field, Input, Modal, Select, cn } from "../../components/ui";
import { PortsInput, SelectorChip, SelectorPicker } from "./inputs";
import {
  buildOptions,
  emptyForm,
  formToRule,
  protoAllowsPorts,
  ruleLabel,
  ruleToForm,
  ruleToHuJson,
  sameRule,
  splitDst,
  validateRule,
  validateSelector,
  PROTOCOLS,
  type ChangeSummary,
  type Draft,
  type DraftAction,
  type DraftRule,
  type RuleForm,
  type SelectorContext,
} from "./model";

export function RulesTab({
  draft,
  server,
  ctx,
  summary,
  writable,
  dispatch,
}: {
  draft: Draft;
  server: PolicyModel;
  ctx: SelectorContext;
  summary: ChangeSummary;
  writable: boolean;
  dispatch: Dispatch<DraftAction>;
}) {
  const [search, setSearch] = useState("");
  const [editing, setEditing] = useState<DraftRule | "new" | null>(null);
  const [deleting, setDeleting] = useState<DraftRule | null>(null);

  // "edited" marks content changes; a bare enable/disable already shows as its own badge.
  const changedKeys = useMemo(
    () =>
      new Set(
        summary.rules.changed
          .filter((c) => !(sameRule({ ...c.before, enabled: c.after.enabled }, c.after) && c.before.enabled !== c.after.enabled))
          .map((c) => c.after.key),
      ),
    [summary],
  );
  const addedKeys = useMemo(() => new Set(summary.rules.added.map((r) => r.key)), [summary]);

  const q = search.trim().toLowerCase();
  const visible = draft.rules.filter(
    (r) =>
      !q ||
      r.name.toLowerCase().includes(q) ||
      r.description.toLowerCase().includes(q) ||
      r.src.some((s) => s.toLowerCase().includes(q)) ||
      r.dst.some((d) => d.toLowerCase().includes(q)) ||
      (r.proto ?? "").includes(q),
  );

  return (
    <div className="space-y-3">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <Input
          placeholder="Search rules…"
          value={search}
          onChange={(e) => setSearch(e.target.value)}
          className="max-w-xs"
        />
        <Button variant="primary" disabled={!writable} onClick={() => setEditing("new")}>
          + Add rule
        </Button>
      </div>

      {draft.rules.length === 0 ? (
        <EmptyState title="No ACL rules">
          <p>
            Without rules nothing can talk to anything. Add a rule to allow traffic from sources
            (users, groups, tags) to destinations (tags, hosts, CIDRs) on specific ports.
          </p>
          {server.otherSections.includes("grants") && (
            <p className="mt-2">
              This policy uses <code>grants</code>; the beta editor manages the legacy <code>acls</code> section only.
            </p>
          )}
        </EmptyState>
      ) : visible.length === 0 ? (
        <EmptyState title="No rules match your search" />
      ) : (
        <ul className="space-y-2">
          {visible.map((r) => {
            const index = draft.rules.indexOf(r);
            return (
              <RuleCard
                key={r.key}
                rule={r}
                index={index}
                hosts={draft.hosts}
                status={addedKeys.has(r.key) ? "new" : changedKeys.has(r.key) ? "edited" : undefined}
                writable={writable}
                onToggle={() => dispatch({ type: "toggleRule", key: r.key })}
                onEdit={() => setEditing(r)}
                onDuplicate={() => dispatch({ type: "duplicateRule", key: r.key })}
                onDelete={() => (r.serverId ? setDeleting(r) : dispatch({ type: "deleteRule", key: r.key }))}
              />
            );
          })}
        </ul>
      )}

      {editing && (
        <RuleEditorModal
          initial={editing === "new" ? null : editing}
          ctx={ctx}
          onClose={() => setEditing(null)}
          onSave={(rule) => {
            if (editing === "new") dispatch({ type: "addRule", rule });
            else dispatch({ type: "updateRule", key: editing.key, patch: rule });
            setEditing(null);
          }}
        />
      )}

      {deleting && (
        <ConfirmDialog
          title="Delete rule"
          danger
          confirmLabel="Delete"
          message={
            <p>
              Remove <strong>{ruleLabel(deleting)}</strong> from the draft? Disabling it instead keeps it
              around for later. The change applies when you save.
            </p>
          }
          onCancel={() => setDeleting(null)}
          onConfirm={() => {
            dispatch({ type: "deleteRule", key: deleting.key });
            setDeleting(null);
          }}
        />
      )}
    </div>
  );
}

function RuleCard({
  rule,
  index,
  hosts,
  status,
  writable,
  onToggle,
  onEdit,
  onDuplicate,
  onDelete,
}: {
  rule: DraftRule;
  index: number;
  hosts: Record<string, string>;
  status?: "new" | "edited";
  writable: boolean;
  onToggle: () => void;
  onEdit: () => void;
  onDuplicate: () => void;
  onDelete: () => void;
}) {
  return (
    <li
      className={cn(
        "rounded-lg border bg-white p-3 shadow-sm dark:bg-slate-900",
        rule.enabled ? "border-slate-200 dark:border-slate-700" : "border-dashed border-slate-300 opacity-60 dark:border-slate-600",
      )}
    >
      <div className="flex flex-wrap items-start gap-3">
        <button
          type="button"
          role="switch"
          aria-checked={rule.enabled}
          disabled={!writable}
          onClick={onToggle}
          title={rule.enabled ? "Enabled — click to disable (removes it from the live policy on save)" : "Disabled — click to enable"}
          className={cn(
            "relative mt-0.5 inline-flex h-5 w-9 flex-none items-center rounded-full transition-colors disabled:cursor-not-allowed",
            rule.enabled ? "bg-indigo-600" : "bg-slate-300 dark:bg-slate-600",
          )}
        >
          <span className={cn("inline-block h-4 w-4 transform rounded-full bg-white shadow transition-transform", rule.enabled ? "translate-x-4" : "translate-x-0.5")} />
        </button>

        <div className="min-w-0 flex-1 space-y-1.5">
          <div className="flex flex-wrap items-center gap-2">
            <span className="text-sm font-medium text-slate-900 dark:text-slate-100">{rule.name || `Rule ${index + 1}`}</span>
            {rule.proto && <Badge tone="gray">{rule.proto}</Badge>}
            {!rule.enabled && <Badge tone="yellow">disabled</Badge>}
            {status === "new" && <Badge tone="green">new</Badge>}
            {status === "edited" && <Badge tone="blue">edited</Badge>}
          </div>
          {rule.description && <p className="text-xs text-slate-500 dark:text-slate-400">{rule.description}</p>}
          <div className="flex flex-wrap items-center gap-1.5 text-sm">
            {rule.src.map((s) => (
              <SelectorChip key={s} value={s} hosts={hosts} />
            ))}
            <span className="px-1 text-slate-400">→</span>
            {rule.dst.map((d) => {
              const { selector, ports } = splitDst(d);
              return <SelectorChip key={d} value={selector} hosts={hosts} suffix={ports} />;
            })}
          </div>
        </div>

        <div className="flex flex-none items-center gap-1">
          <Button variant="ghost" disabled={!writable} onClick={onEdit}>
            Edit
          </Button>
          <Button variant="ghost" disabled={!writable} onClick={onDuplicate} title="Duplicate">
            ⧉
          </Button>
          <Button variant="ghost" disabled={!writable} onClick={onDelete} className="text-red-600 dark:text-red-400" title="Delete">
            ✕
          </Button>
        </div>
      </div>
    </li>
  );
}

export function RuleEditorModal({
  initial,
  ctx,
  onSave,
  onClose,
}: {
  initial: DraftRule | null;
  ctx: SelectorContext;
  onSave: (rule: Omit<DraftRule, "key" | "serverId">) => void;
  onClose: () => void;
}) {
  const [form, setForm] = useState<RuleForm>(() => (initial ? ruleToForm(initial) : emptyForm()));
  const set = (patch: Partial<RuleForm>) => setForm((f) => ({ ...f, ...patch }));

  const srcOptions = useMemo(() => buildOptions(ctx, "src"), [ctx]);
  const dstOptions = useMemo(() => buildOptions(ctx, "dst"), [ctx]);
  const issues = validateRule(form, ctx);
  const errors = issues.filter((i) => i.level === "error");
  const warns = issues.filter((i) => i.level === "warn");
  const portsAllowed = protoAllowsPorts(form.proto);
  const mixed = form.ports.trim() === "" && Object.keys(form.dstPorts).length > 0;
  const preview = ruleToHuJson(formToRule(form));

  return (
    <Modal title={initial ? "Edit rule" : "New rule"} onClose={onClose} wide>
      <div className="space-y-4">
        <div className="grid gap-3 sm:grid-cols-2">
          <Field label="Name" hint="Shown only in Head-Control; headscale has no rule names.">
            <Input value={form.name} onChange={(e) => set({ name: e.target.value })} placeholder="e.g. Engineers → web servers" autoFocus />
          </Field>
          <Field label="Description">
            <Input value={form.description} onChange={(e) => set({ description: e.target.value })} placeholder="optional" />
          </Field>
        </div>

        <Field label="Sources" hint="Who may connect: users, groups, tags, hosts, CIDRs or autogroups.">
          <SelectorPicker
            value={form.src}
            onChange={(src) => set({ src })}
            options={srcOptions}
            validate={(s) => validateSelector(s, "src", ctx)}
            hosts={ctx.hosts}
            placeholder="group:eng, alice@, tag:ci, 10.0.0.0/24 …"
          />
        </Field>

        <Field label="Destinations" hint="What they may reach. Ports are set below.">
          <SelectorPicker
            value={form.dst}
            onChange={(dst) => set({ dst })}
            options={dstOptions}
            validate={(s) => validateSelector(s, "dst", ctx)}
            hosts={ctx.hosts}
            placeholder="tag:web, db1, autogroup:internet, * …"
          />
        </Field>

        <div className="grid gap-3 sm:grid-cols-[12rem_1fr]">
          <Field label="Protocol">
            <Select
              value={form.proto}
              onChange={(e) => {
                const proto = e.target.value;
                set(protoAllowsPorts(proto) ? { proto } : { proto, ports: "*" });
              }}
              className="w-full"
            >
              {PROTOCOLS.map((p) => (
                <option key={p.value} value={p.value}>
                  {p.label}
                </option>
              ))}
            </Select>
          </Field>
          <Field
            label="Ports"
            hint={
              !portsAllowed
                ? "This protocol has no ports."
                : mixed
                  ? "Destinations keep their individual ports unless you type one spec for all."
                  : "Applies to every destination: * for all, or a list like 22, 80-90, 443."
            }
          >
            <PortsInput value={form.ports} onChange={(ports) => set({ ports })} disabled={!portsAllowed} mixed={mixed} />
          </Field>
        </div>

        <Checkbox label="Enabled (disabled rules are kept here but removed from the live policy)" checked={form.enabled} onChange={(e) => set({ enabled: e.target.checked })} />

        {(errors.length > 0 || warns.length > 0) && (
          <div className="space-y-1.5">
            {errors.map((i, n) => (
              <p key={`e${n}`} className="rounded-md border border-red-300 bg-red-50 px-3 py-1.5 text-xs text-red-800 dark:border-red-700 dark:bg-red-950/40 dark:text-red-300">
                {i.text}
              </p>
            ))}
            {warns.map((i, n) => (
              <p key={`w${n}`} className="rounded-md border border-amber-300 bg-amber-50 px-3 py-1.5 text-xs text-amber-900 dark:border-amber-700 dark:bg-amber-950/40 dark:text-amber-200">
                {i.text}
              </p>
            ))}
          </div>
        )}

        <div className="flex justify-end gap-2">
          <Button onClick={onClose}>Cancel</Button>
          <Button variant="primary" disabled={errors.length > 0} onClick={() => onSave(formToRule(form))}>
            {initial ? "Update rule" : "Add rule"}
          </Button>
        </div>
        <CliHint command={preview} />
      </div>
    </Modal>
  );
}
