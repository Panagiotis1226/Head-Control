// Groups, Tag owners and Hosts tabs: tables of the policy's named things,
// each with a small editor modal, rename with reference rewriting, and
// delete with a reference warning.

import { useMemo, useState, type Dispatch, type ReactNode } from "react";
import { ConfirmDialog } from "../../components/common";
import { Badge, Button, EmptyState, Field, Input, Modal, Table, Td, Th, cn } from "../../components/ui";
import { SelectorChip, SelectorPicker } from "./inputs";
import {
  isIpOrCidr,
  referencesOf,
  userSelectors,
  validateSelector,
  type ChangeSummary,
  type Draft,
  type DraftAction,
  type Issue,
  type KeyChanges,
  type KeySection,
  type Reference,
  type SelectorContext,
  type SelectorOption,
} from "./model";

interface TabProps {
  draft: Draft;
  ctx: SelectorContext;
  summary: ChangeSummary;
  writable: boolean;
  dispatch: Dispatch<DraftAction>;
}

function statusOf(name: string, ch: KeyChanges): ReactNode {
  if (ch.added.includes(name)) return <Badge tone="green">new</Badge>;
  if (ch.changed.includes(name)) return <Badge tone="blue">edited</Badge>;
  return null;
}

function UsedBy({ refs }: { refs: Reference[] }) {
  if (refs.length === 0) return <span className="text-xs text-slate-400">unused</span>;
  const rules = refs.filter((r) => r.kind === "rule").length;
  const owners = refs.filter((r) => r.kind === "tagOwner").length;
  const parts = [];
  if (rules) parts.push(`${rules} rule${rules === 1 ? "" : "s"}`);
  if (owners) parts.push(`${owners} tag owner${owners === 1 ? "" : "s"}`);
  return (
    <span className="text-xs text-slate-500" title={refs.map((r) => r.label).join("\n")}>
      {parts.join(", ")}
    </span>
  );
}

function DeleteKeyDialog({
  section,
  name,
  refs,
  onCancel,
  onConfirm,
}: {
  section: KeySection;
  name: string;
  refs: Reference[];
  onCancel: () => void;
  onConfirm: () => void;
}) {
  const noun = section === "groups" ? "group" : section === "tagOwners" ? "tag owner entry" : "host";
  return (
    <ConfirmDialog
      title={`Delete ${noun}`}
      danger={refs.length > 0}
      confirmLabel="Delete"
      message={
        <div className="space-y-2">
          <p>
            Remove <code className="font-mono">{name}</code> from the draft?
          </p>
          {refs.length > 0 && (
            <div className="rounded-md border border-amber-300 bg-amber-50 px-3 py-2 text-xs text-amber-900 dark:border-amber-700 dark:bg-amber-950/40 dark:text-amber-200">
              <p className="font-medium">Still referenced by:</p>
              <ul className="mt-1 list-inside list-disc">
                {refs.map((r) => (
                  <li key={r.kind + r.key}>{r.label}</li>
                ))}
              </ul>
              <p className="mt-1">Those references will break; headscale rejects policies with unknown names.</p>
            </div>
          )}
        </div>
      }
      onCancel={onCancel}
      onConfirm={onConfirm}
    />
  );
}

// ---- shared list editor (groups & tag owners) ----

function ListEntryEditor({
  title,
  prefix,
  nameLabel,
  membersLabel,
  membersHint,
  initial,
  existing,
  options,
  validateMember,
  hosts,
  onSave,
  onClose,
}: {
  title: string;
  prefix: "group:" | "tag:";
  nameLabel: string;
  membersLabel: string;
  membersHint: string;
  initial: { name: string; members: string[] } | null;
  existing: string[];
  options: SelectorOption[];
  validateMember: (raw: string) => Issue | null;
  hosts: Record<string, string>;
  onSave: (name: string, members: string[]) => void;
  onClose: () => void;
}) {
  const [name, setName] = useState(initial?.name ?? "");
  const [members, setMembers] = useState<string[]>(initial?.members ?? []);
  const exists = !!initial && existing.includes(initial.name); // false when declaring an undeclared tag
  const normalized = normalizeName(name, prefix);
  const nameError =
    normalized === prefix
      ? "name is required"
      : /\s/.test(normalized)
        ? "no whitespace allowed"
        : prefix === "tag:" && !/^tag:[A-Za-z]/.test(normalized)
          ? "tag names must start with a letter"
          : normalized !== initial?.name && existing.includes(normalized)
            ? `${normalized} already exists`
            : null;
  const memberErrors = members.map((m) => validateMember(m)).filter((i): i is Issue => !!i && i.level === "error");

  return (
    <Modal title={title} onClose={onClose}>
      <div className="space-y-3">
        <Field label={nameLabel} hint={exists ? "Renaming rewrites every reference in rules and tag owners." : `The ${prefix} prefix is added automatically.`}>
          <Input value={name} onChange={(e) => setName(e.target.value)} placeholder={prefix === "group:" ? "group:engineering" : "tag:web"} autoFocus className="font-mono" />
          {nameError && name !== "" && <p className="mt-1 text-xs text-red-600 dark:text-red-400">{nameError}</p>}
        </Field>
        <Field label={membersLabel} hint={membersHint}>
          <SelectorPicker value={members} onChange={setMembers} options={options} validate={validateMember} hosts={hosts} placeholder={prefix === "group:" ? "alice@, bob@example.com" : "group:eng, alice@"} />
        </Field>
        <div className="flex justify-end gap-2 pt-1">
          <Button onClick={onClose}>Cancel</Button>
          <Button variant="primary" disabled={!!nameError || memberErrors.length > 0} onClick={() => onSave(normalized, members)}>
            {exists ? "Update" : "Add"}
          </Button>
        </div>
      </div>
    </Modal>
  );
}

function normalizeName(raw: string, prefix: "group:" | "tag:"): string {
  let s = raw.trim().toLowerCase();
  if (s && !s.startsWith(prefix)) s = prefix + s;
  return s || prefix;
}

// ---- Groups ----

export function GroupsTab({ draft, ctx, summary, writable, dispatch }: TabProps) {
  const [editing, setEditing] = useState<string | "new" | null>(null);
  const [deleting, setDeleting] = useState<string | null>(null);
  const names = Object.keys(draft.groups).sort();
  const userOptions = useMemo<SelectorOption[]>(
    () => ctx.users.flatMap((u) => userSelectors(u).map((s, i) => ({ value: s, kind: "user" as const, hint: i === 0 ? u.displayName || u.email || undefined : "email" }))),
    [ctx.users],
  );
  const validateMember = (raw: string): Issue | null => {
    const s = raw.trim();
    if (!s || /\s/.test(s)) return { level: "error", text: "users cannot be empty or contain spaces" };
    if (!s.includes("@")) return { level: "error", text: 'write users as "name@" or an email address' };
    return validateSelector(s, "src", ctx);
  };

  return (
    <div className="space-y-3">
      <div className="flex items-center justify-between">
        <p className="text-sm text-slate-500 dark:text-slate-400">Groups collect users. Use them as sources, destinations or tag owners.</p>
        <Button variant="primary" disabled={!writable} onClick={() => setEditing("new")}>
          + Add group
        </Button>
      </div>
      {names.length === 0 ? (
        <EmptyState title="No groups yet" />
      ) : (
        <Table
          head={
            <>
              <Th>Group</Th>
              <Th>Members</Th>
              <Th>Used by</Th>
              <Th className="text-right">Actions</Th>
            </>
          }
        >
          {names.map((g) => (
            <tr key={g}>
              <Td>
                <span className="flex items-center gap-2 font-mono text-sm">
                  {g} {statusOf(g, summary.groups)}
                </span>
              </Td>
              <Td>
                <span className="flex flex-wrap gap-1">
                  {draft.groups[g].length === 0 && <span className="text-xs text-slate-400">no members</span>}
                  {draft.groups[g].map((m) => (
                    <SelectorChip key={m} value={m} />
                  ))}
                </span>
              </Td>
              <Td>
                <UsedBy refs={referencesOf(draft, g)} />
              </Td>
              <Td className="text-right">
                <RowActions writable={writable} onEdit={() => setEditing(g)} onDelete={() => setDeleting(g)} />
              </Td>
            </tr>
          ))}
        </Table>
      )}

      {editing && (
        <ListEntryEditor
          title={editing === "new" ? "New group" : `Edit ${editing}`}
          prefix="group:"
          nameLabel="Group name"
          membersLabel="Members"
          membersHint="Users only (headscale groups cannot contain other groups or tags)."
          initial={editing === "new" ? null : { name: editing, members: draft.groups[editing] }}
          existing={names}
          options={userOptions}
          validateMember={validateMember}
          hosts={draft.hosts}
          onClose={() => setEditing(null)}
          onSave={(name, members) => {
            if (editing !== "new" && name !== editing) dispatch({ type: "renameKey", section: "groups", from: editing, to: name });
            dispatch({ type: "setEntry", section: "groups", name, members });
            setEditing(null);
          }}
        />
      )}
      {deleting && (
        <DeleteKeyDialog
          section="groups"
          name={deleting}
          refs={referencesOf(draft, deleting)}
          onCancel={() => setDeleting(null)}
          onConfirm={() => {
            dispatch({ type: "deleteKey", section: "groups", name: deleting });
            setDeleting(null);
          }}
        />
      )}
    </div>
  );
}

// ---- Tag owners ----

export function TagOwnersTab({ draft, ctx, summary, writable, dispatch }: TabProps) {
  const [editing, setEditing] = useState<{ name: string; members: string[] } | "new" | null>(null);
  const [deleting, setDeleting] = useState<string | null>(null);
  const names = Object.keys(draft.tagOwners).sort();
  const undeclared = [...ctx.nodeTags.keys()].filter((t) => !(t in draft.tagOwners)).sort();

  const ownerOptions = useMemo<SelectorOption[]>(
    () => [
      ...Object.keys(draft.groups)
        .sort()
        .map((g) => ({ value: g, kind: "group" as const, hint: `${draft.groups[g].length} members` })),
      ...ctx.users.flatMap((u) => userSelectors(u).map((s, i) => ({ value: s, kind: "user" as const, hint: i === 0 ? u.displayName || u.email || undefined : "email" }))),
    ],
    [draft.groups, ctx.users],
  );
  const validateOwner = (raw: string): Issue | null => {
    const s = raw.trim();
    if (!s || /\s/.test(s)) return { level: "error", text: "owners cannot be empty or contain spaces" };
    if (!s.startsWith("group:") && !s.includes("@")) return { level: "error", text: "owners are groups (group:…) or users (name@)" };
    return validateSelector(s, "src", ctx);
  };

  return (
    <div className="space-y-3">
      <div className="flex items-center justify-between">
        <p className="text-sm text-slate-500 dark:text-slate-400">Tag owners declare which tags exist and who may assign them to devices.</p>
        <Button variant="primary" disabled={!writable} onClick={() => setEditing("new")}>
          + Add tag
        </Button>
      </div>

      {undeclared.length > 0 && (
        <div className="rounded-md border border-amber-300 bg-amber-50 px-3 py-2 text-xs text-amber-900 dark:border-amber-700 dark:bg-amber-950/40 dark:text-amber-200">
          <p className="font-medium">Tags on devices that are not declared here:</p>
          <div className="mt-1.5 flex flex-wrap gap-1.5">
            {undeclared.map((t) => (
              <span key={t} className="inline-flex items-center gap-1">
                <SelectorChip value={t} warn={`on ${ctx.nodeTags.get(t)} device(s)`} />
                <button
                  type="button"
                  disabled={!writable}
                  onClick={() => setEditing({ name: t, members: [] })}
                  className="text-xs underline decoration-dotted hover:text-amber-950 disabled:opacity-50 dark:hover:text-amber-100"
                >
                  declare
                </button>
              </span>
            ))}
          </div>
        </div>
      )}

      {names.length === 0 ? (
        <EmptyState title="No tag owners yet" />
      ) : (
        <Table
          head={
            <>
              <Th>Tag</Th>
              <Th>Owners</Th>
              <Th>Devices</Th>
              <Th>Used by</Th>
              <Th className="text-right">Actions</Th>
            </>
          }
        >
          {names.map((t) => (
            <tr key={t}>
              <Td>
                <span className="flex items-center gap-2 font-mono text-sm">
                  {t} {statusOf(t, summary.tagOwners)}
                </span>
              </Td>
              <Td>
                <span className="flex flex-wrap gap-1">
                  {draft.tagOwners[t].length === 0 && <span className="text-xs text-slate-400">no owners</span>}
                  {draft.tagOwners[t].map((o) => (
                    <SelectorChip key={o} value={o} />
                  ))}
                </span>
              </Td>
              <Td>
                <span className="text-xs text-slate-500">{ctx.nodeTags.get(t) ?? 0}</span>
              </Td>
              <Td>
                <UsedBy refs={referencesOf(draft, t)} />
              </Td>
              <Td className="text-right">
                <RowActions writable={writable} onEdit={() => setEditing({ name: t, members: draft.tagOwners[t] })} onDelete={() => setDeleting(t)} />
              </Td>
            </tr>
          ))}
        </Table>
      )}

      {editing && (
        <ListEntryEditor
          title={editing === "new" ? "New tag" : editing.name in draft.tagOwners ? `Edit ${editing.name}` : `Declare ${editing.name}`}
          prefix="tag:"
          nameLabel="Tag"
          membersLabel="Owners"
          membersHint="Groups or users allowed to put this tag on a device."
          initial={editing === "new" ? null : editing}
          existing={names}
          options={ownerOptions}
          validateMember={validateOwner}
          hosts={draft.hosts}
          onClose={() => setEditing(null)}
          onSave={(name, members) => {
            if (editing !== "new" && editing.name in draft.tagOwners && name !== editing.name) {
              dispatch({ type: "renameKey", section: "tagOwners", from: editing.name, to: name });
            }
            dispatch({ type: "setEntry", section: "tagOwners", name, members });
            setEditing(null);
          }}
        />
      )}
      {deleting && (
        <DeleteKeyDialog
          section="tagOwners"
          name={deleting}
          refs={referencesOf(draft, deleting)}
          onCancel={() => setDeleting(null)}
          onConfirm={() => {
            dispatch({ type: "deleteKey", section: "tagOwners", name: deleting });
            setDeleting(null);
          }}
        />
      )}
    </div>
  );
}

// ---- Hosts ----

export function HostsTab({ draft, summary, writable, dispatch }: TabProps) {
  const [editing, setEditing] = useState<string | "new" | null>(null);
  const [deleting, setDeleting] = useState<string | null>(null);
  const names = Object.keys(draft.hosts).sort();

  return (
    <div className="space-y-3">
      <div className="flex items-center justify-between">
        <p className="text-sm text-slate-500 dark:text-slate-400">Hosts give names to IPs and CIDRs so rules stay readable.</p>
        <Button variant="primary" disabled={!writable} onClick={() => setEditing("new")}>
          + Add host
        </Button>
      </div>
      {names.length === 0 ? (
        <EmptyState title="No hosts yet" />
      ) : (
        <Table
          head={
            <>
              <Th>Name</Th>
              <Th>Address</Th>
              <Th>Used by</Th>
              <Th className="text-right">Actions</Th>
            </>
          }
        >
          {names.map((h) => (
            <tr key={h}>
              <Td>
                <span className="flex items-center gap-2 font-mono text-sm">
                  {h} {statusOf(h, summary.hosts)}
                </span>
              </Td>
              <Td>
                <span className="font-mono text-sm">{draft.hosts[h]}</span>
              </Td>
              <Td>
                <UsedBy refs={referencesOf(draft, h)} />
              </Td>
              <Td className="text-right">
                <RowActions writable={writable} onEdit={() => setEditing(h)} onDelete={() => setDeleting(h)} />
              </Td>
            </tr>
          ))}
        </Table>
      )}

      {editing && (
        <HostEditor
          initial={editing === "new" ? null : { name: editing, cidr: draft.hosts[editing] }}
          existing={names}
          onClose={() => setEditing(null)}
          onSave={(name, cidr) => {
            if (editing !== "new" && name !== editing) dispatch({ type: "renameKey", section: "hosts", from: editing, to: name });
            dispatch({ type: "setHost", name, cidr });
            setEditing(null);
          }}
        />
      )}
      {deleting && (
        <DeleteKeyDialog
          section="hosts"
          name={deleting}
          refs={referencesOf(draft, deleting)}
          onCancel={() => setDeleting(null)}
          onConfirm={() => {
            dispatch({ type: "deleteKey", section: "hosts", name: deleting });
            setDeleting(null);
          }}
        />
      )}
    </div>
  );
}

function HostEditor({
  initial,
  existing,
  onSave,
  onClose,
}: {
  initial: { name: string; cidr: string } | null;
  existing: string[];
  onSave: (name: string, cidr: string) => void;
  onClose: () => void;
}) {
  const [name, setName] = useState(initial?.name ?? "");
  const [cidr, setCidr] = useState(initial?.cidr ?? "");
  const n = name.trim();
  const nameError = !n
    ? "name is required"
    : !/^[A-Za-z0-9][A-Za-z0-9_.-]*$/.test(n)
      ? "letters, digits, dot, dash and underscore only"
      : /^(group|tag|autogroup):/.test(n)
        ? "host names cannot use a reserved prefix"
        : n !== initial?.name && existing.includes(n)
          ? `${n} already exists`
          : null;
  const cidrError = !cidr.trim() ? "address is required" : !isIpOrCidr(cidr.trim()) ? "enter an IP (10.0.0.5) or CIDR (10.0.0.0/24)" : null;

  return (
    <Modal title={initial ? `Edit ${initial.name}` : "New host"} onClose={onClose}>
      <div className="space-y-3">
        <Field label="Name" hint={initial ? "Renaming rewrites every reference in rules." : undefined}>
          <Input value={name} onChange={(e) => setName(e.target.value)} placeholder="db-primary" autoFocus className="font-mono" />
          {nameError && name !== "" && <p className="mt-1 text-xs text-red-600 dark:text-red-400">{nameError}</p>}
        </Field>
        <Field label="IP or CIDR">
          <Input value={cidr} onChange={(e) => setCidr(e.target.value)} placeholder="10.0.0.5 or 10.0.0.0/24" className="font-mono" />
          {cidrError && cidr !== "" && <p className="mt-1 text-xs text-red-600 dark:text-red-400">{cidrError}</p>}
        </Field>
        <div className="flex justify-end gap-2 pt-1">
          <Button onClick={onClose}>Cancel</Button>
          <Button variant="primary" disabled={!!nameError || !!cidrError} onClick={() => onSave(n, cidr.trim())}>
            {initial ? "Update" : "Add"}
          </Button>
        </div>
      </div>
    </Modal>
  );
}

function RowActions({ writable, onEdit, onDelete }: { writable: boolean; onEdit: () => void; onDelete: () => void }) {
  return (
    <span className={cn("inline-flex gap-1", !writable && "opacity-50")}>
      <Button variant="ghost" disabled={!writable} onClick={onEdit}>
        Edit
      </Button>
      <Button variant="ghost" disabled={!writable} onClick={onDelete} className="text-red-600 dark:text-red-400" title="Delete">
        ✕
      </Button>
    </span>
  );
}
