// ACLs Beta: a structured, NetBird-flavoured editor for the policy's acls,
// groups, tagOwners and hosts. Edits accumulate in a client-side draft and
// are applied in one save through PUT /api/policy/model, which patches the
// HuJSON document server-side so hand-written comments survive. The raw
// editor (Access Controls) is untouched and stays the fallback for
// everything else (grants, ssh, autoApprovers, …).

import { useEffect, useMemo, useReducer, useState } from "react";
import { Link } from "react-router-dom";
import { ApiError } from "../../api/client";
import { useNodes, usePolicyModel, useSavePolicyModel, useUsers } from "../../api/queries";
import type { PolicyModel } from "../../api/types";
import { PageHeader } from "../../components/Layout";
import { ConfirmDialog, errorText } from "../../components/common";
import { Badge, Button, Input, Modal, cn, useToast } from "../../components/ui";
import { GroupsTab, HostsTab, TagOwnersTab } from "./DefinitionsTabs";
import { RulesTab } from "./RulesTab";
import {
  diffDraft,
  draftReducer,
  emptyDraft,
  ruleLabel,
  splitDst,
  toSaveBody,
  type ChangeSummary,
  type KeyChanges,
  type SelectorContext,
} from "./model";

type Tab = "rules" | "groups" | "tagOwners" | "hosts";

const TABS: Array<{ id: Tab; label: string }> = [
  { id: "rules", label: "Rules" },
  { id: "groups", label: "Groups" },
  { id: "tagOwners", label: "Tag owners" },
  { id: "hosts", label: "Hosts" },
];

export function AclsBetaPage() {
  const { data: model, isLoading, error, refetch } = usePolicyModel();
  const { data: users } = useUsers();
  const { data: nodes } = useNodes();
  const save = useSavePolicyModel();
  const toast = useToast();

  const [tab, setTab] = useState<Tab>("rules");
  const [draft, dispatch] = useReducer(draftReducer, emptyDraft);
  const [saveOpen, setSaveOpen] = useState(false);
  const [discardOpen, setDiscardOpen] = useState(false);
  const [comment, setComment] = useState("");
  const [saveError, setSaveError] = useState<string | null>(null);
  // 409 handling: the server's current model when the error body carried it.
  const [conflict, setConflict] = useState<{ current: PolicyModel | null } | null>(null);

  // Changes are measured against the model the draft was loaded from, not the
  // latest poll — otherwise someone else's edit would show up as "yours".
  const summary = useMemo<ChangeSummary>(
    () =>
      draft.base
        ? diffDraft(draft.base, draft)
        : { rules: { added: [], removed: [], changed: [] }, groups: emptyKeys(), tagOwners: emptyKeys(), hosts: emptyKeys(), count: 0 },
    [draft],
  );
  const dirty = summary.count > 0;

  // Adopt the server model whenever the draft is pristine (mirrors AclPage).
  useEffect(() => {
    if (model && !dirty && model.hash !== draft.baseHash) dispatch({ type: "reset", model });
  }, [model, dirty, draft.baseHash]);

  // Don't lose a draft to an accidental tab close.
  useEffect(() => {
    if (!dirty) return;
    const onUnload = (e: BeforeUnloadEvent) => {
      e.preventDefault();
    };
    window.addEventListener("beforeunload", onUnload);
    return () => window.removeEventListener("beforeunload", onUnload);
  }, [dirty]);

  const ctx = useMemo<SelectorContext>(() => {
    const nodeTags = new Map<string, number>();
    for (const n of nodes ?? []) for (const t of n.tags ?? []) nodeTags.set(t, (nodeTags.get(t) ?? 0) + 1);
    return { users: users ?? [], nodeTags, groups: draft.groups, tagOwners: draft.tagOwners, hosts: draft.hosts };
  }, [users, nodes, draft.groups, draft.tagOwners, draft.hosts]);

  const writable = !!model?.writable;
  const drifted = !!model && dirty && model.hash !== draft.baseHash;

  const doSave = () => {
    setSaveError(null);
    save.mutate(toSaveBody(draft, comment), {
      onSuccess: (res) => {
        setSaveOpen(false);
        setComment("");
        if (res.warning) toast.error("Saved with warning", res.warning);
        else if (!res.policyChanged) toast.success("Names and descriptions saved (policy unchanged)");
        else if (res.reloadPending) toast.success("Policy file written — reload headscale to apply");
        else toast.success("Policy applied");
        // The saved draft becomes the new base.
        refetch().then((r) => r.data && dispatch({ type: "reset", model: r.data }));
      },
      onError: (e) => {
        if (e instanceof ApiError && e.status === 409) {
          const cur = e.body?.current;
          setConflict({ current: cur && "rules" in cur ? cur : null });
          setSaveOpen(false);
          return;
        }
        setSaveError(e instanceof ApiError ? e.headscaleMessage || e.message : errorText(e));
        toast.error("Save failed", errorText(e));
      },
    });
  };

  const tabDirty: Record<Tab, boolean> = {
    rules: summary.rules.added.length + summary.rules.removed.length + summary.rules.changed.length > 0,
    groups: keyCount(summary.groups) > 0,
    tagOwners: keyCount(summary.tagOwners) > 0,
    hosts: keyCount(summary.hosts) > 0,
  };
  const counts: Record<Tab, number> = {
    rules: draft.rules.length,
    groups: Object.keys(draft.groups).length,
    tagOwners: Object.keys(draft.tagOwners).length,
    hosts: Object.keys(draft.hosts).length,
  };

  return (
    <div className={cn(dirty && "pb-24")}>
      <PageHeader
        title={
          <span className="flex items-center gap-2">
            ACLs <Badge tone="purple">beta</Badge>
          </span>
        }
        subtitle="Visual editor for rules, groups, tag owners and hosts. Changes are drafted here and applied in one save."
        actions={
          <Link
            to="/acl"
            className="rounded-md border border-slate-300 bg-white px-3 py-1.5 text-sm font-medium text-slate-700 hover:bg-slate-50 dark:border-slate-600 dark:bg-slate-800 dark:text-slate-200 dark:hover:bg-slate-700"
          >
            Open raw editor
          </Link>
        }
      />

      {isLoading && <p className="text-sm text-slate-500">Loading policy…</p>}

      {error && (
        <Notice tone={error instanceof ApiError && error.status === 422 ? "amber" : "red"}>
          <p className="font-medium">{error instanceof ApiError && error.status === 422 ? "This policy cannot be shown in the structured editor" : "Could not load the policy"}</p>
          <p className="mt-1 text-xs">{errorText(error)}</p>
          <p className="mt-1 text-xs">
            Use{" "}
            <Link to="/acl" className="underline">
              Access Controls
            </Link>{" "}
            to edit it as text.
          </p>
        </Notice>
      )}

      {model && (
        <>
          {!model.writable && (
            <Notice tone="amber">
              The policy is read-only in this setup ({model.mode} mode). See Access Controls for how to make it writable.
            </Notice>
          )}
          {model.otherSections.length > 0 && (
            <Notice tone="slate">
              This policy also contains{" "}
              {model.otherSections.map((s, i) => (
                <span key={s}>
                  {i > 0 && ", "}
                  <code className="font-mono">{s}</code>
                </span>
              ))}
              . Those sections are preserved untouched on save and can be edited in{" "}
              <Link to="/acl" className="underline">
                Access Controls
              </Link>
              .
            </Notice>
          )}

          <div className="mb-4 flex max-w-xl gap-1 rounded-md bg-slate-100 p-1 dark:bg-slate-800">
            {TABS.map((t) => (
              <button
                key={t.id}
                onClick={() => setTab(t.id)}
                className={cn(
                  "flex flex-1 items-center justify-center gap-1.5 rounded px-3 py-1.5 text-sm font-medium",
                  tab === t.id ? "bg-white text-slate-900 shadow dark:bg-slate-700 dark:text-slate-100" : "text-slate-500",
                )}
              >
                {t.label}
                <span className="text-xs text-slate-400">{counts[t.id]}</span>
                {tabDirty[t.id] && <span className="h-1.5 w-1.5 rounded-full bg-indigo-500" aria-label="unsaved changes" />}
              </button>
            ))}
          </div>

          {tab === "rules" && <RulesTab draft={draft} server={model} ctx={ctx} summary={summary} writable={writable} dispatch={dispatch} />}
          {tab === "groups" && <GroupsTab draft={draft} ctx={ctx} summary={summary} writable={writable} dispatch={dispatch} />}
          {tab === "tagOwners" && <TagOwnersTab draft={draft} ctx={ctx} summary={summary} writable={writable} dispatch={dispatch} />}
          {tab === "hosts" && <HostsTab draft={draft} ctx={ctx} summary={summary} writable={writable} dispatch={dispatch} />}
        </>
      )}

      {dirty && (
        <div className="fixed inset-x-0 bottom-12 z-20 border-t border-slate-200 bg-white/95 px-4 py-3 backdrop-blur dark:border-slate-700 dark:bg-slate-900/95 md:bottom-0 md:left-56">
          <div className="mx-auto flex max-w-6xl flex-wrap items-center justify-between gap-3">
            <div className="text-sm">
              <span className="font-medium">
                {summary.count} unsaved change{summary.count === 1 ? "" : "s"}
              </span>
              <span className="ml-2 text-xs text-slate-500">{describeSummary(summary)}</span>
              {drifted && <p className="mt-0.5 text-xs text-amber-700 dark:text-amber-300">The policy changed on the server since you started — saving will ask you to reconcile.</p>}
            </div>
            <div className="flex gap-2">
              <Button onClick={() => setDiscardOpen(true)}>Discard</Button>
              <Button variant="primary" disabled={!writable} onClick={() => setSaveOpen(true)}>
                Review &amp; save…
              </Button>
            </div>
          </div>
        </div>
      )}

      {discardOpen && (
        <ConfirmDialog
          title="Discard changes"
          danger
          confirmLabel="Discard"
          message={<p>Throw away all {summary.count} unsaved changes and reload the policy from the server?</p>}
          onCancel={() => setDiscardOpen(false)}
          onConfirm={() => {
            if (model) dispatch({ type: "reset", model });
            setDiscardOpen(false);
          }}
        />
      )}

      {saveOpen && model && (
        <Modal title="Review & save" onClose={() => setSaveOpen(false)} wide>
          <div className="space-y-4 text-sm">
            <SummaryList summary={summary} />
            <p className="text-xs text-slate-500 dark:text-slate-400">
              {model.mode === "database"
                ? "Headscale validates the policy against the live tailnet and applies it immediately."
                : model.mode === "file"
                  ? "The policy file is rewritten atomically and headscale is reloaded (or a reload is reported as pending)."
                  : "Headscale validates the policy first; the mode (database or file) is learned from this save."}{" "}
              Comments and untouched sections of the HuJSON document are preserved.
            </p>
            <Input value={comment} onChange={(e) => setComment(e.target.value)} placeholder="Comment for the version history (optional)" />
            {saveError && (
              <div className="rounded-md border border-red-300 bg-red-50 px-3 py-2 text-red-800 dark:border-red-700 dark:bg-red-950/40 dark:text-red-300">
                <p className="font-medium">✕ Save failed</p>
                <pre className="mt-1 whitespace-pre-wrap font-mono text-xs">{saveError}</pre>
              </div>
            )}
            <div className="flex justify-end gap-2">
              <Button onClick={() => setSaveOpen(false)}>Cancel</Button>
              <Button variant="primary" loading={save.isPending} onClick={doSave}>
                Save
              </Button>
            </div>
          </div>
        </Modal>
      )}

      {conflict && (
        <Modal title="Policy changed elsewhere">
          <div className="space-y-3 text-sm text-slate-700 dark:text-slate-300">
            <p>The policy was changed since you loaded it — by another admin, the raw editor, or headscale itself.</p>
            <p>You can drop your draft and load the new version, or re-apply your changes on top of it and review again.</p>
            <div className="flex flex-wrap justify-end gap-2 pt-1">
              <Button
                onClick={async () => {
                  const fresh = conflict.current ?? (await refetch()).data;
                  if (fresh) dispatch({ type: "reset", model: fresh });
                  setConflict(null);
                }}
              >
                Reload and discard my changes
              </Button>
              <Button
                variant="primary"
                onClick={async () => {
                  const fresh = conflict.current ?? (await refetch()).data;
                  if (fresh) dispatch({ type: "rebase", model: fresh, summary });
                  setConflict(null);
                  setSaveOpen(true);
                }}
              >
                Re-apply my changes on the new version
              </Button>
            </div>
          </div>
        </Modal>
      )}
    </div>
  );
}

// ---- bits ----

function emptyKeys(): KeyChanges {
  return { added: [], removed: [], changed: [] };
}

function keyCount(k: KeyChanges): number {
  return k.added.length + k.removed.length + k.changed.length;
}

function describeSummary(s: ChangeSummary): string {
  const parts: string[] = [];
  const r = s.rules.added.length + s.rules.removed.length + s.rules.changed.length;
  if (r) parts.push(`${r} rule${r === 1 ? "" : "s"}`);
  for (const [label, k] of [["groups", s.groups], ["tag owners", s.tagOwners], ["hosts", s.hosts]] as const) {
    const n = keyCount(k);
    if (n) parts.push(`${n} ${label}`);
  }
  return parts.join(" · ");
}

function Notice({ tone, children }: { tone: "amber" | "slate" | "red"; children: React.ReactNode }) {
  const cls = {
    amber: "border-amber-300 bg-amber-50 text-amber-900 dark:border-amber-700 dark:bg-amber-950/40 dark:text-amber-200",
    slate: "border-slate-300 bg-slate-50 text-slate-700 dark:border-slate-700 dark:bg-slate-900 dark:text-slate-300",
    red: "border-red-300 bg-red-50 text-red-800 dark:border-red-700 dark:bg-red-950/40 dark:text-red-300",
  }[tone];
  return <div className={cn("mb-4 rounded-md border px-3 py-2 text-sm", cls)}>{children}</div>;
}

function SummaryList({ summary }: { summary: ChangeSummary }) {
  const line = (sign: "+" | "~" | "−", text: string, key: string) => (
    <li key={key} className={cn("font-mono text-xs", sign === "+" ? "text-emerald-700 dark:text-emerald-300" : sign === "−" ? "text-red-700 dark:text-red-300" : "text-amber-700 dark:text-amber-300")}>
      {sign} {text}
    </li>
  );
  const sections: Array<{ title: string; items: React.ReactNode[] }> = [];

  const rules: React.ReactNode[] = [
    ...summary.rules.added.map((r) => line("+", ruleLabel(r), "a" + r.key)),
    ...summary.rules.changed.map((c) => {
      const what: string[] = [];
      if (c.before.enabled !== c.after.enabled) what.push(c.after.enabled ? "enabled" : "disabled");
      if ((c.before.proto ?? "") !== (c.after.proto ?? "")) what.push("protocol");
      if (c.before.src.join() !== c.after.src.join()) what.push("sources");
      if (c.before.dst.join() !== c.after.dst.join()) what.push("destinations");
      if (c.before.name !== c.after.name || c.before.description !== c.after.description) what.push("name/description");
      return line("~", `${ruleLabel(c.after)} (${what.join(", ")})`, "c" + c.after.key);
    }),
    ...summary.rules.removed.map((r) => line("−", ruleLabel({ ...r, dst: r.dst.map((d) => splitDst(d).selector + ":" + splitDst(d).ports) }), "r" + r.id)),
  ];
  if (rules.length) sections.push({ title: "Rules", items: rules });

  for (const [title, k] of [["Groups", summary.groups], ["Tag owners", summary.tagOwners], ["Hosts", summary.hosts]] as const) {
    const items = [...k.added.map((x) => line("+", x, "a" + x)), ...k.changed.map((x) => line("~", x, "c" + x)), ...k.removed.map((x) => line("−", x, "r" + x))];
    if (items.length) sections.push({ title, items });
  }

  return (
    <div className="space-y-3">
      {sections.map((s) => (
        <div key={s.title}>
          <p className="mb-1 text-xs font-semibold uppercase tracking-wide text-slate-500">{s.title}</p>
          <ul className="space-y-0.5">{s.items}</ul>
        </div>
      ))}
    </div>
  );
}
