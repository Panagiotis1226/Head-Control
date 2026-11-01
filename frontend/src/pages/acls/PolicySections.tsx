// The rest of the policy, shown under the ACL rules as collapsible sections
// (no extra tabs, so the page stays usable on a phone): grants, SSH, node
// attributes, auto-approvers, tests, SSH tests and network-wide options.
// Entries are edited as forms; anything a form does not know about (newer
// fields, "#" notes) is carried over untouched.

import { useMemo, useState, type Dispatch, type ReactNode } from "react";
import type { PolicyElement } from "../../api/types";
import { ConfirmDialog } from "../../components/common";
import { Badge, Button, Field, Input, Modal, Select, cn } from "../../components/ui";
import { SelectorChip, SelectorPicker } from "./inputs";
import {
  EXTRA_LABELS,
  GRANT_IP_SUGGESTIONS,
  NODEATTR_AUTOGROUPS,
  NODE_ATTRIBUTES,
  PROTOCOLS,
  SSH_DST_AUTOGROUPS,
  SSH_SRC_AUTOGROUPS,
  SSH_USER_SUGGESTIONS,
  buildOptions,
  extraNoun,
  extraStatus,
  getField,
  getList,
  getString,
  listChangeCount,
  restrictOptions,
  restrictedSelector,
  setField,
  validateCheckPeriod,
  validateGrantIp,
  validatePlain,
  validateRoutePrefix,
  validateSelector,
  validateSshUser,
  validateTestTarget,
  type ChangeSummary,
  type Draft,
  type DraftAction,
  type ExtraItem,
  type ExtraList,
  type Issue,
  type SelectorContext,
  type SelectorOption,
} from "./model";

interface SectionsProps {
  draft: Draft;
  ctx: SelectorContext;
  summary: ChangeSummary;
  writable: boolean;
  dispatch: Dispatch<DraftAction>;
}

export function PolicySections(props: SectionsProps) {
  const { draft, summary } = props;
  const aaCount = Object.keys(draft.autoApprovers.routes).length + (draft.autoApprovers.exitNode.length ? 1 : 0);
  const aaDirty = summary.routes.added.length + summary.routes.removed.length + summary.routes.changed.length > 0 || summary.exitNodeChanged;
  return (
    <div className="mt-8 space-y-3">
      <h2 className="text-sm font-semibold uppercase tracking-wide text-slate-500 dark:text-slate-400">More policy sections</h2>
      <ListSection
        {...props}
        list="grants"
        title="Grants"
        hint="Allow access like ACL rules, plus app capabilities (Taildrive, …) and routing via specific nodes."
        render={(v) => <GrantCard v={v} hosts={draft.hosts} />}
        Editor={GrantEditor}
      />
      <ListSection
        {...props}
        list="ssh"
        title="SSH"
        hint="Who may use Tailscale SSH to which machines, as which local users."
        render={(v) => <SshCard v={v} hosts={draft.hosts} />}
        Editor={SshEditor}
      />
      <ListSection
        {...props}
        list="nodeAttrs"
        title="Node attributes"
        hint="Per-device capabilities such as Taildrive, MagicDNS AAAA or a random WireGuard port."
        render={(v) => <NodeAttrCard v={v} hosts={draft.hosts} />}
        Editor={NodeAttrEditor}
      />
      <Section title="Auto approvers" count={aaCount} dirty={aaDirty} hint="Subnet routes and exit nodes approved automatically when their owner advertises them.">
        <AutoApprovers {...props} />
      </Section>
      <ListSection
        {...props}
        list="tests"
        title="Tests"
        hint="Assertions headscale checks on every save: these connections must (or must not) be allowed."
        render={(v) => <TestCard v={v} hosts={draft.hosts} />}
        Editor={TestEditor}
      />
      <ListSection
        {...props}
        list="sshTests"
        title="SSH tests"
        hint="Assertions about which users may SSH into which machines."
        render={(v) => <SshTestCard v={v} hosts={draft.hosts} />}
        Editor={SshTestEditor}
      />
      <Section title="Options" count={draft.randomizeClientPort ? 1 : 0} dirty={summary.randomizeChanged} hint="Network-wide settings.">
        <label className="flex items-center justify-between gap-3 text-sm">
          <span>
            <span className="font-medium">Randomize client port</span>
            <span className="block text-xs text-slate-500 dark:text-slate-400">
              Every device picks a random WireGuard port instead of 41641 (the node attribute does the same per device).
            </span>
          </span>
          <Switch
            checked={draft.randomizeClientPort}
            disabled={!props.writable}
            onChange={(value) => props.dispatch({ type: "setRandomize", value })}
            label="Randomize client port"
          />
        </label>
      </Section>
    </div>
  );
}

// ---- layout ----

function Section({
  title,
  count,
  dirty,
  hint,
  actions,
  children,
}: {
  title: string;
  count: number;
  dirty: boolean;
  hint: string;
  actions?: ReactNode;
  children: ReactNode;
}) {
  // Sections with entries start expanded. Until the user toggles one, follow
  // the count: the first render happens before the policy has loaded.
  const [userOpen, setOpen] = useState<boolean | null>(null);
  const open = userOpen ?? count > 0;
  return (
    <section className="rounded-lg border border-slate-200 bg-white shadow-sm dark:border-slate-700 dark:bg-slate-900">
      <header className="flex items-center gap-2 px-3 py-2.5">
        <button
          type="button"
          onClick={() => setOpen(!open)}
          aria-expanded={open}
          className="flex min-w-0 flex-1 items-center gap-2 text-left"
        >
          <span className="w-4 text-slate-400">{open ? "▾" : "▸"}</span>
          <span className="text-sm font-semibold text-slate-900 dark:text-slate-100">{title}</span>
          <span className="text-xs text-slate-400">{count}</span>
          {dirty && <span className="h-1.5 w-1.5 rounded-full bg-indigo-500" aria-label="unsaved changes" />}
        </button>
        {open && actions}
      </header>
      {open && (
        <div className="space-y-2 border-t border-slate-100 px-3 py-3 dark:border-slate-800">
          <p className="text-xs text-slate-500 dark:text-slate-400">{hint}</p>
          {children}
        </div>
      )}
    </section>
  );
}

function Switch({ checked, disabled, onChange, label }: { checked: boolean; disabled?: boolean; onChange: (v: boolean) => void; label: string }) {
  return (
    <button
      type="button"
      role="switch"
      aria-checked={checked}
      aria-label={label}
      disabled={disabled}
      onClick={() => onChange(!checked)}
      className={cn(
        "relative inline-flex h-5 w-9 flex-none items-center rounded-full transition-colors disabled:cursor-not-allowed",
        checked ? "bg-indigo-600" : "bg-slate-300 dark:bg-slate-600",
      )}
    >
      <span className={cn("inline-block h-4 w-4 transform rounded-full bg-white shadow transition-transform", checked ? "translate-x-4" : "translate-x-0.5")} />
    </button>
  );
}

type EditorProps = {
  initial: PolicyElement | null;
  ctx: SelectorContext;
  onSave: (v: PolicyElement) => void;
  onClose: () => void;
};

function ListSection({
  draft,
  ctx,
  summary,
  writable,
  dispatch,
  list,
  title,
  hint,
  render,
  Editor,
}: SectionsProps & {
  list: ExtraList;
  title: string;
  hint: string;
  render: (v: PolicyElement) => ReactNode;
  Editor: (p: EditorProps) => ReactNode;
}) {
  const items = draft.extras[list];
  const [editing, setEditing] = useState<ExtraItem | "new" | null>(null);
  const [deleting, setDeleting] = useState<ExtraItem | null>(null);
  const noun = extraNoun(list);
  return (
    <Section
      title={title}
      count={items.length}
      dirty={listChangeCount(summary.extras[list]) > 0}
      hint={hint}
      actions={
        <Button variant="primary" disabled={!writable} onClick={() => setEditing("new")}>
          + Add
        </Button>
      }
    >
      {items.length === 0 ? (
        <p className="py-2 text-sm text-slate-400">No {noun}s.</p>
      ) : (
        <ul className="space-y-2">
          {items.map((it, i) => {
            const status = extraStatus(draft, list, it);
            return (
              <li key={it.key} className="rounded-md border border-slate-200 p-2.5 dark:border-slate-700">
                <div className="flex flex-wrap items-start gap-2">
                  <div className="min-w-0 flex-1 space-y-1.5">
                    <div className="flex flex-wrap items-center gap-2">
                      <span className="text-xs font-medium text-slate-500">
                        {EXTRA_LABELS[list]} {i + 1}
                      </span>
                      {status === "new" && <Badge tone="green">new</Badge>}
                      {status === "edited" && <Badge tone="blue">edited</Badge>}
                    </div>
                    {render(it.value)}
                  </div>
                  <div className="flex flex-none items-center gap-1">
                    <Button variant="ghost" disabled={!writable} onClick={() => setEditing(it)}>
                      Edit
                    </Button>
                    <Button
                      variant="ghost"
                      disabled={!writable}
                      title="Delete"
                      className="text-red-600 dark:text-red-400"
                      onClick={() => (it.origin === undefined ? dispatch({ type: "deleteExtra", list, key: it.key }) : setDeleting(it))}
                    >
                      ✕
                    </Button>
                  </div>
                </div>
              </li>
            );
          })}
        </ul>
      )}
      {editing && (
        <Editor
          initial={editing === "new" ? null : editing.value}
          ctx={ctx}
          onClose={() => setEditing(null)}
          onSave={(value) => {
            dispatch({ type: "setExtra", list, key: editing === "new" ? undefined : editing.key, value });
            setEditing(null);
          }}
        />
      )}
      {deleting && (
        <ConfirmDialog
          title={`Delete ${noun}`}
          danger
          confirmLabel="Delete"
          message={<p>Remove this {noun} from the draft? The change applies when you save.</p>}
          onCancel={() => setDeleting(null)}
          onConfirm={() => {
            dispatch({ type: "deleteExtra", list, key: deleting.key });
            setDeleting(null);
          }}
        />
      )}
    </Section>
  );
}

// ---- cards ----

function Chips({ values, hosts, plain, prefix }: { values: string[]; hosts?: Record<string, string>; plain?: boolean; prefix?: string }) {
  if (values.length === 0) return <span className="text-xs text-slate-400">—</span>;
  return (
    <>
      {prefix && <span className="text-xs text-slate-500">{prefix}</span>}
      {values.map((v) => (
        <SelectorChip key={v} value={v} hosts={hosts} tone={plain ? "gray" : undefined} />
      ))}
    </>
  );
}

function Row({ children }: { children: ReactNode }) {
  return <div className="flex flex-wrap items-center gap-1.5 text-sm">{children}</div>;
}

const Arrow = () => <span className="px-1 text-slate-400">→</span>;

function GrantCard({ v, hosts }: { v: PolicyElement; hosts: Record<string, string> }) {
  const app = getField(v, "app");
  const caps = app && typeof app === "object" ? Object.keys(app as object) : [];
  return (
    <>
      <Row>
        <Chips values={getList(v, "src")} hosts={hosts} />
        <Arrow />
        <Chips values={getList(v, "dst")} hosts={hosts} />
      </Row>
      {getList(v, "ip").length > 0 && (
        <Row>
          <Chips values={getList(v, "ip")} plain prefix="ip" />
        </Row>
      )}
      {getList(v, "via").length > 0 && (
        <Row>
          <Chips values={getList(v, "via")} hosts={hosts} prefix="via" />
        </Row>
      )}
      {caps.length > 0 && (
        <Row>
          <span className="text-xs text-slate-500">app</span>
          {caps.map((c) => (
            <Badge key={c} tone="purple">
              <span className="font-mono">{c}</span>
            </Badge>
          ))}
        </Row>
      )}
    </>
  );
}

function SshCard({ v, hosts }: { v: PolicyElement; hosts: Record<string, string> }) {
  const action = getString(v, "action") || "accept";
  const period = getString(v, "checkPeriod");
  return (
    <>
      <Row>
        <Badge tone={action === "check" ? "yellow" : "green"}>{action === "check" ? `check${period ? ` · ${period}` : ""}` : action}</Badge>
        <Chips values={getList(v, "src")} hosts={hosts} />
        <Arrow />
        <Chips values={getList(v, "dst")} hosts={hosts} />
      </Row>
      <Row>
        <Chips values={getList(v, "users")} plain prefix="as" />
      </Row>
      {getList(v, "acceptEnv").length > 0 && (
        <Row>
          <Chips values={getList(v, "acceptEnv")} plain prefix="env" />
        </Row>
      )}
    </>
  );
}

function NodeAttrCard({ v, hosts }: { v: PolicyElement; hosts: Record<string, string> }) {
  return (
    <>
      <Row>
        <Chips values={getList(v, "target")} hosts={hosts} />
        <Arrow />
        <Chips values={getList(v, "attr")} plain />
      </Row>
      {getList(v, "ipPool").length > 0 && (
        <Row>
          <Chips values={getList(v, "ipPool")} plain prefix="ipPool" />
        </Row>
      )}
    </>
  );
}

function TestCard({ v, hosts }: { v: PolicyElement; hosts: Record<string, string> }) {
  const proto = getString(v, "proto");
  return (
    <>
      <Row>
        <Chips values={getList(v, "src")} hosts={hosts} prefix="from" />
        {proto && <Badge tone="gray">{proto}</Badge>}
      </Row>
      {getList(v, "accept").length > 0 && (
        <Row>
          <Chips values={getList(v, "accept")} plain prefix="✓ reaches" />
        </Row>
      )}
      {getList(v, "deny").length > 0 && (
        <Row>
          <Chips values={getList(v, "deny")} plain prefix="✕ blocked" />
        </Row>
      )}
    </>
  );
}

function SshTestCard({ v, hosts }: { v: PolicyElement; hosts: Record<string, string> }) {
  return (
    <>
      <Row>
        <Chips values={getList(v, "src")} hosts={hosts} />
        <Arrow />
        <Chips values={getList(v, "dst")} hosts={hosts} />
      </Row>
      {(["accept", "check", "deny"] as const).map(
        (k) =>
          getList(v, k).length > 0 && (
            <Row key={k}>
              <Chips values={getList(v, k)} plain prefix={k === "accept" ? "✓ as" : k === "check" ? "check as" : "✕ as"} />
            </Row>
          ),
      )}
    </>
  );
}

// ---- editors ----

function suggestions(list: Array<{ value: string; hint: string }>): SelectorOption[] {
  return list.map((x) => ({ value: x.value, kind: "unknown", hint: x.hint }));
}

function Issues({ issues }: { issues: Issue[] }) {
  if (issues.length === 0) return null;
  return (
    <div className="space-y-1.5">
      {issues.map((i, n) => (
        <p
          key={n}
          className={cn(
            "rounded-md border px-3 py-1.5 text-xs",
            i.level === "error"
              ? "border-red-300 bg-red-50 text-red-800 dark:border-red-700 dark:bg-red-950/40 dark:text-red-300"
              : "border-amber-300 bg-amber-50 text-amber-900 dark:border-amber-700 dark:bg-amber-950/40 dark:text-amber-200",
          )}
        >
          {i.text}
        </p>
      ))}
    </div>
  );
}

/** Errors from the values currently in a picker (free text may have been added before a rename). */
function pickerIssues(values: string[], check: (s: string) => Issue | null): Issue[] {
  return values.map(check).filter((i): i is Issue => !!i);
}

function EditorShell({
  title,
  issues,
  initial,
  onClose,
  onSave,
  children,
}: {
  title: string;
  issues: Issue[];
  initial: PolicyElement | null;
  onClose: () => void;
  onSave: () => void;
  children: ReactNode;
}) {
  const blocked = issues.some((i) => i.level === "error");
  return (
    <Modal title={title} onClose={onClose} wide>
      <div className="space-y-4">
        {children}
        <Issues issues={issues} />
        <div className="flex justify-end gap-2">
          <Button onClick={onClose}>Cancel</Button>
          <Button variant="primary" disabled={blocked} onClick={onSave}>
            {initial ? "Update" : "Add"}
          </Button>
        </div>
      </div>
    </Modal>
  );
}

const SELECTOR_KINDS = ["user", "group", "tag", "host", "cidr", "wildcard"] as const;

function GrantEditor({ initial, ctx, onSave, onClose }: EditorProps) {
  const base = initial ?? {};
  const [src, setSrc] = useState(getList(base, "src"));
  const [dst, setDst] = useState(getList(base, "dst"));
  const [ip, setIp] = useState(getList(base, "ip"));
  const [via, setVia] = useState(getList(base, "via"));
  const appRaw = getField(base, "app");
  const [app, setApp] = useState(appRaw === undefined ? "" : JSON.stringify(appRaw, null, 2));

  const srcOptions = useMemo(() => buildOptions(ctx, "src"), [ctx]);
  const dstOptions = useMemo(() => buildOptions(ctx, "dst"), [ctx]);
  const tagOptions = useMemo(() => buildOptions(ctx, "dst").filter((o) => o.kind === "tag"), [ctx]);

  let appValue: unknown;
  const issues: Issue[] = [];
  if (app.trim()) {
    try {
      appValue = JSON.parse(app);
      if (!appValue || typeof appValue !== "object" || Array.isArray(appValue)) throw new Error();
    } catch {
      issues.push({ level: "error", text: 'app must be a JSON object such as {"tailscale.com/cap/drive": [{"shares": ["*"], "access": "rw"}]}' });
    }
  }
  if (src.length === 0) issues.push({ level: "error", text: "at least one source is required" });
  if (dst.length === 0) issues.push({ level: "error", text: "at least one destination is required" });
  if (ip.length === 0 && !app.trim()) issues.push({ level: "error", text: "a grant needs ip ports, an app capability, or both" });
  issues.push(...pickerIssues(src, (s) => validateSelector(s, "src", ctx)));
  issues.push(...pickerIssues(dst, (s) => validateSelector(s, "dst", ctx)));
  issues.push(...pickerIssues(ip, validateGrantIp));

  const save = () => {
    let v = setField(base, "src", src);
    v = setField(v, "dst", dst);
    v = setField(v, "ip", ip);
    v = setField(v, "via", via);
    v = setField(v, "app", app.trim() ? appValue : undefined);
    onSave(v);
  };

  return (
    <EditorShell title={initial ? "Edit grant" : "New grant"} issues={issues} initial={initial} onClose={onClose} onSave={save}>
      <Field label="Sources">
        <SelectorPicker value={src} onChange={setSrc} options={srcOptions} validate={(s) => validateSelector(s, "src", ctx)} hosts={ctx.hosts} placeholder="group:eng, alice@, tag:ci, * …" />
      </Field>
      <Field label="Destinations" hint="Machines or networks, without ports.">
        <SelectorPicker value={dst} onChange={setDst} options={dstOptions} validate={(s) => validateSelector(s, "dst", ctx)} hosts={ctx.hosts} placeholder="tag:web, db1, autogroup:internet, * …" />
      </Field>
      <Field label="Ports (ip)" hint='"*" for everything, or entries like tcp:443, udp:53, 22, 80-90.'>
        <SelectorPicker value={ip} onChange={setIp} options={suggestions(GRANT_IP_SUGGESTIONS)} validate={validateGrantIp} freeText placeholder="tcp:443" />
      </Field>
      <Field label="Via (optional)" hint="Route this traffic through subnet routers or exit nodes with these tags.">
        <SelectorPicker
          value={via}
          onChange={setVia}
          options={tagOptions}
          validate={(s) => (s.trim().startsWith("tag:") ? null : { level: "error", text: "via takes tags, e.g. tag:exit-eu" })}
          hosts={ctx.hosts}
          placeholder="tag:exit-eu"
        />
      </Field>
      <Field label="App capabilities (optional, JSON)" hint="Passed to clients as-is, e.g. Taildrive shares.">
        <textarea
          value={app}
          onChange={(e) => setApp(e.target.value)}
          rows={5}
          spellCheck={false}
          placeholder={'{"tailscale.com/cap/drive": [{"shares": ["*"], "access": "rw"}]}'}
          className="w-full rounded-md border border-slate-300 bg-white px-3 py-1.5 font-mono text-xs text-slate-900 placeholder:text-slate-400 focus:border-indigo-500 focus:outline-none focus:ring-1 focus:ring-indigo-500 dark:border-slate-600 dark:bg-slate-800 dark:text-slate-100"
        />
      </Field>
    </EditorShell>
  );
}

function SshEditor({ initial, ctx, onSave, onClose }: EditorProps) {
  const base = initial ?? {};
  const [action, setAction] = useState(getString(base, "action") || "accept");
  const [period, setPeriod] = useState(getString(base, "checkPeriod"));
  const [src, setSrc] = useState(getList(base, "src"));
  const [dst, setDst] = useState(getList(base, "dst"));
  const [users, setUsers] = useState(getList(base, "users"));
  const [env, setEnv] = useState(getList(base, "acceptEnv"));

  const srcCheck = (s: string) => restrictedSelector(s, "src", ctx, ["user", "group", "tag"], SSH_SRC_AUTOGROUPS);
  const dstCheck = (s: string) => restrictedSelector(s, "dst", ctx, ["user", "tag"], SSH_DST_AUTOGROUPS);
  const srcOptions = useMemo(() => restrictOptions(buildOptions(ctx, "src"), ["user", "group", "tag"], SSH_SRC_AUTOGROUPS), [ctx]);
  const dstOptions = useMemo(
    () => restrictOptions([...buildOptions(ctx, "dst"), { value: "autogroup:self", kind: "autogroup", hint: "the connecting user's own devices" }], ["user", "tag"], SSH_DST_AUTOGROUPS)
      .filter((o, i, all) => all.findIndex((x) => x.value === o.value) === i),
    [ctx],
  );

  const issues: Issue[] = [];
  if (src.length === 0) issues.push({ level: "error", text: "at least one source is required" });
  if (dst.length === 0) issues.push({ level: "error", text: "at least one destination is required" });
  if (users.length === 0) issues.push({ level: "error", text: "at least one user is required (e.g. autogroup:nonroot)" });
  if (action === "check") {
    const p = validateCheckPeriod(period);
    if (p) issues.push(p);
  }
  issues.push(...pickerIssues(src, srcCheck), ...pickerIssues(dst, dstCheck), ...pickerIssues(users, validateSshUser));

  const save = () => {
    let v = setField(base, "action", action);
    v = setField(v, "checkPeriod", action === "check" ? period.trim() : undefined);
    v = setField(v, "src", src);
    v = setField(v, "dst", dst);
    v = setField(v, "users", users);
    v = setField(v, "acceptEnv", env);
    onSave(v);
  };

  return (
    <EditorShell title={initial ? "Edit SSH rule" : "New SSH rule"} issues={issues} initial={initial} onClose={onClose} onSave={save}>
      <div className="grid gap-3 sm:grid-cols-[12rem_1fr]">
        <Field label="Action">
          <Select value={action} onChange={(e) => setAction(e.target.value)} className="w-full">
            <option value="accept">accept</option>
            <option value="check">check (re-authenticate)</option>
          </Select>
        </Field>
        {action === "check" && (
          <Field label="Check period" hint='How long an approval lasts: e.g. 12h, or "always". Empty = headscale default.'>
            <Input value={period} onChange={(e) => setPeriod(e.target.value)} placeholder="12h" className="font-mono" />
          </Field>
        )}
      </div>
      <Field label="Sources" hint="Users, groups, tags, autogroup:member or autogroup:tagged.">
        <SelectorPicker value={src} onChange={setSrc} options={srcOptions} validate={srcCheck} hosts={ctx.hosts} placeholder="group:admins, autogroup:member …" />
      </Field>
      <Field label="Destinations" hint="Tags, users, autogroup:self, autogroup:member or autogroup:tagged.">
        <SelectorPicker value={dst} onChange={setDst} options={dstOptions} validate={dstCheck} hosts={ctx.hosts} placeholder="tag:server, autogroup:self …" />
      </Field>
      <Field label="As local users">
        <SelectorPicker value={users} onChange={setUsers} options={suggestions(SSH_USER_SUGGESTIONS)} validate={validateSshUser} freeText placeholder="autogroup:nonroot, root, ubuntu …" />
      </Field>
      <Field label="Accepted environment variables (optional)">
        <SelectorPicker value={env} onChange={setEnv} options={[]} validate={(s) => validatePlain(s, "variable names")} freeText placeholder="GIT_*, LANG …" />
      </Field>
    </EditorShell>
  );
}

function NodeAttrEditor({ initial, ctx, onSave, onClose }: EditorProps) {
  const base = initial ?? {};
  const [target, setTarget] = useState(getList(base, "target"));
  const [attr, setAttr] = useState(getList(base, "attr"));
  const kinds = [...SELECTOR_KINDS];
  const check = (s: string) => restrictedSelector(s, "src", ctx, kinds, NODEATTR_AUTOGROUPS);
  const options = useMemo(() => restrictOptions(buildOptions(ctx, "src"), [...SELECTOR_KINDS], NODEATTR_AUTOGROUPS), [ctx]);
  const ipPool = getList(base, "ipPool");

  const issues: Issue[] = [];
  if (target.length === 0) issues.push({ level: "error", text: "at least one target is required" });
  if (attr.length === 0 && ipPool.length === 0) issues.push({ level: "error", text: "add at least one attribute" });
  issues.push(...pickerIssues(target, check), ...pickerIssues(attr, (s) => validatePlain(s, "attributes")));

  const save = () => onSave(setField(setField(base, "target", target), "attr", attr));

  return (
    <EditorShell title={initial ? "Edit node attribute" : "New node attribute"} issues={issues} initial={initial} onClose={onClose} onSave={save}>
      <Field label="Targets" hint='Devices that get the attributes: users, groups, tags, hosts, CIDRs, autogroups or "*".'>
        <SelectorPicker value={target} onChange={setTarget} options={options} validate={check} hosts={ctx.hosts} placeholder="*, tag:server, group:eng …" />
      </Field>
      <Field label="Attributes" hint="nextdns:<profile-id> enables NextDNS with that profile.">
        <SelectorPicker value={attr} onChange={setAttr} options={suggestions(NODE_ATTRIBUTES)} validate={(s) => validatePlain(s, "attributes")} freeText placeholder="drive:share, magicdns-aaaa …" />
      </Field>
      {ipPool.length > 0 && <p className="text-xs text-slate-500">ipPool ({ipPool.join(", ")}) is kept as-is; edit it in Access Controls.</p>}
    </EditorShell>
  );
}

function TestEditor({ initial, ctx, onSave, onClose }: EditorProps) {
  const base = initial ?? {};
  const [src, setSrc] = useState(getList(base, "src"));
  const [proto, setProto] = useState(getString(base, "proto"));
  const [accept, setAccept] = useState(getList(base, "accept"));
  const [deny, setDeny] = useState(getList(base, "deny"));
  const srcOptions = useMemo(() => buildOptions(ctx, "src").filter((o) => o.kind !== "wildcard"), [ctx]);
  const srcCheck = (s: string) => validateSelector(s, "src", ctx);

  const issues: Issue[] = [];
  if (src.length !== 1) issues.push({ level: "error", text: "a test has exactly one source" });
  if (accept.length + deny.length === 0) issues.push({ level: "error", text: "list at least one destination that must be reachable or blocked" });
  issues.push(...pickerIssues(src, srcCheck), ...pickerIssues([...accept, ...deny], validateTestTarget));

  const save = () => {
    let v = setField(base, "src", src[0]);
    v = setField(v, "proto", proto);
    v = setField(v, "accept", accept);
    v = setField(v, "deny", deny);
    onSave(v);
  };

  return (
    <EditorShell title={initial ? "Edit test" : "New test"} issues={issues} initial={initial} onClose={onClose} onSave={save}>
      <div className="grid gap-3 sm:grid-cols-[1fr_12rem]">
        <Field label="Source" hint="One user, group, tag, host or IP.">
          <SelectorPicker value={src} onChange={(v) => setSrc(v.slice(-1))} options={srcOptions} validate={srcCheck} hosts={ctx.hosts} placeholder="alice@" />
        </Field>
        <Field label="Protocol">
          <Select value={proto} onChange={(e) => setProto(e.target.value)} className="w-full">
            {PROTOCOLS.map((p) => (
              <option key={p.value} value={p.value}>
                {p.value === "" ? "Default (TCP/UDP/ICMP)" : p.label}
              </option>
            ))}
          </Select>
        </Field>
      </div>
      <Field label="Must reach" hint="target:port, e.g. tag:web:443 or 10.0.0.5:22.">
        <SelectorPicker value={accept} onChange={setAccept} options={[]} validate={validateTestTarget} freeText placeholder="tag:web:443" />
      </Field>
      <Field label="Must be blocked">
        <SelectorPicker value={deny} onChange={setDeny} options={[]} validate={validateTestTarget} freeText placeholder="tag:db:5432" />
      </Field>
    </EditorShell>
  );
}

function SshTestEditor({ initial, ctx, onSave, onClose }: EditorProps) {
  const base = initial ?? {};
  const [src, setSrc] = useState(getList(base, "src"));
  const [dst, setDst] = useState(getList(base, "dst"));
  const [accept, setAccept] = useState(getList(base, "accept"));
  const [check, setCheck] = useState(getList(base, "check"));
  const [deny, setDeny] = useState(getList(base, "deny"));
  const srcOptions = useMemo(() => buildOptions(ctx, "src").filter((o) => o.kind !== "wildcard" && o.kind !== "autogroup"), [ctx]);
  const dstOptions = useMemo(
    () => restrictOptions([...buildOptions(ctx, "dst"), { value: "autogroup:self", kind: "autogroup", hint: "" }], ["tag", "host"], SSH_DST_AUTOGROUPS)
      .filter((o, i, all) => all.findIndex((x) => x.value === o.value) === i),
    [ctx],
  );
  const srcCheck = (s: string) => validateSelector(s, "src", ctx);
  const dstCheck = (s: string) => restrictedSelector(s, "dst", ctx, ["tag", "host"], SSH_DST_AUTOGROUPS);

  const issues: Issue[] = [];
  if (src.length !== 1) issues.push({ level: "error", text: "an SSH test has exactly one source" });
  if (dst.length === 0) issues.push({ level: "error", text: "at least one destination is required" });
  if (accept.length + check.length + deny.length === 0) issues.push({ level: "error", text: "list at least one user under accept, check or deny" });
  issues.push(...pickerIssues(src, srcCheck), ...pickerIssues(dst, dstCheck), ...pickerIssues([...accept, ...check, ...deny], validateSshUser));

  const save = () => {
    let v = setField(base, "src", src[0]);
    v = setField(v, "dst", dst);
    v = setField(v, "accept", accept);
    v = setField(v, "check", check);
    v = setField(v, "deny", deny);
    onSave(v);
  };
  const users = (value: string[], set: (v: string[]) => void, placeholder: string) => (
    <SelectorPicker value={value} onChange={set} options={suggestions(SSH_USER_SUGGESTIONS)} validate={validateSshUser} freeText placeholder={placeholder} />
  );

  return (
    <EditorShell title={initial ? "Edit SSH test" : "New SSH test"} issues={issues} initial={initial} onClose={onClose} onSave={save}>
      <Field label="Source" hint="One user, group, tag, host or IP.">
        <SelectorPicker value={src} onChange={(v) => setSrc(v.slice(-1))} options={srcOptions} validate={srcCheck} hosts={ctx.hosts} placeholder="alice@" />
      </Field>
      <Field label="Destinations" hint="Tags, hosts or SSH autogroups, without ports.">
        <SelectorPicker value={dst} onChange={setDst} options={dstOptions} validate={dstCheck} hosts={ctx.hosts} placeholder="tag:server" />
      </Field>
      <Field label="May log in as">{users(accept, setAccept, "root, ubuntu …")}</Field>
      <Field label="Must re-authenticate (check) as">{users(check, setCheck, "root …")}</Field>
      <Field label="Must not log in as">{users(deny, setDeny, "root …")}</Field>
    </EditorShell>
  );
}

// ---- auto approvers ----

function AutoApprovers({ draft, ctx, writable, dispatch }: SectionsProps) {
  const [editing, setEditing] = useState<{ prefix: string; owners: string[] } | "new" | "exit" | null>(null);
  const routes = Object.keys(draft.autoApprovers.routes).sort();
  return (
    <div className="space-y-2">
      <div className="flex items-center justify-between">
        <span className="text-xs font-medium uppercase tracking-wide text-slate-500">Subnet routes</span>
        <Button variant="ghost" disabled={!writable} onClick={() => setEditing("new")}>
          + Add route
        </Button>
      </div>
      {routes.length === 0 ? (
        <p className="text-sm text-slate-400">No auto-approved routes.</p>
      ) : (
        <ul className="divide-y divide-slate-100 dark:divide-slate-800">
          {routes.map((prefix) => (
            <li key={prefix} className="flex flex-wrap items-center gap-2 py-1.5">
              <span className="font-mono text-sm">{prefix}</span>
              <Arrow />
              <span className="flex min-w-0 flex-1 flex-wrap gap-1">
                <Chips values={draft.autoApprovers.routes[prefix]} hosts={draft.hosts} />
              </span>
              <Button variant="ghost" disabled={!writable} onClick={() => setEditing({ prefix, owners: draft.autoApprovers.routes[prefix] })}>
                Edit
              </Button>
              <Button variant="ghost" disabled={!writable} title="Delete" className="text-red-600 dark:text-red-400" onClick={() => dispatch({ type: "deleteRoute", prefix })}>
                ✕
              </Button>
            </li>
          ))}
        </ul>
      )}
      <div className="flex flex-wrap items-center gap-2 border-t border-slate-100 pt-2 dark:border-slate-800">
        <span className="text-xs font-medium uppercase tracking-wide text-slate-500">Exit nodes</span>
        <span className="flex min-w-0 flex-1 flex-wrap gap-1">
          <Chips values={draft.autoApprovers.exitNode} hosts={draft.hosts} />
        </span>
        <Button variant="ghost" disabled={!writable} onClick={() => setEditing("exit")}>
          Edit
        </Button>
      </div>
      {editing && (
        <ApproverEditor
          ctx={ctx}
          route={editing === "exit" ? null : editing === "new" ? { prefix: "", owners: [] } : editing}
          initialOwners={editing === "exit" ? draft.autoApprovers.exitNode : editing === "new" ? [] : editing.owners}
          existing={routes}
          onClose={() => setEditing(null)}
          onSave={(prefix, owners) => {
            if (editing === "exit") dispatch({ type: "setExitNode", owners });
            else dispatch({ type: "setRoute", prefix, owners, from: editing === "new" ? undefined : editing.prefix });
            setEditing(null);
          }}
        />
      )}
    </div>
  );
}

function ApproverEditor({
  ctx,
  route,
  initialOwners,
  existing,
  onSave,
  onClose,
}: {
  ctx: SelectorContext;
  route: { prefix: string; owners: string[] } | null; // null = exit nodes
  initialOwners: string[];
  existing: string[];
  onSave: (prefix: string, owners: string[]) => void;
  onClose: () => void;
}) {
  const [prefix, setPrefix] = useState(route?.prefix ?? "");
  const [owners, setOwners] = useState(initialOwners);
  const check = (s: string) => restrictedSelector(s, "src", ctx, ["user", "group", "tag"], []);
  const options = useMemo(() => restrictOptions(buildOptions(ctx, "src"), ["user", "group", "tag"], []), [ctx]);
  const issues: Issue[] = pickerIssues(owners, check);
  if (route) {
    const p = prefix.trim();
    const err = validateRoutePrefix(p);
    if (err && p) issues.push({ level: "error", text: err });
    if (!p) issues.push({ level: "error", text: "a route prefix is required" });
    if (p !== route.prefix && existing.includes(p)) issues.push({ level: "error", text: `${p} already has approvers` });
    if (owners.length === 0) issues.push({ level: "error", text: "add at least one approver" });
  }
  const blocked = issues.some((i) => i.level === "error");
  return (
    <Modal title={route ? (route.prefix ? `Edit ${route.prefix}` : "New auto-approved route") : "Exit node approvers"} onClose={onClose}>
      <div className="space-y-3">
        {route && (
          <Field label="Route prefix" hint="Advertised routes inside this prefix are approved automatically.">
            <Input value={prefix} onChange={(e) => setPrefix(e.target.value)} placeholder="10.0.0.0/24" className="font-mono" autoFocus />
          </Field>
        )}
        <Field label="Approved for" hint={route ? "Devices owned by these users, groups or tags." : "Exit nodes advertised by these users, groups or tags are approved automatically. Leave empty to require manual approval."}>
          <SelectorPicker value={owners} onChange={setOwners} options={options} validate={check} hosts={ctx.hosts} placeholder="tag:router, group:admins …" />
        </Field>
        <Issues issues={issues} />
        <div className="flex justify-end gap-2">
          <Button onClick={onClose}>Cancel</Button>
          <Button variant="primary" disabled={blocked} onClick={() => onSave(prefix.trim(), owners)}>
            Save
          </Button>
        </div>
      </div>
    </Modal>
  );
}
