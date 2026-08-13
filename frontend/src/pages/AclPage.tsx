// Access Controls: CodeMirror HuJSON editor with server-side validation
// (POST /api/policy/check as a mandatory pre-save gate), dual-mode saving,
// UI-local version history with diff + rollback, and warn-only lints for
// headscale 0.29 policy semantics.

import { json } from "@codemirror/lang-json";
import { MergeView } from "@codemirror/merge";
import { EditorState } from "@codemirror/state";
import { EditorView, keymap, lineNumbers } from "@codemirror/view";
import { defaultKeymap, history, historyKeymap, indentWithTab } from "@codemirror/commands";
import { useEffect, useMemo, useRef, useState } from "react";
import { ApiError } from "../api/client";
import {
  checkPolicy,
  getPolicyVersion,
  usePolicy,
  usePolicyVersions,
  useSavePolicy,
} from "../api/queries";
import type { PolicyVersion } from "../api/types";
import { PageHeader } from "../components/Layout";
import { CliHint, Code, errorText } from "../components/common";
import { Badge, Button, Card, Input, Modal, cn, useToast } from "../components/ui";
import { relativeTime } from "../lib/format";

// ---- warn-only content lints (headscale 0.29 semantics) ----

interface Hint {
  level: "warn" | "info";
  text: string;
}

function contentHints(doc: string): Hint[] {
  const hints: Hint[] = [];
  if (/"src"\s*:\s*\[[^\]]*"\*"/.test(doc)) {
    hints.push({
      level: "warn",
      text: 'Since headscale 0.29, "*" matches only tailnet addresses (CGNAT + ULA). Use "autogroup:danger-all" (source-only) to match ALL IPs.',
    });
  }
  if (/"proto"\s*:\s*"icmp"/.test(doc)) {
    hints.push({
      level: "warn",
      text: '"proto": "icmp" matches ICMPv4 only since 0.29 — add a second rule with "proto": "ipv6-icmp" for IPv6.',
    });
  }
  if (/"ssh"\s*:/.test(doc) && /"dst"\s*:\s*\[[^\]]*"\*"/.test(doc)) {
    hints.push({
      level: "warn",
      text: "SSH rules reject the wildcard destination since 0.28 — use autogroup:member / autogroup:tagged.",
    });
  }
  for (const section of ["postures", "srcPosture", "ipsets"]) {
    if (new RegExp(`"${section}"\\s*:`).test(doc)) {
      hints.push({ level: "warn", text: `"${section}" is a Tailscale-only feature — headscale does not support it.` });
    }
  }
  if (/"acls"\s*:/.test(doc) && !/"grants"\s*:/.test(doc)) {
    hints.push({
      level: "info",
      text: 'headscale marks "acls" as legacy — "grants" (with ip/app/via, added in 0.29) is recommended for new policies.',
    });
  }
  return hints;
}

const SNIPPETS: Array<{ label: string; text: string }> = [
  { label: "grant", text: `{"src": ["group:example"], "dst": ["tag:server"], "ip": ["tcp:443"]}` },
  { label: "acl rule", text: `{"action": "accept", "src": ["group:example"], "dst": ["tag:server:443"]}` },
  { label: "group", text: `"group:example": ["alice@", "bob@"]` },
  { label: "tagOwner", text: `"tag:server": ["group:example"]` },
  { label: "host", text: `"router": "10.0.0.1"` },
  { label: "autoApprover", text: `"autoApprovers": {"routes": {"10.0.0.0/24": ["tag:router"]}, "exitNode": ["tag:exit"]}` },
  { label: "ssh rule", text: `{"action": "accept", "src": ["group:admins"], "dst": ["autogroup:member"], "users": ["autogroup:nonroot"]}` },
  { label: "ssh check", text: `{"action": "check", "checkPeriod": "12h", "src": ["group:admins"], "dst": ["autogroup:member"], "users": ["root"]}` },
  { label: "test", text: `{"src": "alice@", "accept": ["tag:server:443"], "deny": ["tag:db:5432"]}` },
];

// ---- the page ----

export function AclPage() {
  const { data: state, isLoading, refetch } = usePolicy();
  const { data: versions } = usePolicyVersions();
  const save = useSavePolicy();
  const toast = useToast();

  const editorHost = useRef<HTMLDivElement>(null);
  const viewRef = useRef<EditorView | null>(null);
  const [dirty, setDirty] = useState(false);
  const [checking, setChecking] = useState(false);
  const [checkResult, setCheckResult] = useState<{ ok: boolean; message: string } | null>(null);
  const [saveModal, setSaveModal] = useState(false);
  const [comment, setComment] = useState("");
  const [diffVersion, setDiffVersion] = useState<PolicyVersion | null>(null);
  const loadedHash = useRef<string>("");

  // Mount the editor once.
  useEffect(() => {
    if (!editorHost.current || viewRef.current) return;
    const view = new EditorView({
      parent: editorHost.current,
      state: EditorState.create({
        doc: "",
        extensions: [
          lineNumbers(),
          history(),
          keymap.of([...defaultKeymap, ...historyKeymap, indentWithTab]),
          json(),
          EditorView.theme({
            "&": { minHeight: "24rem", maxHeight: "60vh" },
            ".cm-scroller": { overflow: "auto", fontFamily: "ui-monospace, monospace" },
          }),
          EditorView.updateListener.of((u) => {
            if (u.docChanged) {
              setDirty(true);
              setCheckResult(null);
            }
          }),
        ],
      }),
    });
    viewRef.current = view;
    return () => {
      view.destroy();
      viewRef.current = null;
    };
  }, []);

  // Load server policy into the editor when it arrives (only while pristine).
  useEffect(() => {
    const view = viewRef.current;
    if (!view || !state) return;
    if (!dirty && state.policy !== view.state.doc.toString() && loadedHash.current !== state.policy) {
      view.dispatch({ changes: { from: 0, to: view.state.doc.length, insert: state.policy } });
      loadedHash.current = state.policy;
      setDirty(false);
    }
  }, [state, dirty]);

  const doc = () => viewRef.current?.state.doc.toString() ?? "";
  const hints = useMemo(() => (state ? contentHints(dirty ? doc() : state.policy) : []), [state, dirty, checkResult]);

  const runCheck = async (): Promise<boolean> => {
    setChecking(true);
    try {
      await checkPolicy(doc());
      setCheckResult({ ok: true, message: "Policy is valid against the live tailnet (users, nodes, tests all pass)." });
      return true;
    } catch (e) {
      const msg = e instanceof ApiError ? (e.headscaleMessage || e.message) : errorText(e);
      setCheckResult({ ok: false, message: msg });
      return false;
    } finally {
      setChecking(false);
    }
  };

  const doSave = async () => {
    // check is a mandatory gate before every save.
    if (!(await runCheck())) {
      setSaveModal(false);
      toast.error("Validation failed — fix the policy and try again");
      return;
    }
    save.mutate(
      { policy: doc(), comment: comment || undefined },
      {
        onSuccess: (res) => {
          setSaveModal(false);
          setComment("");
          setDirty(false);
          if (res.warning) {
            toast.error("Saved with warning", res.warning);
          } else if (res.reloadPending) {
            toast.success("Policy file written — reload headscale to apply");
          } else {
            toast.success("Policy applied");
          }
          refetch();
        },
        onError: (e) => toast.error("Save failed", errorText(e)),
      },
    );
  };

  const insertSnippet = (text: string) => {
    const view = viewRef.current;
    if (!view) return;
    const pos = view.state.selection.main.head;
    view.dispatch({ changes: { from: pos, insert: text }, selection: { anchor: pos + text.length } });
    view.focus();
  };

  const loadVersion = async (id: number) => {
    const v = await getPolicyVersion(id);
    const view = viewRef.current;
    if (!view || v.content === undefined) return;
    view.dispatch({ changes: { from: 0, to: view.state.doc.length, insert: v.content } });
    setDirty(true);
    setDiffVersion(null);
    toast.success(`Version #${id} loaded into the editor — review and Save to apply`);
  };

  return (
    <>
      <PageHeader
        title="Access Controls"
        subtitle="HuJSON policy: acls/grants, groups, tagOwners, hosts, autoApprovers, ssh, tests"
        actions={
          <>
            <Button onClick={runCheck} loading={checking}>
              Check
            </Button>
            <Button
              variant="primary"
              disabled={!dirty || !state?.writable}
              onClick={() => setSaveModal(true)}
            >
              Save…
            </Button>
          </>
        }
      />

      {state && <ModeBanner state={state} />}

      <div className="grid gap-4 lg:grid-cols-[1fr_16rem]">
        <div className="min-w-0 space-y-3">
          <div
            ref={editorHost}
            className="overflow-hidden rounded-lg border border-slate-200 bg-white dark:border-slate-700 [&_.cm-editor]:bg-white dark:[&_.cm-editor]:bg-slate-900 dark:[&_.cm-content]:text-slate-100 dark:[&_.cm-gutters]:border-slate-700 dark:[&_.cm-gutters]:bg-slate-800 dark:[&_.cm-gutters]:text-slate-500"
          />
          {isLoading && <p className="text-sm text-slate-500">Loading policy…</p>}

          {checkResult && (
            <div
              className={cn(
                "rounded-md border px-3 py-2 text-sm",
                checkResult.ok
                  ? "border-emerald-300 bg-emerald-50 text-emerald-800 dark:border-emerald-700 dark:bg-emerald-950/40 dark:text-emerald-300"
                  : "border-red-300 bg-red-50 text-red-800 dark:border-red-700 dark:bg-red-950/40 dark:text-red-300",
              )}
            >
              <p className="font-medium">{checkResult.ok ? "✓ Valid" : "✕ Validation failed"}</p>
              <pre className="mt-1 whitespace-pre-wrap font-mono text-xs">{checkResult.message}</pre>
            </div>
          )}

          {hints.map((h, i) => (
            <div
              key={i}
              className={cn(
                "rounded-md border px-3 py-2 text-xs",
                h.level === "warn"
                  ? "border-amber-300 bg-amber-50 text-amber-900 dark:border-amber-700 dark:bg-amber-950/40 dark:text-amber-200"
                  : "border-sky-300 bg-sky-50 text-sky-900 dark:border-sky-700 dark:bg-sky-950/40 dark:text-sky-200",
              )}
            >
              {h.text}
            </div>
          ))}

          <div className="flex flex-wrap items-center gap-1.5">
            <span className="text-xs text-slate-400">Insert:</span>
            {SNIPPETS.map((s) => (
              <button
                key={s.label}
                onClick={() => insertSnippet(s.text)}
                className="rounded border border-slate-200 px-2 py-0.5 text-xs text-slate-600 hover:bg-slate-100 dark:border-slate-700 dark:text-slate-300 dark:hover:bg-slate-800"
              >
                {s.label}
              </button>
            ))}
          </div>
        </div>

        <Card title="History" className="self-start">
          {(versions ?? []).length === 0 ? (
            <p className="text-xs text-slate-400">
              No versions yet — every save (and any change observed outside this UI) is snapshotted
              here.
            </p>
          ) : (
            <ul className="max-h-[50vh] space-y-1.5 overflow-y-auto text-xs">
              {(versions ?? []).map((v) => (
                <li key={v.id} className="rounded border border-slate-200 px-2 py-1.5 dark:border-slate-700">
                  <div className="flex items-center justify-between gap-1">
                    <span className="font-medium">#{v.id}</span>
                    <Badge tone={v.source === "ui" ? "blue" : "gray"}>
                      {v.source === "ui" ? "saved here" : "external"}
                    </Badge>
                  </div>
                  <p className="mt-0.5 text-slate-400">{relativeTime(v.savedAt)}</p>
                  {v.comment && <p className="mt-0.5 italic text-slate-500">{v.comment}</p>}
                  <div className="mt-1 flex gap-2">
                    <button className="text-indigo-600 hover:underline dark:text-indigo-400" onClick={() => setDiffVersion(v)}>
                      diff
                    </button>
                    <button className="text-indigo-600 hover:underline dark:text-indigo-400" onClick={() => loadVersion(v.id)}>
                      load
                    </button>
                  </div>
                </li>
              ))}
            </ul>
          )}
          <p className="mt-3 border-t border-slate-200 pt-2 text-[11px] leading-relaxed text-slate-400 dark:border-slate-700">
            History lives in Head-Control's own database and covers what this UI has observed —
            headscale keeps no policy history itself.
          </p>
        </Card>
      </div>

      {saveModal && state && (
        <Modal title="Save policy" onClose={() => setSaveModal(false)}>
          <div className="space-y-3 text-sm">
            <p className="text-slate-600 dark:text-slate-300">
              The policy is validated against the live tailnet before applying (including{" "}
              <Code>tests</Code>/<Code>sshTests</Code>).{" "}
              {state.mode === "file"
                ? state.dockerReload
                  ? "The mounted policy file is replaced atomically, then headscale is reloaded via SIGHUP."
                  : "The mounted policy file is replaced atomically; you must reload headscale manually afterwards."
                : "In database mode changes apply and push to nodes immediately."}
            </p>
            <label className="block space-y-1">
              <span className="text-xs font-medium text-slate-500">Comment (optional, for history)</span>
              <Input value={comment} onChange={(e) => setComment(e.target.value)} placeholder="e.g. allow ci runners to reach the registry" />
            </label>
            <div className="flex justify-end gap-2">
              <Button onClick={() => setSaveModal(false)}>Cancel</Button>
              <Button variant="primary" loading={save.isPending || checking} onClick={doSave}>
                Check &amp; save
              </Button>
            </div>
            <CliHint command="headscale policy check -f policy.hujson && headscale policy set -f policy.hujson" />
          </div>
        </Modal>
      )}

      {diffVersion && (
        <DiffModal
          version={diffVersion}
          currentDoc={doc() || state?.policy || ""}
          onClose={() => setDiffVersion(null)}
          onLoad={() => loadVersion(diffVersion.id)}
        />
      )}
    </>
  );
}

function ModeBanner({ state }: { state: NonNullable<ReturnType<typeof usePolicy>["data"]> }) {
  if (state.mode === "database") {
    return (
      <div className="mb-4 rounded-md border border-emerald-300 bg-emerald-50 px-3 py-2 text-sm text-emerald-900 dark:border-emerald-700 dark:bg-emerald-950/40 dark:text-emerald-200">
        <Badge tone="green">database mode</Badge>
        <span className="ml-2">Changes apply immediately via the headscale API.</span>
        {state.updatedAt && (
          <span className="ml-2 text-xs opacity-75">Last applied {relativeTime(state.updatedAt)}.</span>
        )}
      </div>
    );
  }
  if (state.mode === "file" && state.fileMounted && state.fileWritable) {
    return (
      <div className="mb-4 rounded-md border border-amber-300 bg-amber-50 px-3 py-2 text-sm text-amber-900 dark:border-amber-700 dark:bg-amber-950/40 dark:text-amber-200">
        <Badge tone="yellow">file mode (managed)</Badge>
        <span className="ml-2">
          Saving replaces the mounted policy file
          {state.dockerReload
            ? " and reloads headscale automatically (SIGHUP via the Docker integration)."
            : " — then reload headscale yourself:"}
        </span>
        {!state.dockerReload && <Code>docker kill -s HUP headscale</Code>}
        {state.reloadPending && (
          <p className="mt-1 font-medium">
            ⚠ The file on disk differs from what headscale is serving — a reload is pending.
          </p>
        )}
      </div>
    );
  }
  if (state.mode === "file") {
    return (
      <div className="mb-4 space-y-1 rounded-md border border-red-300 bg-red-50 px-3 py-2 text-sm text-red-900 dark:border-red-700 dark:bg-red-950/40 dark:text-red-200">
        <p>
          <Badge tone="red">file mode (read-only)</Badge>
          <span className="ml-2">
            Headscale runs with <Code>policy.mode: file</Code> and the policy file isn't mounted
            writable here.
          </span>
        </p>
        <p className="text-xs">
          To edit from this UI: mount the policy file into the Head-Control container
          (<Code>POLICY_FILE_PATH</Code>) — optionally with the Docker reload integration — or switch
          headscale to <Code>policy.mode: database</Code>. The editor still works as a scratchpad and{" "}
          <strong>Check</strong> validates against the live server.
        </p>
      </div>
    );
  }
  return (
    <div className="mb-4 rounded-md border border-slate-300 bg-slate-50 px-3 py-2 text-sm text-slate-700 dark:border-slate-600 dark:bg-slate-800/60 dark:text-slate-300">
      <Badge tone="gray">mode not yet known</Badge>
      <span className="ml-2">
        The first save reveals whether headscale runs in database or file mode (Head-Control never
        probes with writes).
      </span>
    </div>
  );
}

function DiffModal({
  version,
  currentDoc,
  onClose,
  onLoad,
}: {
  version: PolicyVersion;
  currentDoc: string;
  onClose: () => void;
  onLoad: () => void;
}) {
  const host = useRef<HTMLDivElement>(null);
  const [loaded, setLoaded] = useState(false);

  useEffect(() => {
    let mv: MergeView | null = null;
    let cancelled = false;
    getPolicyVersion(version.id).then((v) => {
      if (cancelled || !host.current) return;
      mv = new MergeView({
        parent: host.current,
        a: { doc: v.content ?? "", extensions: [lineNumbers(), json(), EditorView.editable.of(false)] },
        b: { doc: currentDoc, extensions: [lineNumbers(), json(), EditorView.editable.of(false)] },
      });
      setLoaded(true);
    });
    return () => {
      cancelled = true;
      mv?.destroy();
    };
  }, [version.id, currentDoc]);

  return (
    <Modal title={`Version #${version.id} (${relativeTime(version.savedAt)}) vs editor`} onClose={onClose} wide>
      <div className="space-y-3">
        {!loaded && <p className="text-sm text-slate-500">Loading diff…</p>}
        <div
          ref={host}
          className="max-h-[55vh] overflow-auto rounded border border-slate-200 text-xs dark:border-slate-700 [&_.cm-editor]:bg-white dark:[&_.cm-editor]:bg-slate-900 dark:[&_.cm-content]:text-slate-100"
        />
        <div className="flex justify-end gap-2">
          <Button onClick={onClose}>Close</Button>
          <Button variant="primary" onClick={onLoad}>
            Load #{version.id} into editor
          </Button>
        </div>
      </div>
    </Modal>
  );
}
