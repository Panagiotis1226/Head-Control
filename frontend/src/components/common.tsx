// Shared composite components: copy buttons, CLI hints, capability notices,
// confirm dialogs, show-once secret modal.

import { useState, type ReactNode } from "react";
import { Badge, Button, Checkbox, Modal, cn, useToast } from "./ui";

export function CopyButton({ text, label }: { text: string; label?: string }) {
  const [copied, setCopied] = useState(false);
  return (
    <button
      type="button"
      onClick={async () => {
        try {
          await navigator.clipboard.writeText(text);
        } catch {
          // Clipboard API unavailable (plain HTTP) — fall back to a prompt.
          window.prompt("Copy manually:", text);
          return;
        }
        setCopied(true);
        setTimeout(() => setCopied(false), 1500);
      }}
      className="inline-flex items-center gap-1 rounded px-1.5 py-0.5 text-xs text-slate-500 hover:bg-slate-100 hover:text-slate-700 dark:hover:bg-slate-800 dark:hover:text-slate-300"
      title="Copy to clipboard"
    >
      {copied ? "✓ copied" : label ?? "copy"}
    </button>
  );
}

export function Code({ children, block }: { children: string; block?: boolean }) {
  if (block) {
    return (
      <pre className="overflow-x-auto rounded-md bg-slate-950 px-3 py-2 font-mono text-xs leading-relaxed text-slate-100">
        {children}
      </pre>
    );
  }
  return (
    <code className="rounded bg-slate-100 px-1 py-0.5 font-mono text-xs text-slate-800 dark:bg-slate-800 dark:text-slate-200">
      {children}
    </code>
  );
}

/** Collapsible "CLI equivalent" footer for mutation dialogs. */
export function CliHint({ command }: { command: string }) {
  const [open, setOpen] = useState(false);
  return (
    <div className="mt-3 border-t border-slate-200 pt-2 dark:border-slate-700">
      <button
        type="button"
        onClick={() => setOpen(!open)}
        className="text-xs text-slate-500 hover:text-slate-700 dark:text-slate-400 dark:hover:text-slate-200"
      >
        {open ? "▾" : "▸"} CLI equivalent
      </button>
      {open && (
        <div className="mt-1.5 flex items-start gap-2">
          <Code block>{command}</Code>
          <CopyButton text={command} />
        </div>
      )}
    </div>
  );
}

/**
 * Honest capability notice. level:
 *  - "config-only": exists in headscale but only via config.yaml
 *  - "impossible": headscale has no server-side support
 *  - "ui-local": implemented entirely by Head-Control, not headscale
 */
export function CapabilityNotice({
  level,
  children,
}: {
  level: "config-only" | "impossible" | "ui-local";
  children: ReactNode;
}) {
  const styles = {
    "config-only": "border-amber-300 bg-amber-50 text-amber-900 dark:border-amber-700 dark:bg-amber-950/40 dark:text-amber-200",
    impossible: "border-slate-300 bg-slate-50 text-slate-700 dark:border-slate-600 dark:bg-slate-800/60 dark:text-slate-300",
    "ui-local": "border-sky-300 bg-sky-50 text-sky-900 dark:border-sky-700 dark:bg-sky-950/40 dark:text-sky-200",
  } as const;
  const labels = {
    "config-only": "config-file only",
    impossible: "not supported by headscale",
    "ui-local": "Head-Control feature",
  } as const;
  return (
    <div className={cn("rounded-md border px-3 py-2 text-xs leading-relaxed", styles[level])}>
      <Badge tone={level === "impossible" ? "gray" : level === "config-only" ? "yellow" : "blue"}>
        {labels[level]}
      </Badge>
      <span className="ml-2">{children}</span>
    </div>
  );
}

/** Confirmation dialog; set typeToConfirm to require typing the target name. */
export function ConfirmDialog({
  title,
  message,
  confirmLabel = "Confirm",
  danger,
  typeToConfirm,
  cli,
  busy,
  onConfirm,
  onCancel,
}: {
  title: ReactNode;
  message: ReactNode;
  confirmLabel?: string;
  danger?: boolean;
  typeToConfirm?: string;
  cli?: string;
  busy?: boolean;
  onConfirm: () => void;
  onCancel: () => void;
}) {
  const [typed, setTyped] = useState("");
  const blocked = !!typeToConfirm && typed !== typeToConfirm;
  return (
    <Modal title={title} onClose={onCancel}>
      <div className="space-y-3 text-sm text-slate-700 dark:text-slate-300">
        <div>{message}</div>
        {typeToConfirm && (
          <div>
            <p className="mb-1 text-xs text-slate-500">
              Type <Code>{typeToConfirm}</Code> to confirm:
            </p>
            <input
              value={typed}
              onChange={(e) => setTyped(e.target.value)}
              className="w-full rounded-md border border-slate-300 px-3 py-1.5 text-sm dark:border-slate-600 dark:bg-slate-800 dark:text-slate-100"
              autoFocus
            />
          </div>
        )}
        <div className="flex justify-end gap-2 pt-1">
          <Button onClick={onCancel}>Cancel</Button>
          <Button
            variant={danger ? "danger" : "primary"}
            disabled={blocked}
            loading={busy}
            onClick={onConfirm}
          >
            {confirmLabel}
          </Button>
        </div>
        {cli && <CliHint command={cli} />}
      </div>
    </Modal>
  );
}

/** Show-once secret modal (pre-auth keys, API keys). */
export function SecretModal({
  title,
  secret,
  description,
  extraCommand,
  onClose,
}: {
  title: ReactNode;
  secret: string;
  description?: ReactNode;
  extraCommand?: { label: string; command: string };
  onClose: () => void;
}) {
  const [acknowledged, setAcknowledged] = useState(false);
  const toast = useToast();
  return (
    <Modal title={title}>
      <div className="space-y-3 text-sm">
        <div className="rounded-md border border-amber-300 bg-amber-50 px-3 py-2 text-xs text-amber-900 dark:border-amber-700 dark:bg-amber-950/40 dark:text-amber-200">
          This secret is shown <strong>once</strong>. Headscale stores only a hash — it can never be
          retrieved again.
        </div>
        <div className="flex items-center gap-2">
          <Code block>{secret}</Code>
          <CopyButton text={secret} />
        </div>
        {description && <p className="text-slate-600 dark:text-slate-400">{description}</p>}
        {extraCommand && (
          <div>
            <p className="mb-1 text-xs font-medium text-slate-500">{extraCommand.label}</p>
            <div className="flex items-start gap-2">
              <Code block>{extraCommand.command}</Code>
              <CopyButton text={extraCommand.command} />
            </div>
          </div>
        )}
        <Checkbox
          checked={acknowledged}
          onChange={(e) => setAcknowledged(e.target.checked)}
          label="I've stored this secret — it cannot be shown again"
        />
        <div className="flex justify-end">
          <Button
            variant="primary"
            disabled={!acknowledged}
            onClick={() => {
              toast.success("Secret dismissed");
              onClose();
            }}
          >
            Done
          </Button>
        </div>
      </div>
    </Modal>
  );
}

/** Standard error → toast plumbing for mutations. */
export function errorText(err: unknown): string {
  if (err instanceof Error) return err.message;
  return String(err);
}
