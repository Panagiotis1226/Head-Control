// Keys: pre-auth keys (filters, labels, create/expire/delete) and API keys
// (create/expire/delete with self-lockout guard, guided rotation checklist).

import { useMemo, useState } from "react";
import { ApiError } from "../api/client";
import {
  useApiKeys,
  useCreateApiKey,
  useCreatePreAuthKey,
  useDeleteApiKey,
  useDeletePreAuthKey,
  useExpireApiKey,
  useExpirePreAuthKey,
  useMeta,
  usePreAuthKeys,
  useSetKeyLabel,
  useUsers,
} from "../api/queries";
import type { ApiKey, PreAuthKey } from "../api/types";
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
import {
  Badge,
  Button,
  Card,
  Checkbox,
  EmptyState,
  Field,
  Input,
  Modal,
  Select,
  Table,
  Td,
  Th,
  useToast,
} from "../components/ui";
import { DAY, expiresWithin, isExpired, relativeTime, userLabel } from "../lib/format";

export function KeysPage() {
  const [tab, setTab] = useState<"preauth" | "api">("preauth");
  return (
    <>
      <PageHeader
        title="Keys"
        subtitle="Pre-auth keys register devices unattended; API keys grant access to the headscale API."
      />

      <div className="mb-4 flex max-w-md gap-1 rounded-md bg-slate-100 p-1 dark:bg-slate-800">
        {(
          [
            ["preauth", "Pre-auth keys"],
            ["api", "API keys"],
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

      {tab === "preauth" ? <PreAuthKeysTab /> : <ApiKeysTab />}
    </>
  );
}

// ---- pre-auth keys ----

type PakState = "all" | "active" | "used" | "expired";

type PakModal =
  | { kind: "create" }
  | { kind: "label"; pak: PreAuthKey }
  | { kind: "expire"; pak: PreAuthKey }
  | { kind: "delete"; pak: PreAuthKey }
  | null;

function pakMatchesState(k: PreAuthKey, state: PakState): boolean {
  switch (state) {
    case "all":
      return true;
    case "expired":
      return isExpired(k.expiration);
    case "used":
      return k.used;
    case "active":
      return !isExpired(k.expiration) && (k.reusable || !k.used);
  }
}

function PreAuthKeysTab() {
  const { data, isLoading } = usePreAuthKeys();
  const { data: users } = useUsers();
  const { data: meta } = useMeta();
  const [userFilter, setUserFilter] = useState("");
  const [stateFilter, setStateFilter] = useState<PakState>("all");
  const [onlyEphemeral, setOnlyEphemeral] = useState(false);
  const [onlyTagged, setOnlyTagged] = useState(false);
  const [modal, setModal] = useState<PakModal>(null);

  const expire = useExpirePreAuthKey();
  const deleteKey = useDeletePreAuthKey();
  const toast = useToast();

  const keys = data?.preAuthKeys ?? [];
  const labels = data?.labels ?? {};

  const filtered = useMemo(
    () =>
      keys.filter(
        (k) =>
          (!userFilter || k.user?.id === userFilter) &&
          pakMatchesState(k, stateFilter) &&
          (!onlyEphemeral || k.ephemeral) &&
          (!onlyTagged || (k.aclTags ?? []).length > 0),
      ),
    [keys, userFilter, stateFilter, onlyEphemeral, onlyTagged],
  );

  return (
    <>
      <div className="mb-4 flex flex-wrap items-center gap-3">
        <Select value={userFilter} onChange={(e) => setUserFilter(e.target.value)}>
          <option value="">All users</option>
          {(users ?? []).map((u) => (
            <option key={u.id} value={u.id}>
              {userLabel(u)}
            </option>
          ))}
        </Select>
        <Select value={stateFilter} onChange={(e) => setStateFilter(e.target.value as PakState)}>
          <option value="all">All states</option>
          <option value="active">active</option>
          <option value="used">used</option>
          <option value="expired">expired</option>
        </Select>
        <Checkbox
          checked={onlyEphemeral}
          onChange={(e) => setOnlyEphemeral(e.target.checked)}
          label="ephemeral"
        />
        <Checkbox
          checked={onlyTagged}
          onChange={(e) => setOnlyTagged(e.target.checked)}
          label="tagged"
        />
        <div className="ml-auto">
          <Button variant="primary" onClick={() => setModal({ kind: "create" })}>
            + Create key
          </Button>
        </div>
      </div>

      {isLoading ? (
        <p className="text-sm text-slate-500">Loading pre-auth keys…</p>
      ) : keys.length === 0 ? (
        <EmptyState title="No pre-auth keys">
          <p>Create one to register devices without interactive login.</p>
        </EmptyState>
      ) : (
        <>
          <Table
            head={
              <>
                <Th>Key</Th>
                <Th>User</Th>
                <Th>Flags</Th>
                <Th>Tags</Th>
                <Th>Created</Th>
                <Th>Expiration</Th>
                <Th className="w-10" />
              </>
            }
          >
            {filtered.length === 0 ? (
              <tr>
                <Td colSpan={7} className="text-center text-slate-400">
                  No keys match the current filters.
                </Td>
              </tr>
            ) : (
              filtered.map((k) => (
                <PreAuthKeyRow
                  key={k.id}
                  pak={k}
                  label={labels[k.id]}
                  onEditLabel={() => setModal({ kind: "label", pak: k })}
                  onAction={(kind) => setModal({ kind, pak: k })}
                />
              ))
            )}
          </Table>
          <p className="mt-2 text-xs text-slate-500 dark:text-slate-400">
            Key secrets are bcrypt-hashed by headscale since 0.28 — listings show only a prefix.
          </p>
        </>
      )}

      {modal?.kind === "create" && (
        <CreatePreAuthKeyModal
          publicServerUrl={meta?.publicServerUrl ?? ""}
          onClose={() => setModal(null)}
        />
      )}
      {modal?.kind === "label" && (
        <EditLabelModal
          pak={modal.pak}
          currentLabel={labels[modal.pak.id] ?? ""}
          onClose={() => setModal(null)}
        />
      )}
      {modal?.kind === "expire" && (
        <ConfirmDialog
          title="Expire pre-auth key?"
          confirmLabel="Expire key"
          busy={expire.isPending}
          cli={`headscale preauthkeys expire --id ${modal.pak.id}`}
          message={
            <div className="space-y-2">
              <p>
                Key <Code>{modal.pak.key ?? modal.pak.id}</Code> stops accepting new registrations
                immediately.
              </p>
              <p className="text-xs text-slate-500">
                Expiring a reusable key stops future joins but does not disconnect nodes that
                already used it.
              </p>
            </div>
          }
          onCancel={() => setModal(null)}
          onConfirm={() =>
            expire.mutate(
              { id: modal.pak.id },
              {
                onSuccess: () => {
                  toast.success("Pre-auth key expired");
                  setModal(null);
                },
                onError: (e) => toast.error("Expire failed", errorText(e)),
              },
            )
          }
        />
      )}
      {modal?.kind === "delete" && (
        <ConfirmDialog
          title="Delete pre-auth key?"
          danger
          confirmLabel="Delete key"
          busy={deleteKey.isPending}
          cli={`headscale preauthkeys delete --id ${modal.pak.id}`}
          message={
            <p>
              Key <Code>{modal.pak.key ?? modal.pak.id}</Code> is removed from headscale
              permanently. Nodes already registered with it are not affected.
            </p>
          }
          onCancel={() => setModal(null)}
          onConfirm={() =>
            deleteKey.mutate(
              { id: modal.pak.id },
              {
                onSuccess: () => {
                  toast.success("Pre-auth key deleted");
                  setModal(null);
                },
                onError: (e) => toast.error("Delete failed", errorText(e)),
              },
            )
          }
        />
      )}
    </>
  );
}

function PreAuthKeyRow({
  pak: k,
  label,
  onEditLabel,
  onAction,
}: {
  pak: PreAuthKey;
  label?: string;
  onEditLabel: () => void;
  onAction: (kind: "expire" | "delete") => void;
}) {
  const [menuOpen, setMenuOpen] = useState(false);
  return (
    <tr className="hover:bg-slate-50 dark:hover:bg-slate-800/50">
      <Td>
        <span className="flex items-center gap-1">
          <span className="font-mono text-xs">{k.key ?? "—"}</span>
          <button
            onClick={onEditLabel}
            title="Edit label (visible only in this UI)"
            className="rounded px-1 text-slate-400 hover:bg-slate-100 hover:text-slate-600 dark:hover:bg-slate-800 dark:hover:text-slate-300"
          >
            ✎
          </button>
        </span>
        {label && <p className="mt-0.5 text-xs text-slate-400">{label}</p>}
      </Td>
      <Td>{userLabel(k.user)}</Td>
      <Td>
        <span className="flex flex-wrap gap-1">
          {k.reusable && <Badge tone="blue">reusable</Badge>}
          {k.ephemeral && <Badge tone="purple">ephemeral</Badge>}
          {k.used && <Badge tone="gray">used</Badge>}
          {!k.reusable && !k.ephemeral && !k.used && (
            <span className="text-xs text-slate-400">single-use</span>
          )}
        </span>
      </Td>
      <Td>
        {(k.aclTags ?? []).length > 0 ? (
          <span className="flex flex-wrap gap-1">
            {(k.aclTags ?? []).map((t) => (
              <Badge key={t} tone="purple">
                {t}
              </Badge>
            ))}
          </span>
        ) : (
          <span className="text-xs text-slate-400">—</span>
        )}
      </Td>
      <Td>
        <span className="text-xs text-slate-500">{relativeTime(k.createdAt)}</span>
      </Td>
      <Td>
        <span className="flex items-center gap-1.5">
          <span className="text-xs text-slate-500">
            {k.expiration ? relativeTime(k.expiration) : "never"}
          </span>
          {isExpired(k.expiration) && <Badge tone="red">expired</Badge>}
          {!isExpired(k.expiration) && expiresWithin(k.expiration, 3 * DAY) && (
            <Badge tone="yellow">expires soon</Badge>
          )}
        </span>
      </Td>
      <Td className="relative">
        <button
          onClick={() => setMenuOpen(!menuOpen)}
          onBlur={() => setTimeout(() => setMenuOpen(false), 150)}
          className="rounded px-2 py-1 text-slate-400 hover:bg-slate-100 dark:hover:bg-slate-800"
          aria-label="Actions"
        >
          ⋯
        </button>
        {menuOpen && (
          <div className="absolute right-2 top-9 z-20 w-36 rounded-md border border-slate-200 bg-white py-1 shadow-lg dark:border-slate-700 dark:bg-slate-800">
            {(
              [
                ["expire", "Expire…"],
                ["delete", "Delete…"],
              ] as const
            ).map(([kind, text]) => (
              <button
                key={kind}
                onClick={() => onAction(kind)}
                className={`block w-full px-3 py-1.5 text-left text-sm hover:bg-slate-100 dark:hover:bg-slate-700 ${
                  kind === "delete"
                    ? "text-red-600 dark:text-red-400"
                    : "text-slate-700 dark:text-slate-200"
                }`}
              >
                {text}
              </button>
            ))}
          </div>
        )}
      </Td>
    </tr>
  );
}

function EditLabelModal({
  pak,
  currentLabel,
  onClose,
}: {
  pak: PreAuthKey;
  currentLabel: string;
  onClose: () => void;
}) {
  const [label, setLabel] = useState(currentLabel);
  const setLabelMut = useSetKeyLabel();
  const toast = useToast();
  return (
    <Modal title="Edit key label" onClose={onClose}>
      <div className="space-y-3">
        <CapabilityNotice level="ui-local">
          Labels are stored by Head-Control and visible only in this UI — headscale has no key
          labels.
        </CapabilityNotice>
        <Field label={<>Label for <Code>{pak.key ?? pak.id}</Code></>}>
          <Input
            value={label}
            onChange={(e) => setLabel(e.target.value)}
            placeholder="e.g. CI runner key"
            autoFocus
          />
        </Field>
        <div className="flex justify-end gap-2">
          <Button onClick={onClose}>Cancel</Button>
          <Button
            variant="primary"
            loading={setLabelMut.isPending}
            onClick={() =>
              setLabelMut.mutate(
                { id: pak.id, label: label.trim() },
                {
                  onSuccess: () => {
                    toast.success("Label saved");
                    onClose();
                  },
                  onError: (e) => toast.error("Label update failed", errorText(e)),
                },
              )
            }
          >
            Save label
          </Button>
        </div>
      </div>
    </Modal>
  );
}

function CreatePreAuthKeyModal({
  publicServerUrl,
  onClose,
}: {
  publicServerUrl: string;
  onClose: () => void;
}) {
  const { data: users } = useUsers();
  const [userId, setUserId] = useState("");
  const [reusable, setReusable] = useState(false);
  const [ephemeral, setEphemeral] = useState(false);
  const [hours, setHours] = useState(1);
  const [tags, setTags] = useState("");
  const [label, setLabel] = useState("");
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
    <Modal title="Create pre-auth key" onClose={onClose}>
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
          <Checkbox
            checked={reusable}
            onChange={(e) => setReusable(e.target.checked)}
            label="Reusable"
          />
          <Checkbox
            checked={ephemeral}
            onChange={(e) => setEphemeral(e.target.checked)}
            label={
              <>
                Ephemeral{" "}
                <span className="text-xs text-slate-400">(node auto-removed when offline)</span>
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
        <Field
          label="Label (optional)"
          hint="Stored by Head-Control — visible only in this UI, not in headscale."
        >
          <Input
            value={label}
            onChange={(e) => setLabel(e.target.value)}
            placeholder="e.g. CI runner key"
          />
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
                  label: label.trim() || undefined,
                },
                {
                  onSuccess: (res) => {
                    toast.success("Pre-auth key created");
                    setSecret(res.preAuthKey.key ?? "");
                  },
                  onError: (e) => toast.error("Key creation failed", errorText(e)),
                },
              )
            }
          >
            Create key
          </Button>
        </div>
        <CliHint
          command={`headscale preauthkeys create --user ${userId || "<user-id>"} --expiration ${hours}h${reusable ? " --reusable" : ""}${ephemeral ? " --ephemeral" : ""}`}
        />
      </div>
    </Modal>
  );
}

// ---- API keys ----

type ApiKeyModal =
  | { kind: "create" }
  | { kind: "expire"; key: ApiKey }
  | { kind: "expire-lockout"; key: ApiKey }
  | { kind: "delete"; key: ApiKey }
  | { kind: "delete-lockout"; key: ApiKey }
  | null;

function ApiKeysTab() {
  const { data, isLoading } = useApiKeys();
  const [modal, setModal] = useState<ApiKeyModal>(null);
  const expire = useExpireApiKey();
  const deleteKey = useDeleteApiKey();
  const toast = useToast();

  const keys = data?.apiKeys ?? [];
  const uiPrefix = data?.uiApiKeyPrefix ?? "";

  const doExpire = (key: ApiKey, confirmSelfLockout: boolean) =>
    expire.mutate(
      { prefix: key.prefix, confirmSelfLockout: confirmSelfLockout || undefined },
      {
        onSuccess: () => {
          toast.success(`Expired ${key.prefix}`);
          setModal(null);
        },
        onError: (e) => {
          if (e instanceof ApiError && e.status === 409 && e.code === "self_lockout") {
            setModal({ kind: "expire-lockout", key });
            return;
          }
          toast.error("Expire failed", errorText(e));
        },
      },
    );

  const doDelete = (key: ApiKey, confirmSelfLockout: boolean) =>
    deleteKey.mutate(
      { prefix: key.prefix, confirmSelfLockout: confirmSelfLockout || undefined },
      {
        onSuccess: () => {
          toast.success(`Deleted ${key.prefix}`);
          setModal(null);
        },
        onError: (e) => {
          if (e instanceof ApiError && e.status === 409 && e.code === "self_lockout") {
            setModal({ kind: "delete-lockout", key });
            return;
          }
          toast.error("Delete failed", errorText(e));
        },
      },
    );

  return (
    <>
      <div className="mb-4 flex justify-end">
        <Button variant="primary" onClick={() => setModal({ kind: "create" })}>
          + Create key
        </Button>
      </div>

      {isLoading ? (
        <p className="text-sm text-slate-500">Loading API keys…</p>
      ) : keys.length === 0 ? (
        <EmptyState title="No API keys">
          <p>
            Unexpected — Head-Control itself authenticates with an API key. Create one for
            automation or rotation.
          </p>
        </EmptyState>
      ) : (
        <Table
          head={
            <>
              <Th>Prefix</Th>
              <Th>Created</Th>
              <Th>Expiration</Th>
              <Th>Last seen</Th>
              <Th className="w-40" />
            </>
          }
        >
          {keys.map((k) => (
            <tr key={k.id} className="hover:bg-slate-50 dark:hover:bg-slate-800/50">
              <Td>
                <span className="flex items-center gap-1.5">
                  <span className="font-mono text-xs">{k.prefix}</span>
                  <CopyButton text={k.prefix} />
                  {k.prefix === uiPrefix && <Badge tone="blue">used by this UI</Badge>}
                </span>
              </Td>
              <Td>
                <span className="text-xs text-slate-500">{relativeTime(k.createdAt)}</span>
              </Td>
              <Td>
                <span className="flex items-center gap-1.5">
                  <span className="text-xs text-slate-500">
                    {k.expiration ? relativeTime(k.expiration) : "never"}
                  </span>
                  {isExpired(k.expiration) && <Badge tone="red">expired</Badge>}
                  {!isExpired(k.expiration) && expiresWithin(k.expiration, 14 * DAY) && (
                    <Badge tone="yellow">expires soon</Badge>
                  )}
                </span>
              </Td>
              <Td>
                <span className="text-xs text-slate-500">{relativeTime(k.lastSeen)}</span>
              </Td>
              <Td>
                <span className="flex justify-end gap-1">
                  <Button variant="ghost" onClick={() => setModal({ kind: "expire", key: k })}>
                    Expire
                  </Button>
                  <Button
                    variant="ghost"
                    className="text-red-600 dark:text-red-400"
                    onClick={() => setModal({ kind: "delete", key: k })}
                  >
                    Delete
                  </Button>
                </span>
              </Td>
            </tr>
          ))}
        </Table>
      )}

      <Card title="Rotate a key" className="mt-6">
        <ol className="list-decimal space-y-3 pl-5 text-sm text-slate-600 dark:text-slate-300">
          <li>
            Create a new key.{" "}
            <Button className="ml-1" onClick={() => setModal({ kind: "create" })}>
              + Create key
            </Button>
          </li>
          <li>
            Update every consumer with the new secret.
            <div className="mt-1.5 rounded-md border border-amber-300 bg-amber-50 px-3 py-2 text-xs text-amber-900 dark:border-amber-700 dark:bg-amber-950/40 dark:text-amber-200">
              Rotating the key this UI uses? Update <Code>HEADSCALE_API_KEY</Code> in the container
              environment and restart Head-Control <strong>before</strong> step 3 — expiring the old
              key first locks the UI out.
            </div>
          </li>
          <li>Expire the old key from the table above.</li>
        </ol>
        <div className="mt-4">
          <CapabilityNotice level="impossible">
            Headscale 0.29 API keys have no scopes — every key has full access. Scoped OAuth
            clients arrive in headscale 0.30.
          </CapabilityNotice>
        </div>
      </Card>

      {modal?.kind === "create" && <CreateApiKeyModal onClose={() => setModal(null)} />}
      {modal?.kind === "expire" && (
        <ConfirmDialog
          title={`Expire ${modal.key.prefix}?`}
          confirmLabel="Expire key"
          busy={expire.isPending}
          cli={`headscale apikeys expire --prefix ${modal.key.prefix}`}
          message={
            <p>
              The key stops authenticating immediately. Any automation still using it will start
              failing.
            </p>
          }
          onCancel={() => setModal(null)}
          onConfirm={() => doExpire(modal.key, false)}
        />
      )}
      {modal?.kind === "expire-lockout" && (
        <ConfirmDialog
          title="Expire the UI's own key?"
          danger
          confirmLabel="Expire anyway"
          typeToConfirm={modal.key.prefix}
          busy={expire.isPending}
          cli={`headscale apikeys expire --prefix ${modal.key.prefix}`}
          message={
            <p>
              This is the key <strong>Head-Control itself</strong> uses to talk to headscale — the
              UI will break until <Code>HEADSCALE_API_KEY</Code> is updated and the container
              restarts.
            </p>
          }
          onCancel={() => setModal(null)}
          onConfirm={() => doExpire(modal.key, true)}
        />
      )}
      {modal?.kind === "delete" && (
        <ConfirmDialog
          title={`Delete ${modal.key.prefix}?`}
          danger
          confirmLabel="Delete key"
          busy={deleteKey.isPending}
          cli={`headscale apikeys delete --prefix ${modal.key.prefix}`}
          message={
            <p>
              The key is removed from headscale permanently and stops authenticating immediately.
            </p>
          }
          onCancel={() => setModal(null)}
          onConfirm={() => doDelete(modal.key, false)}
        />
      )}
      {modal?.kind === "delete-lockout" && (
        <ConfirmDialog
          title="Delete the UI's own key?"
          danger
          confirmLabel="Delete anyway"
          typeToConfirm={modal.key.prefix}
          busy={deleteKey.isPending}
          cli={`headscale apikeys delete --prefix ${modal.key.prefix}`}
          message={
            <p>
              This is the key <strong>Head-Control itself</strong> uses to talk to headscale — the
              UI will break until <Code>HEADSCALE_API_KEY</Code> is updated and the container
              restarts.
            </p>
          }
          onCancel={() => setModal(null)}
          onConfirm={() => doDelete(modal.key, true)}
        />
      )}
    </>
  );
}

function CreateApiKeyModal({ onClose }: { onClose: () => void }) {
  const [preset, setPreset] = useState("90");
  const [customAt, setCustomAt] = useState("");
  const [secret, setSecret] = useState("");
  const create = useCreateApiKey();
  const toast = useToast();

  if (secret) {
    return (
      <SecretModal
        title="API key created"
        secret={secret}
        description="Use for automation or to rotate the key this UI uses (update HEADSCALE_API_KEY and restart the container)."
        onClose={onClose}
      />
    );
  }

  const expiration =
    preset === "custom"
      ? customAt
        ? new Date(customAt).toISOString()
        : undefined
      : new Date(Date.now() + Number(preset) * DAY).toISOString();

  return (
    <Modal title="Create API key" onClose={onClose}>
      <div className="space-y-3">
        <Field label="Expires in">
          <Select value={preset} onChange={(e) => setPreset(e.target.value)} className="w-full">
            <option value="30">30 days</option>
            <option value="90">90 days (headscale default)</option>
            <option value="180">180 days</option>
            <option value="custom">Custom date…</option>
          </Select>
        </Field>
        {preset === "custom" && (
          <Field label="Expiration date">
            <Input
              type="datetime-local"
              value={customAt}
              onChange={(e) => setCustomAt(e.target.value)}
              min={new Date(Date.now() + 60_000).toISOString().slice(0, 16)}
            />
          </Field>
        )}
        <div className="flex justify-end gap-2">
          <Button onClick={onClose}>Cancel</Button>
          <Button
            variant="primary"
            disabled={preset === "custom" && !customAt}
            loading={create.isPending}
            onClick={() =>
              create.mutate(
                { expiration },
                {
                  onSuccess: (res) => {
                    toast.success("API key created");
                    setSecret(res.apiKey);
                  },
                  onError: (e) => toast.error("Key creation failed", errorText(e)),
                },
              )
            }
          >
            Create key
          </Button>
        </div>
        <CliHint
          command={`headscale apikeys create --expiration ${preset === "custom" ? "<duration>" : `${preset}d`}`}
        />
      </div>
    </Modal>
  );
}
