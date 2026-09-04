// Users: table with avatars, provider badges and machine counts, plus
// create / rename / delete flows with policy-awareness warnings.

import { useState } from "react";
import { useNavigate } from "react-router-dom";
import {
  useCreateUser,
  useDeleteUser,
  useNodes,
  usePolicy,
  usePreAuthKeys,
  useRenameUser,
  useUsers,
} from "../api/queries";
import type { User } from "../api/types";
import { PageHeader } from "../components/Layout";
import {
  CapabilityNotice,
  CliHint,
  ConfirmDialog,
  CopyButton,
  errorText,
} from "../components/common";
import { Badge, Button, EmptyState, Field, Input, Modal, RowMenu, Table, Td, Th, useToast } from "../components/ui";
import { relativeTime, userLabel } from "../lib/format";

// Starts with a letter; letters/digits/hyphens/dots/underscores; at most one
// optional @domain suffix. Length checked separately (≥2).
const USERNAME_RE = /^[a-zA-Z][a-zA-Z0-9-_.]*(@[a-zA-Z0-9-.]+)?$/;

const isValidUsername = (name: string) => name.length >= 2 && USERNAME_RE.test(name);

const isOidcUser = (u: User) => (u.provider ?? "").toLowerCase().includes("oidc");

export function UsersPage() {
  const { data: users, isLoading } = useUsers();
  const { data: nodes } = useNodes();
  const { data: keysData } = usePreAuthKeys();
  const navigate = useNavigate();
  const [modal, setModal] = useState<
    | { kind: "create" }
    | { kind: "rename"; user: User }
    | { kind: "delete"; user: User }
    | null
  >(null);

  const machineCountOf = (u: User) =>
    (nodes ?? []).filter((n) => n.user?.id === u.id).length;
  const keyCountOf = (u: User) =>
    (keysData?.preAuthKeys ?? []).filter((k) => k.user?.id === u.id).length;

  return (
    <>
      <PageHeader
        title="Users"
        subtitle={
          users ? `${users.length} ${users.length === 1 ? "user" : "users"}` : undefined
        }
        actions={
          <Button variant="primary" onClick={() => setModal({ kind: "create" })}>
            + New user
          </Button>
        }
      />

      {isLoading ? (
        <p className="text-sm text-slate-500">Loading users…</p>
      ) : (users ?? []).length === 0 ? (
        <EmptyState title="No users yet">
          <p>
            Machines belong to users. Create your first user, then register devices to it from the
            Machines page.
          </p>
          <div className="mt-3">
            <Button variant="primary" onClick={() => setModal({ kind: "create" })}>
              + New user
            </Button>
          </div>
        </EmptyState>
      ) : (
        <Table
          head={
            <>
              <Th>User</Th>
              <Th>ID</Th>
              <Th>Email</Th>
              <Th>Provider</Th>
              <Th>Machines</Th>
              <Th>Created</Th>
              <Th className="w-10" />
            </>
          }
        >
          {(users ?? []).map((u) => (
            <UserRow
              key={u.id}
              user={u}
              machineCount={machineCountOf(u)}
              onMachines={() => navigate("/machines")}
              onAction={(kind) => setModal({ kind, user: u })}
            />
          ))}
        </Table>
      )}

      <div className="mt-6">
        <CapabilityNotice level="impossible">
          Headscale has no user roles, invites, suspend/restore, approval queue, or SCIM. The
          closest to suspending a user is expiring all their machine keys from the Machines page.
        </CapabilityNotice>
      </div>

      {modal?.kind === "create" && <CreateUserModal onClose={() => setModal(null)} />}
      {modal?.kind === "rename" && (
        <RenameUserModal user={modal.user} onClose={() => setModal(null)} />
      )}
      {modal?.kind === "delete" && (
        <DeleteUserModal
          user={modal.user}
          machineCount={machineCountOf(modal.user)}
          keyCount={keyCountOf(modal.user)}
          onClose={() => setModal(null)}
        />
      )}
    </>
  );
}

// ---- row + avatar ----

function Avatar({ user }: { user: User }) {
  const [broken, setBroken] = useState(false);
  const label = userLabel(user);
  const initials =
    label
      .split(/[\s@._-]+/)
      .filter(Boolean)
      .slice(0, 2)
      .map((part) => part.charAt(0).toUpperCase())
      .join("") || "?";
  if (user.profilePicUrl && !broken) {
    return (
      <img
        src={user.profilePicUrl}
        alt=""
        onError={() => setBroken(true)}
        className="h-8 w-8 shrink-0 rounded-full border border-slate-200 object-cover dark:border-slate-700"
      />
    );
  }
  return (
    <span className="flex h-8 w-8 shrink-0 items-center justify-center rounded-full bg-indigo-100 text-xs font-semibold text-indigo-700 dark:bg-indigo-950/60 dark:text-indigo-300">
      {initials}
    </span>
  );
}

function UserRow({
  user: u,
  machineCount,
  onMachines,
  onAction,
}: {
  user: User;
  machineCount: number;
  onMachines: () => void;
  onAction: (kind: "rename" | "delete") => void;
}) {
  return (
    <tr className="hover:bg-slate-50 dark:hover:bg-slate-800/50">
      <Td>
        <span className="flex items-center gap-2.5">
          <Avatar user={u} />
          <span>
            <span className="flex items-center gap-1.5">
              <span className="font-medium text-slate-900 dark:text-slate-100">
                {userLabel(u)}
              </span>
              {!u.name && <Badge tone="yellow">unnamed (OIDC)</Badge>}
            </span>
            {u.displayName && u.displayName !== u.name && (
              <span className="block text-xs text-slate-400">{u.displayName}</span>
            )}
          </span>
        </span>
      </Td>
      <Td>
        <span className="flex items-center gap-1 font-mono text-xs text-slate-400">
          {u.id}
          <CopyButton text={u.id} />
        </span>
      </Td>
      <Td>
        {u.email ? (
          <span className="text-xs">{u.email}</span>
        ) : (
          <span className="text-slate-400">—</span>
        )}
      </Td>
      <Td>
        {isOidcUser(u) ? (
          <Badge tone="blue" title={u.providerId}>
            OIDC
          </Badge>
        ) : (
          <Badge tone="gray">Local</Badge>
        )}
      </Td>
      <Td>
        <button
          onClick={onMachines}
          title="View machines"
          className="text-slate-700 hover:underline dark:text-slate-300"
        >
          {machineCount}
        </button>
      </Td>
      <Td>
        <span className="text-xs text-slate-500">{relativeTime(u.createdAt)}</span>
      </Td>
      <Td>
        <RowMenu
          items={
            [
              ["rename", "Rename"],
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

function NameValidationError({ name }: { name: string }) {
  if (name.length === 0 || isValidUsername(name)) return null;
  return (
    <p className="text-xs text-red-600">
      Must be at least 2 characters, start with a letter, and contain only letters, digits,
      hyphens, dots or underscores (with at most one optional @domain suffix).
    </p>
  );
}

function CreateUserModal({ onClose }: { onClose: () => void }) {
  const [name, setName] = useState("");
  const [displayName, setDisplayName] = useState("");
  const [email, setEmail] = useState("");
  const create = useCreateUser();
  const toast = useToast();
  const valid = isValidUsername(name);

  return (
    <Modal title="New user" onClose={onClose}>
      <div className="space-y-3">
        <Field
          label="Name"
          hint="Policy files reference users as name@ — use a short, stable name"
        >
          <Input
            value={name}
            onChange={(e) => setName(e.target.value)}
            placeholder="alice"
            autoFocus
          />
        </Field>
        <NameValidationError name={name} />
        <Field label="Display name (optional)">
          <Input
            value={displayName}
            onChange={(e) => setDisplayName(e.target.value)}
            placeholder="Alice Example"
          />
        </Field>
        <Field label="Email (optional)">
          <Input
            type="email"
            value={email}
            onChange={(e) => setEmail(e.target.value)}
            placeholder="alice@example.com"
          />
        </Field>
        <p className="text-xs text-slate-500 dark:text-slate-400">
          OIDC users are auto-provisioned on first login — manual creation is for
          CLI/pre-auth-key workflows.
        </p>
        <div className="flex justify-end gap-2">
          <Button onClick={onClose}>Cancel</Button>
          <Button
            variant="primary"
            disabled={!valid}
            loading={create.isPending}
            onClick={() =>
              create.mutate(
                {
                  name,
                  displayName: displayName || undefined,
                  email: email || undefined,
                },
                {
                  onSuccess: () => {
                    toast.success(`Created user ${name}`);
                    onClose();
                  },
                  onError: (e) => toast.error("User creation failed", errorText(e)),
                },
              )
            }
          >
            Create user
          </Button>
        </div>
        <CliHint command={`headscale users create ${name || "<name>"}`} />
      </div>
    </Modal>
  );
}

function RenameUserModal({ user, onClose }: { user: User; onClose: () => void }) {
  const [name, setName] = useState(user.name ?? "");
  const rename = useRenameUser();
  const toast = useToast();
  const { data: policy } = usePolicy();
  const valid = isValidUsername(name);
  const policyReferencesUser =
    !!user.name && !!policy?.policy && policy.policy.includes(`${user.name}@`);

  return (
    <Modal title={`Rename ${userLabel(user)}`} onClose={onClose}>
      <div className="space-y-3">
        <Field
          label="New name"
          hint="Policy files reference users as name@ — use a short, stable name"
        >
          <Input value={name} onChange={(e) => setName(e.target.value)} autoFocus />
        </Field>
        <NameValidationError name={name} />
        {policyReferencesUser && (
          <div className="rounded-md border border-amber-300 bg-amber-50 px-3 py-2 text-xs text-amber-900 dark:border-amber-700 dark:bg-amber-950/40 dark:text-amber-200">
            {`Your ACL policy references "${user.name}@" — update the policy after renaming or rules may break.`}
          </div>
        )}
        {isOidcUser(user) && (
          <p className="text-xs text-slate-500 dark:text-slate-400">
            OIDC identity is keyed by providerId; renaming is cosmetic for login but changes
            policy username references.
          </p>
        )}
        <div className="flex justify-end gap-2">
          <Button onClick={onClose}>Cancel</Button>
          <Button
            variant="primary"
            disabled={!valid || name === user.name}
            loading={rename.isPending}
            onClick={() =>
              rename.mutate(
                { id: user.id, newName: name },
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
        <CliHint
          command={`headscale users rename --identifier ${user.id} ${name || "<new-name>"}`}
        />
      </div>
    </Modal>
  );
}

function DeleteUserModal({
  user,
  machineCount,
  keyCount,
  onClose,
}: {
  user: User;
  machineCount: number;
  keyCount: number;
  onClose: () => void;
}) {
  const deleteUser = useDeleteUser();
  const toast = useToast();
  return (
    <ConfirmDialog
      title={`Delete ${userLabel(user)}?`}
      danger
      typeToConfirm={userLabel(user)}
      confirmLabel="Delete user"
      busy={deleteUser.isPending}
      cli={`headscale users destroy --identifier ${user.id}`}
      message={
        <div className="space-y-2">
          <p>
            Deletes <strong>{machineCount}</strong>{" "}
            {machineCount === 1 ? "machine" : "machines"} and <strong>{keyCount}</strong>{" "}
            {keyCount === 1 ? "pre-auth key" : "pre-auth keys"} owned by this user.
          </p>
          <p>This cannot be undone — the machines must re-register to return.</p>
        </div>
      }
      onCancel={onClose}
      onConfirm={() =>
        deleteUser.mutate(
          { id: user.id },
          {
            onSuccess: () => {
              toast.success(`Deleted ${userLabel(user)}`);
              onClose();
            },
            onError: (e) => toast.error("Delete failed", errorText(e)),
          },
        )
      }
    />
  );
}
