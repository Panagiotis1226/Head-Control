// Registrations: complete interactive device logins (headscale auth register)
// and decide pending SSH check / web-auth sessions (headscale auth approve|reject),
// plus the UI-local history of handled auth IDs.

import { useState } from "react";
import { useNavigate } from "react-router-dom";
import { ApiError } from "../api/client";
import {
  useAuthDecision,
  useHandoffs,
  useMeta,
  useRegisterDevice,
  useUsers,
} from "../api/queries";
import type { Handoff } from "../api/types";
import { PageHeader } from "../components/Layout";
import { CapabilityNotice, CliHint, Code, errorText } from "../components/common";
import {
  Badge,
  Button,
  Card,
  EmptyState,
  Field,
  Input,
  Select,
  Table,
  Td,
  Th,
  useToast,
} from "../components/ui";
import { relativeTime, userLabel } from "../lib/format";

function isNotFound(e: unknown): boolean {
  return e instanceof ApiError && e.status === 404;
}

export function RegistrationsPage() {
  const { data: meta } = useMeta();

  return (
    <>
      <PageHeader
        title="Registrations"
        subtitle="Approve interactive device logins and SSH check sessions"
      />

      <div className="mb-4">
        <CapabilityNotice level="impossible">
          Headscale v0.29 has no API to list pending requests — ask the device's user for the code
          shown on their registration page. Pre-auth-key joins never appear here; they bypass
          approval entirely.
        </CapabilityNotice>
      </div>

      <div className="grid gap-4 md:grid-cols-2">
        <RegisterCard publicServerUrl={meta?.publicServerUrl ?? ""} />
        <DecisionCard />
      </div>

      <div className="mt-4">
        <HandoffsCard />
      </div>
    </>
  );
}

// ---- register a device ----

function RegisterCard({ publicServerUrl }: { publicServerUrl: string }) {
  const { data: users } = useUsers();
  const [authId, setAuthId] = useState("");
  const [userName, setUserName] = useState("");
  const register = useRegisterDevice();
  const toast = useToast();
  const navigate = useNavigate();

  const submit = () =>
    register.mutate(
      {
        user: userName,
        authId: authId.trim(),
        // Settings → Advanced can switch to the deprecated legacy endpoint
        // for troubleshooting.
        legacy: localStorage.getItem("hc-legacy-register") === "true" || undefined,
      },
      {
        onSuccess: (res) => {
          toast.success(`Registered ${res.node.givenName ?? res.node.name ?? "device"}`);
          navigate(`/machines/${res.node.id}`);
        },
        onError: (e) => {
          if (isNotFound(e)) {
            toast.error(
              "No pending request with that code",
              "It may have expired; ask the user to re-run tailscale up.",
            );
            return;
          }
          toast.error("Registration failed", errorText(e));
        },
      },
    );

  return (
    <Card title="Register a device">
      <div className="space-y-3">
        <Field label="Registration code or URL">
          <Input
            value={authId}
            onChange={(e) => setAuthId(e.target.value)}
            placeholder="hskey-authreq-… or the full registration URL"
          />
        </Field>
        <Field label="Register to user">
          <Select value={userName} onChange={(e) => setUserName(e.target.value)}>
            <option value="">Select a user…</option>
            {(users ?? []).map((u) => (
              <option key={u.id} value={u.name}>
                {userLabel(u)}
              </option>
            ))}
          </Select>
        </Field>
        <div className="flex justify-end">
          <Button
            variant="primary"
            disabled={!userName || !authId.trim()}
            loading={register.isPending}
            onClick={submit}
          >
            Register
          </Button>
        </div>
        <p className="text-xs text-slate-500 dark:text-slate-400">
          On the device, run{" "}
          <Code>{`tailscale up --login-server ${publicServerUrl || "<your-headscale-url>"}`}</Code>{" "}
          — its registration page shows the code to paste above.
        </p>
        <CliHint
          command={`headscale auth register --user ${userName || "<user>"} --auth-id ${authId.trim() || "<id>"}`}
        />
      </div>
    </Card>
  );
}

// ---- approve / reject a session ----

function DecisionCard() {
  const [authId, setAuthId] = useState("");
  const decision = useAuthDecision();
  const toast = useToast();
  const pendingKind = decision.isPending ? decision.variables?.kind : undefined;

  const act = (kind: "approve" | "reject") =>
    decision.mutate(
      { authId: authId.trim(), kind },
      {
        onSuccess: () => {
          toast.success(kind === "approve" ? "Session approved" : "Session rejected");
          setAuthId("");
        },
        onError: (e) => {
          if (isNotFound(e)) {
            toast.error(
              "No pending request with that code",
              "It may have expired; ask the user to re-run tailscale up.",
            );
            return;
          }
          toast.error(kind === "approve" ? "Approve failed" : "Reject failed", errorText(e));
        },
      },
    );

  return (
    <Card title="Approve / reject a session">
      <div className="space-y-3">
        <p className="text-sm text-slate-600 dark:text-slate-300">
          SSH rules with the <Code>check</Code> action pause until an admin decides. Web-auth
          approvals that don't create a node also land here.
        </p>
        <Field label="Auth ID">
          <Input
            value={authId}
            onChange={(e) => setAuthId(e.target.value)}
            placeholder="hskey-auth-…"
          />
        </Field>
        <div className="flex justify-end gap-2">
          <Button
            variant="danger"
            disabled={!authId.trim() || decision.isPending}
            loading={pendingKind === "reject"}
            onClick={() => act("reject")}
          >
            Reject
          </Button>
          <Button
            variant="primary"
            disabled={!authId.trim() || decision.isPending}
            loading={pendingKind === "approve"}
            onClick={() => act("approve")}
          >
            Approve
          </Button>
        </div>
        <CliHint command={`headscale auth approve --auth-id ${authId.trim() || "<id>"}`} />
      </div>
    </Card>
  );
}

// ---- recent handoffs ----

const KIND_TONE: Record<Handoff["kind"], "blue" | "green" | "red"> = {
  register: "blue",
  approve: "green",
  reject: "red",
};

function HandoffsCard() {
  const { data: handoffs, isLoading } = useHandoffs();

  return (
    <Card title="Recent handoffs">
      {isLoading ? (
        <p className="text-sm text-slate-500">Loading history…</p>
      ) : (handoffs ?? []).length === 0 ? (
        <EmptyState title="No registration activity through this UI yet" />
      ) : (
        <Table
          head={
            <>
              <Th>Time</Th>
              <Th>Kind</Th>
              <Th>Auth ID</Th>
              <Th>User</Th>
              <Th>Status</Th>
            </>
          }
        >
          {(handoffs ?? []).map((h) => (
            <tr key={h.id} className="hover:bg-slate-50 dark:hover:bg-slate-800/50">
              <Td>
                <span className="text-xs text-slate-500">{relativeTime(h.time)}</span>
              </Td>
              <Td>
                <Badge tone={KIND_TONE[h.kind]}>{h.kind}</Badge>
              </Td>
              <Td>
                <span title={h.authId} className="block max-w-[12rem] truncate font-mono text-xs">
                  {h.authId}
                </span>
              </Td>
              <Td>{h.userName || "—"}</Td>
              <Td>
                <Badge tone={h.status === "ok" ? "green" : "red"} title={h.detail}>
                  {h.status}
                </Badge>
              </Td>
            </tr>
          ))}
        </Table>
      )}
      <p className="mt-3 text-xs text-slate-500 dark:text-slate-400">
        This history records only auth IDs handled through Head-Control — headscale keeps no
        queryable registration queue.
      </p>
    </Card>
  );
}
