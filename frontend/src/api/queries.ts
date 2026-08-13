// TanStack Query hooks for every backend resource. Polling intervals follow
// the plan: nodes 15s, users/keys/policy 60s, meta 30s; all pause when the
// tab is hidden and refetch on focus (TanStack defaults + refetchInterval).

import {
  useMutation,
  useQuery,
  useQueryClient,
  type UseMutationOptions,
} from "@tanstack/react-query";
import { del, get, post, put } from "./client";
import type {
  ApiKey,
  AuditEntry,
  DnsRecord,
  DnsState,
  Handoff,
  Meta,
  Node,
  Overview,
  PolicySaveResult,
  PolicyState,
  PolicyVersion,
  PreAuthKey,
  User,
} from "./types";

// Note: refetchIntervalInBackground defaults to false in TanStack Query, so
// all polling below pauses automatically while the tab is hidden.

// ---- meta / overview ----

export const useMeta = () =>
  useQuery({
    queryKey: ["meta"],
    queryFn: () => get<Meta>("/api/meta"),
    refetchInterval: 30_000,
    staleTime: 10_000,
  });

export const useOverview = () =>
  useQuery({
    queryKey: ["overview"],
    queryFn: () => get<Overview>("/api/overview"),
    refetchInterval: 30_000,
  });

// ---- nodes ----

export const useNodes = () =>
  useQuery({
    queryKey: ["nodes"],
    queryFn: async () => (await get<{ nodes: Node[] }>("/api/hs/nodes")).nodes,
    refetchInterval: 15_000,
  });

export const useNode = (id: string | undefined) =>
  useQuery({
    queryKey: ["node", id],
    queryFn: async () => (await get<{ node: Node }>(`/api/hs/nodes/${id}`)).node,
    enabled: !!id,
  });

// ---- users ----

export const useUsers = () =>
  useQuery({
    queryKey: ["users"],
    queryFn: async () => (await get<{ users: User[] }>("/api/hs/users")).users,
    refetchInterval: 60_000,
  });

// ---- keys ----

export const usePreAuthKeys = () =>
  useQuery({
    queryKey: ["preauthkeys"],
    queryFn: () =>
      get<{ preAuthKeys: PreAuthKey[]; labels: Record<string, string> }>(
        "/api/hs/preauthkeys",
      ),
    refetchInterval: 60_000,
  });

export const useApiKeys = () =>
  useQuery({
    queryKey: ["apikeys"],
    queryFn: () =>
      get<{ apiKeys: ApiKey[]; uiApiKeyPrefix: string }>("/api/hs/apikeys"),
    refetchInterval: 60_000,
  });

// ---- policy ----

export const usePolicy = (enabled = true) =>
  useQuery({
    queryKey: ["policy"],
    queryFn: () => get<PolicyState>("/api/policy"),
    refetchInterval: 60_000,
    enabled,
  });

export const usePolicyVersions = () =>
  useQuery({
    queryKey: ["policy-versions"],
    queryFn: async () =>
      (await get<{ versions: PolicyVersion[] }>("/api/policy/versions")).versions,
  });

export const getPolicyVersion = async (id: number) =>
  (await get<{ version: PolicyVersion }>(`/api/policy/versions/${id}`)).version;

// ---- dns ----

export const useDns = () =>
  useQuery({
    queryKey: ["dns"],
    queryFn: () => get<DnsState>("/api/dns"),
    refetchInterval: 60_000,
  });

// ---- audit / handoffs ----

export const useAudit = (params: { action?: string; outcome?: string; sinceHours?: number; limit?: number } = {}) =>
  useQuery({
    queryKey: ["audit", params],
    queryFn: async () => {
      const q = new URLSearchParams();
      if (params.action) q.set("action", params.action);
      if (params.outcome) q.set("outcome", params.outcome);
      if (params.sinceHours) q.set("sinceHours", String(params.sinceHours));
      if (params.limit) q.set("limit", String(params.limit));
      const qs = q.toString();
      return (await get<{ entries: AuditEntry[] }>(`/api/audit${qs ? "?" + qs : ""}`)).entries;
    },
  });

export const useHandoffs = () =>
  useQuery({
    queryKey: ["handoffs"],
    queryFn: async () => (await get<{ handoffs: Handoff[] }>("/api/handoffs")).handoffs,
    refetchInterval: 60_000,
  });

// ---- mutations ----

/** Invalidate one or more query keys after a mutation settles. */
function useInvalidating<TData, TVariables>(
  keys: string[][],
  fn: (vars: TVariables) => Promise<TData>,
  options?: Omit<UseMutationOptions<TData, Error, TVariables>, "mutationFn">,
) {
  const qc = useQueryClient();
  return useMutation<TData, Error, TVariables>({
    mutationFn: fn,
    ...options,
    onSettled: (...args) => {
      keys.forEach((k) => qc.invalidateQueries({ queryKey: k }));
      options?.onSettled?.(...args);
    },
  });
}

// Users
export const useCreateUser = () =>
  useInvalidating(
    [["users"], ["overview"]],
    (v: { name: string; displayName?: string; email?: string }) =>
      post<{ user: User }>("/api/hs/users", v),
  );

export const useRenameUser = () =>
  useInvalidating([["users"], ["nodes"]], (v: { id: string; newName: string }) =>
    post<{ user: User }>(`/api/hs/users/${v.id}/rename`, { newName: v.newName }),
  );

export const useDeleteUser = () =>
  useInvalidating([["users"], ["nodes"], ["preauthkeys"], ["overview"]], (v: { id: string }) =>
    del<{ ok: boolean }>(`/api/hs/users/${v.id}`),
  );

// Nodes
export const useRenameNode = () =>
  useInvalidating([["nodes"]], (v: { id: string; newName: string }) =>
    post<{ node: Node }>(`/api/hs/nodes/${v.id}/rename`, { newName: v.newName }),
  );

export const useSetTags = () =>
  useInvalidating([["nodes"]], (v: { id: string; tags: string[] }) =>
    post<{ node: Node }>(`/api/hs/nodes/${v.id}/tags`, { tags: v.tags }),
  );

export const useExpireNode = () =>
  useInvalidating([["nodes"], ["overview"]], (v: { id: string; mode: "now" | "at" | "never"; expiry?: string }) =>
    post<{ node: Node }>(`/api/hs/nodes/${v.id}/expire`, { mode: v.mode, expiry: v.expiry }),
  );

export const useDeleteNode = () =>
  useInvalidating([["nodes"], ["overview"]], (v: { id: string }) =>
    del<{ ok: boolean }>(`/api/hs/nodes/${v.id}`),
  );

export const useSetRoutes = () =>
  useInvalidating(
    [["nodes"], ["overview"]],
    (v: { id: string; approve: string[]; revoke: string[]; expectedApproved: string[] }) =>
      post<{ node: Node }>(`/api/hs/nodes/${v.id}/routes`, {
        approve: v.approve,
        revoke: v.revoke,
        expectedApproved: v.expectedApproved,
      }),
  );

export const useBackfillIps = () =>
  useInvalidating([["nodes"]], (v: { confirmed: boolean }) =>
    post<{ changes: string[]; confirmed: boolean }>(
      `/api/hs/nodes/backfillips?confirmed=${v.confirmed}`,
    ),
  );

export const useDebugCreateNode = () =>
  useInvalidating([["nodes"], ["overview"]], (v: { user: string; key: string; name: string; routes?: string[] }) =>
    post<{ node: Node }>("/api/hs/debug/node", v),
  );

// Registration
export const useRegisterDevice = () =>
  useInvalidating([["nodes"], ["handoffs"], ["overview"]], (v: { user: string; authId: string; legacy?: boolean }) =>
    post<{ node: Node }>("/api/hs/register", v),
  );

export const useAuthDecision = () =>
  useInvalidating([["handoffs"]], (v: { authId: string; kind: "approve" | "reject" }) =>
    post<{ ok: boolean }>(`/api/hs/auth/${v.kind}`, { authId: v.authId }),
  );

// PreAuth keys
export const useCreatePreAuthKey = () =>
  useInvalidating(
    [["preauthkeys"], ["overview"]],
    (v: {
      user: string;
      reusable: boolean;
      ephemeral: boolean;
      expiration?: string;
      aclTags?: string[];
      label?: string;
    }) => post<{ preAuthKey: PreAuthKey }>("/api/hs/preauthkeys", v),
  );

export const useExpirePreAuthKey = () =>
  useInvalidating([["preauthkeys"], ["overview"]], (v: { id: string }) =>
    post<{ ok: boolean }>("/api/hs/preauthkeys/expire", { id: v.id }),
  );

export const useDeletePreAuthKey = () =>
  useInvalidating([["preauthkeys"], ["overview"]], (v: { id: string }) =>
    del<{ ok: boolean }>(`/api/hs/preauthkeys/${v.id}`),
  );

export const useSetKeyLabel = () =>
  useInvalidating([["preauthkeys"]], (v: { id: string; label: string }) =>
    put<{ ok: boolean }>(`/api/keylabels/${v.id}`, { label: v.label }),
  );

// API keys
export const useCreateApiKey = () =>
  useInvalidating([["apikeys"], ["overview"]], (v: { expiration?: string }) =>
    post<{ apiKey: string }>("/api/hs/apikeys", v),
  );

export const useExpireApiKey = () =>
  useInvalidating([["apikeys"], ["overview"]], (v: { prefix?: string; id?: string; confirmSelfLockout?: boolean }) =>
    post<{ ok: boolean }>("/api/hs/apikeys/expire", v),
  );

export const useDeleteApiKey = () =>
  useInvalidating([["apikeys"], ["overview"]], (v: { prefix: string; confirmSelfLockout?: boolean }) =>
    del<{ ok: boolean }>(
      `/api/hs/apikeys/${encodeURIComponent(v.prefix)}${v.confirmSelfLockout ? "?confirmSelfLockout=true" : ""}`,
    ),
  );

// Policy
export const checkPolicy = (policy: string) =>
  post<{ valid: boolean }>("/api/policy/check", { policy });

export const useSavePolicy = () =>
  useInvalidating([["policy"], ["policy-versions"]], (v: { policy: string; comment?: string }) =>
    put<PolicySaveResult>("/api/policy", v),
  );

// DNS
export const useSaveDnsRecords = () =>
  useInvalidating([["dns"]], (v: { records: DnsRecord[]; expectedHash: string; force?: boolean }) =>
    put<{ records: DnsRecord[]; hash: string }>("/api/dns/records", v),
  );

// Audit
export const usePurgeAudit = () =>
  useInvalidating([["audit"], ["overview"]], () => post<{ ok: boolean }>("/api/audit/purge"));
