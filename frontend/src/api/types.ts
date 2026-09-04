// Types mirroring the Head-Control backend API (which mirrors headscale
// v0.29.3). All uint64 IDs are strings — never parse them to numbers.

export interface User {
  id: string;
  name: string;
  createdAt?: string;
  displayName?: string;
  email?: string;
  providerId?: string;
  provider?: string;
  profilePicUrl?: string;
}

export interface PreAuthKey {
  user?: User;
  id: string;
  key?: string; // full secret ONLY in the create response
  reusable: boolean;
  ephemeral: boolean;
  used: boolean;
  expiration?: string;
  createdAt?: string;
  aclTags?: string[];
}

export type RegisterMethod =
  | "REGISTER_METHOD_UNSPECIFIED"
  | "REGISTER_METHOD_AUTH_KEY"
  | "REGISTER_METHOD_CLI"
  | "REGISTER_METHOD_OIDC";

export interface Node {
  id: string;
  machineKey?: string;
  nodeKey?: string;
  discoKey?: string;
  ipAddresses?: string[];
  name?: string;
  user?: User;
  lastSeen?: string;
  expiry?: string;
  preAuthKey?: PreAuthKey;
  createdAt?: string;
  registerMethod?: RegisterMethod;
  givenName?: string;
  online: boolean;
  approvedRoutes?: string[];
  availableRoutes?: string[];
  subnetRoutes?: string[];
  tags?: string[];
}

export interface ApiKey {
  id: string;
  prefix: string;
  expiration?: string;
  createdAt?: string;
  lastSeen?: string;
}

export interface HeadscaleStatus {
  reachable: boolean;
  apiKeyValid: boolean;
  databaseOk: boolean;
  version?: string;
  supported: boolean;
  supportNote?: string;
  latencyMs: number;
  checkedAt?: string;
  lastError?: string;
}

export interface DockerStatus {
  reachable: boolean;
  containerName?: string;
  error?: string;
}

export interface Meta {
  version: string;
  headscale: HeadscaleStatus;
  headscaleUrl: string;
  publicServerUrl: string;
  basePath: string;
  capabilities: {
    policyFileMounted: boolean;
    extraRecords: boolean;
    extraRecordsWritable: boolean;
    configView: boolean;
    docker: boolean;
  };
  docker?: DockerStatus | null;
  uiApiKeyPrefix: string;
}

export interface Overview {
  nodes: { total: number; online: number; expired: number; expiringSoon: number };
  users: number;
  preAuthKeys: { active: number; expiringSoon: number };
  apiKeys: { total: number; expiringSoon: number; uiKeyExpiring: boolean };
  pendingRouteApprovals: number;
  recentAudit: AuditEntry[] | null;
}

export interface AuditEntry {
  id: number;
  time: string;
  action: string;
  targetType?: string;
  targetId?: string;
  targetName?: string;
  summary?: string;
  outcome: "ok" | "error";
  error?: string;
  cli?: string;
}

export interface PolicyState {
  policy: string;
  updatedAt?: string;
  mode: "unknown" | "database" | "file";
  writable: boolean;
  fileMounted: boolean;
  fileWritable: boolean;
  reloadPending: boolean;
  dockerReload: boolean;
}

export interface PolicySaveResult {
  mode: string;
  updatedAt?: string;
  reloadPending: boolean;
  reloaded: boolean;
  versionId: number;
  warning?: string;
}

export interface PolicyVersion {
  id: number;
  savedAt: string;
  source: "ui" | "external-snapshot";
  mode?: string;
  content?: string;
  hash: string;
  comment?: string;
}

// ---- ACLs Beta structured model ----

export interface PolicyModelRule {
  id: string; // content fingerprint
  action: "accept";
  proto?: string;
  src: string[];
  dst: string[];
  name: string;
  description: string;
  enabled: boolean;
}

export interface PolicyModel {
  hash: string;
  mode: PolicyState["mode"];
  writable: boolean;
  reloadPending: boolean;
  updatedAt?: string;
  groups: Record<string, string[]>;
  tagOwners: Record<string, string[]>;
  hosts: Record<string, string>;
  rules: PolicyModelRule[];
  otherSections: string[];
}

export interface PolicyModelSaveRule {
  action: "accept";
  proto?: string;
  src: string[];
  dst: string[];
  name: string;
  description: string;
  enabled: boolean;
}

export interface PolicyModelSave {
  baseHash: string;
  comment?: string;
  groups: Record<string, string[]>;
  tagOwners: Record<string, string[]>;
  hosts: Record<string, string>;
  rules: PolicyModelSaveRule[];
}

export interface PolicyModelSaveResult extends PolicySaveResult {
  policyChanged: boolean;
}

export interface DnsRecord {
  name: string;
  type: "A" | "AAAA";
  value: string;
}

export interface DnsConfigView {
  magicDns?: boolean;
  baseDomain?: string;
  overrideLocalDns?: boolean;
  nameservers?: { global?: string[]; split?: Record<string, string[]> };
  searchDomains?: string[];
  extraRecords?: DnsRecord[];
  extraRecordsPath?: string;
}

export interface DnsState {
  recordsEnabled: boolean;
  recordsWritable: boolean;
  configMounted: boolean;
  records?: DnsRecord[];
  recordsHash?: string;
  config?: DnsConfigView;
  configError?: string;
}

export interface Handoff {
  id: number;
  time: string;
  authId: string;
  kind: "register" | "approve" | "reject";
  userName?: string;
  status: "ok" | "failed";
  detail?: string;
}

// The backend's error envelope.
export interface ApiErrorBody {
  error: {
    code: string;
    message: string;
    headscaleMessage?: string;
    grpcCode?: number;
  };
  // 409 route conflicts also carry the fresh node:
  node?: Node;
  // DNS conflicts carry the current file state; policy-model conflicts the current model:
  current?: { records: DnsRecord[]; hash: string } | PolicyModel;
}
