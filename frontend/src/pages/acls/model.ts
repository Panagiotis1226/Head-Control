// Pure logic for the ACLs Beta editor: selector parsing and validation,
// suggestion building, the client-side draft (reducer), the draft-vs-server
// change summary, and the 409 rebase. No React in here so it is unit-testable.

import type { PolicyModel, PolicyModelRule, PolicyModelSave } from "../../api/types";

// ---- selectors ----

export type Side = "src" | "dst";
export type SelectorKind = "user" | "group" | "tag" | "host" | "autogroup" | "wildcard" | "cidr" | "unknown";

export interface SelectorOption {
  value: string;
  kind: SelectorKind;
  hint?: string;
  warn?: string;
}

export interface Issue {
  level: "error" | "warn";
  text: string;
  field?: "src" | "dst" | "ports" | "proto" | "name";
}

export const AUTOGROUPS: Array<{ value: string; sides: Side[]; hint: string }> = [
  { value: "autogroup:member", sides: ["src", "dst"], hint: "all devices owned by a user" },
  { value: "autogroup:tagged", sides: ["src", "dst"], hint: "all tagged devices" },
  { value: "autogroup:self", sides: ["dst"], hint: "the connecting user's own devices" },
  { value: "autogroup:internet", sides: ["dst"], hint: "the internet, via exit nodes" },
  { value: "autogroup:danger-all", sides: ["src"], hint: "ALL IPs, tailnet or not (0.29 replacement for *)" },
];

export const PROTOCOLS: Array<{ value: string; label: string; ports: boolean }> = [
  { value: "", label: "Any", ports: true },
  { value: "tcp", label: "TCP", ports: true },
  { value: "udp", label: "UDP", ports: true },
  { value: "sctp", label: "SCTP", ports: true },
  { value: "icmp", label: "ICMP (IPv4)", ports: false },
  { value: "ipv6-icmp", label: "ICMPv6", ports: false },
  { value: "gre", label: "GRE", ports: false },
  { value: "esp", label: "ESP", ports: false },
  { value: "ah", label: "AH", ports: false },
  { value: "igmp", label: "IGMP", ports: false },
];

export function protoAllowsPorts(proto: string): boolean {
  const p = PROTOCOLS.find((x) => x.value === proto);
  return p ? p.ports : /^\d+$/.test(proto) ? false : true;
}

/** Split "target:ports" at the LAST colon (port specs never contain one, so IPv6 targets are safe). */
export function splitDst(dst: string): { selector: string; ports: string; error?: string } {
  const i = dst.lastIndexOf(":");
  if (i <= 0 || i === dst.length - 1) {
    return { selector: dst, ports: "", error: 'destination needs ":<ports>", e.g. tag:web:443 or 10.0.0.0/24:*' };
  }
  const selector = dst.slice(0, i);
  const ports = dst.slice(i + 1);
  const p = parsePorts(ports);
  return p.ok ? { selector, ports: p.value } : { selector, ports, error: p.error };
}

export function joinDst(selector: string, ports: string): string {
  return `${selector}:${ports}`;
}

/** Validate/normalize a port spec: "*", "22", "22,80-90". */
export function parsePorts(spec: string): { ok: true; value: string } | { ok: false; error: string } {
  const s = spec.trim();
  if (s === "") return { ok: false, error: "ports are required (use * for all)" };
  if (s === "*") return { ok: true, value: "*" };
  const parts = s.split(",").map((p) => p.trim());
  const seen = new Set<string>();
  const out: string[] = [];
  for (const part of parts) {
    if (part === "") return { ok: false, error: "empty entry in port list" };
    if (part === "*") return { ok: false, error: '"*" cannot be combined with port numbers' };
    const m = /^(\d{1,5})(?:-(\d{1,5}))?$/.exec(part);
    if (!m) return { ok: false, error: `"${part}" is not a port or port range` };
    const lo = Number(m[1]);
    const hi = m[2] === undefined ? lo : Number(m[2]);
    if (lo < 1 || lo > 65535 || hi < 1 || hi > 65535) return { ok: false, error: `"${part}" is outside 1-65535` };
    if (hi < lo) return { ok: false, error: `"${part}" has its bounds reversed` };
    const norm = hi === lo ? String(lo) : `${lo}-${hi}`;
    if (seen.has(norm)) return { ok: false, error: `"${part}" is listed twice` };
    seen.add(norm);
    out.push(norm);
  }
  return { ok: true, value: out.join(",") };
}

export function isIpOrCidr(s: string): boolean {
  const slash = s.indexOf("/");
  const addr = slash >= 0 ? s.slice(0, slash) : s;
  const prefix = slash >= 0 ? s.slice(slash + 1) : undefined;
  if (prefix !== undefined && !/^\d{1,3}$/.test(prefix)) return false;
  const v4 = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(addr);
  if (v4) {
    if (v4.slice(1).some((o) => Number(o) > 255)) return false;
    return prefix === undefined || Number(prefix) <= 32;
  }
  if (!/^[0-9a-fA-F:]+$/.test(addr) || !addr.includes(":")) return false;
  const dbl = addr.split("::");
  if (dbl.length > 2) return false;
  const groups = addr.split(":").filter((g) => g !== "");
  if (groups.some((g) => g.length > 4)) return false;
  if (dbl.length === 2 ? groups.length > 7 : groups.length !== 8) return false;
  return prefix === undefined || Number(prefix) <= 128;
}

export function classify(selector: string, hosts: Record<string, string> = {}): SelectorKind {
  if (selector === "*") return "wildcard";
  if (selector.startsWith("autogroup:")) return "autogroup";
  if (selector.startsWith("group:")) return "group";
  if (selector.startsWith("tag:")) return "tag";
  if (selector.includes("@")) return "user";
  if (isIpOrCidr(selector)) return "cidr";
  if (selector in hosts) return "host";
  return "unknown";
}

// ---- suggestions & validation context ----

export interface SelectorContext {
  users: Array<{ name?: string; email?: string; displayName?: string }>;
  nodeTags: Map<string, number>; // tag -> number of nodes carrying it
  groups: Record<string, string[]>;
  tagOwners: Record<string, string[]>;
  hosts: Record<string, string>;
}

export function userSelectors(u: { name?: string; email?: string }): string[] {
  const out: string[] = [];
  if (u.name) out.push(`${u.name}@`);
  if (u.email && !out.includes(u.email)) out.push(u.email);
  return out;
}

export function buildOptions(ctx: SelectorContext, side: Side): SelectorOption[] {
  const out: SelectorOption[] = [];
  for (const u of ctx.users) {
    const sels = userSelectors(u);
    sels.forEach((s, i) =>
      out.push({ value: s, kind: "user", hint: i === 0 ? (u.displayName || u.email || undefined) : "email" }),
    );
  }
  for (const g of Object.keys(ctx.groups).sort()) {
    const n = ctx.groups[g].length;
    out.push({ value: g, kind: "group", hint: `${n} member${n === 1 ? "" : "s"}` });
  }
  const tags = new Set([...Object.keys(ctx.tagOwners), ...ctx.nodeTags.keys()]);
  for (const t of [...tags].sort()) {
    const declared = t in ctx.tagOwners;
    const n = ctx.nodeTags.get(t) ?? 0;
    out.push({
      value: t,
      kind: "tag",
      hint: declared ? `${n} node${n === 1 ? "" : "s"}` : undefined,
      warn: declared ? undefined : `assigned on ${n} node${n === 1 ? "" : "s"} but not declared in Tag owners`,
    });
  }
  for (const h of Object.keys(ctx.hosts).sort()) out.push({ value: h, kind: "host", hint: ctx.hosts[h] });
  for (const a of AUTOGROUPS) if (a.sides.includes(side)) out.push({ value: a.value, kind: "autogroup", hint: a.hint });
  out.push({
    value: "*",
    kind: "wildcard",
    hint: side === "src" ? "every tailnet address" : "every destination",
    warn: side === "src" ? 'Since 0.29 "*" matches only tailnet addresses; use autogroup:danger-all for all IPs' : undefined,
  });
  return out;
}

export function validateSelector(selector: string, side: Side, ctx: SelectorContext): Issue | null {
  const s = selector.trim();
  if (s === "" || /\s/.test(s)) return { level: "error", text: "selectors cannot be empty or contain spaces" };
  switch (classify(s, ctx.hosts)) {
    case "wildcard":
      return side === "src"
        ? { level: "warn", text: 'Since headscale 0.29, "*" as a source matches only tailnet addresses — use autogroup:danger-all to match all IPs.' }
        : null;
    case "autogroup": {
      const a = AUTOGROUPS.find((x) => x.value === s);
      if (!a) return { level: "error", text: `${s} is not a known autogroup (autogroup:nonroot is SSH-only)` };
      if (!a.sides.includes(side)) return { level: "error", text: `${s} can only be used as a ${a.sides[0] === "src" ? "source" : "destination"}` };
      return null;
    }
    case "group":
      if (!(s in ctx.groups)) return { level: "error", text: `${s} is not declared — add it under Groups first` };
      if (ctx.groups[s].length === 0) return { level: "warn", text: `${s} has no members` };
      return null;
    case "tag":
      if (!(s in ctx.tagOwners)) return { level: "warn", text: `${s} is not declared in Tag owners — headscale will reject the policy unless it is` };
      return null;
    case "user": {
      const known = ctx.users.some((u) => userSelectors(u).includes(s));
      return known ? null : { level: "warn", text: `no user matches ${s}` };
    }
    case "cidr":
    case "host":
      return null;
    default:
      return { level: "error", text: `${s} is not a user, group, tag, host, autogroup or IP/CIDR` };
  }
}

// ---- rule form (destinations and ports kept separate) ----

export interface RuleForm {
  name: string;
  description: string;
  enabled: boolean;
  proto: string;
  src: string[];
  dst: string[]; // selectors only
  ports: string; // shared spec, "" when mixed
  dstPorts: Record<string, string>; // per-selector ports parsed from an existing rule
  /** The rule's dst list as loaded, plus the form fields derived from it; emitted verbatim while untouched. */
  original?: { dst: string[]; snapshot: string };
}

export function emptyForm(): RuleForm {
  return { name: "", description: "", enabled: true, proto: "", src: [], dst: [], ports: "*", dstPorts: {} };
}

/** Merge two port specs ("443" + "80" -> "443,80"), dropping duplicates. */
export function mergePorts(a: string, b: string): string {
  if (a === "*" || b === "*") return "*";
  const parts = [...a.split(","), ...b.split(",")].map((x) => x.trim()).filter(Boolean);
  return [...new Set(parts)].join(",");
}

const dstSnapshot = (f: Pick<RuleForm, "dst" | "ports" | "dstPorts">) => JSON.stringify([f.dst, f.ports, f.dstPorts]);

export function ruleToForm(r: { proto?: string; src: string[]; dst: string[]; name: string; description: string; enabled: boolean }): RuleForm {
  const dst: string[] = [];
  const dstPorts: Record<string, string> = {};
  for (const d of r.dst) {
    const { selector, ports } = splitDst(d);
    if (!dst.includes(selector)) dst.push(selector);
    // The same target listed twice with different ports ("tag:web:443", "tag:web:80") becomes one chip.
    dstPorts[selector] = selector in dstPorts ? mergePorts(dstPorts[selector], ports) : ports;
  }
  const specs = new Set(Object.values(dstPorts));
  const fields = { dst, ports: specs.size === 1 ? [...specs][0] : "", dstPorts };
  return {
    name: r.name,
    description: r.description,
    enabled: r.enabled,
    proto: r.proto ?? "",
    src: [...r.src],
    ...fields,
    original: { dst: [...r.dst], snapshot: dstSnapshot(fields) },
  };
}

export function formToRule(f: RuleForm): Omit<DraftRule, "key" | "serverId"> {
  // Normalize port specs ("443, 8443" -> "443,8443"); invalid text passes through so validation can flag it.
  const norm = (spec: string) => {
    const p = parsePorts(spec);
    return p.ok ? p.value : spec.trim();
  };
  const shared = f.ports.trim();
  // Untouched destinations are written back exactly as loaded so a rename never rewrites the policy.
  const dst =
    f.original && f.original.snapshot === dstSnapshot(f)
      ? [...f.original.dst]
      : f.dst.map((sel) => joinDst(sel, norm(shared !== "" ? shared : f.dstPorts[sel] ?? "")));
  return {
    action: "accept",
    proto: f.proto || undefined,
    src: [...f.src],
    dst,
    name: f.name.trim(),
    description: f.description.trim(),
    enabled: f.enabled,
  };
}

export function validateRule(f: RuleForm, ctx: SelectorContext): Issue[] {
  const issues: Issue[] = [];
  if (f.src.length === 0) issues.push({ level: "error", field: "src", text: "at least one source is required" });
  if (f.dst.length === 0) issues.push({ level: "error", field: "dst", text: "at least one destination is required" });
  for (const s of f.src) {
    const i = validateSelector(s, "src", ctx);
    if (i) issues.push({ ...i, field: "src" });
  }
  for (const d of f.dst) {
    const i = validateSelector(d, "dst", ctx);
    if (i) issues.push({ ...i, field: "dst" });
  }
  const shared = f.ports.trim();
  const allowsPorts = protoAllowsPorts(f.proto);
  if (shared !== "") {
    const p = parsePorts(shared);
    if (!p.ok) issues.push({ level: "error", field: "ports", text: p.error });
    else if (!allowsPorts && p.value !== "*") {
      issues.push({ level: "error", field: "ports", text: `${f.proto} has no ports — use *` });
    }
  } else {
    for (const sel of f.dst) {
      const own = f.dstPorts[sel];
      if (own === undefined || own === "") {
        issues.push({ level: "error", field: "ports", text: `ports required for ${sel}` });
      } else {
        const p = parsePorts(own);
        if (!p.ok) issues.push({ level: "error", field: "ports", text: `${sel}: ${p.error}` });
        else if (!allowsPorts && p.value !== "*") issues.push({ level: "error", field: "ports", text: `${f.proto} has no ports — use * for ${sel}` });
      }
    }
  }
  if (f.proto === "icmp") {
    issues.push({ level: "warn", field: "proto", text: '"icmp" matches ICMPv4 only since 0.29 — add a second rule with ipv6-icmp for IPv6.' });
  }
  if (f.name.length > 120) issues.push({ level: "error", field: "name", text: "name is limited to 120 characters" });
  return issues;
}

// ---- draft ----

export interface DraftRule {
  key: string; // client-side identity
  serverId?: string; // fingerprint of the server rule this one edits
  action: "accept";
  proto?: string;
  src: string[];
  dst: string[];
  name: string;
  description: string;
  enabled: boolean;
}

export interface Draft {
  baseHash: string;
  /** The server model this draft was loaded from; the change summary is computed against it. */
  base: PolicyModel | null;
  groups: Record<string, string[]>;
  tagOwners: Record<string, string[]>;
  hosts: Record<string, string>;
  rules: DraftRule[];
}

export type ListSection = "groups" | "tagOwners";
export type KeySection = ListSection | "hosts";

export type DraftAction =
  | { type: "reset"; model: PolicyModel }
  | { type: "rebase"; model: PolicyModel; summary: ChangeSummary }
  | { type: "addRule"; rule: Omit<DraftRule, "key" | "serverId"> }
  | { type: "updateRule"; key: string; patch: Partial<Omit<DraftRule, "key" | "serverId">> }
  | { type: "duplicateRule"; key: string }
  | { type: "deleteRule"; key: string }
  | { type: "toggleRule"; key: string }
  | { type: "setEntry"; section: ListSection; name: string; members: string[] }
  | { type: "setHost"; name: string; cidr: string }
  | { type: "deleteKey"; section: KeySection; name: string }
  | { type: "renameKey"; section: KeySection; from: string; to: string };

export function newKey(): string {
  if (typeof crypto !== "undefined" && "randomUUID" in crypto) return crypto.randomUUID();
  return Math.random().toString(36).slice(2) + Date.now().toString(36);
}

export const emptyDraft: Draft = { baseHash: "", base: null, groups: {}, tagOwners: {}, hosts: {}, rules: [] };

export function draftFromModel(m: PolicyModel): Draft {
  return {
    baseHash: m.hash,
    base: m,
    groups: cloneLists(m.groups),
    tagOwners: cloneLists(m.tagOwners),
    hosts: { ...m.hosts },
    rules: m.rules.map((r) => ({
      key: r.id,
      serverId: r.id,
      action: "accept",
      proto: r.proto || undefined,
      src: [...r.src],
      dst: [...r.dst],
      name: r.name ?? "",
      description: r.description ?? "",
      enabled: r.enabled,
    })),
  };
}

function cloneLists(m: Record<string, string[]>): Record<string, string[]> {
  return Object.fromEntries(Object.entries(m).map(([k, v]) => [k, [...v]]));
}

/** Rewrite one selector inside a rule's src/dst (dst keeps its ports). */
function renameInRule(r: DraftRule, from: string, to: string): DraftRule {
  return {
    ...r,
    src: r.src.map((s) => (s === from ? to : s)),
    dst: r.dst.map((d) => {
      const { selector, ports } = splitDst(d);
      return selector === from ? joinDst(to, ports) : d;
    }),
  };
}

export function draftReducer(d: Draft, a: DraftAction): Draft {
  switch (a.type) {
    case "reset":
      return draftFromModel(a.model);
    case "rebase":
      return rebaseDraft(d, a.model, a.summary);
    case "addRule":
      return { ...d, rules: [...d.rules, { ...a.rule, key: newKey() }] };
    case "updateRule":
      return { ...d, rules: d.rules.map((r) => (r.key === a.key ? { ...r, ...a.patch } : r)) };
    case "duplicateRule": {
      const idx = d.rules.findIndex((r) => r.key === a.key);
      if (idx < 0) return d;
      const src = d.rules[idx];
      const copy: DraftRule = { ...src, key: newKey(), serverId: undefined, name: src.name ? `${src.name} (copy)` : "" };
      return { ...d, rules: [...d.rules.slice(0, idx + 1), copy, ...d.rules.slice(idx + 1)] };
    }
    case "deleteRule":
      return { ...d, rules: d.rules.filter((r) => r.key !== a.key) };
    case "toggleRule":
      return { ...d, rules: d.rules.map((r) => (r.key === a.key ? { ...r, enabled: !r.enabled } : r)) };
    case "setEntry":
      return { ...d, [a.section]: { ...d[a.section], [a.name]: [...a.members] } };
    case "setHost":
      return { ...d, hosts: { ...d.hosts, [a.name]: a.cidr } };
    case "deleteKey": {
      const next = { ...d[a.section] } as Record<string, unknown>;
      delete next[a.name];
      return { ...d, [a.section]: next };
    }
    case "renameKey": {
      if (a.from === a.to || !(a.from in d[a.section])) return d;
      const section = Object.fromEntries(
        Object.entries(d[a.section]).map(([k, v]) => [k === a.from ? a.to : k, v]),
      ) as Record<string, string[]> & Record<string, string>;
      let next: Draft = { ...d, [a.section]: section };
      next = { ...next, rules: next.rules.map((r) => renameInRule(r, a.from, a.to)) };
      if (a.section === "groups") {
        next = {
          ...next,
          tagOwners: Object.fromEntries(
            Object.entries(next.tagOwners).map(([t, owners]) => [t, owners.map((o) => (o === a.from ? a.to : o))]),
          ),
        };
      }
      return next;
    }
  }
}

// ---- change summary ----

export interface KeyChanges {
  added: string[];
  removed: string[];
  changed: string[];
}

export interface ChangeSummary {
  rules: {
    added: DraftRule[];
    removed: PolicyModelRule[];
    changed: Array<{ before: PolicyModelRule; after: DraftRule }>;
  };
  groups: KeyChanges;
  tagOwners: KeyChanges;
  hosts: KeyChanges;
  count: number;
}

function sameList(a: string[], b: string[]): boolean {
  return a.length === b.length && a.every((x, i) => x === b[i]);
}

export function sameRule(before: PolicyModelRule, after: DraftRule): boolean {
  return (
    (before.proto ?? "") === (after.proto ?? "") &&
    sameList(before.src, after.src) &&
    sameList(before.dst, after.dst) &&
    (before.name ?? "") === after.name &&
    (before.description ?? "") === after.description &&
    before.enabled === after.enabled
  );
}

function diffKeys<V>(server: Record<string, V>, draft: Record<string, V>, eq: (a: V, b: V) => boolean): KeyChanges {
  const out: KeyChanges = { added: [], removed: [], changed: [] };
  for (const k of Object.keys(server)) {
    if (!(k in draft)) out.removed.push(k);
    else if (!eq(server[k], draft[k])) out.changed.push(k);
  }
  for (const k of Object.keys(draft)) if (!(k in server)) out.added.push(k);
  return out;
}

export function diffDraft(server: PolicyModel, d: Draft): ChangeSummary {
  const byId = new Map(server.rules.map((r) => [r.id, r]));
  const draftIds = new Set(d.rules.map((r) => r.serverId).filter((x): x is string => !!x));
  const rules: ChangeSummary["rules"] = { added: [], removed: [], changed: [] };
  for (const r of d.rules) {
    if (!r.serverId) rules.added.push(r);
    else {
      const before = byId.get(r.serverId);
      if (!before) rules.added.push(r);
      else if (!sameRule(before, r)) rules.changed.push({ before, after: r });
    }
  }
  for (const r of server.rules) if (!draftIds.has(r.id)) rules.removed.push(r);

  const groups = diffKeys(server.groups, d.groups, sameList);
  const tagOwners = diffKeys(server.tagOwners, d.tagOwners, sameList);
  const hosts = diffKeys(server.hosts, d.hosts, (a, b) => a === b);
  const count =
    rules.added.length + rules.removed.length + rules.changed.length +
    [groups, tagOwners, hosts].reduce((n, k) => n + k.added.length + k.removed.length + k.changed.length, 0);
  return { rules, groups, tagOwners, hosts, count };
}

/** Three-way merge after a 409: keep what the user touched, adopt everything else from the server. */
export function rebaseDraft(d: Draft, server: PolicyModel, summary: ChangeSummary): Draft {
  const fresh = draftFromModel(server);

  const mergeKeys = <V>(section: KeySection, sv: Record<string, V>, dv: Record<string, V>, ch: KeyChanges): Record<string, V> => {
    const out: Record<string, V> = { ...sv };
    for (const k of [...ch.added, ...ch.changed]) if (k in dv) out[k] = dv[k];
    for (const k of ch.removed) delete out[k];
    void section;
    return out;
  };

  const removed = new Set(summary.rules.removed.map((r) => r.id));
  const changed = new Map(summary.rules.changed.map((c) => [c.after.serverId!, c.after]));
  let rules: DraftRule[] = [];
  for (const r of fresh.rules) {
    if (removed.has(r.key)) continue;
    const edited = changed.get(r.key);
    rules.push(edited ? { ...edited, key: r.key, serverId: r.key } : r);
    changed.delete(r.key);
  }
  // Edited rules whose server twin vanished become plain additions.
  for (const orphan of changed.values()) rules.push({ ...orphan, key: newKey(), serverId: undefined });
  rules = [...rules, ...summary.rules.added.map((r) => ({ ...r, serverId: undefined }))];

  return {
    baseHash: server.hash,
    base: server,
    groups: mergeKeys("groups", fresh.groups, d.groups, summary.groups),
    tagOwners: mergeKeys("tagOwners", fresh.tagOwners, d.tagOwners, summary.tagOwners),
    hosts: mergeKeys("hosts", fresh.hosts, d.hosts, summary.hosts),
    rules,
  };
}

// ---- references ----

export interface Reference {
  kind: "rule" | "tagOwner";
  key: string; // rule key or tag name
  label: string;
}

export function ruleLabel(r: { name: string; src: string[]; dst: string[] }, index?: number): string {
  if (r.name) return r.name;
  const short = (xs: string[]) => (xs.length > 2 ? `${xs.slice(0, 2).join(", ")} +${xs.length - 2}` : xs.join(", "));
  const base = `${short(r.src)} → ${short(r.dst.map((d) => splitDst(d).selector))}`;
  return index === undefined ? base : `Rule ${index + 1}: ${base}`;
}

export function referencesOf(d: Draft, selector: string): Reference[] {
  const out: Reference[] = [];
  d.rules.forEach((r, i) => {
    const hit = r.src.includes(selector) || r.dst.some((x) => splitDst(x).selector === selector);
    if (hit) out.push({ kind: "rule", key: r.key, label: ruleLabel(r, i) });
  });
  for (const [tag, owners] of Object.entries(d.tagOwners)) {
    if (owners.includes(selector)) out.push({ kind: "tagOwner", key: tag, label: tag });
  }
  return out;
}

// ---- save body ----

export function toSaveBody(d: Draft, comment?: string): PolicyModelSave {
  return {
    baseHash: d.baseHash,
    comment: comment?.trim() || undefined,
    groups: d.groups,
    tagOwners: d.tagOwners,
    hosts: d.hosts,
    rules: d.rules.map((r) => ({
      action: "accept",
      ...(r.proto ? { proto: r.proto } : {}),
      src: r.src,
      dst: r.dst,
      name: r.name,
      description: r.description,
      enabled: r.enabled,
    })),
  };
}

/** Compact HuJSON preview of one rule (for CLI hints / review). */
export function ruleToHuJson(r: { proto?: string; src: string[]; dst: string[] }): string {
  const q = (xs: string[]) => `[${xs.map((x) => JSON.stringify(x)).join(", ")}]`;
  return `{"action": "accept"${r.proto ? `, "proto": ${JSON.stringify(r.proto)}` : ""}, "src": ${q(r.src)}, "dst": ${q(r.dst)}}`;
}
