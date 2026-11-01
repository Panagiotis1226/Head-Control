import { describe, expect, it } from "vitest";
import type { PolicyModel } from "../../api/types";
import {
  buildOptions,
  canonical,
  getList,
  setField,
  validateCheckPeriod,
  validateGrantIp,
  validateTestTarget,
  diffDraft,
  draftFromModel,
  draftReducer,
  formToRule,
  isIpOrCidr,
  joinDst,
  parsePorts,
  rebaseDraft,
  referencesOf,
  ruleToForm,
  splitDst,
  toSaveBody,
  validateRule,
  validateSelector,
  type SelectorContext,
} from "./model";

const ctx: SelectorContext = {
  users: [{ name: "alice", email: "alice@example.com" }, { name: "bob" }],
  nodeTags: new Map([["tag:web", 2], ["tag:orphan", 1]]),
  groups: { "group:eng": ["alice@"], "group:empty": [] },
  tagOwners: { "tag:web": ["group:eng"], "tag:db": ["alice@"] },
  hosts: { db1: "10.0.0.5/32" },
};

const server: PolicyModel = {
  hash: "h1",
  mode: "database",
  writable: true,
  reloadPending: false,
  groups: { "group:eng": ["alice@"] },
  tagOwners: { "tag:web": ["group:eng"] },
  hosts: { db1: "10.0.0.5/32" },
  rules: [
    { id: "r1", action: "accept", src: ["group:eng"], dst: ["tag:web:443"], name: "Eng to web", description: "", enabled: true },
    { id: "r2", action: "accept", proto: "tcp", src: ["tag:web"], dst: ["db1:5432"], name: "", description: "", enabled: true },
  ],
  grants: [],
  ssh: [],
  nodeAttrs: [],
  tests: [],
  sshTests: [],
  autoApprovers: { routes: {}, exitNode: [] },
  randomizeClientPort: false,
  otherSections: [],
};

describe("splitDst / joinDst", () => {
  it("splits at the last colon", () => {
    expect(splitDst("tag:web:443")).toMatchObject({ selector: "tag:web", ports: "443" });
    expect(splitDst("10.0.0.0/24:22-25")).toMatchObject({ selector: "10.0.0.0/24", ports: "22-25" });
    expect(splitDst("host:*")).toMatchObject({ selector: "host", ports: "*" });
    expect(splitDst("fd7a:115c:a1e0::2:22")).toMatchObject({ selector: "fd7a:115c:a1e0::2", ports: "22" });
    expect(splitDst("fd7a::/64:*")).toMatchObject({ selector: "fd7a::/64", ports: "*" });
  });
  it("reports missing or bad ports", () => {
    expect(splitDst("tag:web").error).toBeDefined();
    expect(splitDst("tag:web:").error).toBeDefined();
    expect(splitDst("tag:web:abc").error).toBeDefined();
  });
  it("round-trips", () => {
    for (const d of ["tag:web:443", "10.0.0.0/24:22-25", "fd7a:115c:a1e0::2:22", "*:*"]) {
      const { selector, ports } = splitDst(d);
      expect(joinDst(selector, ports)).toBe(d);
    }
  });
});

describe("parsePorts", () => {
  it("accepts valid specs and normalizes", () => {
    expect(parsePorts("*")).toEqual({ ok: true, value: "*" });
    expect(parsePorts("22")).toEqual({ ok: true, value: "22" });
    expect(parsePorts("22,80-90")).toEqual({ ok: true, value: "22,80-90" });
    expect(parsePorts(" 22 , 443 ")).toEqual({ ok: true, value: "22,443" });
    expect(parsePorts("80-80")).toEqual({ ok: true, value: "80" });
  });
  it("rejects invalid specs", () => {
    for (const bad of ["", "0", "70000", "90-80", "22,*", "22,,80", "abc", "22-"]) {
      expect(parsePorts(bad).ok, bad).toBe(false);
    }
  });
});

describe("isIpOrCidr", () => {
  it("recognizes v4 and v6 with and without prefix", () => {
    expect(isIpOrCidr("10.0.0.1")).toBe(true);
    expect(isIpOrCidr("10.0.0.0/24")).toBe(true);
    expect(isIpOrCidr("fd7a:115c:a1e0::2")).toBe(true);
    expect(isIpOrCidr("fd7a::/64")).toBe(true);
    expect(isIpOrCidr("::1")).toBe(true);
  });
  it("rejects non-addresses", () => {
    expect(isIpOrCidr("tag:x")).toBe(false);
    expect(isIpOrCidr("10.0.0.0/33")).toBe(false);
    expect(isIpOrCidr("300.1.1.1")).toBe(false);
    expect(isIpOrCidr("fd7a::1::2")).toBe(false);
    expect(isIpOrCidr("db1")).toBe(false);
  });
});

describe("validateSelector", () => {
  it("handles each kind and side", () => {
    expect(validateSelector("*", "src", ctx)?.level).toBe("warn");
    expect(validateSelector("*", "dst", ctx)).toBeNull();
    expect(validateSelector("autogroup:internet", "src", ctx)?.level).toBe("error");
    expect(validateSelector("autogroup:internet", "dst", ctx)).toBeNull();
    expect(validateSelector("autogroup:nonroot", "dst", ctx)?.level).toBe("error");
    expect(validateSelector("group:eng", "src", ctx)).toBeNull();
    expect(validateSelector("group:empty", "src", ctx)?.level).toBe("warn");
    expect(validateSelector("group:missing", "src", ctx)?.level).toBe("error");
    expect(validateSelector("tag:web", "dst", ctx)).toBeNull();
    expect(validateSelector("tag:orphan", "dst", ctx)?.level).toBe("warn");
    expect(validateSelector("alice@", "src", ctx)).toBeNull();
    expect(validateSelector("alice@example.com", "src", ctx)).toBeNull();
    expect(validateSelector("carol@", "src", ctx)?.level).toBe("warn");
    expect(validateSelector("db1", "dst", ctx)).toBeNull();
    expect(validateSelector("10.0.0.0/8", "dst", ctx)).toBeNull();
    expect(validateSelector("nonsense", "dst", ctx)?.level).toBe("error");
    expect(validateSelector("has space", "dst", ctx)?.level).toBe("error");
  });
});

describe("buildOptions", () => {
  it("lists users, groups, tags (flagging undeclared), hosts, side-aware autogroups", () => {
    const src = buildOptions(ctx, "src");
    const dst = buildOptions(ctx, "dst");
    expect(src.map((o) => o.value)).toContain("alice@");
    expect(src.map((o) => o.value)).toContain("alice@example.com");
    expect(src.find((o) => o.value === "tag:orphan")?.warn).toBeDefined();
    expect(src.find((o) => o.value === "tag:db")?.hint).toBe("0 nodes");
    expect(src.map((o) => o.value)).toContain("autogroup:danger-all");
    expect(src.map((o) => o.value)).not.toContain("autogroup:internet");
    expect(dst.map((o) => o.value)).toContain("autogroup:internet");
    expect(dst.map((o) => o.value)).not.toContain("autogroup:danger-all");
    expect(dst.find((o) => o.value === "*")?.warn).toBeUndefined();
  });
});

describe("rule form", () => {
  it("separates shared ports and rebuilds destinations", () => {
    const f = ruleToForm(server.rules[0]);
    expect(f.dst).toEqual(["tag:web"]);
    expect(f.ports).toBe("443");
    f.dst.push("db1");
    expect(formToRule(f).dst).toEqual(["tag:web:443", "db1:443"]);
  });
  it("merges a target listed twice and writes untouched destinations back verbatim", () => {
    const f = ruleToForm({ src: ["a@"], dst: ["tag:web:443", "tag:web:80"], name: "", description: "", enabled: true });
    expect(f.dst).toEqual(["tag:web"]);
    expect(f.ports).toBe("443,80");
    f.name = "renamed only";
    expect(formToRule(f).dst).toEqual(["tag:web:443", "tag:web:80"]); // unchanged on disk
    f.ports = "443";
    expect(formToRule(f).dst).toEqual(["tag:web:443"]);
  });
  it("normalizes typed port specs when joining", () => {
    const f = ruleToForm({ src: ["a@"], dst: ["tag:web:443"], name: "", description: "", enabled: true });
    f.ports = " 443, 8443 ";
    expect(formToRule(f).dst).toEqual(["tag:web:443,8443"]);
  });
  it("keeps per-destination ports when mixed", () => {
    const f = ruleToForm({ src: ["a@"], dst: ["tag:web:443", "db1:5432"], name: "", description: "", enabled: true });
    expect(f.ports).toBe("");
    expect(f.dstPorts).toEqual({ "tag:web": "443", db1: "5432" });
    expect(formToRule(f).dst).toEqual(["tag:web:443", "db1:5432"]);
    expect(validateRule(f, ctx).filter((i) => i.level === "error")).toEqual([]);
    f.dst.push("10.0.0.0/8");
    expect(validateRule(f, ctx).some((i) => i.field === "ports" && i.level === "error")).toBe(true);
  });
  it("validates protocol/port combinations", () => {
    const f = ruleToForm({ src: ["group:eng"], dst: ["tag:web:443"], name: "", description: "", enabled: true });
    f.proto = "icmp";
    const issues = validateRule(f, ctx);
    expect(issues.some((i) => i.field === "ports" && i.level === "error")).toBe(true);
    f.ports = "*";
    expect(validateRule(f, ctx).filter((i) => i.level === "error")).toEqual([]);
    expect(validateRule(f, ctx).some((i) => i.field === "proto" && i.level === "warn")).toBe(true);
  });
});

describe("draft reducer and diff", () => {
  it("is clean right after loading", () => {
    const d = draftFromModel(server);
    expect(diffDraft(server, d).count).toBe(0);
  });
  it("tracks adds, toggles, deletes and edits", () => {
    let d = draftFromModel(server);
    d = draftReducer(d, { type: "toggleRule", key: "r1" });
    d = draftReducer(d, { type: "deleteRule", key: "r2" });
    d = draftReducer(d, {
      type: "addRule",
      rule: { action: "accept", src: ["alice@"], dst: ["*:*"], name: "new", description: "", enabled: true },
    });
    const s = diffDraft(server, d);
    expect(s.rules.changed.map((c) => c.before.id)).toEqual(["r1"]);
    expect(s.rules.removed.map((r) => r.id)).toEqual(["r2"]);
    expect(s.rules.added.map((r) => r.name)).toEqual(["new"]);
    expect(s.count).toBe(3);
    const body = toSaveBody(d, " note ");
    expect(body.baseHash).toBe("h1");
    expect(body.comment).toBe("note");
    expect(body.rules).toHaveLength(2);
    expect(body.rules[0].enabled).toBe(false);
    expect("proto" in body.rules[1]).toBe(false);
  });
  it("is order-sensitive on src/dst like the backend fingerprint", () => {
    let d = draftFromModel(server);
    d = draftReducer(d, { type: "updateRule", key: "r1", patch: { src: ["group:eng", "bob@"] } });
    expect(diffDraft(server, d).rules.changed).toHaveLength(1);
  });
  it("renames keys and rewrites references", () => {
    let d = draftFromModel(server);
    d = draftReducer(d, { type: "renameKey", section: "groups", from: "group:eng", to: "group:dev" });
    expect(d.groups["group:dev"]).toEqual(["alice@"]);
    expect(d.rules[0].src).toEqual(["group:dev"]);
    expect(d.tagOwners["tag:web"]).toEqual(["group:dev"]);
    d = draftReducer(d, { type: "renameKey", section: "hosts", from: "db1", to: "db-primary" });
    expect(d.rules[1].dst).toEqual(["db-primary:5432"]);
    const s = diffDraft(server, d);
    expect(s.groups.added).toEqual(["group:dev"]);
    expect(s.groups.removed).toEqual(["group:eng"]);
    expect(s.hosts).toEqual({ added: ["db-primary"], removed: ["db1"], changed: [] });
  });
  it("reports references before a delete", () => {
    const d = draftFromModel(server);
    const refs = referencesOf(d, "group:eng");
    expect(refs.map((r) => r.kind)).toEqual(["rule", "tagOwner"]);
    expect(referencesOf(d, "db1")).toHaveLength(1);
    expect(referencesOf(d, "nothing")).toHaveLength(0);
  });
  it("sets and deletes entries", () => {
    let d = draftFromModel(server);
    d = draftReducer(d, { type: "setEntry", section: "groups", name: "group:ops", members: ["bob@"] });
    d = draftReducer(d, { type: "setHost", name: "gw", cidr: "10.0.0.1" });
    d = draftReducer(d, { type: "deleteKey", section: "tagOwners", name: "tag:web" });
    const s = diffDraft(server, d);
    expect(s.groups.added).toEqual(["group:ops"]);
    expect(s.hosts.added).toEqual(["gw"]);
    expect(s.tagOwners.removed).toEqual(["tag:web"]);
  });
});

describe("rebaseDraft", () => {
  it("keeps the user's changes and adopts server changes", () => {
    let d = draftFromModel(server);
    d = draftReducer(d, { type: "updateRule", key: "r1", patch: { name: "renamed" } });
    d = draftReducer(d, { type: "deleteRule", key: "r2" });
    d = draftReducer(d, { type: "setHost", name: "gw", cidr: "10.0.0.1" });
    d = draftReducer(d, { type: "addRule", rule: { action: "accept", src: ["bob@"], dst: ["gw:*"], name: "", description: "", enabled: true } });
    const summary = diffDraft(server, d);

    const newer: PolicyModel = {
      ...server,
      hash: "h2",
      groups: { ...server.groups, "group:ops": ["bob@"] },
      rules: [
        { ...server.rules[1] }, // r2 still there (user deleted it)
        { id: "r3", action: "accept", src: ["*"], dst: ["*:*"], name: "", description: "", enabled: true },
      ], // r1 vanished on the server
    };
    const r = rebaseDraft(d, newer, summary);
    expect(r.baseHash).toBe("h2");
    expect(r.base).toBe(newer);
    expect(r.groups["group:ops"]).toEqual(["bob@"]); // adopted
    expect(r.hosts.gw).toBe("10.0.0.1"); // kept
    const ids = r.rules.map((x) => x.serverId);
    expect(ids).not.toContain("r2"); // deletion kept
    expect(ids).toContain("r3"); // server addition adopted
    expect(r.rules.filter((x) => !x.serverId).map((x) => x.name).sort()).toEqual(["", "renamed"]); // orphaned edit + new rule
    expect(diffDraft(newer, r).count).toBe(4);
  });
});

// ---- other policy sections ----

const full: PolicyModel = {
  ...server,
  hash: "f1",
  grants: [{ src: ["*"], dst: ["*"], app: { "tailscale.com/cap/drive": [{ shares: ["*"], access: "rw" }] } }],
  nodeAttrs: [{ target: ["group:eng"], attr: ["drive:share"] }],
  ssh: [{ Action: "accept", src: ["group:eng"], dst: ["tag:web"], users: ["root"], "#note": "keep" }],
  tests: [],
  sshTests: [],
  autoApprovers: { routes: { "10.0.0.0/24": ["group:eng"] }, exitNode: ["tag:exit"] },
  randomizeClientPort: false,
};

describe("element helpers", () => {
  it("canonical ignores key order", () => {
    expect(canonical({ b: 1, a: [2, { d: 1, c: 2 }] })).toBe(canonical({ a: [2, { c: 2, d: 1 }], b: 1 }));
  });
  it("setField keeps the document's spelling and unknown members", () => {
    const v = setField(full.ssh[0], "action", "check");
    expect(v).toEqual({ Action: "check", src: ["group:eng"], dst: ["tag:web"], users: ["root"], "#note": "keep" });
    expect(setField(v, "users", [])).not.toHaveProperty("users");
    expect(getList({ Src: "alice@" }, "src")).toEqual(["alice@"]);
  });
});

describe("other sections in the draft", () => {
  it("starts clean and tracks edits per section", () => {
    let d = draftFromModel(full);
    expect(diffDraft(full, d).count).toBe(0);
    d = draftReducer(d, { type: "setExtra", list: "nodeAttrs", value: { target: ["*"], attr: ["magicdns-aaaa"] } });
    d = draftReducer(d, { type: "setExtra", list: "ssh", key: d.extras.ssh[0].key, value: setField(d.extras.ssh[0].value, "users", ["autogroup:nonroot"]) });
    d = draftReducer(d, { type: "deleteExtra", list: "grants", key: d.extras.grants[0].key });
    d = draftReducer(d, { type: "setRoute", prefix: "10.1.0.0/16", owners: ["tag:r"] });
    d = draftReducer(d, { type: "setExitNode", owners: [] });
    d = draftReducer(d, { type: "setRandomize", value: true });
    const s = diffDraft(full, d);
    expect(s.extras.nodeAttrs).toEqual({ added: 1, removed: 0, changed: 0 });
    expect(s.extras.ssh).toEqual({ added: 0, removed: 0, changed: 1 });
    expect(s.extras.grants).toEqual({ added: 0, removed: 1, changed: 0 });
    expect(s.routes.added).toEqual(["10.1.0.0/16"]);
    expect(s.exitNodeChanged && s.randomizeChanged).toBe(true);
    expect(s.count).toBe(6);

    const body = toSaveBody(d);
    expect(body.grants).toEqual([]);
    expect(body.nodeAttrs).toHaveLength(2);
    expect(body.ssh[0]).toMatchObject({ Action: "accept", users: ["autogroup:nonroot"], "#note": "keep" });
    expect(body.autoApprovers).toEqual({ routes: { "10.0.0.0/24": ["group:eng"], "10.1.0.0/16": ["tag:r"] }, exitNode: [] });
    expect(body.randomizeClientPort).toBe(true);
  });

  it("renaming a group rewrites the other sections but not app payloads", () => {
    let d = draftFromModel(full);
    d = draftReducer(d, { type: "renameKey", section: "groups", from: "group:eng", to: "group:dev" });
    expect(d.extras.nodeAttrs[0].value).toEqual({ target: ["group:dev"], attr: ["drive:share"] });
    expect(d.extras.ssh[0].value).toMatchObject({ src: ["group:dev"] });
    expect(d.autoApprovers.routes["10.0.0.0/24"]).toEqual(["group:dev"]);
    expect(d.extras.grants[0].value).toEqual(full.grants[0]);
    expect(referencesOf(draftFromModel(full), "group:eng").filter((r) => r.kind === "policy")).toHaveLength(3);
  });

  it("rebases edits onto a newer server version", () => {
    let d = draftFromModel(full);
    d = draftReducer(d, { type: "setExtra", list: "nodeAttrs", key: d.extras.nodeAttrs[0].key, value: { target: ["group:eng"], attr: ["drive:share", "drive:access"] } });
    d = draftReducer(d, { type: "setExtra", list: "tests", value: { src: "alice@", accept: ["tag:web:443"] } });
    const summary = diffDraft(full, d);
    const newer: PolicyModel = {
      ...full,
      hash: "f2",
      nodeAttrs: [{ target: ["*"], attr: ["magicdns-aaaa"] }, ...full.nodeAttrs], // someone else added one
      grants: [], // and removed the grant
      randomizeClientPort: true,
    };
    const r = rebaseDraft(d, newer, summary);
    expect(r.base).toBe(newer);
    expect(r.extras.nodeAttrs.map((i) => i.value)).toEqual([{ target: ["*"], attr: ["magicdns-aaaa"] }, { target: ["group:eng"], attr: ["drive:share", "drive:access"] }]);
    expect(r.extras.grants).toEqual([]); // untouched section follows the server
    expect(r.extras.tests.map((i) => i.value)).toEqual([{ src: "alice@", accept: ["tag:web:443"] }]);
    expect(r.randomizeClientPort).toBe(true);
    const after = diffDraft(newer, r);
    expect(after.extras.nodeAttrs).toEqual({ added: 0, removed: 0, changed: 1 });
    expect(after.extras.tests.added).toBe(1);
  });
});

describe("section validators", () => {
  it("grant ip entries", () => {
    for (const ok of ["*", "443", "22,80-90", "tcp:443", "udp:53", "icmp:*", "6:443"]) expect(validateGrantIp(ok), ok).toBeNull();
    for (const bad of ["quic:443", "tcp:", "tcp:70000", "a:b:c"]) expect(validateGrantIp(bad)?.level, bad).toBe("error");
  });
  it("ssh check periods", () => {
    for (const ok of ["", "always", "12h", "30m", "1h30m", "168h"]) expect(validateCheckPeriod(ok), ok).toBeNull();
    for (const bad of ["12", "1d", "169h", "soon"]) expect(validateCheckPeriod(bad)?.level, bad).toBe("error");
  });
  it("test targets need a port", () => {
    expect(validateTestTarget("tag:web:443")).toBeNull();
    expect(validateTestTarget("tag:web")?.level).toBe("error");
  });
});
