package aclmodel

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

const fixture = `// Tailnet policy — hand written, keep the comments!
{
  /* who is who */
  "groups": {
    // engineers
    "group:eng": ["alice@", "bob@"],
    "group:ops": ["carol@"],
  },
  "tagOwners": {
    "tag:web": ["group:eng"],
  },
  "hosts": {
    "db1": "10.0.0.5/32",
  },
  "acls": [
    // rule one: eng to web
    {"action": "accept", "src": ["group:eng"], "dst": ["tag:web:443"]},
    // rule two: ops everywhere
    {"action": "accept", "proto": "tcp", "src": ["group:ops"], "dst": ["*:*"]},
    // rule three: db access
    {"action": "accept", "src": ["tag:web"], "dst": ["db1:5432"]},
  ],
  "ssh": [
    {"action": "accept", "src": ["group:ops"], "dst": ["autogroup:member"], "users": ["autogroup:nonroot"]},
  ],
}
`

func mustParse(t *testing.T, raw string) *Document {
	t.Helper()
	d, err := ParseDocument(raw)
	if err != nil {
		t.Fatalf("ParseDocument: %v", err)
	}
	return d
}

func inputFrom(m Model) *Input {
	in := &Input{Groups: m.Groups, TagOwners: m.TagOwners, Hosts: m.Hosts, Rules: []InputRule{}}
	for _, r := range m.ACLs {
		in.Rules = append(in.Rules, InputRule{Action: r.Action, Proto: r.Proto, Src: r.Src, Dst: r.Dst, Enabled: true})
	}
	return in
}

// roundTrip applies the input to the fixture and re-parses the result.
func roundTrip(t *testing.T, raw string, in *Input) (string, *Document) {
	t.Helper()
	d := mustParse(t, raw)
	patch, err := d.Plan(in)
	if err != nil {
		t.Fatal(err)
	}
	out, err := d.Apply(patch)
	if err != nil {
		t.Fatalf("apply: %v\npatch: %s", err, patch.bytes)
	}
	nd, err := ParseDocument(out)
	if err != nil {
		t.Fatalf("re-parse failed: %v\n%s", err, out)
	}
	want := ModelFromInput(d.Model, in)
	if !EqualModels(nd.Model, want) {
		t.Fatalf("patched model differs from requested model\n%s", out)
	}
	return out, nd
}

func TestParseDocument(t *testing.T) {
	d := mustParse(t, fixture)
	if len(d.Model.Groups) != 2 || len(d.Model.ACLs) != 3 || d.Model.Hosts["db1"] != "10.0.0.5/32" {
		t.Fatalf("unexpected model: %+v", d.Model)
	}
	if len(d.Other) != 0 || !d.Model.HasList["ssh"] || len(d.Model.Lists["ssh"]) != 1 {
		t.Fatalf("ssh should be an editable list section: other=%v lists=%v", d.Other, d.Model.Lists)
	}
	if d.Model.ACLs[1].Proto != "tcp" || d.Model.ACLs[0].Proto != "" {
		t.Fatalf("proto decode wrong: %+v", d.Model.ACLs)
	}
	if d.Fresh || d.Formatted {
		t.Fatalf("hand-written fixture should be neither fresh nor formatted")
	}

	for _, raw := range []string{"", "   \n", "// just a comment\n", "/* block */"} {
		d := mustParse(t, raw)
		if !d.Fresh || d.Model.HasACLs || len(d.Other) != 0 {
			t.Fatalf("%q should parse as a fresh empty policy: %+v", raw, d)
		}
	}
	// null sections count as absent.
	d = mustParse(t, `{"acls": null, "groups": {}}`)
	if d.Model.HasACLs || !d.Model.HasGroups {
		t.Fatalf("null handling wrong: %+v", d.Model)
	}
}

func TestParseDocumentUnsupported(t *testing.T) {
	cases := map[string]string{
		`[1,2]`: "",
		`{"acls":[{"action":"accept","src":[1],"dst":["*:*"]}]}`:                 "acls[0]",
		`{"acls":[{"action":"accept","src":["a"],"dst":["*:*"],"comment":"x"}]}`: "acls[0]",
		`{"groups":{"group:x":"alice@"}}`:                                        "groups",
		`{"hosts":{"a":["10.0.0.1"]}}`:                                           "hosts",
		`{"tagOwners":[]}`:                                                       "tagOwners",
		`{"acls": {}}`:                                                           "acls",
		`{ this is not json`:                                                     "",
	}
	for raw, path := range cases {
		_, err := ParseDocument(raw)
		var ue *UnsupportedError
		if !errors.As(err, &ue) {
			t.Fatalf("%s: expected UnsupportedError, got %v", raw, err)
		}
		if ue.Path != path {
			t.Fatalf("%s: path %q, want %q", raw, ue.Path, path)
		}
	}
}

func TestFingerprint(t *testing.T) {
	a := Rule{Action: "accept", Src: []string{"group:eng"}, Dst: []string{"tag:web:443"}}
	same := []Rule{
		{Action: " ACCEPT ", Src: []string{" group:eng"}, Dst: []string{"tag:web:443 "}},
		{Action: "accept", Proto: "", Src: []string{"group:eng"}, Dst: []string{"tag:web:443"}},
	}
	for _, r := range same {
		if Fingerprint(r) != Fingerprint(a) {
			t.Fatalf("expected equal fingerprints for %+v", r)
		}
	}
	different := []Rule{
		{Action: "accept", Proto: "tcp", Src: []string{"group:eng"}, Dst: []string{"tag:web:443"}},
		{Action: "accept", Src: []string{"group:eng", "x@"}, Dst: []string{"tag:web:443"}},
		{Action: "accept", Src: []string{"group:eng"}, Dst: []string{"tag:web:80"}},
	}
	for _, r := range different {
		if Fingerprint(r) == Fingerprint(a) {
			t.Fatalf("expected different fingerprint for %+v", r)
		}
	}
	// Element order matters.
	x := Rule{Action: "accept", Src: []string{"a@", "b@"}, Dst: []string{"*:*"}}
	y := Rule{Action: "accept", Src: []string{"b@", "a@"}, Dst: []string{"*:*"}}
	if Fingerprint(x) == Fingerprint(y) {
		t.Fatal("reordered src must change the fingerprint")
	}
}

func TestPatchNoOp(t *testing.T) {
	d := mustParse(t, fixture)
	_, n, err := BuildPatch(d.Model, inputFrom(d.Model))
	if err != nil || n != 0 {
		t.Fatalf("expected zero ops, got %d (%v)", n, err)
	}
	// Untouched (nil) sections also produce nothing.
	_, n, _ = BuildPatch(d.Model, &Input{})
	if n != 0 {
		t.Fatalf("nil sections should be untouched, got %d ops", n)
	}
}

func TestPatchPreservesComments(t *testing.T) {
	d := mustParse(t, fixture)
	in := inputFrom(d.Model)
	// add a group, edit the middle rule, delete the host, disable nothing.
	in.Groups["group:sec"] = []string{"dave@"}
	in.Rules[1].Dst = []string{"tag:web:22"}
	delete(in.Hosts, "db1")

	out, nd := roundTrip(t, fixture, in)
	for _, c := range []string{
		"// Tailnet policy — hand written, keep the comments!",
		"/* who is who */",
		"// engineers",
		"// rule one: eng to web",
		"// rule three: db access",
		`"ssh"`,
		`"autogroup:nonroot"`,
	} {
		if !strings.Contains(out, c) {
			t.Fatalf("lost %q in output:\n%s", c, out)
		}
	}
	if strings.Contains(out, `"db1": "10.0.0.5/32"`) {
		t.Fatalf("host should be removed:\n%s", out)
	}
	if nd.Model.ACLs[1].Dst[0] != "tag:web:22" || len(nd.Model.Groups) != 3 {
		t.Fatalf("model not updated: %+v", nd.Model)
	}
}

func TestPatchReorderAndDisable(t *testing.T) {
	d := mustParse(t, fixture)
	in := inputFrom(d.Model)
	// reverse the rules and disable the middle one
	in.Rules[0], in.Rules[2] = in.Rules[2], in.Rules[0]
	in.Rules[1].Enabled = false
	out, nd := roundTrip(t, fixture, in)
	if len(nd.Model.ACLs) != 2 || nd.Model.ACLs[0].Dst[0] != "db1:5432" || nd.Model.ACLs[1].Dst[0] != "tag:web:443" {
		t.Fatalf("unexpected rules after reorder: %+v\n%s", nd.Model.ACLs, out)
	}
	if strings.Contains(out, `"group:ops"], "dst": ["*:*"]`) {
		t.Fatalf("disabled rule should be gone:\n%s", out)
	}
	// Emptying acls leaves an empty array (key kept).
	in = inputFrom(d.Model)
	in.Rules = []InputRule{}
	_, nd = roundTrip(t, fixture, in)
	if !nd.Model.HasACLs || len(nd.Model.ACLs) != 0 {
		t.Fatalf("expected empty acls array: %+v", nd.Model)
	}
}

func TestPatchAddsMissingSections(t *testing.T) {
	raw := `{
  // only hosts here
  "hosts": {"router": "10.0.0.1"},
}`
	in := &Input{
		Groups: map[string][]string{"group:eng": {"alice@"}},
		Hosts:  map[string]string{"router": "10.0.0.1"},
		Rules:  []InputRule{{Action: "accept", Src: []string{"group:eng"}, Dst: []string{"router:*"}, Enabled: true}},
	}
	out, nd := roundTrip(t, raw, in)
	if !nd.Model.HasGroups || !nd.Model.HasACLs || nd.Model.HasTagOwners {
		t.Fatalf("sections wrong: %+v\n%s", nd.Model, out)
	}
	if !strings.Contains(out, "// only hosts here") {
		t.Fatalf("comment lost:\n%s", out)
	}
	// Empty new sections are not added at all.
	in = &Input{Groups: map[string][]string{}, Hosts: map[string]string{"router": "10.0.0.1"}}
	d := mustParse(t, raw)
	_, n, _ := BuildPatch(d.Model, in)
	if n != 0 {
		t.Fatalf("empty absent section should not be added, got %d ops", n)
	}
}

func TestPatchFreshDocument(t *testing.T) {
	in := &Input{
		Groups:    map[string][]string{"group:eng": {"alice@"}},
		TagOwners: map[string][]string{"tag:web": {"group:eng"}},
		Hosts:     map[string]string{},
		Rules:     []InputRule{{Action: "accept", Src: []string{"group:eng"}, Dst: []string{"tag:web:443"}, Enabled: true}},
	}
	out, nd := roundTrip(t, "// fresh start\n", in)
	if !strings.Contains(out, "// fresh start") || !strings.Contains(out, "\n") {
		t.Fatalf("fresh document should keep the comment and be formatted:\n%s", out)
	}
	if len(nd.Model.ACLs) != 1 || nd.Model.HasHosts {
		t.Fatalf("model wrong: %+v", nd.Model)
	}
}

func TestPointerEscaping(t *testing.T) {
	raw := `{"hosts": {"a/b": "10.0.0.1", "c~d": "10.0.0.2"}}`
	in := &Input{Hosts: map[string]string{"a/b": "10.0.0.9", "e/f~g": "10.0.0.3"}}
	_, nd := roundTrip(t, raw, in)
	if nd.Model.Hosts["a/b"] != "10.0.0.9" || nd.Model.Hosts["e/f~g"] != "10.0.0.3" || len(nd.Model.Hosts) != 2 {
		t.Fatalf("escaped keys wrong: %+v", nd.Model.Hosts)
	}
}

func TestLCS(t *testing.T) {
	a := []string{"x", "a", "b", "c", "y"}
	b := []string{"a", "z", "b", "c"}
	ka, kb := lcs(a, b)
	got := 0
	for _, k := range ka {
		if k {
			got++
		}
	}
	if got != 3 || !kb[0] || kb[1] || !kb[2] || !kb[3] {
		t.Fatalf("lcs wrong: %v %v", ka, kb)
	}
}

func TestValidate(t *testing.T) {
	ok := &Input{
		Groups:    map[string][]string{"group:eng": {"alice@", "bob@example.com"}},
		TagOwners: map[string][]string{"tag:web": {"group:eng", "carol@"}},
		Hosts:     map[string]string{"db1": "10.0.0.5/32", "v6": "fd7a:115c:a1e0::1"},
		Rules: []InputRule{
			{Action: "accept", Proto: "tcp", Src: []string{"group:eng"}, Dst: []string{"tag:web:443", "db1:22-25", "fd7a:115c:a1e0::2:22", "*:*"}, Enabled: true},
			{Action: "Accept", Proto: "17", Src: []string{"*"}, Dst: []string{"autogroup:internet:*"}, Enabled: false},
		},
	}
	if err := Validate(ok); err != nil {
		t.Fatalf("valid input rejected: %v", err)
	}

	bad := []struct {
		path string
		in   *Input
	}{
		{"groups[eng]", &Input{Groups: map[string][]string{"eng": {"a@"}}}},
		{"groups[group:eng][0]", &Input{Groups: map[string][]string{"group:eng": {"alice"}}}},
		{"tagOwners[web]", &Input{TagOwners: map[string][]string{"web": {"a@"}}}},
		{"tagOwners[tag:web][0]", &Input{TagOwners: map[string][]string{"tag:web": {"tag:other"}}}},
		{"hosts[db 1]", &Input{Hosts: map[string]string{"db 1": "10.0.0.1"}}},
		{"hosts[db1]", &Input{Hosts: map[string]string{"db1": "not-an-ip"}}},
		{"rules[0].action", &Input{Rules: []InputRule{{Action: "deny", Src: []string{"a@"}, Dst: []string{"*:*"}}}}},
		{"rules[0].proto", &Input{Rules: []InputRule{{Action: "accept", Proto: "quic", Src: []string{"a@"}, Dst: []string{"*:*"}}}}},
		{"rules[0].src", &Input{Rules: []InputRule{{Action: "accept", Dst: []string{"*:*"}}}}},
		{"rules[0].dst", &Input{Rules: []InputRule{{Action: "accept", Src: []string{"a@"}}}}},
		{"rules[0].dst[0]", &Input{Rules: []InputRule{{Action: "accept", Src: []string{"a@"}, Dst: []string{"tag:web"}}}}},
		{"rules[0].dst[0]", &Input{Rules: []InputRule{{Action: "accept", Src: []string{"a@"}, Dst: []string{"tag:web:22,*"}}}}},
		{"rules[0].name", &Input{Rules: []InputRule{{Action: "accept", Src: []string{"a@"}, Dst: []string{"*:*"}, Name: strings.Repeat("x", 121)}}}},
	}
	for _, c := range bad {
		err := Validate(c.in)
		var ve *ValidationError
		if !errors.As(err, &ve) {
			t.Fatalf("%s: expected ValidationError, got %v", c.path, err)
		}
		if ve.Path != c.path {
			t.Fatalf("expected path %q, got %q (%s)", c.path, ve.Path, ve.Msg)
		}
	}
}

func TestTidyLayout(t *testing.T) {
	raw := `{
  "groups": {
    "group:eng": ["alice@"],
  },
  "hosts": {},
  "acls": [
    // one
    {"action": "accept", "src": ["group:eng"], "dst": ["tag:web:443"]},
  ],
}
`
	in := &Input{
		Groups:    map[string][]string{"group:eng": {"alice@"}, "group:sec": {"dave@"}},
		TagOwners: map[string][]string{"tag:web": {"group:eng"}},
		Hosts:     map[string]string{"db1": "10.0.0.5"},
		Rules: []InputRule{
			{Action: "accept", Src: []string{"group:eng"}, Dst: []string{"tag:web:443"}, Enabled: true},
			{Action: "accept", Proto: "udp", Src: []string{"group:sec"}, Dst: []string{"*:53"}, Enabled: true},
		},
	}
	out, _ := roundTrip(t, raw, in)
	want := `{
  "groups": {
    "group:eng": ["alice@"],
    "group:sec": ["dave@"],
  },
  "hosts": {
    "db1": "10.0.0.5"
  },
  "acls": [
    // one
    {"action": "accept", "src": ["group:eng"], "dst": ["tag:web:443"]},
    {"action": "accept", "proto": "udp", "src": ["group:sec"], "dst": ["*:53"]},
  ],
  "tagOwners": {
    "tag:web": ["group:eng"]
  }
}
`
	if out != want {
		t.Fatalf("layout mismatch:\n--- got ---\n%s\n--- want ---\n%s", out, want)
	}
}

// Headscale matches top-level keys case-insensitively, so "ACLs" is a valid
// spelling. Patches must address the key as written; adding a lower-case
// twin makes headscale reject the document ("duplicate object member name").
func TestMixedCaseSectionKeys(t *testing.T) {
	raw := `{
  "Groups": {
    "group:eng": ["alice@"],
  },
  "TagOwners": {
    "tag:web": ["group:eng"],
  },
  "ACLs": [
    // keep me
    {"action": "accept", "src": ["group:eng"], "dst": ["tag:web:443"]},
  ],
}
`
	d := mustParse(t, raw)
	if !d.Model.HasACLs || !d.Model.HasGroups || !d.Model.HasTagOwners || len(d.Other) != 0 {
		t.Fatalf("mixed-case sections not recognised: %+v other=%v", d.Model, d.Other)
	}
	if d.KeyName("acls") != "ACLs" || d.KeyName("hosts") != "hosts" {
		t.Fatalf("KeyName wrong: %q %q", d.KeyName("acls"), d.KeyName("hosts"))
	}
	in := inputFrom(d.Model)
	in.Rules = append(in.Rules, InputRule{Action: "accept", Src: []string{"alice@"}, Dst: []string{"tag:web:22"}, Enabled: true})
	in.Groups["group:ops"] = []string{"bob@"}
	in.Hosts = map[string]string{"db1": "10.0.0.5"}
	out, nd := roundTrip(t, raw, in)
	if strings.Contains(out, `"acls"`) || strings.Count(out, `"ACLs"`) != 1 || strings.Count(out, `"Groups"`) != 1 {
		t.Fatalf("expected the original key spelling only:\n%s", out)
	}
	if !strings.Contains(out, "// keep me") || !strings.Contains(out, `"hosts"`) || len(nd.Model.ACLs) != 2 {
		t.Fatalf("round trip wrong:\n%s", out)
	}

	_, err := ParseDocument(`{"acls": [], "ACLs": []}`)
	var ue *UnsupportedError
	if !errors.As(err, &ue) || ue.Path != "acls" {
		t.Fatalf("expected duplicate-section error, got %v", err)
	}
}

// ---- all policy sections ----

const fullFixture = `// full policy
{
  "ACLs": [
    {"Action": "accept", "src": ["*"], "dst": ["*:*"]},
  ],
  "nodeAttrs": [
    // taildrive everywhere
    { "target": ["*"], "attr": ["drive:share", "drive:access"] },
  ],
  "grants": [
    {
      "src": ["*"],
      "dst": ["*"],
      "app": {
        "tailscale.com/cap/drive": [{ "shares": ["*"], "access": "rw" }],
      },
    },
  ],
  "ssh": [
    {"action": "check", "checkPeriod": "12h", "src": ["autogroup:member"], "dst": ["autogroup:self"], "users": ["autogroup:nonroot"]},
  ],
  "autoApprovers": {
    "routes": {
      // lab subnet
      "10.0.0.0/24": ["tag:router"],
    },
    "exitNode": ["tag:exit"],
  },
  "tests": [
    {"src": "alice@", "accept": ["tag:web:443"]},
  ],
}
`

func TestParseAllSections(t *testing.T) {
	d := mustParse(t, fullFixture)
	if len(d.Other) != 0 {
		t.Fatalf("every section should be editable, other=%v", d.Other)
	}
	m := d.Model
	if len(m.Lists["nodeAttrs"]) != 1 || len(m.Lists["grants"]) != 1 || len(m.Lists["ssh"]) != 1 || len(m.Lists["tests"]) != 1 || m.HasList["sshTests"] {
		t.Fatalf("lists wrong: %+v", m.Lists)
	}
	if m.Lists["nodeAttrs"][0] != `{"attr":["drive:share","drive:access"],"target":["*"]}` {
		t.Fatalf("canonical form wrong: %s", m.Lists["nodeAttrs"][0])
	}
	if !m.HasAutoApprovers || !m.HasAARoutes || m.AutoApprovers.Routes["10.0.0.0/24"][0] != "tag:router" || m.AutoApprovers.ExitNode[0] != "tag:exit" {
		t.Fatalf("autoApprovers wrong: %+v", m.AutoApprovers)
	}
	if m.RandomizeClientPort != nil {
		t.Fatal("randomizeClientPort should be absent")
	}
}

func fullInput(m Model) *Input {
	in := inputFrom(m)
	raw := func(xs []string) []json.RawMessage {
		out := []json.RawMessage{}
		for _, x := range xs {
			out = append(out, json.RawMessage(x))
		}
		return out
	}
	in.Grants, in.SSH, in.NodeAttrs = raw(m.Lists["grants"]), raw(m.Lists["ssh"]), raw(m.Lists["nodeAttrs"])
	in.Tests, in.SSHTests = raw(m.Lists["tests"]), raw(m.Lists["sshTests"])
	aa := m.AutoApprovers
	routes := map[string][]string{}
	for k, v := range aa.Routes {
		routes[k] = v
	}
	in.AutoApprovers = &AutoApprovers{Routes: routes, ExitNode: append([]string{}, aa.ExitNode...)}
	f := m.RandomizeClientPort != nil && *m.RandomizeClientPort
	in.RandomizeClientPort = &f
	return in
}

func TestAllSectionsNoOp(t *testing.T) {
	d := mustParse(t, fullFixture)
	p, err := d.Plan(fullInput(d.Model))
	if err != nil || p.Ops != 0 {
		t.Fatalf("expected no ops, got %d (%v): %s", p.Ops, err, p.bytes)
	}
	// Key order and whitespace inside a submitted element do not matter.
	in := fullInput(d.Model)
	in.NodeAttrs = []json.RawMessage{json.RawMessage(`{ "target": ["*"], "attr": ["drive:share", "drive:access"] }`)}
	if p, _ := d.Plan(in); p.Ops != 0 {
		t.Fatalf("reordered keys should be identical, got %s", p.bytes)
	}
}

func TestEditAllSections(t *testing.T) {
	d := mustParse(t, fullFixture)
	in := fullInput(d.Model)
	// nodeAttrs: add one; grants: unchanged; ssh: edit; tests: remove all;
	// sshTests: add (section absent); autoApprovers: add a route, change exit;
	// randomizeClientPort: add.
	in.NodeAttrs = append(in.NodeAttrs, json.RawMessage(`{"target":["tag:dns"],"attr":["magicdns-aaaa"]}`))
	in.SSH = []json.RawMessage{json.RawMessage(`{"action":"accept","src":["group:admins"],"dst":["tag:server"],"users":["root"]}`)}
	in.Tests = []json.RawMessage{}
	in.SSHTests = []json.RawMessage{json.RawMessage(`{"src":"alice@","dst":["tag:server"],"accept":["root"]}`)}
	in.AutoApprovers.Routes["192.168.1.0/24"] = []string{"group:admins"}
	in.AutoApprovers.ExitNode = []string{"tag:exit", "tag:exit2"}
	tr := true
	in.RandomizeClientPort = &tr

	out, nd := roundTrip(t, fullFixture, in)
	for _, want := range []string{
		"// full policy", "// taildrive everywhere", "// lab subnet",
		`{"target": ["tag:dns"], "attr": ["magicdns-aaaa"]}`,
		`{"action": "accept", "src": ["group:admins"], "dst": ["tag:server"], "users": ["root"]}`,
		`"192.168.1.0/24": ["group:admins"]`,
		`"exitNode": ["tag:exit", "tag:exit2"]`,
		`"randomizeClientPort": true`,
		`"tailscale.com/cap/drive"`, // grant untouched
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("missing %q in:\n%s", want, out)
		}
	}
	if strings.Contains(out, "12h") || len(nd.Model.Lists["tests"]) != 0 || !nd.Model.HasList["tests"] {
		t.Fatalf("ssh not replaced or tests not emptied:\n%s", out)
	}
	// Inserted lines are indented like their siblings and keep the
	// container's trailing-comma style, including nested routes.
	for _, line := range []string{
		"\n    {\"target\": [\"tag:dns\"], \"attr\": [\"magicdns-aaaa\"]},\n",
		"\n      \"192.168.1.0/24\": [\"group:admins\"],\n",
	} {
		if !strings.Contains(out, line) {
			t.Fatalf("expected line %q in:\n%s", line, out)
		}
	}

	// Turning randomizeClientPort off removes the key.
	in2 := fullInput(nd.Model)
	f := false
	in2.RandomizeClientPort = &f
	out2, _ := roundTrip(t, out, in2)
	if strings.Contains(out2, "randomizeClientPort") {
		t.Fatalf("randomizeClientPort should be removed:\n%s", out2)
	}
}

func TestAutoApproversFromScratch(t *testing.T) {
	raw := `{
  "acls": [],
}
`
	d := mustParse(t, raw)
	in := fullInput(d.Model)
	in.AutoApprovers = &AutoApprovers{Routes: map[string][]string{"10.0.0.0/8": {"tag:router"}}, ExitNode: []string{"tag:exit"}}
	out, nd := roundTrip(t, raw, in)
	want := `  "autoApprovers": {
    "routes": {
      "10.0.0.0/8": ["tag:router"]
    },
    "exitNode": ["tag:exit"]
  }`
	if !strings.Contains(out, want) || !nd.Model.HasAARoutes {
		t.Fatalf("layout wrong:\n%s", out)
	}
	// Adding a route to a document that has only exitNode creates "routes".
	raw2 := `{"autoApprovers": {"exitNode": ["tag:exit"]}}`
	d2 := mustParse(t, raw2)
	in2 := fullInput(d2.Model)
	in2.AutoApprovers.Routes = map[string][]string{"10.1.0.0/16": {"tag:r"}}
	_, nd2 := roundTrip(t, raw2, in2)
	if nd2.Model.AutoApprovers.Routes["10.1.0.0/16"][0] != "tag:r" {
		t.Fatalf("routes not added: %+v", nd2.Model.AutoApprovers)
	}
}

// Since v0.29.4 headscale ignores "#" members anywhere in the policy. The
// editor must load such policies and leave the members untouched.
func TestMetadataMembersPreserved(t *testing.T) {
	raw := `{
  "#owner": "ops team",
  "groups": {
    "#note": "managed by hand",
    "group:eng": ["alice@"],
  },
  "acls": [
    {"#name": "eng to all", "action": "accept", "src": ["group:eng"], "dst": ["*:*"]},
  ],
  "autoApprovers": {"#why": "lab", "exitNode": ["tag:exit"]},
}
`
	d := mustParse(t, raw)
	if len(d.Other) != 0 || len(d.Model.Groups) != 1 || len(d.Model.ACLs) != 1 || d.Model.AutoApprovers.ExitNode[0] != "tag:exit" {
		t.Fatalf("metadata not skipped: other=%v model=%+v", d.Other, d.Model)
	}
	in := fullInput(d.Model)
	in.Groups["group:ops"] = []string{"bob@"}
	in.Rules = append(in.Rules, InputRule{Action: "accept", Src: []string{"group:ops"}, Dst: []string{"*:22"}, Enabled: true})
	in.AutoApprovers.ExitNode = []string{"tag:exit", "tag:exit2"}
	out, _ := roundTrip(t, raw, in)
	for _, want := range []string{`"#owner": "ops team"`, `"#note": "managed by hand"`, `"#name": "eng to all"`, `"#why": "lab"`} {
		if !strings.Contains(out, want) {
			t.Fatalf("lost %s:\n%s", want, out)
		}
	}
}

func TestListSectionValidation(t *testing.T) {
	in := &Input{Grants: []json.RawMessage{json.RawMessage(`["not","an","object"]`)}}
	var ve *ValidationError
	if err := Validate(in); !errors.As(err, &ve) || ve.Path != "grants[0]" {
		t.Fatalf("expected grants[0] error, got %v", err)
	}
	in = &Input{AutoApprovers: &AutoApprovers{Routes: map[string][]string{"10.0.0.1": {"tag:r"}}}}
	if err := Validate(in); !errors.As(err, &ve) || !strings.Contains(ve.Path, "autoApprovers.routes") {
		t.Fatalf("expected route prefix error, got %v", err)
	}
	if _, err := ParseDocument(`{"autoApprovers": {"routes": {}, "Routes": {}}}`); err == nil {
		t.Fatal("duplicate routes key should be unsupported")
	}
}
