// Package aclmodel is the structured view of a headscale policy document used
// by the ACLs Beta editor. It parses HuJSON (comments, trailing commas) into
// the sections the editor understands — groups, tagOwners, hosts and acls as
// typed values; grants, ssh, nodeAttrs, tests and sshTests as opaque JSON
// objects; autoApprovers and randomizeClientPort — fingerprints acls rules
// so UI-local metadata can be attached to them, validates
// editor input, and turns an (old, new) model pair into a minimal RFC 6902
// JSON Patch that is applied on the HuJSON syntax tree. Untouched parts of
// the document, including every comment, survive a save byte-for-byte.
//
// The package is pure: no store, no HTTP, no headscale client.
package aclmodel

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/tailscale/hujson"
)

// Rule is one entry of the legacy "acls" list.
type Rule struct {
	Action string   `json:"action"`
	Proto  string   `json:"proto,omitempty"`
	Src    []string `json:"src"`
	Dst    []string `json:"dst"`
}

// Model is the standardized content of the editable sections. The Has*
// flags distinguish "section absent" from "section present but empty".
type Model struct {
	Groups    map[string][]string
	TagOwners map[string][]string
	Hosts     map[string]string
	ACLs      []Rule

	HasGroups    bool
	HasTagOwners bool
	HasHosts     bool
	HasACLs      bool

	// Lists holds the elements of grants, ssh, nodeAttrs, tests and sshTests
	// as canonical JSON (see Canonical), keyed by section. Their contents are
	// validated by headscale; this package only diffs them.
	Lists   map[string][]string
	HasList map[string]bool

	AutoApprovers    AutoApprovers
	HasAutoApprovers bool
	HasAARoutes      bool
	HasAAExitNode    bool

	// RandomizeClientPort is nil when the key is absent.
	RandomizeClientPort *bool
}

// AutoApprovers is the autoApprovers section: route prefixes and exit nodes
// that are approved automatically for the listed owners.
type AutoApprovers struct {
	Routes   map[string][]string `json:"routes"`
	ExitNode []string            `json:"exitNode"`
}

// ListSections are the sections whose elements are kept as opaque JSON.
var ListSections = []string{"grants", "ssh", "nodeAttrs", "tests", "sshTests"}

// isMetadata reports a "#"-prefixed member name. Since v0.29.4 headscale
// strips such members at every level of the policy (policy editors keep
// their own notes in them), so the editor ignores and preserves them.
func isMetadata(name string) bool { return strings.HasPrefix(name, "#") }

// Document is a parsed policy: the exact syntax tree plus its Model.
type Document struct {
	root hujson.Value
	// Fresh reports that the input had no JSON value (empty or comments
	// only), so the output may be formatted freely.
	Fresh bool
	// Formatted reports that the input was already in hujson's canonical
	// format, so re-formatting after a patch produces no unrelated churn.
	Formatted bool
	Model     Model
	// Other lists top-level keys this editor does not manage, in document
	// order (grants, ssh, autoApprovers, tests, ...).
	Other []string
	// keys maps each editable section to the key name actually used in the
	// document. Headscale matches keys case-insensitively, so "ACLs" is a
	// valid spelling of acls and every patch must address it as written.
	keys map[string]string
	// aaKeys maps "routes"/"exitNode" to their spelling inside autoApprovers.
	aaKeys map[string]string
}

// KeyName returns the document's spelling of an editable section (the
// canonical lower-case name when the section is absent).
func (d *Document) KeyName(section string) string {
	if k, ok := d.keys[section]; ok {
		return k
	}
	return section
}

// UnsupportedError marks a document this editor cannot represent (bad
// HuJSON, non-object root, or a section with an unexpected shape). The raw
// editor can still handle it.
type UnsupportedError struct {
	Path string
	Msg  string
}

func (e *UnsupportedError) Error() string {
	if e.Path == "" {
		return e.Msg
	}
	return e.Path + ": " + e.Msg
}

// Editable sections, in the order they are emitted for new documents.
var editableSections = []string{
	"groups", "tagOwners", "hosts", "acls",
	"grants", "ssh", "nodeAttrs", "autoApprovers", "tests", "sshTests", "randomizeClientPort",
}

// editableSection returns the canonical section a top-level key refers to
// (case-insensitively, like headscale's decoder), or "".
func editableSection(key string) string {
	for _, s := range editableSections {
		if strings.EqualFold(s, key) {
			return s
		}
	}
	return ""
}

// ParseDocument parses a policy document. Empty or comments-only input is a
// fresh, empty policy.
func ParseDocument(raw string) (*Document, error) {
	d := &Document{keys: map[string]string{}, aaKeys: map[string]string{}}
	if strings.TrimSpace(raw) == "" {
		d.root, _ = hujson.Parse([]byte("{}"))
		d.Fresh = true
		d.Formatted = true
	} else {
		v, err := hujson.Parse([]byte(raw))
		if err != nil {
			// Comments only? Append an empty object and see if that parses to
			// an object with no members; the comments become BeforeExtra.
			v2, err2 := hujson.Parse([]byte(raw + "\n{}"))
			if obj, ok := v2.Value.(*hujson.Object); err2 != nil || !ok || len(obj.Members) != 0 {
				return nil, &UnsupportedError{Msg: "policy is not valid HuJSON: " + err.Error()}
			}
			v = v2
			d.Fresh = true
		}
		d.root = v
		if !d.Fresh {
			f := v.Clone()
			f.Format()
			d.Formatted = bytes.Equal(f.Pack(), []byte(raw))
		}
	}

	obj, ok := d.root.Value.(*hujson.Object)
	if !ok {
		return nil, &UnsupportedError{Msg: "policy root must be a JSON object"}
	}

	// Standardize a copy and decode the sections strictly.
	std := d.root.Clone()
	std.Standardize()
	var top map[string]json.RawMessage
	if err := json.Unmarshal(std.Pack(), &top); err != nil {
		return nil, &UnsupportedError{Msg: "policy is not valid JSON after comment stripping: " + err.Error()}
	}

	for _, m := range obj.Members {
		lit, ok := m.Name.Value.(hujson.Literal)
		if !ok {
			return nil, &UnsupportedError{Msg: "object key is not a string"}
		}
		key := lit.String()
		if isMetadata(key) {
			continue
		}
		section := editableSection(key)
		if section == "" {
			d.Other = append(d.Other, key)
			continue
		}
		if prev, dup := d.keys[section]; dup {
			return nil, &UnsupportedError{Path: section, Msg: fmt.Sprintf("appears twice (%q and %q) — headscale rejects duplicate keys", prev, key)}
		}
		d.keys[section] = key
	}
	if d.Other == nil {
		d.Other = []string{}
	}

	if raw, ok := present(top, d.KeyName("groups")); ok {
		m, err := decodeListMap(raw)
		if err != nil {
			return nil, &UnsupportedError{Path: "groups", Msg: `must be an object of "group:name": ["user@", ...]`}
		}
		d.Model.Groups, d.Model.HasGroups = m, true
	}
	if raw, ok := present(top, d.KeyName("tagOwners")); ok {
		m, err := decodeListMap(raw)
		if err != nil {
			return nil, &UnsupportedError{Path: "tagOwners", Msg: `must be an object of "tag:name": ["group:x", "user@", ...]`}
		}
		d.Model.TagOwners, d.Model.HasTagOwners = m, true
	}
	if raw, ok := present(top, d.KeyName("hosts")); ok {
		m, err := decodeStringMap(raw)
		if err != nil {
			return nil, &UnsupportedError{Path: "hosts", Msg: `must be an object of "name": "ip-or-cidr"`}
		}
		d.Model.Hosts, d.Model.HasHosts = m, true
	}
	if raw, ok := present(top, d.KeyName("acls")); ok {
		var items []json.RawMessage
		if err := json.Unmarshal(raw, &items); err != nil {
			return nil, &UnsupportedError{Path: "acls", Msg: "must be an array of rules"}
		}
		d.Model.ACLs = make([]Rule, 0, len(items))
		for i, item := range items {
			var r Rule
			if err := decodeRule(item, &r); err != nil {
				return nil, &UnsupportedError{
					Path: fmt.Sprintf("acls[%d]", i),
					Msg:  `must be an object with only "action", "proto", "src" and "dst" (strings / arrays of strings)`,
				}
			}
			if r.Src == nil {
				r.Src = []string{}
			}
			if r.Dst == nil {
				r.Dst = []string{}
			}
			d.Model.ACLs = append(d.Model.ACLs, r)
		}
		d.Model.HasACLs = true
	}
	d.Model.Lists = map[string][]string{}
	d.Model.HasList = map[string]bool{}
	for _, section := range ListSections {
		d.Model.Lists[section] = []string{}
		raw, ok := present(top, d.KeyName(section))
		if !ok {
			continue
		}
		var items []json.RawMessage
		if err := json.Unmarshal(raw, &items); err != nil {
			return nil, &UnsupportedError{Path: section, Msg: "must be an array of objects"}
		}
		for i, item := range items {
			c, err := Canonical(item)
			if err != nil {
				return nil, &UnsupportedError{Path: fmt.Sprintf("%s[%d]", section, i), Msg: "must be an object"}
			}
			d.Model.Lists[section] = append(d.Model.Lists[section], c)
		}
		d.Model.HasList[section] = true
	}
	if raw, ok := present(top, d.KeyName("autoApprovers")); ok {
		if err := d.decodeAutoApprovers(raw); err != nil {
			return nil, err
		}
	}
	if raw, ok := present(top, d.KeyName("randomizeClientPort")); ok {
		var b bool
		if err := json.Unmarshal(raw, &b); err != nil {
			return nil, &UnsupportedError{Path: "randomizeClientPort", Msg: "must be true or false"}
		}
		d.Model.RandomizeClientPort = &b
	}
	if d.Model.Groups == nil {
		d.Model.Groups = map[string][]string{}
	}
	if d.Model.TagOwners == nil {
		d.Model.TagOwners = map[string][]string{}
	}
	if d.Model.Hosts == nil {
		d.Model.Hosts = map[string]string{}
	}
	if d.Model.ACLs == nil {
		d.Model.ACLs = []Rule{}
	}
	if d.Model.AutoApprovers.Routes == nil {
		d.Model.AutoApprovers.Routes = map[string][]string{}
	}
	if d.Model.AutoApprovers.ExitNode == nil {
		d.Model.AutoApprovers.ExitNode = []string{}
	}
	return d, nil
}

// present reports whether key exists with a non-null value.
func present(top map[string]json.RawMessage, key string) (json.RawMessage, bool) {
	raw, ok := top[key]
	if !ok || bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
		return nil, false
	}
	return raw, true
}

func strictUnmarshal(raw json.RawMessage, v any) error {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return err
	}
	// Reject trailing garbage.
	if dec.More() {
		return fmt.Errorf("unexpected trailing data")
	}
	return nil
}

// decodeListMap decodes {"name": ["a", "b"]}, skipping "#" metadata members.
func decodeListMap(raw json.RawMessage) (map[string][]string, error) {
	var members map[string]json.RawMessage
	if err := json.Unmarshal(raw, &members); err != nil {
		return nil, err
	}
	out := make(map[string][]string, len(members))
	for k, v := range members {
		if isMetadata(k) {
			continue
		}
		var list []string
		if err := strictUnmarshal(v, &list); err != nil || list == nil {
			return nil, fmt.Errorf("%s: not a list of strings", k)
		}
		out[k] = list
	}
	return out, nil
}

// decodeStringMap decodes {"name": "value"}, skipping "#" metadata members.
func decodeStringMap(raw json.RawMessage) (map[string]string, error) {
	var members map[string]json.RawMessage
	if err := json.Unmarshal(raw, &members); err != nil {
		return nil, err
	}
	out := make(map[string]string, len(members))
	for k, v := range members {
		if isMetadata(k) {
			continue
		}
		var str string
		if err := strictUnmarshal(v, &str); err != nil {
			return nil, fmt.Errorf("%s: not a string", k)
		}
		out[k] = str
	}
	return out, nil
}

// decodeRule decodes one acls rule, ignoring "#" metadata members.
func decodeRule(raw json.RawMessage, r *Rule) error {
	var members map[string]json.RawMessage
	if err := json.Unmarshal(raw, &members); err != nil {
		return err
	}
	for k := range members {
		if isMetadata(k) {
			delete(members, k)
		}
	}
	b, err := json.Marshal(members)
	if err != nil {
		return err
	}
	return strictUnmarshal(b, r)
}

// decodeAutoApprovers decodes the autoApprovers section, recording how the
// document spells "routes" and "exitNode" so patches address them as written.
func (d *Document) decodeAutoApprovers(raw json.RawMessage) error {
	var members map[string]json.RawMessage
	if err := json.Unmarshal(raw, &members); err != nil {
		return &UnsupportedError{Path: "autoApprovers", Msg: `must be an object with "routes" and/or "exitNode"`}
	}
	for _, k := range sortedKeys(members) {
		v := members[k]
		switch {
		case isMetadata(k):
		case strings.EqualFold(k, "routes"):
			if _, dup := d.aaKeys["routes"]; dup {
				return &UnsupportedError{Path: "autoApprovers.routes", Msg: "appears twice"}
			}
			d.aaKeys["routes"] = k
			if !bytes.Equal(bytes.TrimSpace(v), []byte("null")) {
				m, err := decodeListMap(v)
				if err != nil {
					return &UnsupportedError{Path: "autoApprovers.routes", Msg: `must be an object of "prefix": ["tag:x", ...]`}
				}
				d.Model.AutoApprovers.Routes = m
				d.Model.HasAARoutes = true
			}
		case strings.EqualFold(k, "exitNode"):
			if _, dup := d.aaKeys["exitNode"]; dup {
				return &UnsupportedError{Path: "autoApprovers.exitNode", Msg: "appears twice"}
			}
			d.aaKeys["exitNode"] = k
			if !bytes.Equal(bytes.TrimSpace(v), []byte("null")) {
				var list []string
				if err := strictUnmarshal(v, &list); err != nil {
					return &UnsupportedError{Path: "autoApprovers.exitNode", Msg: "must be a list of strings"}
				}
				d.Model.AutoApprovers.ExitNode = list
				d.Model.HasAAExitNode = true
			}
		default:
			return &UnsupportedError{Path: "autoApprovers." + k, Msg: "unknown key"}
		}
	}
	d.Model.HasAutoApprovers = true
	return nil
}

// aaKeyName returns the document's spelling of an autoApprovers member.
func (d *Document) aaKeyName(member string) string {
	if k, ok := d.aaKeys[member]; ok {
		return k
	}
	return member
}

// Canonical returns the canonical JSON of one list-section element: an
// object with sorted keys, compact, numbers preserved, HTML not escaped.
// Comments and formatting never affect it; content and array order do.
func Canonical(raw json.RawMessage) (string, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		return "", err
	}
	if dec.More() {
		return "", fmt.Errorf("unexpected trailing data")
	}
	if _, ok := v.(map[string]any); !ok {
		return "", fmt.Errorf("not an object")
	}
	return encodeCompact(v), nil
}

func encodeCompact(v any) string {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	_ = enc.Encode(v) // values come from a successful decode
	return strings.TrimSpace(buf.String())
}

// Raw returns the current document text.
func (d *Document) Raw() string { return string(d.root.Pack()) }

// canonicalRule is the fingerprint input: sorted keys, trimmed values,
// order-preserving arrays. Reordering src/dst is a real document change and
// must not collide.
type canonicalRule struct {
	Action string   `json:"action"`
	Dst    []string `json:"dst"`
	Proto  string   `json:"proto,omitempty"`
	Src    []string `json:"src"`
}

// Normalize returns the rule with trimmed, case-normalized scalar fields.
func Normalize(r Rule) Rule {
	out := Rule{
		Action: strings.ToLower(strings.TrimSpace(r.Action)),
		Proto:  strings.ToLower(strings.TrimSpace(r.Proto)),
		Src:    make([]string, len(r.Src)),
		Dst:    make([]string, len(r.Dst)),
	}
	for i, s := range r.Src {
		out.Src[i] = strings.TrimSpace(s)
	}
	for i, s := range r.Dst {
		out.Dst[i] = strings.TrimSpace(s)
	}
	return out
}

// Fingerprint returns the stable identity of a rule: hex sha256 of its
// canonical JSON. Whitespace, key order, comments and formatting never
// affect it; content and element order do.
func Fingerprint(r Rule) string {
	n := Normalize(r)
	b, _ := json.Marshal(canonicalRule{Action: n.Action, Dst: n.Dst, Proto: n.Proto, Src: n.Src})
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// RuleJSON returns the compact canonical JSON of a rule as written into the
// policy (key order action, proto, src, dst).
func RuleJSON(r Rule) string {
	b, _ := json.Marshal(Normalize(r))
	return string(b)
}
