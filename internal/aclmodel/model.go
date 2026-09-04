// Package aclmodel is the structured view of a headscale policy document used
// by the ACLs Beta editor. It parses HuJSON (comments, trailing commas) into
// the four sections the editor understands — groups, tagOwners, hosts, acls —
// fingerprints rules so UI-local metadata can be attached to them, validates
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
}

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
var editableSections = []string{"groups", "tagOwners", "hosts", "acls"}

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
	d := &Document{keys: map[string]string{}}
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
		if err := strictUnmarshal(raw, &d.Model.Groups); err != nil {
			return nil, &UnsupportedError{Path: "groups", Msg: `must be an object of "group:name": ["user@", ...]`}
		}
		d.Model.HasGroups = true
	}
	if raw, ok := present(top, d.KeyName("tagOwners")); ok {
		if err := strictUnmarshal(raw, &d.Model.TagOwners); err != nil {
			return nil, &UnsupportedError{Path: "tagOwners", Msg: `must be an object of "tag:name": ["group:x", "user@", ...]`}
		}
		d.Model.HasTagOwners = true
	}
	if raw, ok := present(top, d.KeyName("hosts")); ok {
		if err := strictUnmarshal(raw, &d.Model.Hosts); err != nil {
			return nil, &UnsupportedError{Path: "hosts", Msg: `must be an object of "name": "ip-or-cidr"`}
		}
		d.Model.HasHosts = true
	}
	if raw, ok := present(top, d.KeyName("acls")); ok {
		var items []json.RawMessage
		if err := json.Unmarshal(raw, &items); err != nil {
			return nil, &UnsupportedError{Path: "acls", Msg: "must be an array of rules"}
		}
		d.Model.ACLs = make([]Rule, 0, len(items))
		for i, item := range items {
			var r Rule
			if err := strictUnmarshal(item, &r); err != nil {
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
