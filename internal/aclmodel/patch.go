package aclmodel

import (
	"bytes"
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/tailscale/hujson"
)

// op is one RFC 6902 operation. Value is pre-rendered HuJSON so inserted
// text carries the document's spacing style.
type op struct {
	Op    string          `json:"op"`
	Path  string          `json:"path"`
	Value json.RawMessage `json:"value,omitempty"`
}

// Patch is a planned change to a Document.
type Patch struct {
	Ops   int
	bytes []byte
	ops   []op
	// containers whose last element had a trailing comma before patching
	trailing map[string]bool
	// containers that were empty before patching
	wasEmpty map[string]bool
}

// escapePointer escapes one JSON Pointer token (RFC 6901).
func escapePointer(s string) string {
	return strings.ReplaceAll(strings.ReplaceAll(s, "~", "~0"), "/", "~1")
}

func unescapePointer(s string) string {
	return strings.ReplaceAll(strings.ReplaceAll(s, "~1", "/"), "~0", "~")
}

// Plan computes the minimal JSON Patch that turns the document's model into
// the one described by in. Untouched keys and rules emit no operation, so
// their comments survive.
func (d *Document) Plan(in *Input) (*Patch, error) {
	unit := d.indentUnit()
	var ops []op
	old := d.Model

	// Sections are addressed by the key name the document actually uses
	// ("ACLs" is valid for headscale); adding a lower-case twin would make
	// headscale reject the document for duplicate keys.
	if in.Groups != nil {
		ops = append(ops, diffListMap(d.KeyName("groups"), old.HasGroups, old.Groups, in.Groups, unit)...)
	}
	if in.TagOwners != nil {
		ops = append(ops, diffListMap(d.KeyName("tagOwners"), old.HasTagOwners, old.TagOwners, in.TagOwners, unit)...)
	}
	if in.Hosts != nil {
		ops = append(ops, diffStringMap(d.KeyName("hosts"), old.HasHosts, old.Hosts, in.Hosts, unit)...)
	}
	if in.Rules != nil {
		ops = append(ops, diffACLs(d.KeyName("acls"), old.HasACLs, old.ACLs, in.EnabledRules(), unit)...)
	}

	p := &Patch{Ops: len(ops), ops: ops, trailing: map[string]bool{}, wasEmpty: map[string]bool{}}
	if len(ops) == 0 {
		p.bytes = []byte("[]")
		return p, nil
	}
	for _, s := range editableSections {
		k := d.KeyName(s)
		if v := d.root.Find("/" + escapePointer(k)); v != nil {
			last, n := lastChild(v)
			p.wasEmpty[k] = n == 0
			p.trailing[k] = last != nil && last.AfterExtra != nil
		}
	}
	p.bytes = encodePatch(ops)
	return p, nil
}

// encodePatch writes the operations by hand: encoding/json would compact the
// pre-rendered values and lose their spacing.
func encodePatch(ops []op) []byte {
	var sb strings.Builder
	sb.WriteString("[")
	for i, o := range ops {
		if i > 0 {
			sb.WriteString(",\n")
		}
		sb.WriteString(`{"op": ` + quote(o.Op) + `, "path": ` + quote(o.Path))
		if o.Value != nil {
			sb.WriteString(`, "value": `)
			sb.Write(o.Value)
		}
		sb.WriteString("}")
	}
	sb.WriteString("]")
	return []byte(sb.String())
}

// BuildPatch is the Model-only form used by tests and callers that do not
// need layout tidying.
func BuildPatch(old Model, in *Input) ([]byte, int, error) {
	d := &Document{Model: old}
	d.root, _ = hujson.Parse([]byte("{}"))
	p, err := d.Plan(in)
	if err != nil {
		return nil, 0, err
	}
	return p.bytes, p.Ops, nil
}

// Apply applies a planned patch and returns the new document text. Inserted
// nodes are indented like their neighbours; nothing else is reformatted
// unless the document was already in hujson's canonical format.
func (d *Document) Apply(p *Patch) (string, error) {
	if p.Ops == 0 {
		return d.Raw(), nil
	}
	if err := d.root.Patch(p.bytes); err != nil {
		return "", fmt.Errorf("applying policy patch: %w", err)
	}
	if d.Formatted {
		d.root.Format()
	} else {
		d.tidy(p)
	}
	return d.Raw(), nil
}

// ---- diffing ----

func diffListMap(section string, had bool, old, cur map[string][]string, unit string) []op {
	base := "/" + escapePointer(section)
	if !had {
		if len(cur) == 0 {
			return nil
		}
		var sb strings.Builder
		sb.WriteString("{")
		for i, k := range sortedKeys(cur) {
			if i > 0 {
				sb.WriteString(",")
			}
			sb.WriteString("\n" + unit + unit + quote(k) + ": " + renderStrings(cur[k]))
		}
		sb.WriteString("\n" + unit + "}")
		return []op{{Op: "add", Path: base, Value: json.RawMessage(sb.String())}}
	}
	var ops []op
	for _, k := range sortedKeys(old) {
		if _, ok := cur[k]; !ok {
			ops = append(ops, op{Op: "remove", Path: base + "/" + escapePointer(k)})
		}
	}
	for _, k := range sortedKeys(cur) {
		ov, ok := old[k]
		switch {
		case !ok:
			ops = append(ops, op{Op: "add", Path: base + "/" + escapePointer(k), Value: json.RawMessage(renderStrings(cur[k]))})
		case !equalStrings(ov, cur[k]):
			ops = append(ops, op{Op: "replace", Path: base + "/" + escapePointer(k), Value: json.RawMessage(renderStrings(cur[k]))})
		}
	}
	return ops
}

func diffStringMap(section string, had bool, old, cur map[string]string, unit string) []op {
	base := "/" + escapePointer(section)
	if !had {
		if len(cur) == 0 {
			return nil
		}
		var sb strings.Builder
		sb.WriteString("{")
		for i, k := range sortedKeys(cur) {
			if i > 0 {
				sb.WriteString(",")
			}
			sb.WriteString("\n" + unit + unit + quote(k) + ": " + quote(cur[k]))
		}
		sb.WriteString("\n" + unit + "}")
		return []op{{Op: "add", Path: base, Value: json.RawMessage(sb.String())}}
	}
	var ops []op
	for _, k := range sortedKeys(old) {
		if _, ok := cur[k]; !ok {
			ops = append(ops, op{Op: "remove", Path: base + "/" + escapePointer(k)})
		}
	}
	for _, k := range sortedKeys(cur) {
		ov, ok := old[k]
		switch {
		case !ok:
			ops = append(ops, op{Op: "add", Path: base + "/" + escapePointer(k), Value: json.RawMessage(quote(cur[k]))})
		case ov != cur[k]:
			ops = append(ops, op{Op: "replace", Path: base + "/" + escapePointer(k), Value: json.RawMessage(quote(cur[k]))})
		}
	}
	return ops
}

// diffACLs identifies rules by fingerprint and keeps the longest common
// subsequence in place: removes (descending) then adds (ascending) rebuild
// exactly the new list while unchanged rules keep their position and
// comments.
func diffACLs(section string, had bool, old, cur []Rule, unit string) []op {
	base := "/" + escapePointer(section)
	if !had {
		if len(cur) == 0 {
			return nil
		}
		var sb strings.Builder
		sb.WriteString("[")
		for i, r := range cur {
			if i > 0 {
				sb.WriteString(",")
			}
			sb.WriteString("\n" + unit + unit + renderRule(r))
		}
		sb.WriteString("\n" + unit + "]")
		return []op{{Op: "add", Path: base, Value: json.RawMessage(sb.String())}}
	}
	oldFP := make([]string, len(old))
	for i, r := range old {
		oldFP[i] = Fingerprint(r)
	}
	curFP := make([]string, len(cur))
	for i, r := range cur {
		curFP[i] = Fingerprint(r)
	}
	keepOld, keepCur := lcs(oldFP, curFP)

	var ops []op
	for i := len(old) - 1; i >= 0; i-- {
		if !keepOld[i] {
			ops = append(ops, op{Op: "remove", Path: fmt.Sprintf("%s/%d", base, i)})
		}
	}
	for j := range cur {
		if !keepCur[j] {
			ops = append(ops, op{Op: "add", Path: fmt.Sprintf("%s/%d", base, j), Value: json.RawMessage(renderRule(cur[j]))})
		}
	}
	return ops
}

// lcs marks the elements of a and b that belong to one longest common
// subsequence.
func lcs(a, b []string) (keepA, keepB []bool) {
	n, m := len(a), len(b)
	dp := make([][]int, n+1)
	for i := range dp {
		dp[i] = make([]int, m+1)
	}
	for i := n - 1; i >= 0; i-- {
		for j := m - 1; j >= 0; j-- {
			if a[i] == b[j] {
				dp[i][j] = dp[i+1][j+1] + 1
			} else if dp[i+1][j] >= dp[i][j+1] {
				dp[i][j] = dp[i+1][j]
			} else {
				dp[i][j] = dp[i][j+1]
			}
		}
	}
	keepA = make([]bool, n)
	keepB = make([]bool, m)
	i, j := 0, 0
	for i < n && j < m {
		switch {
		case a[i] == b[j]:
			keepA[i], keepB[j] = true, true
			i++
			j++
		case dp[i+1][j] >= dp[i][j+1]:
			i++
		default:
			j++
		}
	}
	return keepA, keepB
}

// ---- rendering (headscale docs style: one rule per line) ----

func quote(s string) string {
	b, _ := json.Marshal(s)
	return string(b)
}

func renderStrings(ss []string) string {
	parts := make([]string, len(ss))
	for i, s := range ss {
		parts[i] = quote(s)
	}
	return "[" + strings.Join(parts, ", ") + "]"
}

func renderRule(r Rule) string {
	r = Normalize(r)
	var sb strings.Builder
	sb.WriteString(`{"action": ` + quote(r.Action))
	if r.Proto != "" {
		sb.WriteString(`, "proto": ` + quote(r.Proto))
	}
	sb.WriteString(`, "src": ` + renderStrings(r.Src))
	sb.WriteString(`, "dst": ` + renderStrings(r.Dst) + "}")
	return sb.String()
}

// ---- layout tidying ----

// indentUnit guesses the document's indentation from its top-level members
// (two spaces when there is nothing to learn from).
func (d *Document) indentUnit() string {
	if obj, ok := d.root.Value.(*hujson.Object); ok {
		for _, m := range obj.Members {
			if ind, ok := indentOf(m.Name.BeforeExtra); ok && ind != "" {
				return ind
			}
		}
	}
	return "  "
}

// indentOf returns the whitespace following the last newline in extra.
func indentOf(extra hujson.Extra) (string, bool) {
	i := bytes.LastIndexByte(extra, '\n')
	if i < 0 {
		return "", false
	}
	tail := extra[i+1:]
	for _, c := range tail {
		if c != ' ' && c != '\t' {
			return "", false
		}
	}
	return string(tail), true
}

func lastChild(v *hujson.Value) (*hujson.Value, int) {
	switch c := v.Value.(type) {
	case *hujson.Object:
		if len(c.Members) == 0 {
			return nil, 0
		}
		return &c.Members[len(c.Members)-1].Value, len(c.Members)
	case *hujson.Array:
		if len(c.Elements) == 0 {
			return nil, 0
		}
		return &c.Elements[len(c.Elements)-1], len(c.Elements)
	}
	return nil, 0
}

// tidy gives every node inserted by the patch a newline + indentation like
// its siblings, restores the container's trailing-comma style, and puts the
// closing bracket of a previously-empty container on its own line.
func (d *Document) tidy(p *Patch) {
	unit := d.indentUnit()
	root, ok := d.root.Value.(*hujson.Object)
	if !ok {
		return
	}
	touched := map[string]bool{}
	for _, o := range p.ops {
		if o.Op == "remove" && !strings.Contains(o.Path[1:], "/") {
			continue
		}
		parts := strings.SplitN(o.Path[1:], "/", 2)
		section := unescapePointer(parts[0]) // actual key name as written in the document
		touched[section] = true
		if len(parts) == 1 {
			// whole-section add: indent the key like other top-level keys
			for i := range root.Members {
				if lit, ok := root.Members[i].Name.Value.(hujson.Literal); ok && lit.String() == section {
					if _, ok := indentOf(root.Members[i].Name.BeforeExtra); !ok {
						root.Members[i].Name.BeforeExtra = hujson.Extra("\n" + unit)
					}
					if len(root.Members[i].Value.BeforeExtra) == 0 {
						root.Members[i].Value.BeforeExtra = hujson.Extra(" ")
					}
				}
			}
			continue
		}
		if o.Op != "add" && o.Op != "replace" {
			continue
		}
		sec := d.root.Find("/" + parts[0])
		if sec == nil {
			continue
		}
		key := unescapePointer(parts[1])
		switch c := sec.Value.(type) {
		case *hujson.Object:
			for i := range c.Members {
				lit, ok := c.Members[i].Name.Value.(hujson.Literal)
				if !ok || lit.String() != key {
					continue
				}
				if _, ok := indentOf(c.Members[i].Name.BeforeExtra); !ok {
					c.Members[i].Name.BeforeExtra = hujson.Extra("\n" + siblingIndent(sec, unit))
				}
				if len(c.Members[i].Value.BeforeExtra) == 0 {
					c.Members[i].Value.BeforeExtra = hujson.Extra(" ")
				}
			}
		case *hujson.Array:
			var idx int
			if _, err := fmt.Sscanf(key, "%d", &idx); err != nil || idx < 0 || idx >= len(c.Elements) {
				continue
			}
			if _, ok := indentOf(c.Elements[idx].BeforeExtra); !ok {
				c.Elements[idx].BeforeExtra = hujson.Extra("\n" + siblingIndent(sec, unit))
			}
		}
	}
	for section := range touched {
		sec := d.root.Find("/" + escapePointer(section))
		if sec == nil {
			continue
		}
		last, n := lastChild(sec)
		if n == 0 {
			continue
		}
		if p.trailing[section] && last.AfterExtra == nil {
			last.AfterExtra = hujson.Extra{}
		}
		if p.wasEmpty[section] {
			// closing bracket on its own line, aligned with the key
			ind := unit
			for i := range root.Members {
				if lit, ok := root.Members[i].Name.Value.(hujson.Literal); ok && lit.String() == section {
					if x, ok := indentOf(root.Members[i].Name.BeforeExtra); ok {
						ind = x
					}
				}
			}
			switch c := sec.Value.(type) {
			case *hujson.Object:
				if _, ok := indentOf(c.AfterExtra); !ok {
					c.AfterExtra = hujson.Extra("\n" + ind)
				}
			case *hujson.Array:
				if _, ok := indentOf(c.AfterExtra); !ok {
					c.AfterExtra = hujson.Extra("\n" + ind)
				}
			}
		}
	}
}

// siblingIndent returns the indentation used by existing children of a
// container (falling back to one unit deeper than the container's key).
func siblingIndent(sec *hujson.Value, unit string) string {
	switch c := sec.Value.(type) {
	case *hujson.Object:
		for _, m := range c.Members {
			if ind, ok := indentOf(m.Name.BeforeExtra); ok {
				return ind
			}
		}
	case *hujson.Array:
		for _, e := range c.Elements {
			if ind, ok := indentOf(e.BeforeExtra); ok {
				return ind
			}
		}
	}
	return unit + unit
}

// ---- helpers ----

func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func nonNil(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// EqualModels reports whether the editable content of two models is the
// same (used to assert a patched document matches the requested model).
func EqualModels(a, b Model) bool {
	if len(a.Groups) != len(b.Groups) || len(a.TagOwners) != len(b.TagOwners) ||
		len(a.Hosts) != len(b.Hosts) || len(a.ACLs) != len(b.ACLs) {
		return false
	}
	for k, v := range a.Groups {
		if w, ok := b.Groups[k]; !ok || !equalStrings(nonNil(v), nonNil(w)) {
			return false
		}
	}
	for k, v := range a.TagOwners {
		if w, ok := b.TagOwners[k]; !ok || !equalStrings(nonNil(v), nonNil(w)) {
			return false
		}
	}
	for k, v := range a.Hosts {
		if w, ok := b.Hosts[k]; !ok || v != w {
			return false
		}
	}
	for i := range a.ACLs {
		if Fingerprint(a.ACLs[i]) != Fingerprint(b.ACLs[i]) {
			return false
		}
	}
	return true
}

// ModelFromInput builds the model an Input describes, given the sections
// the old document had (nil sections in the input are carried over).
func ModelFromInput(old Model, in *Input) Model {
	m := Model{
		Groups: old.Groups, TagOwners: old.TagOwners, Hosts: old.Hosts, ACLs: old.ACLs,
		HasGroups: old.HasGroups, HasTagOwners: old.HasTagOwners, HasHosts: old.HasHosts, HasACLs: old.HasACLs,
	}
	if in.Groups != nil {
		m.Groups = in.Groups
		m.HasGroups = old.HasGroups || len(in.Groups) > 0
	}
	if in.TagOwners != nil {
		m.TagOwners = in.TagOwners
		m.HasTagOwners = old.HasTagOwners || len(in.TagOwners) > 0
	}
	if in.Hosts != nil {
		m.Hosts = in.Hosts
		m.HasHosts = old.HasHosts || len(in.Hosts) > 0
	}
	if in.Rules != nil {
		m.ACLs = in.EnabledRules()
		m.HasACLs = old.HasACLs || len(m.ACLs) > 0
	}
	return m
}
