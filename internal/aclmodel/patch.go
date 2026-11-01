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
	// containers (by JSON Pointer) whose last child had a trailing comma
	// before patching
	trailing map[string]bool
	// containers (by JSON Pointer) that were empty before patching
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
	ptr := func(section string) string { return "/" + escapePointer(d.KeyName(section)) }
	if in.Groups != nil {
		ops = append(ops, diffListMap(ptr("groups"), old.HasGroups, old.Groups, in.Groups, unit, unit)...)
	}
	if in.TagOwners != nil {
		ops = append(ops, diffListMap(ptr("tagOwners"), old.HasTagOwners, old.TagOwners, in.TagOwners, unit, unit)...)
	}
	if in.Hosts != nil {
		ops = append(ops, diffStringMap(ptr("hosts"), old.HasHosts, old.Hosts, in.Hosts, unit, unit)...)
	}
	if in.Rules != nil {
		rules := in.EnabledRules()
		oldIDs := make([]string, len(old.ACLs))
		for i, r := range old.ACLs {
			oldIDs[i] = Fingerprint(r)
		}
		curIDs := make([]string, len(rules))
		for i, r := range rules {
			curIDs[i] = Fingerprint(r)
		}
		ops = append(ops, diffSeq(ptr("acls"), old.HasACLs, oldIDs, curIDs, func(j int) string { return renderRule(rules[j]) }, unit, unit)...)
	}
	for _, section := range ListSections {
		items, err := in.CanonicalList(section)
		if err != nil {
			return nil, err
		}
		if items == nil {
			continue
		}
		ops = append(ops, diffSeq(ptr(section), old.HasList[section], old.Lists[section], items, func(j int) string { return renderCanonical(items[j]) }, unit, unit)...)
	}
	if in.AutoApprovers != nil {
		ops = append(ops, d.diffAutoApprovers(ptr("autoApprovers"), in.AutoApprovers, unit)...)
	}
	if in.RandomizeClientPort != nil {
		path, want, cur := ptr("randomizeClientPort"), *in.RandomizeClientPort, old.RandomizeClientPort
		switch {
		case want && cur == nil:
			ops = append(ops, op{Op: "add", Path: path, Value: json.RawMessage("true")})
		case want && !*cur:
			ops = append(ops, op{Op: "replace", Path: path, Value: json.RawMessage("true")})
		case !want && cur != nil:
			// false is headscale's default: drop the key instead of writing it.
			ops = append(ops, op{Op: "remove", Path: path})
		}
	}

	p := &Patch{Ops: len(ops), ops: ops, trailing: map[string]bool{}, wasEmpty: map[string]bool{}}
	if len(ops) == 0 {
		p.bytes = []byte("[]")
		return p, nil
	}
	for _, o := range ops {
		parent, _ := splitPointer(o.Path)
		if parent == "" {
			continue
		}
		if v := d.root.Find(parent); v != nil {
			last, n := lastChild(v)
			p.wasEmpty[parent] = n == 0
			p.trailing[parent] = last != nil && last.AfterExtra != nil
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

// diffListMap diffs an object of string lists at base (an escaped JSON
// Pointer). ind is the indentation of base's own key; unit one level.
func diffListMap(base string, had bool, old, cur map[string][]string, ind, unit string) []op {
	if !had {
		if len(cur) == 0 {
			return nil
		}
		return []op{{Op: "add", Path: base, Value: json.RawMessage(renderListMapBlock(cur, ind, unit))}}
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

func diffStringMap(base string, had bool, old, cur map[string]string, ind, unit string) []op {
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
			sb.WriteString("\n" + ind + unit + quote(k) + ": " + quote(cur[k]))
		}
		sb.WriteString("\n" + ind + "}")
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

// diffSeq diffs an array whose elements are identified by oldIDs/curIDs. It
// keeps the longest common subsequence in place: removes (descending) then
// adds (ascending) rebuild exactly the new list while unchanged elements keep
// their position and comments. render(j) renders curIDs[j]'s element.
func diffSeq(base string, had bool, oldIDs, curIDs []string, render func(j int) string, ind, unit string) []op {
	if !had {
		if len(curIDs) == 0 {
			return nil
		}
		var sb strings.Builder
		sb.WriteString("[")
		for j := range curIDs {
			if j > 0 {
				sb.WriteString(",")
			}
			sb.WriteString("\n" + ind + unit + render(j))
		}
		sb.WriteString("\n" + ind + "]")
		return []op{{Op: "add", Path: base, Value: json.RawMessage(sb.String())}}
	}
	keepOld, keepCur := lcs(oldIDs, curIDs)

	var ops []op
	for i := len(oldIDs) - 1; i >= 0; i-- {
		if !keepOld[i] {
			ops = append(ops, op{Op: "remove", Path: fmt.Sprintf("%s/%d", base, i)})
		}
	}
	for j := range curIDs {
		if !keepCur[j] {
			ops = append(ops, op{Op: "add", Path: fmt.Sprintf("%s/%d", base, j), Value: json.RawMessage(render(j))})
		}
	}
	return ops
}

// diffAutoApprovers patches the autoApprovers object member by member, so
// untouched routes keep their comments.
func (d *Document) diffAutoApprovers(base string, cur *AutoApprovers, unit string) []op {
	old := d.Model
	routes := cur.Routes
	if routes == nil {
		routes = map[string][]string{}
	}
	exit := nonNil(cur.ExitNode)
	if !old.HasAutoApprovers {
		if len(routes) == 0 && len(exit) == 0 {
			return nil
		}
		return []op{{Op: "add", Path: base, Value: json.RawMessage(renderAutoApprovers(routes, exit, unit, unit))}}
	}
	ind := unit + unit // members of a top-level object
	var ops []op
	routesPtr := base + "/" + escapePointer(d.aaKeyName("routes"))
	if old.HasAARoutes {
		ops = append(ops, diffListMap(routesPtr, true, old.AutoApprovers.Routes, routes, ind, unit)...)
	} else if _, present := d.aaKeys["routes"]; present && len(routes) > 0 {
		// "routes": null
		ops = append(ops, op{Op: "replace", Path: routesPtr, Value: json.RawMessage(renderListMapBlock(routes, ind, unit))})
	} else {
		ops = append(ops, diffListMap(routesPtr, false, nil, routes, ind, unit)...)
	}
	exitPtr := base + "/" + escapePointer(d.aaKeyName("exitNode"))
	_, exitPresent := d.aaKeys["exitNode"]
	switch {
	case exitPresent && !equalStrings(old.AutoApprovers.ExitNode, exit):
		ops = append(ops, op{Op: "replace", Path: exitPtr, Value: json.RawMessage(renderStrings(exit))})
	case !exitPresent && len(exit) > 0:
		ops = append(ops, op{Op: "add", Path: exitPtr, Value: json.RawMessage(renderStrings(exit))})
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

// renderListMapBlock renders {"k": [...], ...} on multiple lines; ind is the
// indentation of the object's own key.
func renderListMapBlock(m map[string][]string, ind, unit string) string {
	var sb strings.Builder
	sb.WriteString("{")
	for i, k := range sortedKeys(m) {
		if i > 0 {
			sb.WriteString(",")
		}
		sb.WriteString("\n" + ind + unit + quote(k) + ": " + renderStrings(nonNil(m[k])))
	}
	sb.WriteString("\n" + ind + "}")
	return sb.String()
}

func renderAutoApprovers(routes map[string][]string, exit []string, ind, unit string) string {
	var parts []string
	if len(routes) > 0 {
		parts = append(parts, "\n"+ind+unit+`"routes": `+renderListMapBlock(routes, ind+unit, unit))
	}
	if len(exit) > 0 {
		parts = append(parts, "\n"+ind+unit+`"exitNode": `+renderStrings(exit))
	}
	return "{" + strings.Join(parts, ",") + "\n" + ind + "}"
}

// preferredKeyOrder is the order in which known members are written for a
// new list-section element (src before dst reads naturally); other members
// follow alphabetically. Order does not affect identity.
var preferredKeyOrder = []string{
	"action", "checkPeriod", "src", "dst", "target", "ip", "proto", "users",
	"attr", "ipPool", "via", "app", "acceptEnv", "accept", "deny", "check",
}

// renderCanonical renders a canonical element on one line, headscale-docs
// style: {"src": ["a"], "dst": ["b"]}.
func renderCanonical(c string) string {
	dec := json.NewDecoder(strings.NewReader(c))
	dec.UseNumber()
	var v any
	_ = dec.Decode(&v) // c is canonical JSON
	return renderValue(v, true)
}

func renderValue(v any, top bool) string {
	switch t := v.(type) {
	case map[string]any:
		keys := make([]string, 0, len(t))
		if top {
			for _, k := range preferredKeyOrder {
				for name := range t {
					if strings.EqualFold(name, k) {
						keys = append(keys, name)
					}
				}
			}
		}
		rest := make([]string, 0, len(t))
		for name := range t {
			if !containsString(keys, name) {
				rest = append(rest, name)
			}
		}
		sort.Strings(rest)
		keys = append(keys, rest...)
		parts := make([]string, len(keys))
		for i, k := range keys {
			parts[i] = quoteRaw(k) + ": " + renderValue(t[k], false)
		}
		return "{" + strings.Join(parts, ", ") + "}"
	case []any:
		parts := make([]string, len(t))
		for i, e := range t {
			parts[i] = renderValue(e, false)
		}
		return "[" + strings.Join(parts, ", ") + "]"
	case string:
		return quoteRaw(t)
	default:
		return encodeCompact(t)
	}
}

func quoteRaw(s string) string { return encodeCompact(s) }

func containsString(xs []string, s string) bool {
	for _, x := range xs {
		if x == s {
			return true
		}
	}
	return false
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

// splitPointer splits a JSON Pointer into its parent pointer ("" for the
// root) and its last, unescaped token.
func splitPointer(ptr string) (parent, last string) {
	i := strings.LastIndexByte(ptr, '/')
	return ptr[:i], unescapePointer(ptr[i+1:])
}

// container returns the value at a JSON Pointer ("" is the root).
func (d *Document) container(ptr string) *hujson.Value {
	if ptr == "" {
		return &d.root
	}
	return d.root.Find(ptr)
}

// ownIndent returns the indentation of the line on which the value at ptr
// starts: the indent of its member key, or of the array element itself.
func (d *Document) ownIndent(ptr, unit string) string {
	if ptr == "" {
		return ""
	}
	parentPtr, key := splitPointer(ptr)
	parent := d.container(parentPtr)
	if parent != nil {
		switch c := parent.Value.(type) {
		case *hujson.Object:
			for i := range c.Members {
				if lit, ok := c.Members[i].Name.Value.(hujson.Literal); ok && lit.String() == key {
					if ind, ok := indentOf(c.Members[i].Name.BeforeExtra); ok {
						return ind
					}
				}
			}
		case *hujson.Array:
			var idx int
			if _, err := fmt.Sscanf(key, "%d", &idx); err == nil && idx >= 0 && idx < len(c.Elements) {
				if ind, ok := indentOf(c.Elements[idx].BeforeExtra); ok {
					return ind
				}
			}
		}
	}
	return d.ownIndent(parentPtr, unit) + unit
}

// tidy gives every node inserted by the patch a newline + indentation like
// its siblings, restores each container's trailing-comma style, and puts the
// closing bracket of a previously-empty container on its own line.
func (d *Document) tidy(p *Patch) {
	unit := d.indentUnit()
	touched := map[string]bool{}
	for _, o := range p.ops {
		parentPtr, key := splitPointer(o.Path)
		touched[parentPtr] = true
		if o.Op != "add" && o.Op != "replace" {
			continue
		}
		parent := d.container(parentPtr)
		if parent == nil {
			continue
		}
		childIndent := siblingIndent(parent, d.ownIndent(parentPtr, unit)+unit)
		switch c := parent.Value.(type) {
		case *hujson.Object:
			for i := range c.Members {
				lit, ok := c.Members[i].Name.Value.(hujson.Literal)
				if !ok || lit.String() != key {
					continue
				}
				if _, ok := indentOf(c.Members[i].Name.BeforeExtra); !ok {
					c.Members[i].Name.BeforeExtra = hujson.Extra("\n" + childIndent)
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
				c.Elements[idx].BeforeExtra = hujson.Extra("\n" + childIndent)
			}
		}
	}
	for ptr := range touched {
		if ptr == "" {
			continue
		}
		sec := d.container(ptr)
		if sec == nil {
			continue
		}
		last, n := lastChild(sec)
		if n == 0 {
			continue
		}
		if p.trailing[ptr] && last.AfterExtra == nil {
			last.AfterExtra = hujson.Extra{}
		}
		if p.wasEmpty[ptr] {
			// closing bracket on its own line, aligned with the container's key
			ind := d.ownIndent(ptr, unit)
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
// container, or fallback when it has none on their own lines.
func siblingIndent(sec *hujson.Value, fallback string) string {
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
	return fallback
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
	for _, section := range ListSections {
		if !equalStrings(nonNil(a.Lists[section]), nonNil(b.Lists[section])) {
			return false
		}
	}
	ar, br := a.AutoApprovers.Routes, b.AutoApprovers.Routes
	if len(ar) != len(br) || !equalStrings(nonNil(a.AutoApprovers.ExitNode), nonNil(b.AutoApprovers.ExitNode)) {
		return false
	}
	for k, v := range ar {
		if w, ok := br[k]; !ok || !equalStrings(nonNil(v), nonNil(w)) {
			return false
		}
	}
	return boolValue(a.RandomizeClientPort) == boolValue(b.RandomizeClientPort)
}

func boolValue(b *bool) bool { return b != nil && *b }

// ModelFromInput builds the model an Input describes, given the sections
// the old document had (nil sections in the input are carried over).
func ModelFromInput(old Model, in *Input) Model {
	m := old
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
	m.Lists = map[string][]string{}
	for _, section := range ListSections {
		m.Lists[section] = old.Lists[section]
		if items, err := in.CanonicalList(section); err == nil && items != nil {
			m.Lists[section] = items
		}
	}
	if in.AutoApprovers != nil {
		m.AutoApprovers = AutoApprovers{Routes: in.AutoApprovers.Routes, ExitNode: nonNil(in.AutoApprovers.ExitNode)}
		if m.AutoApprovers.Routes == nil {
			m.AutoApprovers.Routes = map[string][]string{}
		}
	}
	if in.RandomizeClientPort != nil {
		v := *in.RandomizeClientPort
		m.RandomizeClientPort = &v
	}
	return m
}
