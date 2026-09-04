package policy

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/panagiotis1226/head-control/internal/aclmodel"
	"github.com/panagiotis1226/head-control/internal/store"
)

// ModelRule is one rule as shown by the ACLs Beta editor: the policy rule
// plus UI-local metadata. Disabled rules exist only in Head-Control's store.
type ModelRule struct {
	ID          string   `json:"id"` // content fingerprint
	Action      string   `json:"action"`
	Proto       string   `json:"proto,omitempty"`
	Src         []string `json:"src"`
	Dst         []string `json:"dst"`
	Name        string   `json:"name"`
	Description string   `json:"description"`
	Enabled     bool     `json:"enabled"`
}

// ModelState is the structured view served to the ACLs Beta editor.
type ModelState struct {
	Hash          string              `json:"hash"` // of the served policy text; echo back as baseHash
	Mode          string              `json:"mode"`
	Writable      bool                `json:"writable"`
	ReloadPending bool                `json:"reloadPending"`
	UpdatedAt     *time.Time          `json:"updatedAt,omitempty"`
	Groups        map[string][]string `json:"groups"`
	TagOwners     map[string][]string `json:"tagOwners"`
	Hosts         map[string]string   `json:"hosts"`
	Rules         []ModelRule         `json:"rules"`
	OtherSections []string            `json:"otherSections"`
}

// ModelInput is the editor's save request.
type ModelInput struct {
	BaseHash string `json:"baseHash"`
	Force    bool   `json:"force,omitempty"`
	Comment  string `json:"comment,omitempty"`
	aclmodel.Input
}

// ModelSaveResult is a SaveResult plus whether the policy text changed at all
// (metadata-only saves never touch headscale).
type ModelSaveResult struct {
	SaveResult
	PolicyChanged bool `json:"policyChanged"`
}

// ModelConflictError reports a stale baseHash; Current carries the fresh
// state so the UI can rebase.
type ModelConflictError struct{ Current *ModelState }

func (e *ModelConflictError) Error() string {
	return "the policy changed since you loaded it (another admin, the raw editor, or headscale itself)"
}

// GetModel returns the structured policy view.
func (m *Manager) GetModel(ctx context.Context) (*ModelState, error) {
	st, err := m.Get(ctx)
	if err != nil {
		return nil, err
	}
	doc, err := aclmodel.ParseDocument(st.Policy)
	if err != nil {
		return nil, err
	}
	return m.modelState(st, doc), nil
}

func (m *Manager) modelState(st *State, doc *aclmodel.Document) *ModelState {
	metas, err := m.st.ListRuleMeta()
	if err != nil {
		m.log.Warn("could not read acl rule metadata", "err", err)
	}
	byFP := make(map[string]store.RuleMeta, len(metas))
	for _, rm := range metas {
		byFP[rm.Fingerprint] = rm
	}

	rules := make([]ModelRule, 0, len(doc.Model.ACLs)+len(metas))
	live := map[string]bool{}
	for _, r := range doc.Model.ACLs {
		fp := aclmodel.Fingerprint(r)
		live[fp] = true
		mr := ModelRule{ID: fp, Action: r.Action, Proto: r.Proto, Src: r.Src, Dst: r.Dst, Enabled: true}
		if meta, ok := byFP[fp]; ok {
			mr.Name, mr.Description = meta.Name, meta.Description
		}
		rules = append(rules, mr)
	}
	// Disabled rules are re-inserted at their remembered position (metas are
	// sorted by position, so sequential insertion keeps the intended order).
	// A disabled rule that reappeared in the live policy is shown once, live.
	for _, rm := range metas {
		if rm.Enabled || live[rm.Fingerprint] || rm.RuleJSON == "" {
			continue
		}
		var r aclmodel.Rule
		if err := json.Unmarshal([]byte(rm.RuleJSON), &r); err != nil {
			continue
		}
		mr := ModelRule{ID: rm.Fingerprint, Action: r.Action, Proto: r.Proto, Src: r.Src, Dst: r.Dst,
			Name: rm.Name, Description: rm.Description, Enabled: false}
		pos := rm.Position
		if pos > len(rules) {
			pos = len(rules)
		}
		if pos < 0 {
			pos = 0
		}
		rules = append(rules[:pos], append([]ModelRule{mr}, rules[pos:]...)...)
	}

	return &ModelState{
		Hash:          store.HashContent(st.Policy),
		Mode:          st.Mode,
		Writable:      st.Writable,
		ReloadPending: st.ReloadPending,
		UpdatedAt:     st.UpdatedAt,
		Groups:        doc.Model.Groups,
		TagOwners:     doc.Model.TagOwners,
		Hosts:         doc.Model.Hosts,
		Rules:         rules,
		OtherSections: doc.Other,
	}
}

// SaveModel validates the input, patches the served policy document
// (comments preserved), saves through the normal Save path (headscale check,
// mode handling, version history) and then syncs the metadata sidecar.
func (m *Manager) SaveModel(ctx context.Context, in *ModelInput) (*ModelSaveResult, error) {
	m.modelMu.Lock()
	defer m.modelMu.Unlock()

	if err := aclmodel.Validate(&in.Input); err != nil {
		return nil, err
	}
	if in.BaseHash == "" && !in.Force {
		return nil, &aclmodel.ValidationError{Path: "baseHash", Msg: "required (load the policy first)"}
	}

	st, err := m.Get(ctx)
	if err != nil {
		return nil, err
	}
	doc, err := aclmodel.ParseDocument(st.Policy)
	if err != nil {
		return nil, err
	}
	if !in.Force && store.HashContent(st.Policy) != in.BaseHash {
		return nil, &ModelConflictError{Current: m.modelState(st, doc)}
	}

	oldModel := doc.Model
	patch, err := doc.Plan(&in.Input)
	if err != nil {
		return nil, err
	}

	res := &ModelSaveResult{}
	if patch.Ops == 0 {
		res.Mode = st.Mode
		res.UpdatedAt = st.UpdatedAt
		res.ReloadPending = st.ReloadPending
	} else {
		newDoc, err := doc.Apply(patch)
		if err != nil {
			return nil, err
		}
		// Never ship a document that differs from what the user reviewed.
		check, err := aclmodel.ParseDocument(newDoc)
		if err != nil {
			return nil, fmt.Errorf("internal: patched policy does not parse: %w", err)
		}
		if !aclmodel.EqualModels(check.Model, aclmodel.ModelFromInput(oldModel, &in.Input)) {
			return nil, fmt.Errorf("internal: patched policy does not match the requested model")
		}
		sr, err := m.Save(ctx, newDoc, in.Comment)
		if err != nil {
			return nil, err
		}
		res.SaveResult = *sr
		res.PolicyChanged = true
	}

	if in.Rules != nil {
		if err := m.st.ReplaceRuleMeta(metaRows(in.Rules)); err != nil {
			m.log.Warn("could not save acl rule metadata", "err", err)
			if res.Warning == "" {
				res.Warning = "policy saved, but rule names/descriptions could not be stored: " + err.Error()
			}
		}
	}
	return res, nil
}

// metaRows converts submitted rules into sidecar rows. Plain enabled rules
// without a name or description need no row.
func metaRows(rules []aclmodel.InputRule) []store.RuleMeta {
	var out []store.RuleMeta
	seen := map[string]int{}
	for i, r := range rules {
		if r.Enabled && r.Name == "" && r.Description == "" {
			continue
		}
		rule := r.Rule()
		row := store.RuleMeta{
			Fingerprint: aclmodel.Fingerprint(rule),
			Name:        r.Name,
			Description: r.Description,
			Enabled:     r.Enabled,
			RuleJSON:    aclmodel.RuleJSON(rule),
			Position:    i,
		}
		if idx, dup := seen[row.Fingerprint]; dup {
			out[idx] = row // identical rules share one row; last wins
			continue
		}
		seen[row.Fingerprint] = len(out)
		out = append(out, row)
	}
	return out
}
