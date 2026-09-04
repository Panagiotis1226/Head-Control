package store

import "testing"

func TestRuleMetaRoundTrip(t *testing.T) {
	st, err := OpenMemory()
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	rows := []RuleMeta{
		{Fingerprint: "b", Name: "second", Enabled: false, RuleJSON: `{"action":"accept"}`, Position: 1},
		{Fingerprint: "a", Name: "first", Description: "d", Enabled: true, Position: 0},
	}
	if err := st.ReplaceRuleMeta(rows); err != nil {
		t.Fatal(err)
	}
	got, err := st.ListRuleMeta()
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[0].Fingerprint != "a" || got[1].Fingerprint != "b" || got[1].Enabled || got[1].RuleJSON == "" || got[0].Description != "d" {
		t.Fatalf("unexpected rows: %+v", got)
	}
	// Wholesale replacement drops old rows.
	if err := st.ReplaceRuleMeta([]RuleMeta{{Fingerprint: "c", Name: "only", Enabled: true}}); err != nil {
		t.Fatal(err)
	}
	got, _ = st.ListRuleMeta()
	if len(got) != 1 || got[0].Fingerprint != "c" {
		t.Fatalf("expected only c, got %+v", got)
	}
	if err := st.ReplaceRuleMeta(nil); err != nil {
		t.Fatal(err)
	}
	if got, _ = st.ListRuleMeta(); len(got) != 0 {
		t.Fatalf("expected empty table, got %+v", got)
	}
}
