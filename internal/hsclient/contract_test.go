package hsclient

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"
	"testing"
)

// TestContractCoverage pins the client to the headscale v0.29.3 API: every
// operation in the vendored swagger spec must be declared covered, and the
// client must not declare operations absent from the spec.
func TestContractCoverage(t *testing.T) {
	raw, err := os.ReadFile("../../testdata/headscale-v0.29.3.swagger.json")
	if err != nil {
		t.Fatalf("reading pinned spec: %v", err)
	}
	var spec struct {
		Swagger string                                `json:"swagger"`
		Paths   map[string]map[string]json.RawMessage `json:"paths"`
	}
	if err := json.Unmarshal(raw, &spec); err != nil {
		t.Fatalf("parsing pinned spec: %v", err)
	}
	if spec.Swagger != "2.0" {
		t.Fatalf("expected Swagger 2.0 spec, got %q — headscale changed spec formats; revisit the client", spec.Swagger)
	}

	specOps := map[string]bool{}
	for path, methods := range spec.Paths {
		for method := range methods {
			if method == "parameters" { // swagger allows shared params under a path
				continue
			}
			specOps[strings.ToUpper(method)+" "+path] = true
		}
	}

	covered := map[string]bool{}
	for _, op := range CoveredOperations() {
		if covered[op] {
			t.Errorf("operation declared covered twice: %s", op)
		}
		covered[op] = true
	}

	var missing, extra []string
	for op := range specOps {
		if !covered[op] {
			missing = append(missing, op)
		}
	}
	for op := range covered {
		if !specOps[op] {
			extra = append(extra, op)
		}
	}
	sort.Strings(missing)
	sort.Strings(extra)
	if len(missing) > 0 {
		t.Errorf("spec operations NOT covered by the client:\n  %s", strings.Join(missing, "\n  "))
	}
	if len(extra) > 0 {
		t.Errorf("client declares operations absent from the spec:\n  %s", strings.Join(extra, "\n  "))
	}
	if want := 29; len(specOps) != want {
		t.Errorf("expected %d operations in the pinned spec, found %d", want, len(specOps))
	}
}

// TestContractFieldEncoding asserts the uint64-as-string convention the
// client relies on is what the spec declares for identifier fields.
func TestContractFieldEncoding(t *testing.T) {
	raw, err := os.ReadFile("../../testdata/headscale-v0.29.3.swagger.json")
	if err != nil {
		t.Fatalf("reading pinned spec: %v", err)
	}
	var spec struct {
		Definitions map[string]struct {
			Properties map[string]struct {
				Type   string `json:"type"`
				Format string `json:"format"`
			} `json:"properties"`
		} `json:"definitions"`
	}
	if err := json.Unmarshal(raw, &spec); err != nil {
		t.Fatalf("parsing pinned spec: %v", err)
	}
	for _, probe := range []struct{ def, field string }{
		{"v1User", "id"},
		{"v1Node", "id"},
		{"v1PreAuthKey", "id"},
		{"v1ApiKey", "id"},
		{"v1CreatePreAuthKeyRequest", "user"},
	} {
		def, ok := spec.Definitions[probe.def]
		if !ok {
			t.Errorf("definition %s missing from spec", probe.def)
			continue
		}
		f, ok := def.Properties[probe.field]
		if !ok {
			t.Errorf("%s.%s missing from spec", probe.def, probe.field)
			continue
		}
		if f.Type != "string" || f.Format != "uint64" {
			t.Errorf("%s.%s: expected string/uint64 encoding, spec says %s/%s — revisit ID handling",
				probe.def, probe.field, f.Type, f.Format)
		}
	}
}

// TestAPIKeyPrefix covers both key formats headscale has used.
func TestAPIKeyPrefix(t *testing.T) {
	for _, tc := range []struct{ key, want string }{
		{"hskey-api-abc123-supersecret", "abc123"},
		{"oldprefix.oldsecret", "oldprefix"},
		{"garbage", ""},
	} {
		c := &Client{apiKey: tc.key}
		if got := c.APIKeyPrefix(); got != tc.want {
			t.Errorf("APIKeyPrefix(%q) = %q, want %q", tc.key, got, tc.want)
		}
	}
}

func ExampleError() {
	e := parseError(400, []byte(`{"code":3,"message":"invalid tag","details":[]}`))
	fmt.Println(e.Code, e.Message)
	// Output: 3 invalid tag
}
