// Copyright by cenroq AG
// Contact: info@cenroq.com

package policies_test

import (
	"testing"
	"testing/fstest"

	"github.com/cenroq/kubeapt/v2/pkg/policies"
)

const findingPolicyYAML = `apiVersion: admissionregistration.k8s.io/v1
kind: ValidatingAdmissionPolicy
metadata:
  name: with-finding
  annotations:
    cenroq.io/finding: "oq-0276"
spec:
  validations:
  - expression: "true"
---
apiVersion: admissionregistration.k8s.io/v1
kind: ValidatingAdmissionPolicy
metadata:
  name: legacy-uuid
  annotations:
    kubeapt.io/uuid: "23ef68db-2409-43a1-854d-c46477a533a9"
spec:
  validations:
  - expression: "true"
---
apiVersion: admissionregistration.k8s.io/v1
kind: ValidatingAdmissionPolicy
metadata:
  name: without-id
spec:
  validations:
  - expression: "true"
`

const testDocsURL = policies.DocsBaseURL + "/oq-0276"

// cenroq.io/finding is the id. kubeapt.io/uuid is read only as a fallback, and
// the caller is told so it can warn that the policy set needs re-publishing.
func TestFindingID(t *testing.T) {
	tests := []struct {
		name           string
		annotations    map[string]string
		wantID         string
		wantDeprecated bool
	}{
		{"finding", map[string]string{policies.AnnotationFinding: "oq-0276"}, "oq-0276", false},
		{"trimmed", map[string]string{policies.AnnotationFinding: "  oq-0276 "}, "oq-0276", false},
		{"legacy uuid", map[string]string{policies.AnnotationUUID: " 23ef68db "}, "23ef68db", true},
		{"finding wins", map[string]string{policies.AnnotationFinding: "oq-0276", policies.AnnotationUUID: "23ef68db"}, "oq-0276", false},
		{"blank finding falls back", map[string]string{policies.AnnotationFinding: " ", policies.AnnotationUUID: "23ef68db"}, "23ef68db", true},
		{"neither", map[string]string{"other": "x"}, "", false},
		{"nil map", nil, "", false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			id, deprecated := policies.FindingID(tc.annotations)
			if id != tc.wantID || deprecated != tc.wantDeprecated {
				t.Fatalf("FindingID = %q, %v; want %q, %v", id, deprecated, tc.wantID, tc.wantDeprecated)
			}
		})
	}
}

// There is deliberately no fallback: a policy with no id has no page.
func TestDocsURL(t *testing.T) {
	tests := map[string]string{
		"":          "",
		"   ":       "",
		"oq-0276":   testDocsURL,
		" oq-0276 ": testDocsURL,
	}
	for id, want := range tests {
		if got := policies.DocsURL(id); got != want {
			t.Errorf("DocsURL(%q) = %q, want %q", id, got, want)
		}
	}
}

func TestDocsURLFromAnnotations(t *testing.T) {
	if got := policies.DocsURLFromAnnotations(nil); got != "" {
		t.Errorf("nil map = %q", got)
	}
	if got := policies.DocsURLFromAnnotations(map[string]string{"other": "x"}); got != "" {
		t.Errorf("absent annotation = %q", got)
	}
	if got := policies.DocsURLFromAnnotations(map[string]string{policies.AnnotationFinding: "oq-0276"}); got != testDocsURL {
		t.Errorf("finding = %q, want %q", got, testDocsURL)
	}
	legacy := map[string]string{policies.AnnotationUUID: "23ef68db"}
	if got := policies.DocsURLFromAnnotations(legacy); got != policies.DocsBaseURL+"/23ef68db" {
		t.Errorf("legacy uuid = %q", got)
	}
}

func TestPolicyFindingIDAndDocsURL(t *testing.T) {
	bundle, err := policies.Load(fstest.MapFS{"p.yaml": {Data: []byte(findingPolicyYAML)}}, ".")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	with, _ := bundle.Get("with-finding")
	if got := with.FindingID(); got != "oq-0276" {
		t.Errorf("FindingID() = %q", got)
	}
	if got := with.DocsURL(); got != testDocsURL {
		t.Errorf("DocsURL() = %q, want %q", got, testDocsURL)
	}

	legacy, _ := bundle.Get("legacy-uuid")
	if got := legacy.FindingID(); got != "23ef68db-2409-43a1-854d-c46477a533a9" {
		t.Errorf("legacy FindingID() = %q, want the uuid fallback", got)
	}

	without, _ := bundle.Get("without-id")
	if without.FindingID() != "" || without.DocsURL() != "" {
		t.Errorf("policy without id: FindingID %q DocsURL %q", without.FindingID(), without.DocsURL())
	}

	var missing *policies.Policy
	if missing.FindingID() != "" || missing.DocsURL() != "" {
		t.Error("nil policy must report no id")
	}
}
