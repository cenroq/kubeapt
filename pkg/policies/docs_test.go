// Copyright by cenroq AG
// Contact: info@cenroq.com

package policies_test

import (
	"testing"
	"testing/fstest"

	"github.com/cenroq/kubeapt/v2/pkg/policies"
)

const uuidPolicyYAML = `apiVersion: admissionregistration.k8s.io/v1
kind: ValidatingAdmissionPolicy
metadata:
  name: with-uuid
  annotations:
    kubeapt.io/uuid: "23ef68db-2409-43a1-854d-c46477a533a9"
spec:
  validations:
  - expression: "true"
---
apiVersion: admissionregistration.k8s.io/v1
kind: ValidatingAdmissionPolicy
metadata:
  name: without-uuid
spec:
  validations:
  - expression: "true"
`

const testDocsURL = policies.DocsBaseURL + "/23ef68db-2409-43a1-854d-c46477a533a9"

// There is deliberately no fallback: a policy with no uuid has no page.
func TestDocsURL(t *testing.T) {
	tests := map[string]string{
		"":     "",
		"   ":  "",
		"abc":  policies.DocsBaseURL + "/abc",
		" ab ": policies.DocsBaseURL + "/ab",
	}
	for uuid, want := range tests {
		if got := policies.DocsURL(uuid); got != want {
			t.Errorf("DocsURL(%q) = %q, want %q", uuid, got, want)
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
	annotations := map[string]string{policies.AnnotationUUID: "23ef68db-2409-43a1-854d-c46477a533a9"}
	if got := policies.DocsURLFromAnnotations(annotations); got != testDocsURL {
		t.Errorf("present annotation = %q, want %q", got, testDocsURL)
	}
}

func TestPolicyUUIDAndDocsURL(t *testing.T) {
	bundle, err := policies.Load(fstest.MapFS{"p.yaml": {Data: []byte(uuidPolicyYAML)}}, ".")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	with, _ := bundle.Get("with-uuid")
	if got := with.UUID(); got != "23ef68db-2409-43a1-854d-c46477a533a9" {
		t.Errorf("UUID() = %q", got)
	}
	if got := with.DocsURL(); got != testDocsURL {
		t.Errorf("DocsURL() = %q, want %q", got, testDocsURL)
	}

	without, _ := bundle.Get("without-uuid")
	if without.UUID() != "" || without.DocsURL() != "" {
		t.Errorf("policy without uuid: UUID %q DocsURL %q", without.UUID(), without.DocsURL())
	}

	var missing *policies.Policy
	if missing.UUID() != "" || missing.DocsURL() != "" {
		t.Error("nil policy must report no uuid")
	}
}
