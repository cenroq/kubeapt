// Copyright by cenroq AG
// Contact: info@cenroq.com

package policies_test

import (
	"testing"
	"testing/fstest"

	"github.com/cenroq/kubeapt/v2/internal/scanaccess"
	"github.com/cenroq/kubeapt/v2/pkg/policies"
	"github.com/cenroq/kubeapt/v2/pkg/types"
)

// The key names are wire format shared with the published policy sets, so
// they are pinned rather than derived.
func TestMetadataAnnotationKeys(t *testing.T) {
	keys := map[string]string{
		policies.AnnotationSeverity:          "security.cenroq.io/severity",
		policies.AnnotationDisplayName:       "security.cenroq.io/displayName",
		policies.AnnotationDescription:       "security.cenroq.io/description",
		policies.AnnotationCategory:          "security.cenroq.io/category",
		policies.AnnotationResource:          "security.cenroq.io/resource",
		policies.AnnotationRemediation:       "security.cenroq.io/remediation",
		policies.AnnotationProduct:           "security.cenroq.io/product",
		policies.LegacyAnnotationSeverity:    "security.kubeapt.io/severity",
		policies.LegacyAnnotationDisplayName: "security.kubeapt.io/displayName",
		policies.LegacyAnnotationDescription: "security.kubeapt.io/description",
		policies.LegacyAnnotationCategory:    "security.kubeapt.io/category",
		policies.LegacyAnnotationResource:    "security.kubeapt.io/resource",
		policies.LegacyAnnotationRemediation: "security.kubeapt.io/remediation",
		policies.LegacyAnnotationProduct:     "security.kubeapt.io/product",
	}
	for got, want := range keys {
		if got != want {
			t.Errorf("key = %q, want %q", got, want)
		}
	}
}

// Text metadata reads security.cenroq.io, then the legacy security.kubeapt.io
// key, then Kyverno's. Each accessor is checked against its own key triple.
func TestTextMetadataFromAnnotations(t *testing.T) {
	accessors := []struct {
		name                    string
		get                     func(map[string]string) string
		cenroq, legacy, kyverno string
	}{
		{"DisplayName", policies.DisplayNameFromAnnotations, policies.AnnotationDisplayName, policies.LegacyAnnotationDisplayName, policies.KyvernoAnnotationTitle},
		{"Description", policies.DescriptionFromAnnotations, policies.AnnotationDescription, policies.LegacyAnnotationDescription, policies.KyvernoAnnotationDescription},
		{"Category", policies.CategoryFromAnnotations, policies.AnnotationCategory, policies.LegacyAnnotationCategory, policies.KyvernoAnnotationCategory},
	}
	for _, a := range accessors {
		t.Run(a.name, func(t *testing.T) {
			cases := []struct {
				name string
				in   map[string]string
				want string
			}{
				{"cenroq", map[string]string{a.cenroq: " new "}, "new"},
				{"legacy", map[string]string{a.legacy: "old"}, "old"},
				{"kyverno", map[string]string{a.kyverno: "kyv"}, "kyv"},
				{"cenroq beats legacy and kyverno", map[string]string{a.cenroq: "new", a.legacy: "old", a.kyverno: "kyv"}, "new"},
				{"legacy beats kyverno", map[string]string{a.legacy: "old", a.kyverno: "kyv"}, "old"},
				{"blank cenroq falls back", map[string]string{a.cenroq: "  ", a.legacy: "old"}, "old"},
				{"none", map[string]string{"other": "x"}, ""},
				{"nil map", nil, ""},
			}
			for _, tc := range cases {
				if got := a.get(tc.in); got != tc.want {
					t.Errorf("%s: got %q, want %q", tc.name, got, tc.want)
				}
			}
		})
	}
}

// Severity reads only the cenroq and legacy keys; Kyverno's scale spells the
// middle rung "medium", so its key is never consulted.
func TestSeverityFromAnnotations(t *testing.T) {
	cases := []struct {
		name string
		in   map[string]string
		want types.Severity
	}{
		{"cenroq", map[string]string{policies.AnnotationSeverity: "high"}, types.SeverityHigh},
		{"legacy", map[string]string{policies.LegacyAnnotationSeverity: "Low"}, types.SeverityLow},
		{"cenroq wins", map[string]string{policies.AnnotationSeverity: "Critical", policies.LegacyAnnotationSeverity: "Low"}, types.SeverityCritical},
		{"blank cenroq falls back", map[string]string{policies.AnnotationSeverity: " ", policies.LegacyAnnotationSeverity: "Moderate"}, types.SeverityModerate},
		{"kyverno ignored", map[string]string{policies.KyvernoAnnotationSeverity: "high"}, types.SeverityNotRated},
		{"unrecognized", map[string]string{policies.AnnotationSeverity: "showstopper"}, types.SeverityNotRated},
		{"nil map", nil, types.SeverityNotRated},
	}
	for _, tc := range cases {
		if got := policies.SeverityFromAnnotations(tc.in); got != tc.want {
			t.Errorf("%s: got %q, want %q", tc.name, got, tc.want)
		}
	}
}

// UsesLegacyAnnotations is true exactly when some value would come from a
// security.kubeapt.io key, which is what the deprecation warning counts.
func TestUsesLegacyAnnotations(t *testing.T) {
	cases := []struct {
		name string
		in   map[string]string
		want bool
	}{
		{"legacy only", map[string]string{policies.LegacyAnnotationSeverity: "High"}, true},
		{"legacy-only field among cenroq fields", map[string]string{policies.AnnotationSeverity: "High", policies.LegacyAnnotationProduct: "k8s"}, true},
		{"blank cenroq with legacy value", map[string]string{policies.AnnotationRemediation: " ", policies.LegacyAnnotationRemediation: "fix"}, true},
		{"cenroq only", map[string]string{policies.AnnotationSeverity: "High", policies.AnnotationDisplayName: "x"}, false},
		{"every legacy value shadowed", map[string]string{policies.AnnotationSeverity: "High", policies.LegacyAnnotationSeverity: "Low"}, false},
		{"blank legacy value", map[string]string{policies.LegacyAnnotationSeverity: "  "}, false},
		{"kyverno only", map[string]string{policies.KyvernoAnnotationTitle: "x"}, false},
		{"nil map", nil, false},
	}
	for _, tc := range cases {
		if got := policies.UsesLegacyAnnotations(tc.in); got != tc.want {
			t.Errorf("%s: got %v, want %v", tc.name, got, tc.want)
		}
	}
}

const legacyAnnotatedPolicyYAML = `apiVersion: admissionregistration.k8s.io/v1
kind: ValidatingAdmissionPolicy
metadata:
  name: legacy-policy
  annotations:
    security.kubeapt.io/displayName: Old Title
    security.kubeapt.io/description: Old description.
    security.kubeapt.io/category: Old Category
    security.kubeapt.io/severity: moderate
    policies.kyverno.io/title: Kyverno Title
spec:
  failurePolicy: Fail
  matchConstraints:
    resourceRules:
      - apiGroups: [""]
        apiVersions: ["v1"]
        operations: ["CREATE"]
        resources: ["pods"]
  validations:
    - expression: "true"
`

// A bundle published before the switch still loads with its names and
// severity intact, and the legacy key beats Kyverno's.
func TestPolicyMetadata_LegacyFallback(t *testing.T) {
	bundle, err := policies.Load(fstest.MapFS{"p.yaml": {Data: []byte(legacyAnnotatedPolicyYAML)}}, ".")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	p, _ := bundle.Get("legacy-policy")
	if got := p.Title(); got != "Old Title" {
		t.Errorf("Title() = %q, want the security.kubeapt.io displayName", got)
	}
	if got := p.Description(); got != "Old description." {
		t.Errorf("Description() = %q", got)
	}
	if got := p.Category(); got != "Old Category" {
		t.Errorf("Category() = %q", got)
	}
	if got := p.Parsed(scanaccess.Token{}).Severity; got != types.SeverityModerate {
		t.Errorf("Severity = %q, want Moderate from the legacy key", got)
	}
}
