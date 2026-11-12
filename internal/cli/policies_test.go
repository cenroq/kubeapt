package cli

import (
    "os"
    "path/filepath"
    "testing"

    admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
    metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

    "github.com/cenroq/kubeapt/v2/internal/config"
    "github.com/cenroq/kubeapt/v2/pkg/policies"
)

func setHome(t *testing.T) {
    t.Helper()
    home := t.TempDir()
    t.Setenv("HOME", home)
}

func TestPolicyIndexHelpers(t *testing.T) {
    index := policiesIndex{
        LatestVersion: "1.2.3",
        Versions:      []string{"1.0.0", "1.2.3"},
        Policies:      []policiesIndexItem{{Name: "demo", File: "demo.yaml"}},
    }

    if v, err := resolvePolicyVersion(index, ""); err != nil || v != "1.2.3" {
        t.Fatalf("unexpected resolvePolicyVersion: %v %v", v, err)
    }
    if _, ok := findPolicyIndexEntry(index, "demo"); !ok {
        t.Fatalf("expected to find policy index entry")
    }
    if !policyVersionInIndex(index, "1.0.0") {
        t.Fatalf("expected version to be in index")
    }
    if policiesArchiveURL("1.0.0") == "" {
        t.Fatalf("expected archive URL")
    }
}

func TestPolicyFilePath(t *testing.T) {
    setHome(t)

    dir, err := config.PolicyVersionDir("1.0.0")
    if err != nil {
        t.Fatalf("failed to get policy dir: %v", err)
    }
    if err := os.MkdirAll(dir, 0o755); err != nil {
        t.Fatalf("failed to create policy dir: %v", err)
    }

    file := filepath.Join(dir, "demo.yaml")
    if err := os.WriteFile(file, []byte("x"), 0o644); err != nil {
        t.Fatalf("failed to write policy file: %v", err)
    }

    if got, err := policyFilePath("1.0.0", "demo.yaml"); err != nil || got != file {
        t.Fatalf("unexpected policyFilePath: %v %v", got, err)
    }

    if _, err := policyFilePath("1.0.0", "missing.yaml"); err == nil {
        t.Fatalf("expected error for missing file")
    }
}

func TestPolicyAnnotationsFrom(t *testing.T) {
    policy := admissionregistrationv1.ValidatingAdmissionPolicy{
        ObjectMeta: metav1.ObjectMeta{
            Annotations: map[string]string{
                policies.AnnotationDisplayName: "Demo",
                policies.AnnotationSeverity:    "high",
                policies.AnnotationResource:    "pods",
                policies.AnnotationRemediation: "drop it",
                policies.AnnotationProduct:     "kubernetes",
                policies.AnnotationDescription: "describes",
                policies.AnnotationFinding:     " oq-0327 ",
            },
        },
    }
    ann := policyAnnotationsFrom(policy)
    want := policyAnnotations{DisplayName: "Demo", Description: "describes", Resource: "pods", Severity: "high", Remediation: "drop it", Product: "kubernetes",
        Finding: "oq-0327", Docs: policies.DocsBaseURL + "/oq-0327"}
    if ann != want {
        t.Fatalf("annotations = %+v, want %+v", ann, want)
    }
}

func TestPolicyAnnotationsFromWithoutAnnotations(t *testing.T) {
    if got := policyAnnotationsFrom(admissionregistrationv1.ValidatingAdmissionPolicy{}); got != (policyAnnotations{}) {
        t.Fatalf("annotations = %+v, want zero value", got)
    }
}

// Policy sets published before the switch carry only security.kubeapt.io
// keys; they must still be shown, and security.cenroq.io wins when both exist.
func TestPolicyAnnotationsFromLegacyKeys(t *testing.T) {
    policy := admissionregistrationv1.ValidatingAdmissionPolicy{
        ObjectMeta: metav1.ObjectMeta{
            Annotations: map[string]string{
                policies.LegacyAnnotationDisplayName: "Old",
                policies.LegacyAnnotationDescription: "old description",
                policies.LegacyAnnotationResource:    "pods",
                policies.LegacyAnnotationSeverity:    "low",
                policies.LegacyAnnotationRemediation: "old fix",
                policies.LegacyAnnotationProduct:     "kubernetes",
                policies.AnnotationDisplayName:       "New",
                policies.AnnotationUUID:              "23ef68db",
            },
        },
    }
    ann := policyAnnotationsFrom(policy)
    want := policyAnnotations{DisplayName: "New", Description: "old description", Resource: "pods", Severity: "low", Remediation: "old fix", Product: "kubernetes",
        Finding: "23ef68db", Docs: policies.DocsBaseURL + "/23ef68db"}
    if ann != want {
        t.Fatalf("annotations = %+v, want %+v", ann, want)
    }
}

func TestToValidatingAdmissionPolicy(t *testing.T) {
    obj := map[string]interface{}{
        "apiVersion": "admissionregistration.k8s.io/v1",
        "kind":       "ValidatingAdmissionPolicy",
        "metadata": map[string]interface{}{
            "name": "demo",
        },
    }
    policy, err := toValidatingAdmissionPolicy(obj)
    if err != nil {
        t.Fatalf("unexpected error: %v", err)
    }
    if policy.Name != "demo" {
        t.Fatalf("unexpected policy name: %s", policy.Name)
    }
}
