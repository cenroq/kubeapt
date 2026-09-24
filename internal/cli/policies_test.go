package cli

import (
    "os"
    "path/filepath"
    "testing"

    admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
    metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

    "github.com/cenroq/kubeapt/v2/internal/config"
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
                policyAnnotationDisplayName: "Demo",
                policyAnnotationSeverity:    "high",
                policyAnnotationUUID:        testPolicyUUID,
            },
        },
    }
    ann := policyAnnotationsFrom(policy)
    if ann.DisplayName != "Demo" || ann.Severity != "high" {
        t.Fatalf("unexpected annotations: %+v", ann)
    }
    if want := policyDocsBaseURL + "/" + testPolicyUUID; ann.URL != want {
        t.Fatalf("URL = %q, want %q", ann.URL, want)
    }

    bare := admissionregistrationv1.ValidatingAdmissionPolicy{
        ObjectMeta: metav1.ObjectMeta{
            Annotations: map[string]string{policyAnnotationDisplayName: "Demo"},
        },
    }
    if got := policyAnnotationsFrom(bare); got.URL != "" {
        t.Fatalf("policy without a uuid must have no URL, got %q", got.URL)
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
