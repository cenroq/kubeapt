// Copyright by cenroq AG
// Contact: info@cenroq.com

package cli

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/cenroq/kubeapt/v2/pkg/policies"
)

const validateAnnotationPolicyYAML = `apiVersion: admissionregistration.k8s.io/v1
kind: ValidatingAdmissionPolicy
metadata:
  name: no-hostpid
  annotations:
    security.cenroq.io/displayName: "No host PID"
    security.cenroq.io/severity: "High"
spec:
  failurePolicy: Fail
  matchConstraints:
    resourceRules:
      - apiGroups: [""]
        apiVersions: ["v1"]
        operations: ["CREATE"]
        resources: ["pods"]
  validations:
    - expression: "!has(object.spec.hostPID) || object.spec.hostPID == false"
      message: "hostPID is not allowed"
`

const validateAnnotationPodYAML = `apiVersion: v1
kind: Pod
metadata:
  name: bad
  namespace: default
spec:
  hostPID: true
  containers:
  - name: app
    image: nginx
`

// A policy set published before the switch to security.cenroq.io still rates
// its policies, and leaves both streams clean: the deprecation note is debug
// level only for now (see logDeprecatedPolicyAnnotations).
func TestValidateReadsLegacyAnnotationsQuietly(t *testing.T) {
	tests := []struct {
		name   string
		policy string
	}{
		{"legacy annotations", strings.ReplaceAll(validateAnnotationPolicyYAML, "security.cenroq.io/", "security.kubeapt.io/")},
		{"cenroq annotations", validateAnnotationPolicyYAML},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			isolateCluster(t, "")
			dir := t.TempDir()
			policyPath := filepath.Join(dir, "policy.yaml")
			podPath := filepath.Join(dir, "pod.yaml")
			for path, content := range map[string]string{policyPath: tc.policy, podPath: validateAnnotationPodYAML} {
				if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
					t.Fatal(err)
				}
			}

			var stdout, stderr bytes.Buffer
			cmd := ValidateCmd(func() string { return "info" })
			cmd.SilenceUsage = true
			cmd.SilenceErrors = true
			cmd.SetOut(&stdout)
			cmd.SetErr(&stderr)
			cmd.SetArgs([]string{"-p", policyPath, "-r", podPath, "--ignore-bindings", "-f", "json"})
			if err := cmd.Execute(); err != nil {
				t.Fatalf("validate: %v\nstderr:\n%s", err, stderr.String())
			}

			if strings.Contains(stderr.String(), "deprecated security.kubeapt.io/*") {
				t.Fatalf("deprecation note printed at the default level; stderr:\n%s", stderr.String())
			}
			var envelope struct {
				Results struct {
					Bindings []struct {
						Policy   string `json:"policy"`
						Severity string `json:"severity"`
					} `json:"bindings"`
				} `json:"results"`
			}
			if err := json.Unmarshal(stdout.Bytes(), &envelope); err != nil {
				t.Fatalf("stdout is not JSON (%v):\n%s", err, stdout.String())
			}
			if len(envelope.Results.Bindings) != 1 || envelope.Results.Bindings[0].Severity != "High" {
				t.Errorf("bindings = %+v, want one High binding either way", envelope.Results.Bindings)
			}
		})
	}
}

func TestDeprecatedPolicyAnnotationsNote(t *testing.T) {
	items := []admissionregistrationv1.ValidatingAdmissionPolicy{
		{ObjectMeta: metav1.ObjectMeta{Name: "legacy", Annotations: map[string]string{policies.LegacyAnnotationSeverity: "High"}}},
		{ObjectMeta: metav1.ObjectMeta{Name: "partial", Annotations: map[string]string{policies.AnnotationSeverity: "High", policies.LegacyAnnotationProduct: "k8s"}}},
		{ObjectMeta: metav1.ObjectMeta{Name: "cenroq", Annotations: map[string]string{policies.AnnotationSeverity: "High"}}},
		{ObjectMeta: metav1.ObjectMeta{Name: "bare"}},
	}
	note := deprecatedPolicyAnnotationsNote(items)
	if !strings.HasPrefix(note, "2 policy(ies)") || !strings.Contains(note, "deprecated security.kubeapt.io/*") ||
		!strings.Contains(note, "security.cenroq.io/*") {
		t.Errorf("note = %q", note)
	}
	clean := []admissionregistrationv1.ValidatingAdmissionPolicy{
		{ObjectMeta: metav1.ObjectMeta{Name: "cenroq", Annotations: map[string]string{policies.AnnotationSeverity: "High"}}},
	}
	if note := deprecatedPolicyAnnotationsNote(clean); note != "" {
		t.Errorf("clean policies note = %q, want none", note)
	}

	// Debug level only: at the default level nothing is printed.
	log := captureLog(t)
	logDeprecatedPolicyAnnotations(items)
	if log.Len() != 0 {
		t.Errorf("logged at the default level: %q", log.String())
	}
}
