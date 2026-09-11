// Copyright by cenroq AG
// Contact: info@cenroq.com

package analyze_test

import (
	"strings"
	"testing"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"

	"github.com/cenroq/kubeapt/v2/pkg/analyze"
	"github.com/cenroq/kubeapt/v2/pkg/types"
)

const annotatedProbe = `{
  "apiVersion": "v1",
  "kind": "Pod",
  "metadata": {
    "name": "privileged",
    "annotations": {
      "analyze.kubeapt.io/id": "priv-container",
      "analyze.kubeapt.io/expect": "blocked",
      "security.kubeapt.io/displayName": "Privileged container",
      "security.kubeapt.io/description": "Runs a container with full host privileges",
      "security.kubeapt.io/category": "Workload Escape",
      "security.kubeapt.io/severity": "Critical",
      "example.com/keep-me": "yes"
    }
  },
  "spec": {"containers": [{"name": "app", "securityContext": {"privileged": true}}]}
}`

func TestNewProbeReadsMetadata(t *testing.T) {
	p, err := analyze.NewProbe(object(t, annotatedProbe), "/bundle/probes/privileged-pod.yaml")
	if err != nil {
		t.Fatalf("NewProbe: %v", err)
	}

	if p.ID != "priv-container" {
		t.Errorf("ID = %q", p.ID)
	}
	if p.DisplayName != "Privileged container" {
		t.Errorf("DisplayName = %q", p.DisplayName)
	}
	if p.Description != "Runs a container with full host privileges" {
		t.Errorf("Description = %q", p.Description)
	}
	if p.Category != "Workload Escape" {
		t.Errorf("Category = %q", p.Category)
	}
	if p.Severity != types.SeverityCritical {
		t.Errorf("Severity = %q", p.Severity)
	}
	if p.Expect != analyze.ExpectBlocked {
		t.Errorf("Expect = %q", p.Expect)
	}
	if p.SourceFile != "/bundle/probes/privileged-pod.yaml" {
		t.Errorf("SourceFile = %q", p.SourceFile)
	}
}

// A policy is free to match on annotations, so the object on the wire must be
// the dangerous object and nothing else.
func TestNewProbeStripsKubeaptAnnotations(t *testing.T) {
	p, err := analyze.NewProbe(object(t, annotatedProbe), "")
	if err != nil {
		t.Fatalf("NewProbe: %v", err)
	}

	got := p.Object.GetAnnotations()
	for key := range got {
		if strings.HasPrefix(key, "analyze.kubeapt.io/") || strings.HasPrefix(key, "security.kubeapt.io/") {
			t.Errorf("annotation %q survived stripping", key)
		}
	}
	if got["example.com/keep-me"] != "yes" {
		t.Errorf("third-party annotation was dropped: %v", got)
	}
}

func TestNewProbeRemovesEmptyAnnotationsBlock(t *testing.T) {
	raw := `{
	  "apiVersion": "v1",
	  "kind": "Pod",
	  "metadata": {"name": "p", "annotations": {"security.kubeapt.io/severity": "High"}},
	  "spec": {}
	}`
	p, err := analyze.NewProbe(object(t, raw), "")
	if err != nil {
		t.Fatalf("NewProbe: %v", err)
	}

	metadata, _, _ := unstructured.NestedMap(p.Object.Object, "metadata")
	if _, present := metadata["annotations"]; present {
		t.Fatalf("empty annotations block left behind: %v", metadata)
	}
}

func TestNewProbeDoesNotMutateInput(t *testing.T) {
	input := object(t, annotatedProbe)
	if _, err := analyze.NewProbe(input, ""); err != nil {
		t.Fatalf("NewProbe: %v", err)
	}
	if input.GetAnnotations()["security.kubeapt.io/severity"] != "Critical" {
		t.Fatal("NewProbe mutated the caller's object")
	}
}

func TestNewProbeExpectDefaultsToBlocked(t *testing.T) {
	p, err := analyze.NewProbe(object(t, `{"apiVersion":"v1","kind":"Pod","metadata":{"name":"p"}}`), "")
	if err != nil {
		t.Fatalf("NewProbe: %v", err)
	}
	if p.Expect != analyze.ExpectBlocked {
		t.Fatalf("Expect = %q, want blocked", p.Expect)
	}
}

func TestNewProbeExpectAllowed(t *testing.T) {
	raw := `{"apiVersion":"v1","kind":"Pod","metadata":{"name":"p","annotations":{"analyze.kubeapt.io/expect":"Allowed"}}}`
	p, err := analyze.NewProbe(object(t, raw), "")
	if err != nil {
		t.Fatalf("NewProbe: %v", err)
	}
	if p.Expect != analyze.ExpectAllowed {
		t.Fatalf("Expect = %q, want allowed", p.Expect)
	}
}

// A typo must not silently invert a probe's meaning and turn a finding into a
// pass, so an unrecognised value is an error rather than a default.
func TestNewProbeRejectsInvalidExpect(t *testing.T) {
	raw := `{"apiVersion":"v1","kind":"Pod","metadata":{"name":"p","annotations":{"analyze.kubeapt.io/expect":"blocke"}}}`
	_, err := analyze.NewProbe(object(t, raw), "")
	if err == nil {
		t.Fatal("expected an error for an invalid expect value")
	}
	if !strings.Contains(err.Error(), "blocke") {
		t.Fatalf("error should name the bad value: %v", err)
	}
}

func TestNewProbeIDFallbacks(t *testing.T) {
	tests := []struct {
		name       string
		raw        string
		sourceFile string
		want       string
	}{
		{
			name:       "filename stem",
			raw:        `{"apiVersion":"v1","kind":"Pod","metadata":{"name":"anything"}}`,
			sourceFile: "/bundle/probes/hostpath-mount.yaml",
			want:       "hostpath-mount",
		},
		{
			name: "kind and name",
			raw:  `{"apiVersion":"v1","kind":"Pod","metadata":{"name":"anything"}}`,
			want: "pod-anything",
		},
		{
			name: "kind only",
			raw:  `{"apiVersion":"rbac.authorization.k8s.io/v1","kind":"ClusterRole"}`,
			want: "clusterrole",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			p, err := analyze.NewProbe(object(t, tc.raw), tc.sourceFile)
			if err != nil {
				t.Fatalf("NewProbe: %v", err)
			}
			if p.ID != tc.want {
				t.Fatalf("ID = %q, want %q", p.ID, tc.want)
			}
		})
	}
}

func TestNewProbeDisplayNameFallsBackToKindAndName(t *testing.T) {
	p, err := analyze.NewProbe(object(t, `{"apiVersion":"v1","kind":"Pod","metadata":{"name":"host-pid"}}`), "")
	if err != nil {
		t.Fatalf("NewProbe: %v", err)
	}
	if p.DisplayName != "Pod host-pid" {
		t.Fatalf("DisplayName = %q", p.DisplayName)
	}
}

func TestNewProbeAcceptsKyvernoTitleAndDescription(t *testing.T) {
	raw := `{
	  "apiVersion": "v1",
	  "kind": "Pod",
	  "metadata": {"name": "p", "annotations": {
	    "policies.kyverno.io/title": "Host PID",
	    "policies.kyverno.io/description": "Shares the host process namespace",
	    "policies.kyverno.io/category": "Pod Security"
	  }}
	}`
	p, err := analyze.NewProbe(object(t, raw), "")
	if err != nil {
		t.Fatalf("NewProbe: %v", err)
	}
	if p.DisplayName != "Host PID" || p.Description != "Shares the host process namespace" || p.Category != "Pod Security" {
		t.Fatalf("kyverno annotations not read: %+v", p)
	}
}

func TestNewProbeUnannotatedSeverityIsNotRated(t *testing.T) {
	p, err := analyze.NewProbe(object(t, `{"apiVersion":"v1","kind":"Pod","metadata":{"name":"p"}}`), "")
	if err != nil {
		t.Fatalf("NewProbe: %v", err)
	}
	if p.Severity != types.SeverityNotRated {
		t.Fatalf("Severity = %q, want Not Rated", p.Severity)
	}
}

func TestNewProbeRejectsInvalidObjects(t *testing.T) {
	tests := []struct {
		name string
		obj  *unstructured.Unstructured
	}{
		{"nil", nil},
		{"empty", &unstructured.Unstructured{Object: map[string]any{}}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := analyze.NewProbe(tc.obj, ""); err == nil {
				t.Fatal("expected an error")
			}
		})
	}

	t.Run("missing kind", func(t *testing.T) {
		if _, err := analyze.NewProbe(object(t, `{"metadata":{"name":"p"}}`), ""); err == nil {
			t.Fatal("expected an error for a missing apiVersion and kind")
		}
	})
}
