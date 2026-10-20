// Copyright by cenroq AG
// Contact: info@cenroq.com

package analyze_test

import (
	"strings"
	"testing"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"

	"github.com/cenroq/kubeapt/v2/pkg/analyze"
	"github.com/cenroq/kubeapt/v2/pkg/policies"
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

// The policy's title wins over the probe's because a shipped deny manifest has
// none of its own; the probe's description wins because one it does carry is
// more specific than its policy's.
func TestProbeTitleAndSummaryFallbacks(t *testing.T) {
	tests := []struct {
		name        string
		probe       analyze.Probe
		wantTitle   string
		wantSummary string
	}{
		{
			name:        "no policy",
			probe:       analyze.Probe{DisplayName: "Pod p", Description: "own"},
			wantTitle:   "Pod p",
			wantSummary: "own",
		},
		{
			name:        "policy titled",
			probe:       analyze.Probe{DisplayName: "Pod p", Policy: &analyze.PolicyRef{DisplayName: "Host PID", Description: "policy"}},
			wantTitle:   "Host PID",
			wantSummary: "policy",
		},
		{
			name:        "policy untitled",
			probe:       analyze.Probe{DisplayName: "Pod p", Description: "own", Policy: &analyze.PolicyRef{Name: "pod-hostpid", Description: "policy"}},
			wantTitle:   "Pod p",
			wantSummary: "own",
		},
		{
			name:        "nothing",
			probe:       analyze.Probe{},
			wantTitle:   "",
			wantSummary: "",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.probe.Title(); got != tc.wantTitle {
				t.Errorf("Title() = %q, want %q", got, tc.wantTitle)
			}
			if got := tc.probe.Summary(); got != tc.wantSummary {
				t.Errorf("Summary() = %q, want %q", got, tc.wantSummary)
			}
		})
	}
}

func TestProbeDocsURL(t *testing.T) {
	if got := (analyze.Probe{}).DocsURL(); got != "" {
		t.Errorf("no uuid: DocsURL() = %q, want empty", got)
	}
	if got := (analyze.Probe{UUID: "abc"}).DocsURL(); got != policies.DocsBaseURL+"/abc" {
		t.Errorf("DocsURL() = %q", got)
	}
}

func TestNewProbeReadsAndStripsUUID(t *testing.T) {
	raw := `{"apiVersion":"v1","kind":"Pod","metadata":{"name":"p","annotations":{"kubeapt.io/uuid":"  abc  "}}}`
	p, err := analyze.NewProbe(object(t, raw), "")
	if err != nil {
		t.Fatalf("NewProbe: %v", err)
	}
	if p.UUID != "abc" {
		t.Errorf("UUID = %q, want trimmed abc", p.UUID)
	}
	if _, present := p.Object.GetAnnotations()[analyze.AnnotationUUID]; present {
		t.Error("kubeapt.io/uuid reached the object under test")
	}
}

// Shipped probes violate their policy *through* annotations. Stripping one of
// those would submit a compliant object and report a false pass, so only
// kubeapt's own prefixes may go.
func TestNewProbeKeepsViolatingAnnotations(t *testing.T) {
	raw := `{"apiVersion":"v1","kind":"Pod","metadata":{"name":"p","annotations":{
	  "container.apparmor.security.beta.kubernetes.io/main": "unconfined",
	  "nginx.ingress.kubernetes.io/server-snippet": "return 200;",
	  "kubeapt.io/uuid": "u",
	  "analyze.kubeapt.io/id": "i",
	  "security.kubeapt.io/severity": "High"
	}}}`
	p, err := analyze.NewProbe(object(t, raw), "")
	if err != nil {
		t.Fatalf("NewProbe: %v", err)
	}
	got := p.Object.GetAnnotations()
	want := map[string]string{
		"container.apparmor.security.beta.kubernetes.io/main": "unconfined",
		"nginx.ingress.kubernetes.io/server-snippet":          "return 200;",
	}
	if len(got) != len(want) {
		t.Fatalf("annotations = %v, want %v", got, want)
	}
	for key, value := range want {
		if got[key] != value {
			t.Errorf("annotation %s = %q, want %q", key, got[key], value)
		}
	}
}
