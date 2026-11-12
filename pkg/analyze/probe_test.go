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
      "security.cenroq.io/displayName": "Privileged container",
      "security.cenroq.io/description": "Runs a container with full host privileges",
      "security.cenroq.io/category": "Workload Escape",
      "security.cenroq.io/severity": "Critical",
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
func TestNewProbeStripsOwnAnnotations(t *testing.T) {
	p, err := analyze.NewProbe(object(t, annotatedProbe), "")
	if err != nil {
		t.Fatalf("NewProbe: %v", err)
	}

	got := p.Object.GetAnnotations()
	for key := range got {
		if strings.HasPrefix(key, "analyze.kubeapt.io/") || strings.HasPrefix(key, "security.cenroq.io/") {
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
	  "metadata": {"name": "p", "annotations": {"security.cenroq.io/severity": "High"}},
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
	if input.GetAnnotations()["security.cenroq.io/severity"] != "Critical" {
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
		t.Errorf("no finding id: DocsURL() = %q, want empty", got)
	}
	if got := (analyze.Probe{FindingID: "oq-0276"}).DocsURL(); got != policies.DocsBaseURL+"/oq-0276" {
		t.Errorf("DocsURL() = %q", got)
	}
}

// cenroq.io/finding is the id; kubeapt.io/uuid is still read so today's
// bundles keep their policy join, but it is flagged so the CLI can warn.
func TestNewProbeReadsFindingID(t *testing.T) {
	tests := []struct {
		name           string
		annotations    string
		wantID         string
		wantDeprecated bool
	}{
		{"finding", `"cenroq.io/finding":"  oq-0276  "`, "oq-0276", false},
		{"legacy uuid", `"kubeapt.io/uuid":"23ef68db"`, "23ef68db", true},
		{"finding wins", `"cenroq.io/finding":"oq-0276","kubeapt.io/uuid":"23ef68db"`, "oq-0276", false},
		{"blank finding falls back", `"cenroq.io/finding":"  ","kubeapt.io/uuid":"23ef68db"`, "23ef68db", true},
		{"neither", `"example.com/other":"x"`, "", false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			raw := `{"apiVersion":"v1","kind":"Pod","metadata":{"name":"p","annotations":{` + tc.annotations + `}}}`
			p, err := analyze.NewProbe(object(t, raw), "")
			if err != nil {
				t.Fatalf("NewProbe: %v", err)
			}
			if p.FindingID != tc.wantID || p.DeprecatedID != tc.wantDeprecated {
				t.Errorf("FindingID %q DeprecatedID %v, want %q %v", p.FindingID, p.DeprecatedID, tc.wantID, tc.wantDeprecated)
			}
			// Neither id may alter the object under test.
			annotations := p.Object.GetAnnotations()
			for _, key := range []string{analyze.AnnotationFinding, policies.AnnotationUUID} {
				if _, present := annotations[key]; present {
					t.Errorf("%s reached the object under test", key)
				}
			}
		})
	}
}

// Shipped probes violate their policy *through* annotations. Stripping one of
// those would submit a compliant object and report a false pass, so only
// kubeapt's own prefixes and the exact cenroq keys may go: other cenroq.io and
// security.cenroq.io annotations belong to the object under test.
func TestNewProbeKeepsViolatingAnnotations(t *testing.T) {
	raw := `{"apiVersion":"v1","kind":"Pod","metadata":{"name":"p","annotations":{
	  "container.apparmor.security.beta.kubernetes.io/main": "unconfined",
	  "nginx.ingress.kubernetes.io/server-snippet": "return 200;",
	  "cenroq.io/owner": "team-a",
	  "pss.security.cenroq.io/enforce": "restricted",
	  "security.cenroq.io/enforce": "disabled",
	  "cenroq.io/finding": "oq-0276",
	  "kubeapt.io/uuid": "u",
	  "analyze.kubeapt.io/id": "i",
	  "security.cenroq.io/severity": "High",
	  "security.cenroq.io/product": "kubernetes",
	  "security.kubeapt.io/severity": "High",
	  "security.kubeapt.io/remediation": "fix it"
	}}}`
	p, err := analyze.NewProbe(object(t, raw), "")
	if err != nil {
		t.Fatalf("NewProbe: %v", err)
	}
	got := p.Object.GetAnnotations()
	want := map[string]string{
		"container.apparmor.security.beta.kubernetes.io/main": "unconfined",
		"nginx.ingress.kubernetes.io/server-snippet":          "return 200;",
		"cenroq.io/owner":                "team-a",
		"pss.security.cenroq.io/enforce": "restricted",
		"security.cenroq.io/enforce":     "disabled",
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

// Probe metadata reads security.cenroq.io first and falls back to the legacy
// security.kubeapt.io keys, reporting the fallback so the CLI can warn.
func TestNewProbeReadsLegacyMetadata(t *testing.T) {
	tests := []struct {
		name           string
		annotations    string
		wantTitle      string
		wantSeverity   types.Severity
		wantCategory   string
		wantDeprecated bool
	}{
		{
			name:         "cenroq keys",
			annotations:  `"security.cenroq.io/displayName":"New","security.cenroq.io/severity":"High","security.cenroq.io/category":"Escape"`,
			wantTitle:    "New",
			wantSeverity: types.SeverityHigh,
			wantCategory: "Escape",
		},
		{
			name:           "legacy keys",
			annotations:    `"security.kubeapt.io/displayName":"Old","security.kubeapt.io/severity":"Low","security.kubeapt.io/category":"Old Cat"`,
			wantTitle:      "Old",
			wantSeverity:   types.SeverityLow,
			wantCategory:   "Old Cat",
			wantDeprecated: true,
		},
		{
			name: "cenroq wins over legacy",
			annotations: `"security.cenroq.io/displayName":"New","security.kubeapt.io/displayName":"Old",` +
				`"security.cenroq.io/severity":"Critical","security.kubeapt.io/severity":"Low"`,
			wantTitle:    "New",
			wantSeverity: types.SeverityCritical,
		},
		{
			name:           "legacy fills a gap the cenroq keys leave",
			annotations:    `"security.cenroq.io/displayName":"New","security.kubeapt.io/severity":"Moderate"`,
			wantTitle:      "New",
			wantSeverity:   types.SeverityModerate,
			wantDeprecated: true,
		},
		{
			name:         "kyverno title but never kyverno severity",
			annotations:  `"policies.kyverno.io/title":"Kyverno","policies.kyverno.io/severity":"high"`,
			wantTitle:    "Kyverno",
			wantSeverity: types.SeverityNotRated,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			raw := `{"apiVersion":"v1","kind":"Pod","metadata":{"name":"p","annotations":{` + tc.annotations + `}}}`
			p, err := analyze.NewProbe(object(t, raw), "")
			if err != nil {
				t.Fatalf("NewProbe: %v", err)
			}
			if p.DisplayName != tc.wantTitle || p.Severity != tc.wantSeverity || p.Category != tc.wantCategory {
				t.Errorf("DisplayName %q Severity %q Category %q, want %q %q %q",
					p.DisplayName, p.Severity, p.Category, tc.wantTitle, tc.wantSeverity, tc.wantCategory)
			}
			if p.DeprecatedAnnotations != tc.wantDeprecated {
				t.Errorf("DeprecatedAnnotations = %v, want %v", p.DeprecatedAnnotations, tc.wantDeprecated)
			}
		})
	}
}
