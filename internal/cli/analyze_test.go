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

	"github.com/jedib0t/go-pretty/v6/table"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"

	"github.com/cenroq/kubeapt/v2/pkg/analyze"
	"github.com/cenroq/kubeapt/v2/pkg/types"
)

const privilegedProbeYAML = `apiVersion: v1
kind: Pod
metadata:
  name: privileged-probe
  annotations:
    analyze.kubeapt.io/id: privileged-container
    security.kubeapt.io/displayName: Privileged container
    security.kubeapt.io/severity: Critical
spec:
  containers:
    - name: app
      image: busybox
      securityContext:
        privileged: true
`

const hostPathProbeYAML = `apiVersion: v1
kind: Pod
metadata:
  name: hostpath-probe
  annotations:
    security.kubeapt.io/severity: High
spec:
  containers:
    - name: app
      image: busybox
  volumes:
    - name: host
      hostPath:
        path: /
`

func writeProbeDir(t *testing.T, files map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	for name, body := range files {
		path := filepath.Join(dir, name)
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatalf("mkdir: %v", err)
		}
		if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
	}
	return dir
}

func TestParseAnalyzeFlagsValidation(t *testing.T) {
	tests := []struct {
		name    string
		args    []string
		wantErr string
	}{
		{
			name:    "invalid format",
			args:    []string{"--format", "yaml"},
			wantErr: "invalid format yaml, expected table or json",
		},
		{
			name:    "invalid report",
			args:    []string{"--report", "everything"},
			wantErr: "invalid report everything, expected summary or all",
		},
		{
			name:    "zero timeout",
			args:    []string{"--timeout", "0s"},
			wantErr: "--timeout must be greater than zero",
		},
		{
			name:    "negative timeout",
			args:    []string{"--timeout", "-5s"},
			wantErr: "--timeout must be greater than zero",
		},
		{
			name:    "probes with bundle",
			args:    []string{"--probes", "./probes", "--bundle", "other"},
			wantErr: "--probes cannot be combined with --bundle",
		},
		{
			name:    "probes with bundle-version",
			args:    []string{"--probes", "./probes", "--bundle-version", "1.0.0"},
			wantErr: "--bundle-version cannot be combined with --probes",
		},
		{
			name:    "bundle-version without bundle",
			args:    []string{"--bundle-version", "1.0.0"},
			wantErr: "--bundle-version requires --bundle",
		},
		{
			name:    "all-namespaces with namespaces",
			args:    []string{"--all-namespaces", "--namespaces", "prod"},
			wantErr: "--all-namespaces cannot be used together with --namespaces",
		},
		{
			name:    "selector with all-namespaces",
			args:    []string{"--namespace-selector", "env=prod", "--all-namespaces"},
			wantErr: "--namespace-selector cannot be used together with --all-namespaces or --namespaces",
		},
		{
			name:    "selector with namespaces",
			args:    []string{"--namespace-selector", "env=prod", "--namespaces", "prod"},
			wantErr: "--namespace-selector cannot be used together with --all-namespaces or --namespaces",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cmd := AnalyzeCmd()
			if err := cmd.ParseFlags(tc.args); err != nil {
				t.Fatalf("ParseFlags: %v", err)
			}
			_, err := parseAnalyzeFlags(cmd)
			if err == nil {
				t.Fatalf("expected an error")
			}
			if err.Error() != tc.wantErr {
				t.Fatalf("error = %q, want %q", err.Error(), tc.wantErr)
			}
		})
	}
}

func TestParseAnalyzeFlagsDefaults(t *testing.T) {
	cmd := AnalyzeCmd()
	if err := cmd.ParseFlags(nil); err != nil {
		t.Fatalf("ParseFlags: %v", err)
	}
	request, err := parseAnalyzeFlags(cmd)
	if err != nil {
		t.Fatalf("parseAnalyzeFlags: %v", err)
	}
	if request.bundleName != defaultProbeBundle {
		t.Errorf("bundle = %q, want %q", request.bundleName, defaultProbeBundle)
	}
	if request.outputFormat != "table" || request.reportMode != "summary" {
		t.Errorf("format/report = %q/%q", request.outputFormat, request.reportMode)
	}
	if request.timeout.Seconds() != 30 {
		t.Errorf("timeout = %v", request.timeout)
	}
	if request.pipeline {
		t.Error("pipeline should default to false")
	}
}

func TestParseAnalyzeFlagsCommaLists(t *testing.T) {
	cmd := AnalyzeCmd()
	if err := cmd.ParseFlags([]string{"--probe", " a , b ,, c ", "--namespaces", "prod,staging"}); err != nil {
		t.Fatalf("ParseFlags: %v", err)
	}
	request, err := parseAnalyzeFlags(cmd)
	if err != nil {
		t.Fatalf("parseAnalyzeFlags: %v", err)
	}
	if strings.Join(request.probeIDs, "|") != "a|b|c" {
		t.Errorf("probeIDs = %v", request.probeIDs)
	}
	if strings.Join(request.namespaces, "|") != "prod|staging" {
		t.Errorf("namespaces = %v", request.namespaces)
	}
}

func TestLoadProbesFromDirectory(t *testing.T) {
	dir := writeProbeDir(t, map[string]string{
		"privileged.yaml":      privilegedProbeYAML,
		"nested/hostpath.yaml": hostPathProbeYAML,
	})

	probes, err := loadProbes(analyzeRequest{probesPath: dir})
	if err != nil {
		t.Fatalf("loadProbes: %v", err)
	}
	if len(probes) != 2 {
		t.Fatalf("loaded %d probes, want 2", len(probes))
	}
	// Sorted by id: the annotated one, then the filename-derived one.
	if probes[0].ID != "hostpath" || probes[1].ID != "privileged-container" {
		t.Fatalf("ids = %q, %q", probes[0].ID, probes[1].ID)
	}
	if probes[1].Severity != types.SeverityCritical {
		t.Errorf("severity = %q", probes[1].Severity)
	}
	if probes[1].DisplayName != "Privileged container" {
		t.Errorf("display name = %q", probes[1].DisplayName)
	}
	// kubeapt's own annotations must not reach the API server.
	if _, present := probes[1].Object.GetAnnotations()["security.kubeapt.io/severity"]; present {
		t.Error("probe annotations were not stripped")
	}
}

func TestLoadProbesFromSingleFile(t *testing.T) {
	dir := writeProbeDir(t, map[string]string{"privileged.yaml": privilegedProbeYAML})

	probes, err := loadProbes(analyzeRequest{probesPath: filepath.Join(dir, "privileged.yaml")})
	if err != nil {
		t.Fatalf("loadProbes: %v", err)
	}
	if len(probes) != 1 {
		t.Fatalf("loaded %d probes, want 1", len(probes))
	}
}

// A multi-document file cannot use the filename as an id for both documents,
// so the ids fall back to kind and name instead of colliding.
func TestLoadProbesMultiDocumentFile(t *testing.T) {
	dir := writeProbeDir(t, map[string]string{
		"pair.yaml": privilegedProbeYAML + "---\n" + hostPathProbeYAML,
	})

	probes, err := loadProbes(analyzeRequest{probesPath: dir})
	if err != nil {
		t.Fatalf("loadProbes: %v", err)
	}
	if len(probes) != 2 {
		t.Fatalf("loaded %d probes, want 2", len(probes))
	}
	if probes[0].ID != "pod-hostpath-probe" {
		t.Errorf("ids = %q, %q", probes[0].ID, probes[1].ID)
	}
}

func TestLoadProbesRejectsDuplicateIDs(t *testing.T) {
	dir := writeProbeDir(t, map[string]string{
		"a.yaml": privilegedProbeYAML,
		"b.yaml": privilegedProbeYAML,
	})

	_, err := loadProbes(analyzeRequest{probesPath: dir})
	if err == nil || !strings.Contains(err.Error(), "duplicate probe id") {
		t.Fatalf("expected a duplicate id error, got %v", err)
	}
}

func TestLoadProbesRejectsInvalidExpect(t *testing.T) {
	dir := writeProbeDir(t, map[string]string{
		"bad.yaml": `apiVersion: v1
kind: Pod
metadata:
  name: p
  annotations:
    analyze.kubeapt.io/expect: blocke
`,
	})

	_, err := loadProbes(analyzeRequest{probesPath: dir})
	if err == nil || !strings.Contains(err.Error(), "blocke") {
		t.Fatalf("expected an invalid expect error, got %v", err)
	}
}

func TestLoadProbesEmptyDirectory(t *testing.T) {
	_, err := loadProbes(analyzeRequest{probesPath: t.TempDir()})
	if err == nil || !strings.Contains(err.Error(), "no probe manifests found") {
		t.Fatalf("expected an empty-source error, got %v", err)
	}
}

func TestLoadProbesMissingPath(t *testing.T) {
	_, err := loadProbes(analyzeRequest{probesPath: filepath.Join(t.TempDir(), "absent")})
	if err == nil {
		t.Fatal("expected an error for a missing path")
	}
}

// A policy bundle has policies.yaml and bindings.yaml but no probes/, and the
// error has to say so rather than reporting an empty catalogue.
func TestResolveProbeSourceRejectsPolicyBundle(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	versionDir := filepath.Join(home, ".config", "kubeapt", "bundles", "pod-security-admission", "1.0.0")
	if err := os.MkdirAll(versionDir, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(versionDir, "policies.yaml"), []byte("{}\n"), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}

	_, err := resolveProbeSource(analyzeRequest{bundleName: "pod-security-admission"})
	if err == nil || !strings.Contains(err.Error(), "not a probe bundle") {
		t.Fatalf("expected a probe-bundle error, got %v", err)
	}
}

func TestResolveProbeSourceFindsProbesDirectory(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	probesDir := filepath.Join(home, ".config", "kubeapt", "bundles", "admission-probes", "2.0.0", "probes")
	if err := os.MkdirAll(probesDir, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}

	got, err := resolveProbeSource(analyzeRequest{bundleName: "admission-probes"})
	if err != nil {
		t.Fatalf("resolveProbeSource: %v", err)
	}
	if got != probesDir {
		t.Fatalf("got %q, want %q", got, probesDir)
	}
}

func TestResolveProbeSourceBundleNotInstalled(t *testing.T) {
	t.Setenv("HOME", t.TempDir())

	_, err := resolveProbeSource(analyzeRequest{bundleName: "admission-probes"})
	if err == nil || !strings.Contains(err.Error(), "is not installed") {
		t.Fatalf("expected a not-installed error, got %v", err)
	}
}

func TestFilterProbes(t *testing.T) {
	probes := []analyze.Probe{{ID: "a"}, {ID: "b"}, {ID: "c"}}

	selected, err := filterProbes(probes, []string{"c", "a"})
	if err != nil {
		t.Fatalf("filterProbes: %v", err)
	}
	if len(selected) != 2 || selected[0].ID != "a" || selected[1].ID != "c" {
		t.Fatalf("selected = %+v", selected)
	}

	if all, err := filterProbes(probes, nil); err != nil || len(all) != 3 {
		t.Fatalf("empty filter should pass everything: %v %d", err, len(all))
	}

	_, err = filterProbes(probes, []string{"a", "nope", "also-nope"})
	if err == nil || !strings.Contains(err.Error(), "also-nope, nope") {
		t.Fatalf("expected sorted unknown ids, got %v", err)
	}
}

func result(id string, severity types.Severity, verdict analyze.Verdict, namespace string) analyze.Result {
	return analyze.Result{
		Probe:     analyze.Probe{ID: id, Severity: severity, Object: &unstructured.Unstructured{Object: map[string]any{"kind": "Pod"}}},
		Namespace: namespace,
		Verdict:   verdict,
		Outcome:   analyze.OutcomeAdmitted,
	}
}

// Failures must be at the top of the report, ordered by how bad they are.
func TestSortAnalyzeResults(t *testing.T) {
	results := []analyze.Result{
		result("z-pass", types.SeverityLow, analyze.VerdictPass, "default"),
		result("b-fail-high", types.SeverityHigh, analyze.VerdictFail, "default"),
		result("a-warn", types.SeverityCritical, analyze.VerdictWarn, "default"),
		result("a-fail-critical", types.SeverityCritical, analyze.VerdictFail, "b"),
		result("a-fail-critical", types.SeverityCritical, analyze.VerdictFail, "a"),
		result("m-inconclusive", types.SeverityHigh, analyze.VerdictInconclusive, "default"),
	}
	sortAnalyzeResults(results)

	got := make([]string, 0, len(results))
	for _, r := range results {
		got = append(got, r.Probe.ID+"/"+r.Namespace)
	}
	want := []string{
		"a-fail-critical/a",
		"a-fail-critical/b",
		"b-fail-high/default",
		"a-warn/default",
		"m-inconclusive/default",
		"z-pass/default",
	}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("order =\n  %v\nwant\n  %v", got, want)
	}
}

func TestRenderAnalyzeTable(t *testing.T) {
	results := []analyze.Result{
		{
			Probe:     analyze.Probe{ID: "privileged", Severity: types.SeverityCritical, Object: &unstructured.Unstructured{Object: map[string]any{"kind": "Pod"}}},
			Namespace: "default",
			Outcome:   analyze.OutcomeAdmitted,
			Verdict:   analyze.VerdictFail,
		},
		{
			Probe:     analyze.Probe{ID: "hostpath", Severity: types.SeverityHigh, Object: &unstructured.Unstructured{Object: map[string]any{"kind": "Pod"}}},
			Namespace: "default",
			Outcome:   analyze.OutcomeBlocked,
			Verdict:   analyze.VerdictPass,
			Enforcer:  analyze.Enforcer{Type: analyze.EnforcerPSA, Name: "restricted:latest", Message: "violates PodSecurity"},
		},
	}
	summary := analyze.Summarize(results)

	var buf bytes.Buffer
	renderAnalyzeTable(results, summary, "summary", &buf, table.StyleDefault, false)
	out := buf.String()

	for _, want := range []string{"privileged", "hostpath", "Admitted", "Blocked", "PodSecurity restricted:latest", "Fail", "Pass"} {
		if !strings.Contains(out, want) {
			t.Errorf("table missing %q:\n%s", want, out)
		}
	}
	if strings.Contains(strings.ToUpper(out), "DETAIL") {
		t.Error("summary mode should not render the Detail column")
	}
}

func TestRenderAnalyzeTableReportAll(t *testing.T) {
	results := []analyze.Result{
		{
			Probe:     analyze.Probe{ID: "mutated", Object: &unstructured.Unstructured{Object: map[string]any{"kind": "Pod"}}},
			Namespace: "default",
			Outcome:   analyze.OutcomeMutated,
			Verdict:   analyze.VerdictWarn,
			Mutations: []string{"spec.containers[0].securityContext.privileged"},
		},
	}

	var buf bytes.Buffer
	renderAnalyzeTable(results, analyze.Summarize(results), "all", &buf, table.StyleDefault, false)
	out := buf.String()

	if !strings.Contains(strings.ToUpper(out), "DETAIL") {
		t.Errorf("report all should render the Detail column:\n%s", out)
	}
	if !strings.Contains(out, "changed spec.containers[0].securityContext.privileged") {
		t.Errorf("mutation paths missing:\n%s", out)
	}
}

func TestBuildAnalyzeJSON(t *testing.T) {
	results := []analyze.Result{
		{
			Probe: analyze.Probe{
				ID: "privileged", DisplayName: "Privileged container",
				Severity: types.SeverityCritical, Expect: analyze.ExpectBlocked,
				Object: &unstructured.Unstructured{Object: map[string]any{"apiVersion": "v1", "kind": "Pod"}},
			},
			Namespace: "default",
			Outcome:   analyze.OutcomeAdmitted,
			Verdict:   analyze.VerdictFail,
		},
		{
			Probe:     analyze.Probe{ID: "hostpath", Expect: analyze.ExpectBlocked, Object: &unstructured.Unstructured{Object: map[string]any{"kind": "Pod"}}},
			Namespace: "default",
			Outcome:   analyze.OutcomeBlocked,
			Verdict:   analyze.VerdictPass,
			Enforcer:  analyze.Enforcer{Type: analyze.EnforcerUnattributed, Message: "something new"},
		},
	}
	payload := buildAnalyzeJSON(results, analyze.Summarize(results))

	encoded, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var decoded analyzeJSONPayload
	if err := json.Unmarshal(encoded, &decoded); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if decoded.Summary.Total != 2 || decoded.Summary.Fail != 1 || decoded.Summary.Pass != 1 {
		t.Fatalf("summary = %+v", decoded.Summary)
	}
	if decoded.Summary.ByOutcome["Admitted"] != 1 {
		t.Errorf("byOutcome = %v", decoded.Summary.ByOutcome)
	}
	if decoded.Results[0].EnforcedBy != nil {
		t.Error("an admitted probe should carry no enforcer")
	}
	// An unrecognised denial still has to carry the server's own words.
	if decoded.Results[1].EnforcedBy == nil || decoded.Results[1].EnforcedBy.Message != "something new" {
		t.Errorf("unattributed message dropped: %+v", decoded.Results[1].EnforcedBy)
	}
}

func TestCollisionFreeName(t *testing.T) {
	got := collisionFreeName("privileged-probe")
	if !strings.HasPrefix(got, "privileged-probe-kubeapt-") {
		t.Fatalf("name = %q", got)
	}
	if got == collisionFreeName("privileged-probe") {
		t.Fatal("collision suffix is not random")
	}

	long := strings.Repeat("a", 300)
	if trimmed := collisionFreeName(long); len(trimmed) > 253 {
		t.Fatalf("name exceeds the API server limit: %d", len(trimmed))
	}
	if got := collisionFreeName(""); !strings.HasPrefix(got, "probe-kubeapt-") {
		t.Fatalf("empty base = %q", got)
	}
	if got := collisionFreeName("trailing-"); !strings.HasPrefix(got, "trailing-kubeapt-") {
		t.Fatalf("trailing separator not trimmed: %q", got)
	}
}

func TestDetailCell(t *testing.T) {
	tests := []struct {
		name   string
		result analyze.Result
		want   string
	}{
		{
			name:   "mutation paths",
			result: analyze.Result{Outcome: analyze.OutcomeMutated, Mutations: []string{"a", "b"}},
			want:   "changed a, b",
		},
		{
			name: "blocked shows the first line of the denial",
			result: analyze.Result{
				Outcome:  analyze.OutcomeBlocked,
				Enforcer: analyze.Enforcer{Message: "denied the request:\nbecause reasons"},
			},
			want: "denied the request:",
		},
		{
			name:   "inconclusive shows the reason",
			result: analyze.Result{Outcome: analyze.OutcomeInconclusive, Reason: analyze.ReasonRBAC, Detail: "not permitted to create pods"},
			want:   "rbac: not permitted to create pods",
		},
		{
			name:   "reason without detail",
			result: analyze.Result{Outcome: analyze.OutcomeSkipped, Reason: analyze.ReasonKindNotServed},
			want:   "kind-not-served",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := detailCell(tc.result); got != tc.want {
				t.Fatalf("got %q, want %q", got, tc.want)
			}
		})
	}
}

func TestEnforcerCellOnlyForBlocked(t *testing.T) {
	blocked := analyze.Result{Outcome: analyze.OutcomeBlocked, Enforcer: analyze.Enforcer{Type: analyze.EnforcerPSA, Name: "restricted:latest"}}
	if got := enforcerCell(blocked); got != "PodSecurity restricted:latest" {
		t.Errorf("blocked cell = %q", got)
	}
	admitted := analyze.Result{Outcome: analyze.OutcomeAdmitted}
	if got := enforcerCell(admitted); got != "-" {
		t.Errorf("admitted cell = %q", got)
	}
}

func TestNamespaceCellForClusterScoped(t *testing.T) {
	if got := namespaceCell(""); got != "-" {
		t.Fatalf("cluster-scoped namespace cell = %q", got)
	}
}
