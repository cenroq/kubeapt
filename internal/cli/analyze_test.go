// Copyright by cenroq AG
// Contact: info@cenroq.com

package cli

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/fatih/color"
	"github.com/jedib0t/go-pretty/v6/table"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"

	"github.com/cenroq/kubeapt/v2/internal/logging"
	"github.com/cenroq/kubeapt/v2/pkg/analyze"
	"github.com/cenroq/kubeapt/v2/pkg/policies"
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

const bundleProbeUUID = "23ef68db-2409-43a1-854d-c46477a533a9"

const bundlePolicyYAML = `apiVersion: admissionregistration.k8s.io/v1
kind: ValidatingAdmissionPolicy
metadata:
  name: pod-hostpid
  annotations:
    kubeapt.io/uuid: "` + bundleProbeUUID + `"
    security.kubeapt.io/displayName: "Shares the Host PID Namespace"
    security.kubeapt.io/severity: "High"
`

// The banner and the "# policy:" header mirror a real bundle's probes/deny.yaml,
// which is comments plus a leading --- before the first document.
const bundleDenyYAML = `# Deliberately non-compliant manifests, one per policy in this bundle.
---
# policy: pod-hostpid
apiVersion: v1
kind: Pod
metadata:
  name: hostpid-pod
  annotations:
    kubeapt.io/uuid: "` + bundleProbeUUID + `"
spec:
  hostPID: true
  containers:
  - name: main
    image: busybox:1.36
`

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
func TestLoadProbesRejectsBundleWithoutProbes(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	versionDir := filepath.Join(home, ".config", "kubeapt", "bundles", "pod-security-admission", "1.0.0")
	if err := os.MkdirAll(versionDir, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(versionDir, "policies.yaml"), []byte("{}\n"), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}

	_, err := loadProbes(analyzeRequest{bundleName: "pod-security-admission"})
	if err == nil || !strings.Contains(err.Error(), "ships no probes/") {
		t.Fatalf("expected a missing-probes error, got %v", err)
	}
}

// A bundle is loaded whole so each probe's uuid resolves against the bundle's
// own policies.yaml.
func TestLoadProbesFromBundleJoinsPolicies(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	versionDir := filepath.Join(home, ".config", "kubeapt", "bundles", "cenroq-best-practices", "2.0.0")
	if err := os.MkdirAll(filepath.Join(versionDir, "probes"), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(versionDir, "policies.yaml"), []byte(bundlePolicyYAML), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := os.WriteFile(filepath.Join(versionDir, "probes", "deny.yaml"), []byte(bundleDenyYAML), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}

	probes, err := loadProbes(analyzeRequest{bundleName: "cenroq-best-practices"})
	if err != nil {
		t.Fatalf("loadProbes: %v", err)
	}
	if len(probes) != 1 {
		t.Fatalf("loaded %d probes, want 1", len(probes))
	}
	probe := probes[0]
	if probe.UUID != bundleProbeUUID {
		t.Fatalf("uuid = %q", probe.UUID)
	}
	if probe.Policy == nil || probe.Policy.Name != "pod-hostpid" {
		t.Fatalf("policy not joined: %+v", probe.Policy)
	}
	// The deny manifest carries no severity of its own; it comes from the policy.
	if probe.Severity != types.SeverityHigh {
		t.Errorf("severity = %q, want High", probe.Severity)
	}
	if want := policies.DocsBaseURL + "/" + bundleProbeUUID; probe.DocsURL() != want {
		t.Errorf("docs url = %q, want %q", probe.DocsURL(), want)
	}
	// kubeapt.io/uuid must not reach the API server.
	if _, present := probe.Object.GetAnnotations()[policies.AnnotationUUID]; present {
		t.Error("uuid annotation was not stripped from the submitted object")
	}
}

func TestLoadProbesBundleNotInstalled(t *testing.T) {
	t.Setenv("HOME", t.TempDir())

	_, err := loadProbes(analyzeRequest{bundleName: "cenroq-best-practices"})
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

// analyze was deliberately left unregistered while its probe corpus did not
// exist; it must now be reachable from the root command.
func TestRootRegistersAnalyze(t *testing.T) {
	cmd, _, err := rootCmd.Find([]string{"analyze"})
	if err != nil || cmd.Name() != "analyze" {
		t.Fatalf("Find(analyze) = %v, %v", cmd, err)
	}
}

// wrongTypeValue satisfies pflag.Value but reports a type no getter accepts.
type wrongTypeValue struct{}

func (wrongTypeValue) String() string   { return "" }
func (wrongTypeValue) Set(string) error { return nil }
func (wrongTypeValue) Type() string     { return "wrong" }

// A flag whose lookup fails must stop the run rather than proceed on a zero
// value, which for --pipeline would silently disable the CI gate.
func TestParseAnalyzeFlagsSurfacesLookupErrors(t *testing.T) {
	flags := []string{"bundle", "bundle-version", "probes", "probe", "all-namespaces", "namespaces",
		"namespace-selector", "format", "report", "output", "pipeline", "timeout"}
	for _, name := range flags {
		t.Run(name, func(t *testing.T) {
			cmd := AnalyzeCmd()
			if err := cmd.ParseFlags(nil); err != nil {
				t.Fatalf("ParseFlags: %v", err)
			}
			cmd.Flags().Lookup(name).Value = wrongTypeValue{}
			if _, err := parseAnalyzeFlags(cmd); err == nil || !strings.Contains(err.Error(), "wrong") {
				t.Fatalf("err = %v, want a lookup error for --%s", err, name)
			}
		})
	}
}

func TestPolicyCell(t *testing.T) {
	tests := []struct {
		probe analyze.Probe
		want  string
	}{
		{analyze.Probe{}, "-"},
		{analyze.Probe{Policy: &analyze.PolicyRef{Name: "pod-hostpid", DisplayName: "Host PID"}}, "Host PID"},
		{analyze.Probe{Policy: &analyze.PolicyRef{Name: "pod-hostpid"}}, "pod-hostpid"},
	}
	for _, tc := range tests {
		if got := policyCell(tc.probe); got != tc.want {
			t.Errorf("policyCell(%+v) = %q, want %q", tc.probe.Policy, got, tc.want)
		}
	}
}

// The OSC 8 escape is only emitted when colour is on: unlike fatih/color it
// does not disable itself on a non-TTY and would litter a report file.
func TestLinkedProbeName(t *testing.T) {
	linked := analyze.Probe{ID: "hostpid", UUID: bundleProbeUUID}
	if got := linkedProbeName(linked, false); got != "hostpid" {
		t.Errorf("without color = %q", got)
	}
	if got := linkedProbeName(analyze.Probe{ID: "hostpid"}, true); got != "hostpid" {
		t.Errorf("without uuid = %q", got)
	}
	got := linkedProbeName(linked, true)
	if !strings.Contains(got, "\x1b]8;;"+policies.DocsURL(bundleProbeUUID)) || !strings.Contains(got, "hostpid") {
		t.Errorf("hyperlink = %q", got)
	}
}

func TestProbeKindAndCounts(t *testing.T) {
	pod := &unstructured.Unstructured{Object: map[string]any{"kind": "Pod"}}
	noKind := &unstructured.Unstructured{Object: map[string]any{}}
	if got := probeKind(analyze.Probe{}); got != "" {
		t.Errorf("probeKind(nil object) = %q", got)
	}
	if got := probeKind(analyze.Probe{Object: pod}); got != "Pod" {
		t.Errorf("probeKind = %q", got)
	}
	counts := probeKindCounts([]analyze.Result{
		{Probe: analyze.Probe{Object: pod}},
		{Probe: analyze.Probe{Object: pod}},
		{Probe: analyze.Probe{}},
		{Probe: analyze.Probe{Object: noKind}},
	})
	if len(counts) != 1 || counts["Pod"] != 2 {
		t.Fatalf("counts = %v, want map[Pod:2]", counts)
	}
}

func TestMaxInt(t *testing.T) {
	if maxInt(3, 1) != 3 || maxInt(1, 3) != 3 || maxInt(2, 2) != 2 {
		t.Fatal("maxInt is wrong")
	}
}

func TestDetailCellFallsBackToDetail(t *testing.T) {
	result := analyze.Result{Outcome: analyze.OutcomeAdmitted, Detail: "first\nsecond"}
	if got := detailCell(result); got != "first" {
		t.Fatalf("detailCell = %q, want first", got)
	}
}

func linkResult(id, uuid string, verdict analyze.Verdict) analyze.Result {
	return analyze.Result{Probe: analyze.Probe{ID: id, UUID: uuid}, Verdict: verdict}
}

func TestPrintProbeLinks(t *testing.T) {
	var buf bytes.Buffer
	printProbeLinks([]analyze.Result{
		linkResult("passed", "u-pass", analyze.VerdictPass),
		linkResult("no-uuid", "", analyze.VerdictFail),
		linkResult("failed", "u-fail", analyze.VerdictFail),
		linkResult("failed-again", "u-fail", analyze.VerdictFail),
		linkResult("warned", "u-warn", analyze.VerdictWarn),
	}, &buf)
	out := buf.String()

	if !strings.HasPrefix(out, "Policy details\n") {
		t.Fatalf("missing header:\n%s", out)
	}
	for _, want := range []string{policies.DocsURL("u-fail"), policies.DocsURL("u-warn")} {
		if strings.Count(out, want) != 1 {
			t.Errorf("want %s listed exactly once:\n%s", want, out)
		}
	}
	// A pass needs no explanation, and the reader is pointed at a policy only once.
	if strings.Contains(out, "u-pass") || strings.Contains(out, "failed-again") {
		t.Errorf("pass or duplicate listed:\n%s", out)
	}

	buf.Reset()
	printProbeLinks([]analyze.Result{linkResult("passed", "u", analyze.VerdictPass)}, &buf)
	if buf.Len() != 0 {
		t.Errorf("nothing to link should print nothing, got %q", buf.String())
	}
}

// A cluster enforcing nothing fails every probe; the footer must not bury the
// summary under 150 URLs.
func TestPrintProbeLinksCapsTheList(t *testing.T) {
	var results []analyze.Result
	for i := 0; i < maxProbeLinks+5; i++ {
		results = append(results, linkResult(fmt.Sprintf("p%02d", i), fmt.Sprintf("u%02d", i), analyze.VerdictFail))
	}
	var buf bytes.Buffer
	printProbeLinks(results, &buf)

	lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
	if len(lines) != 1+maxProbeLinks+1 {
		t.Fatalf("got %d lines, want header + %d links + overflow", len(lines), maxProbeLinks)
	}
	if !strings.Contains(lines[len(lines)-1], "and 5 more") {
		t.Errorf("overflow line = %q", lines[len(lines)-1])
	}
}

func TestRenderVerdictAndSeverityColor(t *testing.T) {
	previous := color.NoColor
	color.NoColor = false
	t.Cleanup(func() { color.NoColor = previous })

	verdicts := []analyze.Verdict{analyze.VerdictFail, analyze.VerdictWarn, analyze.VerdictPass, analyze.VerdictInconclusive}
	seen := map[string]bool{}
	for _, verdict := range verdicts {
		got := renderVerdict(verdict, true)
		if !strings.Contains(got, "\x1b[") || !strings.Contains(got, string(verdict)) {
			t.Errorf("renderVerdict(%s) = %q, want a coloured label", verdict, got)
		}
		seen[got] = true
		if plain := renderVerdict(verdict, false); plain != string(verdict) {
			t.Errorf("renderVerdict(%s, false) = %q", verdict, plain)
		}
	}
	if len(seen) != len(verdicts) {
		t.Errorf("verdicts share colours: %v", seen)
	}
	if got := renderSeverity("Critical", true); !strings.Contains(got, "\x1b[") {
		t.Errorf("renderSeverity = %q, want a coloured label", got)
	}
}

// captureLog routes logging output into a buffer for one test.
func captureLog(t *testing.T) *bytes.Buffer {
	t.Helper()
	if err := logging.Init("", "info"); err != nil {
		t.Fatalf("logging.Init: %v", err)
	}
	var buf bytes.Buffer
	logging.SetOutputWriter(&buf)
	t.Cleanup(func() { logging.SetOutputWriter(os.Stdout) })
	return &buf
}

func TestRenderAnalyzeTableWarnsAboutInconclusive(t *testing.T) {
	log := captureLog(t)
	results := []analyze.Result{
		analyze.InconclusiveResult(analyze.Probe{ID: "hostpid", UUID: bundleProbeUUID,
			Policy: &analyze.PolicyRef{Name: "pod-hostpid", DisplayName: "Host PID"}}, "a", analyze.ReasonRBAC, "not permitted"),
	}
	var buf bytes.Buffer
	renderAnalyzeTable(results, analyze.Summarize(results), "summary", &buf, table.StyleDefault, false)

	if !strings.Contains(log.String(), "1 probe(s) produced no verdict") {
		t.Errorf("inconclusive warning missing:\n%s", log.String())
	}
	if !strings.Contains(log.String(), "--report all") {
		t.Errorf("report-all hint missing:\n%s", log.String())
	}
	out := buf.String()
	for _, want := range []string{"POLICY", "Host PID", "Policy details", policies.DocsURL(bundleProbeUUID)} {
		if !strings.Contains(out, want) {
			t.Errorf("table missing %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "\x1b") {
		t.Errorf("escape codes in an uncoloured table:\n%q", out)
	}
}

func TestSortAnalyzeResultsBreaksTiesByID(t *testing.T) {
	results := []analyze.Result{
		result("zeta", types.SeverityHigh, analyze.VerdictFail, "a"),
		result("alpha", types.SeverityHigh, analyze.VerdictFail, "a"),
	}
	sortAnalyzeResults(results)
	if results[0].Probe.ID != "alpha" {
		t.Fatalf("order = %s, %s", results[0].Probe.ID, results[1].Probe.ID)
	}
}

// A deny manifest carries only a uuid, so the JSON must carry what the uuid
// resolved to: the policy's name, title, description and catalogue link.
func TestBuildAnalyzeJSONCarriesPolicy(t *testing.T) {
	results := []analyze.Result{{
		Probe: analyze.Probe{
			ID: "hostpid", DisplayName: "Pod hostpid-pod", UUID: bundleProbeUUID,
			Policy: &analyze.PolicyRef{Name: "pod-hostpid", DisplayName: "Host PID", Description: "Exposes every process."},
		},
		Outcome: analyze.OutcomeAdmitted,
		Verdict: analyze.VerdictFail,
	}}
	entry := buildAnalyzeJSON(results, analyze.Summarize(results)).Results[0]

	if entry.Policy != "pod-hostpid" || entry.UUID != bundleProbeUUID || entry.URL != policies.DocsURL(bundleProbeUUID) {
		t.Errorf("policy fields = %q %q %q", entry.Policy, entry.UUID, entry.URL)
	}
	if entry.DisplayName != "Host PID" || entry.Description != "Exposes every process." {
		t.Errorf("title/summary = %q / %q", entry.DisplayName, entry.Description)
	}
	if entry.Kind != "" || entry.APIVersion != "" {
		t.Errorf("a probe with no object reported kind %q apiVersion %q", entry.Kind, entry.APIVersion)
	}
}

// A local path may be a whole extracted bundle, which loads with its policies.
func TestLoadProbesFromLocalBundleDirectory(t *testing.T) {
	dir := writeProbeDir(t, map[string]string{
		"policies.yaml":    bundlePolicyYAML,
		"probes/deny.yaml": bundleDenyYAML,
	})
	probes, err := loadProbes(analyzeRequest{probesPath: dir})
	if err != nil {
		t.Fatalf("loadProbes: %v", err)
	}
	if len(probes) != 1 || probes[0].Policy == nil || probes[0].Policy.Name != "pod-hostpid" {
		t.Fatalf("probes = %+v", probes)
	}
}
