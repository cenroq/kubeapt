// Copyright by cenroq AG
// Contact: info@cenroq.com

package cli

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"testing"

	authorizationv1 "k8s.io/api/authorization/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/client-go/kubernetes/scheme"

	"github.com/cenroq/kubeapt/v2/internal/format"
	"github.com/cenroq/kubeapt/v2/internal/kubernetes"
	"github.com/cenroq/kubeapt/v2/internal/logging"
	"github.com/cenroq/kubeapt/v2/pkg/policies"
)

// fakeCluster is just enough of an API server to run analyze end to end:
// legacy discovery, SelfSubjectAccessReview, namespace listing, and dry-run
// creates whose admission answer is chosen by the probe's name.
//
// Every create that does not carry dryRun=All fails the test. That is the
// property the whole command rests on: nothing analyze submits is persisted.
type fakeCluster struct {
	t      *testing.T
	server *httptest.Server

	// namespaces is what a namespace list returns, with each one's labels.
	namespaces map[string]map[string]string
	// locked is a namespace the access review refuses.
	locked string
	// failNamespaceList makes listing namespaces a server error.
	failNamespaceList bool

	mu       sync.Mutex
	creates  []string
	collided map[string]bool
}

func newFakeCluster(t *testing.T) *fakeCluster {
	t.Helper()
	c := &fakeCluster{
		t: t,
		namespaces: map[string]map[string]string{
			"default": {},
			"prod-a":  {"env": "prod"},
			"prod-b":  {"env": "prod"},
			"staging": {"env": "staging"},
		},
		collided: map[string]bool{},
	}
	c.server = httptest.NewServer(http.HandlerFunc(c.serve))
	t.Cleanup(c.server.Close)
	return c
}

// createdIn lists the namespace/name of every create the cluster received.
func (c *fakeCluster) createdIn() []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := append([]string(nil), c.creates...)
	sort.Strings(out)
	return out
}

func writeJSON(w http.ResponseWriter, code int, body string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_, _ = io.WriteString(w, body)
}

// status renders a metav1.Status. kind and apiVersion are required: without
// them client-go cannot decode the body and the message degrades to "unknown",
// which would defeat enforcer attribution.
func status(code int, reason, message string) string {
	encoded, _ := json.Marshal(message)
	return fmt.Sprintf(`{"kind":"Status","apiVersion":"v1","status":"Failure","code":%d,"reason":%q,"message":%s}`, code, reason, encoded)
}

func (c *fakeCluster) serve(w http.ResponseWriter, r *http.Request) {
	path := r.URL.Path
	switch {
	case r.Method == http.MethodGet && path == "/api":
		writeJSON(w, 200, `{"kind":"APIVersions","versions":["v1"]}`)
	case r.Method == http.MethodGet && path == "/apis":
		writeJSON(w, 200, `{"kind":"APIGroupList","apiVersion":"v1","groups":[{"name":"rbac.authorization.k8s.io",
		  "versions":[{"groupVersion":"rbac.authorization.k8s.io/v1","version":"v1"}],
		  "preferredVersion":{"groupVersion":"rbac.authorization.k8s.io/v1","version":"v1"}}]}`)
	case r.Method == http.MethodGet && path == "/api/v1":
		writeJSON(w, 200, `{"kind":"APIResourceList","groupVersion":"v1","resources":[
		  {"name":"pods","singularName":"pod","namespaced":true,"kind":"Pod","verbs":["create","get","list"]},
		  {"name":"namespaces","singularName":"namespace","namespaced":false,"kind":"Namespace","verbs":["get","list"]}]}`)
	case r.Method == http.MethodGet && path == "/apis/rbac.authorization.k8s.io/v1":
		writeJSON(w, 200, `{"kind":"APIResourceList","groupVersion":"rbac.authorization.k8s.io/v1","resources":[
		  {"name":"clusterroles","singularName":"clusterrole","namespaced":false,"kind":"ClusterRole","verbs":["create","get","list"]}]}`)
	case r.Method == http.MethodPost && path == "/apis/authorization.k8s.io/v1/selfsubjectaccessreviews":
		c.serveAccessReview(w, r)
	case r.Method == http.MethodGet && path == "/api/v1/namespaces":
		c.serveNamespaces(w, r)
	case r.Method == http.MethodPost && strings.HasPrefix(path, "/api/v1/namespaces/") && strings.HasSuffix(path, "/pods"):
		namespace := strings.TrimSuffix(strings.TrimPrefix(path, "/api/v1/namespaces/"), "/pods")
		c.serveCreate(w, r, namespace)
	case r.Method == http.MethodPost && path == "/apis/rbac.authorization.k8s.io/v1/clusterroles":
		c.serveCreate(w, r, "")
	default:
		c.t.Errorf("unexpected request %s %s", r.Method, r.URL)
		writeJSON(w, 404, status(404, "NotFound", "not served by the fake"))
	}
}

// The typed clientset sends the review as protobuf, so it is decoded with the
// scheme's deserializer rather than as JSON.
func (c *fakeCluster) serveAccessReview(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	decoded, _, err := scheme.Codecs.UniversalDeserializer().Decode(body, nil, nil)
	review, ok := decoded.(*authorizationv1.SelfSubjectAccessReview)
	if err != nil || !ok || review.Spec.ResourceAttributes == nil {
		c.t.Errorf("undecodable access review (%v): %q", err, body)
		writeJSON(w, 500, status(500, "InternalError", "bad review"))
		return
	}
	review.Status.Allowed = c.locked == "" || review.Spec.ResourceAttributes.Namespace != c.locked
	review.Kind, review.APIVersion = "SelfSubjectAccessReview", "authorization.k8s.io/v1"
	encoded, _ := json.Marshal(review)
	writeJSON(w, 201, string(encoded))
}

func (c *fakeCluster) serveNamespaces(w http.ResponseWriter, r *http.Request) {
	if c.failNamespaceList {
		writeJSON(w, 500, status(500, "InternalError", "etcd unavailable"))
		return
	}
	selector, err := labels.Parse(r.URL.Query().Get("labelSelector"))
	if err != nil {
		writeJSON(w, 400, status(400, "BadRequest", err.Error()))
		return
	}
	var items []string
	for name, nsLabels := range c.namespaces {
		if selector.Matches(labels.Set(nsLabels)) {
			items = append(items, fmt.Sprintf(`{"metadata":{"name":%q}}`, name))
		}
	}
	writeJSON(w, 200, `{"kind":"NamespaceList","apiVersion":"v1","metadata":{},"items":[`+strings.Join(items, ",")+`]}`)
}

func (c *fakeCluster) serveCreate(w http.ResponseWriter, r *http.Request, namespace string) {
	query := r.URL.Query()
	if query.Get("dryRun") != "All" || query.Get("fieldManager") != "kubeapt" {
		c.t.Errorf("create without dryRun=All and fieldManager=kubeapt: %s", r.URL)
		writeJSON(w, 500, status(500, "InternalError", "refusing a real create"))
		return
	}
	var obj map[string]any
	if err := json.NewDecoder(r.Body).Decode(&obj); err != nil {
		c.t.Errorf("undecodable create body: %v", err)
		writeJSON(w, 500, status(500, "InternalError", "bad body"))
		return
	}
	metadata, _ := obj["metadata"].(map[string]any)
	name, _ := metadata["name"].(string)
	if got, _ := metadata["namespace"].(string); got != namespace {
		c.t.Errorf("%s: body namespace %q does not match the URL's %q", name, got, namespace)
	}
	annotations, _ := metadata["annotations"].(map[string]any)
	for key := range annotations {
		if strings.Contains(key, "kubeapt.io/") {
			c.t.Errorf("%s: kubeapt annotation %q reached the API server", name, key)
		}
	}

	c.mu.Lock()
	c.creates = append(c.creates, namespace+"/"+name)
	firstCollision := name == "existing-probe" && !c.collided[namespace]
	if firstCollision {
		c.collided[namespace] = true
	}
	c.mu.Unlock()

	switch {
	case strings.Contains(name, "hostpid"):
		writeJSON(w, 403, status(403, "Forbidden",
			fmt.Sprintf(`pods %q is forbidden: violates PodSecurity "restricted:latest": host namespaces (hostPID=true)`, name)))
	case firstCollision:
		writeJSON(w, 409, status(409, "AlreadyExists", fmt.Sprintf("pods %q already exists", name)))
	case strings.Contains(name, "mutated"):
		spec, _ := obj["spec"].(map[string]any)
		spec["hostNetwork"] = false
		encoded, _ := json.Marshal(obj)
		writeJSON(w, 201, string(encoded))
	default:
		encoded, _ := json.Marshal(obj)
		writeJSON(w, 201, string(encoded))
	}
}

// kubeconfig writes a kubeconfig pointing at the fake, with an optional
// context namespace.
func (c *fakeCluster) kubeconfig(namespace string) string {
	c.t.Helper()
	path := filepath.Join(c.t.TempDir(), "config")
	config := fmt.Sprintf(`apiVersion: v1
kind: Config
clusters:
- name: fake
  cluster:
    server: %s
contexts:
- name: fake
  context:
    cluster: fake
    user: fake
    namespace: %q
current-context: fake
users:
- name: fake
  user:
    token: test
`, c.server.URL, namespace)
	if err := os.WriteFile(path, []byte(config), 0o600); err != nil {
		c.t.Fatalf("write kubeconfig: %v", err)
	}
	return path
}

// isolateCluster points analyze at kubeconfigPath and nothing else. HOME,
// KUBECONFIG and the in-cluster variables are all neutralised so that no test
// can ever fall through to a developer's real cluster or installed bundles.
// It returns the temporary HOME.
func isolateCluster(t *testing.T, kubeconfig string) string {
	t.Helper()
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("KUBECONFIG", filepath.Join(t.TempDir(), "absent"))
	t.Setenv("KUBERNETES_SERVICE_HOST", "")
	t.Setenv("KUBERNETES_SERVICE_PORT", "")

	previous := kubeconfigPath
	kubeconfigPath = kubeconfig
	t.Cleanup(func() {
		kubeconfigPath = previous
		kubernetes.SetKubeconfig("")
		logging.SetOutputWriter(os.Stdout)
		logging.SetReportWriter(os.Stdout)
	})
	return home
}

// runAnalyzeCmd executes a fresh analyze command and returns what it wrote.
func runAnalyzeCmd(t *testing.T, out io.Writer, args ...string) error {
	t.Helper()
	cmd := AnalyzeCmd()
	cmd.SilenceUsage = true
	cmd.SilenceErrors = true
	cmd.SetOut(out)
	cmd.SetErr(out)
	// Never nil: cobra would fall back to os.Args, which holds go test's flags.
	cmd.SetArgs(append([]string{}, args...))
	return cmd.Execute()
}

type analyzeEnvelope struct {
	Metadata format.JSONMetadata `json:"metadata"`
	Results  analyzeJSONPayload  `json:"results"`
}

func runAnalyzeJSON(t *testing.T, args ...string) (analyzeEnvelope, error) {
	t.Helper()
	var buf bytes.Buffer
	err := runAnalyzeCmd(t, &buf, append([]string{"-f", "json"}, args...)...)
	var envelope analyzeEnvelope
	if buf.Len() > 0 {
		if decodeErr := json.Unmarshal(buf.Bytes(), &envelope); decodeErr != nil {
			t.Fatalf("output is not a JSON envelope (%v):\n%s", decodeErr, buf.String())
		}
	}
	return envelope, err
}

// byProbe indexes results as "probe@namespace".
func byProbe(payload analyzeJSONPayload) map[string]analyzeJSONResult {
	out := map[string]analyzeJSONResult{}
	for _, r := range payload.Results {
		out[r.Probe+"@"+r.Namespace] = r
	}
	return out
}

func clusterPod(name string, spec string) string {
	return fmt.Sprintf(`apiVersion: v1
kind: Pod
metadata:
  name: %s
  annotations:
    security.kubeapt.io/severity: High
spec:
%s  containers:
  - name: main
    image: busybox:1.36
`, name, spec)
}

// A corpus covering every route through the runner.
func clusterProbeDir(t *testing.T) string {
	return writeProbeDir(t, map[string]string{
		"hostpid.yaml":  clusterPod("hostpid-probe", "  hostPID: true\n"),
		"admitted.yaml": clusterPod("admitted-probe", "  hostIPC: true\n"),
		"mutated.yaml":  clusterPod("mutated-probe", "  hostNetwork: true\n"),
		"existing.yaml": clusterPod("existing-probe", ""),
		"clusterrole.yaml": `apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: wildcard-probe
rules:
- apiGroups: ["*"]
  resources: ["*"]
  verbs: ["*"]
`,
		"crd.yaml": `apiVersion: cilium.io/v2
kind: CiliumNetworkPolicy
metadata:
  name: not-installed
`,
		"ephemeral.yaml":       clusterPod("ephemeral-probe", ""),
		"ephemeral.debug.yaml": "securityContext:\n  privileged: true\n",
	})
}

func TestAnalyzeAgainstCluster(t *testing.T) {
	cluster := newFakeCluster(t)
	isolateCluster(t, cluster.kubeconfig(""))

	envelope, err := runAnalyzeJSON(t, "--probes", clusterProbeDir(t), "--namespaces", "a,b")
	if err != nil {
		t.Fatalf("analyze: %v", err)
	}
	results := byProbe(envelope.Results)

	want := map[string]struct{ outcome, verdict string }{
		"hostpid@a":     {"Blocked", "Pass"},
		"hostpid@b":     {"Blocked", "Pass"},
		"admitted@a":    {"Admitted", "Fail"},
		"mutated@b":     {"Mutated", "Warn"},
		"existing@a":    {"Admitted", "Fail"},
		"clusterrole@":  {"Admitted", "Fail"},
		"crd@":          {"Skipped", "Inconclusive"},
		"ephemeral@":    {"Skipped", "Inconclusive"},
		"clusterrole@a": {},
	}
	for key, w := range want {
		got, ok := results[key]
		if w.outcome == "" {
			if ok {
				t.Errorf("%s: a cluster-scoped probe was fanned out per namespace", key)
			}
			continue
		}
		if !ok {
			t.Errorf("%s: no result; have %v", key, keys(results))
			continue
		}
		if got.Outcome != w.outcome || got.Verdict != w.verdict {
			t.Errorf("%s: outcome %s verdict %s, want %s/%s", key, got.Outcome, got.Verdict, w.outcome, w.verdict)
		}
	}

	blocked := results["hostpid@a"]
	if blocked.EnforcedBy == nil || blocked.EnforcedBy.Type != "PodSecurity" || blocked.EnforcedBy.Name != "restricted:latest" {
		t.Errorf("enforcer not attributed: %+v", blocked.EnforcedBy)
	}
	if got := results["mutated@b"].Mutations; len(got) != 1 || got[0] != "spec.hostNetwork" {
		t.Errorf("mutations = %v", got)
	}
	// The live object of the same name forced a retry under a fresh name.
	if got := results["existing@a"].SubmittedAs; !strings.HasPrefix(got, "existing-probe-kubeapt-") {
		t.Errorf("submittedAs = %q, want a collision-free name", got)
	}
	if results["crd@"].Reason != "kind-not-served" || results["ephemeral@"].Reason != "unsupported" {
		t.Errorf("skip reasons = %q, %q", results["crd@"].Reason, results["ephemeral@"].Reason)
	}

	// 4 submittable namespaced probes over 2 namespaces, plus one result each
	// for the cluster-scoped, unserved and unsupported probes.
	if summary := envelope.Results.Summary; summary.Total != 11 || summary.Fail != 5 || summary.Pass != 2 || summary.Warn != 2 || summary.Inconclusive != 2 {
		t.Errorf("summary = %+v", summary)
	}
	if got := strings.Join(envelope.Metadata.Kubernetes.Namespaces, ","); got != "a,b" {
		t.Errorf("metadata namespaces = %q", got)
	}
	if got := envelope.Metadata.Kubernetes.Resources; got["Pod"] != 9 || got["ClusterRole"] != 1 || got["CiliumNetworkPolicy"] != 1 {
		t.Errorf("metadata resources = %v", got)
	}
	for _, created := range cluster.createdIn() {
		if strings.Contains(created, "not-installed") || strings.Contains(created, "ephemeral") {
			t.Errorf("an unsubmittable probe reached the cluster: %s", created)
		}
	}
}

// With no namespace flag the active kubeconfig context decides. That only
// works if the kubeconfig is loaded before the namespace is resolved.
func TestAnalyzeDefaultsToContextNamespace(t *testing.T) {
	cluster := newFakeCluster(t)
	isolateCluster(t, cluster.kubeconfig("team-a"))
	dir := writeProbeDir(t, map[string]string{"admitted.yaml": clusterPod("admitted-probe", "")})

	envelope, err := runAnalyzeJSON(t, "--probes", dir)
	if err != nil {
		t.Fatalf("analyze: %v", err)
	}
	if got := cluster.createdIn(); len(got) != 1 || got[0] != "team-a/admitted-probe" {
		t.Fatalf("creates = %v, want one into the context namespace team-a", got)
	}
	if got := envelope.Metadata.Kubernetes.Namespaces; len(got) != 1 || got[0] != "team-a" {
		t.Errorf("metadata namespaces = %v", got)
	}
}

// Without --probes analyze runs the installed default bundle, and each probe's
// uuid resolves to the policy it tests.
func TestAnalyzeRunsInstalledDefaultBundle(t *testing.T) {
	cluster := newFakeCluster(t)
	home := isolateCluster(t, cluster.kubeconfig(""))
	versionDir := filepath.Join(home, ".config", "kubeapt", "bundles", defaultProbeBundle, "2.0.0")
	for name, body := range map[string]string{"policies.yaml": bundlePolicyYAML, "probes/deny.yaml": bundleDenyYAML} {
		path := filepath.Join(versionDir, name)
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatalf("mkdir: %v", err)
		}
		if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
			t.Fatalf("write: %v", err)
		}
	}

	envelope, err := runAnalyzeJSON(t, "--namespaces", "a")
	if err != nil {
		t.Fatalf("analyze: %v", err)
	}
	if len(envelope.Results.Results) != 1 {
		t.Fatalf("results = %+v", envelope.Results.Results)
	}
	got := envelope.Results.Results[0]
	if got.Policy != "pod-hostpid" || got.UUID != bundleProbeUUID || got.URL != policies.DocsURL(bundleProbeUUID) {
		t.Errorf("policy join = %q %q %q", got.Policy, got.UUID, got.URL)
	}
	if got.DisplayName != "Shares the Host PID Namespace" || got.Severity != "High" {
		t.Errorf("display = %q severity = %q", got.DisplayName, got.Severity)
	}
	if got.Verdict != "Pass" {
		t.Errorf("verdict = %q, want Pass for the hostPID deny manifest", got.Verdict)
	}
}

// A report written to a file is plain text: no colour, no hyperlink escapes,
// and the catalogue link spelled out in the footer.
func TestAnalyzeWritesReportFile(t *testing.T) {
	cluster := newFakeCluster(t)
	isolateCluster(t, cluster.kubeconfig(""))
	dir := writeProbeDir(t, map[string]string{
		"policies.yaml":    bundlePolicyYAML,
		"probes/deny.yaml": strings.Replace(bundleDenyYAML, "hostpid-pod", "plain-pod", 1),
	})
	report := filepath.Join(t.TempDir(), "report.txt")

	var stdout bytes.Buffer
	if err := runAnalyzeCmd(t, &stdout, "--probes", dir, "--namespaces", "a", "--output", report, "--report", "all"); err != nil {
		t.Fatalf("analyze: %v", err)
	}
	data, err := os.ReadFile(report)
	if err != nil {
		t.Fatalf("read report: %v", err)
	}
	out := string(data)
	for _, want := range []string{"Admission probe results", "POLICY", "DETAIL", "Shares the Host PID Namespace", "Policy details", policies.DocsURL(bundleProbeUUID)} {
		if !strings.Contains(out, want) {
			t.Errorf("report missing %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "\x1b") {
		t.Errorf("escape codes in a report file:\n%q", out)
	}
	if !strings.Contains(stdout.String(), "1 dangerous object(s) were admitted") {
		t.Errorf("summary log missing from stdout:\n%s", stdout.String())
	}
}

func TestAnalyzePipelineExitCode(t *testing.T) {
	cluster := newFakeCluster(t)
	isolateCluster(t, cluster.kubeconfig(""))

	admitted := writeProbeDir(t, map[string]string{"admitted.yaml": clusterPod("admitted-probe", "")})
	if _, err := runAnalyzeJSON(t, "--probes", admitted, "--namespaces", "a", "--pipeline"); err == nil ||
		!strings.Contains(err.Error(), "1 dangerous object(s) were admitted") {
		t.Fatalf("err = %v, want the pipeline to fail on an admitted probe", err)
	}

	blocked := writeProbeDir(t, map[string]string{"hostpid.yaml": clusterPod("hostpid-probe", "  hostPID: true\n")})
	if _, err := runAnalyzeJSON(t, "--probes", blocked, "--namespaces", "a", "--pipeline"); err != nil {
		t.Fatalf("err = %v, want success when everything is blocked", err)
	}
}

// RBAC refusing the create is not admission refusing it: the namespace is
// reported as untested and nothing is sent there.
func TestAnalyzeRBACDeniedNamespaceIsInconclusive(t *testing.T) {
	cluster := newFakeCluster(t)
	cluster.locked = "locked"
	isolateCluster(t, cluster.kubeconfig(""))
	dir := writeProbeDir(t, map[string]string{"hostpid.yaml": clusterPod("hostpid-probe", "  hostPID: true\n")})

	envelope, err := runAnalyzeJSON(t, "--probes", dir, "--namespaces", "open,locked")
	if err != nil {
		t.Fatalf("analyze: %v", err)
	}
	results := byProbe(envelope.Results)
	if got := results["hostpid@locked"]; got.Verdict != "Inconclusive" || got.Reason != "rbac" {
		t.Errorf("locked = verdict %q reason %q", got.Verdict, got.Reason)
	}
	if got := results["hostpid@open"]; got.Verdict != "Pass" {
		t.Errorf("open = verdict %q", got.Verdict)
	}
	for _, created := range cluster.createdIn() {
		if strings.HasPrefix(created, "locked/") {
			t.Errorf("probe submitted into the RBAC-denied namespace: %s", created)
		}
	}
}

func TestAnalyzeNamespaceSelection(t *testing.T) {
	cluster := newFakeCluster(t)
	isolateCluster(t, cluster.kubeconfig(""))
	dir := writeProbeDir(t, map[string]string{"admitted.yaml": clusterPod("admitted-probe", "")})

	tests := []struct {
		name string
		args []string
		want string
	}{
		{"all namespaces, sorted", []string{"-A"}, "default,prod-a,prod-b,staging"},
		{"label selector", []string{"--namespace-selector", "env=prod"}, "prod-a,prod-b"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			envelope, err := runAnalyzeJSON(t, append([]string{"--probes", dir}, tc.args...)...)
			if err != nil {
				t.Fatalf("analyze: %v", err)
			}
			if got := strings.Join(envelope.Metadata.Kubernetes.Namespaces, ","); got != tc.want {
				t.Fatalf("namespaces = %q, want %q", got, tc.want)
			}
		})
	}

	if _, err := runAnalyzeJSON(t, "--probes", dir, "--namespace-selector", "env=none"); err == nil ||
		!strings.Contains(err.Error(), "no namespaces matched selector env=none") {
		t.Errorf("empty selector err = %v", err)
	}

	cluster.failNamespaceList = true
	for _, args := range [][]string{{"-A"}, {"--namespace-selector", "env=prod"}} {
		if _, err := runAnalyzeJSON(t, append([]string{"--probes", dir}, args...)...); err == nil {
			t.Errorf("%v: expected the namespace list error to surface", args)
		}
	}
}

// failingWriter rejects every write, standing in for a closed stdout.
type failingWriter struct{}

func (failingWriter) Write([]byte) (int, error) { return 0, errors.New("stdout closed") }

func TestAnalyzeErrors(t *testing.T) {
	cluster := newFakeCluster(t)
	dir := writeProbeDir(t, map[string]string{"admitted.yaml": clusterPod("admitted-probe", "")})

	tests := []struct {
		name       string
		kubeconfig string
		args       []string
		want       string
	}{
		{"missing probes path", cluster.kubeconfig(""), []string{"--probes", filepath.Join(dir, "absent")}, "no such file"},
		{"unknown probe id", cluster.kubeconfig(""), []string{"--probes", dir, "--probe", "nope"}, "unknown probe id nope"},
		{"invalid format", cluster.kubeconfig(""), []string{"--probes", dir, "-f", "yaml"}, "invalid format yaml"},
		{"missing kubeconfig", filepath.Join(t.TempDir(), "absent"), []string{"--probes", dir}, "kubeconfig not found"},
		{"unwritable output", cluster.kubeconfig(""), []string{"--probes", dir, "--namespaces", "a", "--output", filepath.Join(dir, "absent", "report.txt")}, "failed to open output file"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			isolateCluster(t, tc.kubeconfig)
			err := runAnalyzeCmd(t, io.Discard, tc.args...)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err = %v, want %q", err, tc.want)
			}
		})
	}

	t.Run("failing stdout", func(t *testing.T) {
		isolateCluster(t, cluster.kubeconfig(""))
		err := runAnalyzeCmd(t, failingWriter{}, "--probes", dir, "--namespaces", "a", "-f", "json")
		if err == nil || !strings.Contains(err.Error(), "stdout closed") {
			t.Fatalf("err = %v, want the write error", err)
		}
	})
}

func keys(m map[string]analyzeJSONResult) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
