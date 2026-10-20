// Copyright by cenroq AG
// Contact: info@cenroq.com

package analyze

import (
	"errors"
	"io/fs"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/cenroq/kubeapt/v2/pkg/policies"
	"github.com/cenroq/kubeapt/v2/pkg/types"
)

const testUUID = "23ef68db-2409-43a1-854d-c46477a533a9"

// bundleDeny mirrors a real probes/deny.yaml: a comment banner, a leading
// separator, and per-document "# policy:" headers.
const bundleDeny = `# Deliberately non-compliant manifests, one per policy in this bundle.
#
# Every document here is expected to be REJECTED.
---
# policy: pod-hostpid
apiVersion: v1
kind: Pod
metadata:
  name: hostpid-pod
  annotations:
    kubeapt.io/uuid: "` + testUUID + `"
spec:
  hostPID: true
---
# policy: pod-hostipc
apiVersion: v1
kind: Pod
metadata:
  name: hostipc-pod
  annotations:
    kubeapt.io/uuid: "aaaaaaaa-0000-0000-0000-000000000000"
spec:
  hostIPC: true
`

const bundlePolicies = `apiVersion: admissionregistration.k8s.io/v1
kind: ValidatingAdmissionPolicy
metadata:
  name: pod-hostpid
  annotations:
    kubeapt.io/uuid: "` + testUUID + `"
    security.kubeapt.io/displayName: "Shares the Host PID Namespace"
    security.kubeapt.io/description: "Exposes every process on the node."
    security.kubeapt.io/severity: "High"
`

func bundleFS() fstest.MapFS {
	return fstest.MapFS{
		"policies.yaml":    {Data: []byte(bundlePolicies)},
		"bindings.yaml":    {Data: []byte("apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: not-a-probe\n")},
		"README.md":        {Data: []byte("# bundle")},
		"probes/deny.yaml": {Data: []byte(bundleDeny)},
	}
}

// The banner and the per-document comments must not become probes, and the
// merged file must not mint two probes called "deny".
func TestLoadProbesMergedDenyFile(t *testing.T) {
	probes, err := LoadProbes(bundleFS(), "probes")
	if err != nil {
		t.Fatalf("LoadProbes: %v", err)
	}
	if len(probes) != 2 {
		t.Fatalf("loaded %d probes, want 2", len(probes))
	}
	for _, probe := range probes {
		if probe.ID == "deny" {
			t.Fatalf("probe id fell back to the shared filename: %+v", probe)
		}
		if probe.Expect != ExpectBlocked {
			t.Errorf("%s expect = %q, want blocked", probe.ID, probe.Expect)
		}
		if probe.UUID == "" {
			t.Errorf("%s carries no uuid", probe.ID)
		}
		// The uuid identifies the probe to kubeapt; it must not alter the
		// object under test.
		if _, present := probe.Object.GetAnnotations()[AnnotationUUID]; present {
			t.Errorf("%s still carries the uuid annotation", probe.ID)
		}
	}
}

func TestLoadBundleJoinsPolicyMetadata(t *testing.T) {
	probes, err := LoadBundle(bundleFS(), ".")
	if err != nil {
		t.Fatalf("LoadBundle: %v", err)
	}
	var matched *Probe
	for i := range probes {
		if probes[i].UUID == testUUID {
			matched = &probes[i]
		}
	}
	if matched == nil {
		t.Fatal("probe with the policy uuid was not loaded")
	}
	if matched.Policy == nil {
		t.Fatal("policy was not joined")
	}
	if matched.Policy.Name != "pod-hostpid" {
		t.Errorf("policy name = %q", matched.Policy.Name)
	}
	// A shipped deny manifest carries no descriptive annotations, so both the
	// label and the summary must come from the policy rather than falling back
	// to "Kind name", which would name the fixture instead of the weakness.
	if matched.Title() != "Shares the Host PID Namespace" {
		t.Errorf("title = %q", matched.Title())
	}
	if matched.Summary() != "Exposes every process on the node." {
		t.Errorf("summary = %q", matched.Summary())
	}
	if matched.DisplayName == matched.Title() {
		t.Error("probe fallback name and policy title should differ in this fixture")
	}
	// A deny manifest carries no severity of its own.
	if matched.Severity != types.SeverityHigh {
		t.Errorf("severity = %q, want High", matched.Severity)
	}
	if want := policies.DocsURL(testUUID); matched.DocsURL() != want {
		t.Errorf("docs url = %q, want %q", matched.DocsURL(), want)
	}

	// The probe whose uuid is not in policies.yaml stays unresolved rather
	// than borrowing another policy's metadata.
	for i := range probes {
		if probes[i].UUID != testUUID && probes[i].Policy != nil {
			t.Errorf("%s resolved to a policy it does not belong to", probes[i].ID)
		}
	}
}

// policies.yaml and bindings.yaml sit beside the corpus in a bundle root;
// submitting either would measure nothing.
func TestLoadProbesSkipsPolicyFiles(t *testing.T) {
	probes, err := LoadProbes(bundleFS(), ".")
	if err != nil {
		t.Fatalf("LoadProbes: %v", err)
	}
	for _, probe := range probes {
		if kind := probe.Object.GetKind(); kind == "ValidatingAdmissionPolicy" || kind == "ConfigMap" {
			t.Errorf("%s loaded a non-probe file as a probe (kind %s)", probe.ID, kind)
		}
	}
	if len(probes) != 2 {
		t.Fatalf("loaded %d probes, want only the 2 deny documents", len(probes))
	}
}

// An EphemeralContainer case is a compliant Pod plus a fragment. Submitting the
// Pod would be admitted and read as a Fail, so the pair is reported as
// unsupported instead -- never as a pass.
func TestLoadProbesMarksEphemeralPairUnsupported(t *testing.T) {
	fsys := fstest.MapFS{
		"ephemeralcontainer-privileged.yaml": {Data: []byte(`apiVersion: v1
kind: Pod
metadata:
  name: ephemeral-privileged
  annotations:
    kubeapt.io/uuid: "` + testUUID + `"
spec:
  containers:
  - name: main
    image: busybox:1.36
`)},
		"ephemeralcontainer-privileged.debug.yaml": {Data: []byte("securityContext:\n  privileged: true\n")},
	}
	probes, err := LoadProbes(fsys, ".")
	if err != nil {
		t.Fatalf("LoadProbes: %v", err)
	}
	if len(probes) != 1 {
		t.Fatalf("loaded %d probes, want 1 (the fragment is not a probe)", len(probes))
	}
	if probes[0].Unsupported == "" {
		t.Fatal("ephemeral pair was not marked unsupported")
	}

	result := UnsupportedResult(probes[0], "")
	if result.Verdict != VerdictInconclusive {
		t.Errorf("verdict = %q, want Inconclusive", result.Verdict)
	}
	if result.Reason != ReasonUnsupported {
		t.Errorf("reason = %q", result.Reason)
	}
}

func TestExpectationForFile(t *testing.T) {
	cases := map[string]Expectation{
		"deny.yaml":       ExpectBlocked,
		"allow.yaml":      ExpectAllowed,
		"allow-tls.yaml":  ExpectAllowed,
		"privileged.yaml": ExpectBlocked,
	}
	for name, want := range cases {
		if got := expectationForFile(name); got != want {
			t.Errorf("expectationForFile(%q) = %q, want %q", name, got, want)
		}
	}
}

func TestLoadProbesRejectsDuplicateIDs(t *testing.T) {
	doc := `apiVersion: v1
kind: Pod
metadata:
  name: same
  annotations:
    analyze.kubeapt.io/id: clash
`
	fsys := fstest.MapFS{
		"a.yaml": {Data: []byte(doc)},
		"b.yaml": {Data: []byte(doc)},
	}
	if _, err := LoadProbes(fsys, "."); err == nil {
		t.Fatal("expected a duplicate id error")
	}
}

func TestLoadProbesEmptyDirectory(t *testing.T) {
	if _, err := LoadProbes(fstest.MapFS{"README.md": {Data: []byte("x")}}, "."); err == nil {
		t.Fatal("expected an error for a directory with no probes")
	}
}

// A bundle built before the catalogue existed is still runnable; it just
// cannot name the policy behind a verdict.
func TestLoadPolicyIndexSkipsPoliciesWithoutUUID(t *testing.T) {
	fsys := fstest.MapFS{"policies.yaml": {Data: []byte(`apiVersion: admissionregistration.k8s.io/v1
kind: ValidatingAdmissionPolicy
metadata:
  name: no-uuid
  annotations:
    security.kubeapt.io/severity: "High"
`)}}
	index, err := LoadPolicyIndex(fsys, "policies.yaml")
	if err != nil {
		t.Fatalf("LoadPolicyIndex: %v", err)
	}
	if len(index) != 0 {
		t.Fatalf("index = %v, want empty", index)
	}
}

func podDoc(name string, annotations ...string) string {
	doc := "apiVersion: v1\nkind: Pod\nmetadata:\n  name: " + name + "\n"
	if len(annotations) > 0 {
		doc += "  annotations:\n"
		for _, a := range annotations {
			doc += "    " + a + "\n"
		}
	}
	return doc + "spec:\n  hostPID: true\n"
}

func TestLoadPolicyIndexMissingFile(t *testing.T) {
	_, err := LoadPolicyIndex(fstest.MapFS{}, "policies.yaml")
	if !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("err = %v, want fs.ErrNotExist", err)
	}
}

func TestLoadPolicyIndexRejectsMalformedPolicy(t *testing.T) {
	fsys := fstest.MapFS{"policies.yaml": {Data: []byte("apiVersion: admissionregistration.k8s.io/v1\nkind: ValidatingAdmissionPolicy\nmetadata: [not, a, map]\n")}}
	_, err := LoadPolicyIndex(fsys, "policies.yaml")
	if err == nil || !strings.Contains(err.Error(), "policies.yaml doc 0") {
		t.Fatalf("err = %v, want an error naming the document", err)
	}
}

// Kyverno-converted policies carry their title and description under Kyverno's
// keys; the index must find them there too.
func TestLoadPolicyIndexReadsAllFields(t *testing.T) {
	fsys := fstest.MapFS{"policies.yaml": {Data: []byte(`apiVersion: admissionregistration.k8s.io/v1
kind: ValidatingAdmissionPolicy
metadata:
  name: kyverno-style
  annotations:
    kubeapt.io/uuid: " ` + testUUID + ` "
    policies.kyverno.io/title: "Disallow Host PID"
    policies.kyverno.io/description: "From Kyverno."
    security.kubeapt.io/severity: "critical"
`)}}
	index, err := LoadPolicyIndex(fsys, "policies.yaml")
	if err != nil {
		t.Fatalf("LoadPolicyIndex: %v", err)
	}
	want := PolicyRef{
		UUID:        testUUID,
		Name:        "kyverno-style",
		DisplayName: "Disallow Host PID",
		Description: "From Kyverno.",
		Severity:    types.SeverityCritical,
		URL:         policies.DocsURL(testUUID),
	}
	if got := index[testUUID]; got != want {
		t.Fatalf("ref = %+v\nwant  %+v", got, want)
	}
}

func TestAttachPolicies(t *testing.T) {
	index := map[string]PolicyRef{testUUID: {UUID: testUUID, Name: "pod-hostpid", Severity: types.SeverityHigh}}
	probes := []Probe{
		{ID: "unrated", UUID: testUUID, Severity: types.SeverityNotRated},
		{ID: "rated", UUID: testUUID, Severity: types.SeverityLow},
		{ID: "unknown", UUID: "not-in-index", Severity: types.SeverityNotRated},
	}
	AttachPolicies(probes, index)

	if probes[0].Policy == nil || probes[0].Severity != types.SeverityHigh {
		t.Errorf("unrated probe: policy %+v severity %q", probes[0].Policy, probes[0].Severity)
	}
	// The probe's own rating is more specific than its policy's.
	if probes[1].Severity != types.SeverityLow {
		t.Errorf("explicit severity overwritten: %q", probes[1].Severity)
	}
	if probes[2].Policy != nil {
		t.Errorf("unknown uuid resolved to %+v", probes[2].Policy)
	}
	if probes[0].Policy == probes[1].Policy {
		t.Error("probes share one PolicyRef; mutating one would change the other")
	}
}

func TestLoadProbesEmptyDirMeansRoot(t *testing.T) {
	probes, err := LoadProbes(fstest.MapFS{"p.yaml": {Data: []byte(podDoc("p"))}}, "")
	if err != nil || len(probes) != 1 {
		t.Fatalf("probes %d, err %v", len(probes), err)
	}
}

func TestLoadProbesMissingDirectory(t *testing.T) {
	_, err := LoadProbes(fstest.MapFS{}, "missing")
	if err == nil || !strings.Contains(err.Error(), "analyze: read missing") {
		t.Fatalf("err = %v", err)
	}
}

func TestLoadProbesPropagatesInvalidExpect(t *testing.T) {
	fsys := fstest.MapFS{"bad.yaml": {Data: []byte(podDoc("p", "analyze.kubeapt.io/expect: blocke"))}}
	_, err := LoadProbes(fsys, ".")
	if err == nil || !strings.Contains(err.Error(), "bad.yaml doc 0") || !strings.Contains(err.Error(), "blocke") {
		t.Fatalf("err = %v, want one naming the file, document and value", err)
	}
}

func TestLoadProbesFileSelection(t *testing.T) {
	fsys := fstest.MapFS{
		"a.yml":         {Data: []byte(podDoc("a"))},
		"b.json":        {Data: []byte(`{"apiVersion":"v1","kind":"Pod","metadata":{"name":"b"}}`)},
		"Policies.YAML": {Data: []byte(bundlePolicies)},
		"bundle.json":   {Data: []byte(`{"name":"bundle"}`)},
		"notes.txt":     {Data: []byte("not yaml: [")},
	}
	probes, err := LoadProbes(fsys, ".")
	if err != nil {
		t.Fatalf("LoadProbes: %v", err)
	}
	var ids []string
	for _, p := range probes {
		ids = append(ids, p.ID)
	}
	if strings.Join(ids, ",") != "a,b" {
		t.Fatalf("ids = %v, want the .yml and .json probes only", ids)
	}
}

// Null documents -- whitespace between separators, a leading separator, a
// comment banner -- are not probes, and must not change how the rest are named.
func TestLoadProbesSkipsNullDocuments(t *testing.T) {
	data := "\n---\n# banner only\n---\n   \n---\n" + podDoc("one") + "---\n" + podDoc("two")
	probes, err := LoadProbes(fstest.MapFS{"deny.yaml": {Data: []byte(data)}}, ".")
	if err != nil {
		t.Fatalf("LoadProbes: %v", err)
	}
	if len(probes) != 2 || probes[0].ID != "pod-one" || probes[1].ID != "pod-two" {
		t.Fatalf("probes = %+v", probes)
	}
}

// A typo in one document of a merged deny.yaml must fail the load. Skipping it
// would drop a probe silently and rename its sole surviving sibling "deny".
func TestLoadProbesRejectsMalformedDocument(t *testing.T) {
	data := podDoc("good") + "---\napiVersion: v1\nkind: Pod\nmetadata:\n  name: broken\n   badindent: true\nspec: [unclosed\n"
	probes, err := LoadProbes(fstest.MapFS{"deny.yaml": {Data: []byte(data)}}, ".")
	if err == nil || !strings.Contains(err.Error(), "deny.yaml doc 1") {
		t.Fatalf("err = %v, want one naming deny.yaml doc 1", err)
	}
	if probes != nil {
		t.Fatalf("partial result returned: %+v", probes)
	}
}

// An invalid separator used to discard the whole file, including the document
// buffered before it.
func TestLoadProbesRejectsInvalidSeparator(t *testing.T) {
	data := podDoc("one") + "--- garbage\n" + podDoc("two")
	_, err := LoadProbes(fstest.MapFS{"deny.yaml": {Data: []byte(data)}}, ".")
	if err == nil || !strings.Contains(err.Error(), "deny.yaml") {
		t.Fatalf("err = %v, want a syntax error naming the file", err)
	}
}

// The filename sets the default expectation; an explicit annotation wins in
// both directions.
func TestLoadProbesExplicitExpectationBeatsFilename(t *testing.T) {
	fsys := fstest.MapFS{
		"allow.yaml": {Data: []byte(podDoc("allow-default") + "---\n" + podDoc("allow-explicit", "analyze.kubeapt.io/expect: blocked"))},
		"deny.yaml":  {Data: []byte(podDoc("deny-default") + "---\n" + podDoc("deny-explicit", "analyze.kubeapt.io/expect: allowed"))},
	}
	probes, err := LoadProbes(fsys, ".")
	if err != nil {
		t.Fatalf("LoadProbes: %v", err)
	}
	want := map[string]Expectation{
		"pod-allow-default":  ExpectAllowed,
		"pod-allow-explicit": ExpectBlocked,
		"pod-deny-default":   ExpectBlocked,
		"pod-deny-explicit":  ExpectAllowed,
	}
	for _, p := range probes {
		if p.Expect != want[p.ID] {
			t.Errorf("%s expect = %q, want %q", p.ID, p.Expect, want[p.ID])
		}
	}
	if len(probes) != len(want) {
		t.Fatalf("loaded %d probes, want %d", len(probes), len(want))
	}
}

// A companion with nothing in it contributes no probe rather than an empty one.
func TestLoadProbesEphemeralCompanionWithoutDocuments(t *testing.T) {
	fsys := fstest.MapFS{
		"eph.yaml":       {Data: []byte("# kubectl debug only\n")},
		"eph.debug.yaml": {Data: []byte("securityContext:\n  privileged: true\n")},
		"other.yaml":     {Data: []byte(podDoc("other"))},
	}
	probes, err := LoadProbes(fsys, ".")
	if err != nil {
		t.Fatalf("LoadProbes: %v", err)
	}
	if len(probes) != 1 || probes[0].ID != "other" {
		t.Fatalf("probes = %+v", probes)
	}
}

// Only the companion's first document stands for the ephemeral technique.
func TestLoadProbesEphemeralCompanionKeepsFirstDocument(t *testing.T) {
	fsys := fstest.MapFS{
		"eph.yaml":       {Data: []byte(podDoc("one") + "---\n" + podDoc("two"))},
		"eph.debug.yaml": {Data: []byte("securityContext:\n  privileged: true\n")},
	}
	probes, err := LoadProbes(fsys, ".")
	if err != nil {
		t.Fatalf("LoadProbes: %v", err)
	}
	if len(probes) != 1 || probes[0].ID != "pod-one" {
		t.Fatalf("probes = %+v", probes)
	}
	if !strings.Contains(probes[0].Unsupported, "eph.yaml") {
		t.Errorf("unsupported reason does not name the file: %q", probes[0].Unsupported)
	}
}

func TestLoadProbeFile(t *testing.T) {
	fsys := fstest.MapFS{
		"pair.yaml":          {Data: []byte(podDoc("zz") + "---\n" + podDoc("aa"))},
		"allow-benign.yaml":  {Data: []byte(podDoc("benign"))},
		"comments.yaml":      {Data: []byte("# nothing here\n")},
		"dup.yaml":           {Data: []byte(podDoc("x", "analyze.kubeapt.io/id: same") + "---\n" + podDoc("y", "analyze.kubeapt.io/id: same"))},
		"invalid-expect.yml": {Data: []byte(podDoc("x", "analyze.kubeapt.io/expect: maybe"))},
	}

	probes, err := LoadProbeFile(fsys, "pair.yaml")
	if err != nil {
		t.Fatalf("LoadProbeFile: %v", err)
	}
	if len(probes) != 2 || probes[0].ID != "pod-aa" || probes[1].ID != "pod-zz" {
		t.Fatalf("probes not sorted by id: %+v", probes)
	}

	allowed, err := LoadProbeFile(fsys, "allow-benign.yaml")
	if err != nil || len(allowed) != 1 || allowed[0].Expect != ExpectAllowed || allowed[0].ID != "allow-benign" {
		t.Fatalf("allow file: %+v, %v", allowed, err)
	}

	for name, want := range map[string]string{
		"missing.yaml":       "analyze: read missing.yaml",
		"comments.yaml":      "no probe manifests found in comments.yaml",
		"dup.yaml":           `duplicate probe id "same"`,
		"invalid-expect.yml": "maybe",
	} {
		if _, err := LoadProbeFile(fsys, name); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("LoadProbeFile(%s) err = %v, want %q", name, err, want)
		}
	}
}

func TestLoadBundleEmptyRootMeansDot(t *testing.T) {
	probes, err := LoadBundle(bundleFS(), "")
	if err != nil || len(probes) != 2 {
		t.Fatalf("probes %d, err %v", len(probes), err)
	}
}

func TestLoadBundleWithoutProbesDirectory(t *testing.T) {
	_, err := LoadBundle(fstest.MapFS{"policies.yaml": {Data: []byte(bundlePolicies)}}, ".")
	if err == nil {
		t.Fatal("expected an error for a bundle with no probes/")
	}
}

// A bundle without policies.yaml still runs; it just cannot name its policies.
func TestLoadBundleWithoutPolicies(t *testing.T) {
	fsys := bundleFS()
	delete(fsys, "policies.yaml")
	probes, err := LoadBundle(fsys, ".")
	if err != nil {
		t.Fatalf("LoadBundle: %v", err)
	}
	for _, p := range probes {
		if p.Policy != nil {
			t.Errorf("%s resolved a policy with no policies.yaml", p.ID)
		}
	}
}

// A policies.yaml that is present but broken is an error. Swallowing it would
// strip every name, severity and link from the report without saying why.
func TestLoadBundleRejectsCorruptPolicies(t *testing.T) {
	fsys := bundleFS()
	fsys["policies.yaml"] = &fstest.MapFile{Data: []byte("apiVersion: admissionregistration.k8s.io/v1\nkind: ValidatingAdmissionPolicy\nmetadata: [not, a, map]\n")}
	if _, err := LoadBundle(fsys, "."); err == nil || !strings.Contains(err.Error(), "policies.yaml") {
		t.Fatalf("err = %v, want an error naming policies.yaml", err)
	}
}

func TestIsManifestName(t *testing.T) {
	for name, want := range map[string]bool{
		"a.yaml": true, "a.YML": true, "a.json": true, "a.md": false, "yaml": false,
	} {
		if got := isManifestName(name); got != want {
			t.Errorf("isManifestName(%q) = %v", name, got)
		}
	}
}
