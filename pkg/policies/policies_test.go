// Copyright by cenroq AG
// Contact: info@cenroq.com

package policies_test

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/cenroq/kubeapt/v2/internal/scanaccess"
	"github.com/cenroq/kubeapt/v2/pkg/policies"
	"github.com/cenroq/kubeapt/v2/pkg/types"
	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
)

const (
	policyHighSeverityYAML = `apiVersion: admissionregistration.k8s.io/v1
kind: ValidatingAdmissionPolicy
metadata:
  name: test-policy
  annotations:
    security.cenroq.io/severity: high
spec:
  failurePolicy: Fail
  matchConstraints:
    resourceRules:
      - apiGroups: [""]
        apiVersions: ["v1"]
        operations: ["CREATE"]
        resources: ["pods"]
  validations:
    - expression: "object.metadata.name != 'forbidden'"
      message: "name must not be 'forbidden'"
`

	bindingForTestPolicyYAML = `apiVersion: admissionregistration.k8s.io/v1
kind: ValidatingAdmissionPolicyBinding
metadata:
  name: test-binding
spec:
  policyName: test-policy
  validationActions: [Deny]
`

	secondBindingForTestPolicyYAML = `apiVersion: admissionregistration.k8s.io/v1
kind: ValidatingAdmissionPolicyBinding
metadata:
  name: test-binding-2
spec:
  policyName: test-policy
  validationActions: [Warn]
`

	unrelatedConfigMapYAML = `apiVersion: v1
kind: ConfigMap
metadata:
  name: should-be-ignored
data:
  key: value
`

	deploymentPolicyYAML = `apiVersion: admissionregistration.k8s.io/v1
kind: ValidatingAdmissionPolicy
metadata:
  name: deploy-policy
  annotations:
    security.cenroq.io/severity: low
spec:
  matchConstraints:
    resourceRules:
      - apiGroups: ["apps"]
        apiVersions: ["v1"]
        operations: ["CREATE"]
        resources: ["deployments"]
  validations:
    - expression: "true"
      message: "ok"
`
)

func TestLoad_SinglePolicy(t *testing.T) {
	fsys := fstest.MapFS{
		"policies.yaml": {Data: []byte(policyHighSeverityYAML)},
	}

	bundle, err := policies.Load(fsys, ".")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if bundle.Len() != 1 {
		t.Fatalf("Len = %d, want 1", bundle.Len())
	}

	policy, ok := bundle.Get("test-policy")
	if !ok {
		t.Fatal("Get(test-policy) = false")
	}
	if policy.ID != "test-policy" {
		t.Errorf("ID = %q, want test-policy", policy.ID)
	}
	if !bytes.Contains(policy.RawYAML, []byte("name: test-policy")) {
		t.Errorf("RawYAML missing policy name marker; got %q", policy.RawYAML)
	}
	if len(policy.BindingYAML) != 0 {
		t.Errorf("BindingYAML = %q, want empty for unbound policy", policy.BindingYAML)
	}

	parsed := policy.Parsed(scanaccess.Token{})
	if parsed == nil || parsed.VAP == nil {
		t.Fatal("Parsed handle missing VAP")
	}
	if parsed.Severity != types.SeverityHigh {
		t.Errorf("Severity = %q, want High", parsed.Severity)
	}
	if len(parsed.Bindings) != 0 {
		t.Errorf("Bindings = %d, want 0", len(parsed.Bindings))
	}
}

func TestLoad_PolicyWithBinding(t *testing.T) {
	fsys := fstest.MapFS{
		"policies.yaml": {Data: []byte(policyHighSeverityYAML)},
		"bindings.yaml": {Data: []byte(bindingForTestPolicyYAML)},
	}

	bundle, err := policies.Load(fsys, ".")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	policy, _ := bundle.Get("test-policy")
	if policy == nil {
		t.Fatal("test-policy not found")
	}
	if !bytes.Contains(policy.BindingYAML, []byte("name: test-binding")) {
		t.Errorf("BindingYAML missing binding name; got %q", policy.BindingYAML)
	}

	parsed := policy.Parsed(scanaccess.Token{})
	if len(parsed.Bindings) != 1 {
		t.Fatalf("Bindings = %d, want 1", len(parsed.Bindings))
	}
	if parsed.Bindings[0].Spec.PolicyName != "test-policy" {
		t.Errorf("binding.spec.policyName = %q, want test-policy", parsed.Bindings[0].Spec.PolicyName)
	}
}

func TestLoad_MultipleBindingsTargetingSamePolicy(t *testing.T) {
	fsys := fstest.MapFS{
		"all.yaml": {Data: []byte(policyHighSeverityYAML + "---\n" + bindingForTestPolicyYAML + "---\n" + secondBindingForTestPolicyYAML)},
	}
	bundle, err := policies.Load(fsys, ".")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	policy, _ := bundle.Get("test-policy")
	if policy == nil {
		t.Fatal("policy missing")
	}
	if !bytes.Contains(policy.BindingYAML, []byte("test-binding")) || !bytes.Contains(policy.BindingYAML, []byte("test-binding-2")) {
		t.Errorf("BindingYAML missing one of the two bindings; got %q", policy.BindingYAML)
	}
	// "---" separator must appear between the two binding documents.
	if !bytes.Contains(policy.BindingYAML, []byte("\n---\n")) {
		t.Errorf("BindingYAML missing document separator; got %q", policy.BindingYAML)
	}
	parsed := policy.Parsed(scanaccess.Token{})
	if len(parsed.Bindings) != 2 {
		t.Errorf("Bindings = %d, want 2", len(parsed.Bindings))
	}
}

func TestLoad_DuplicatePolicyIDReturnsSentinel(t *testing.T) {
	fsys := fstest.MapFS{
		"a.yaml": {Data: []byte(policyHighSeverityYAML)},
		"b.yaml": {Data: []byte(policyHighSeverityYAML)},
	}
	_, err := policies.Load(fsys, ".")
	if err == nil {
		t.Fatal("Load: want error, got nil")
	}
	if !errors.Is(err, policies.ErrDuplicatePolicy) {
		t.Errorf("err = %v, want errors.Is ErrDuplicatePolicy", err)
	}
}

func TestLoad_IgnoresOtherKinds(t *testing.T) {
	fsys := fstest.MapFS{
		"policies.yaml": {Data: []byte(policyHighSeverityYAML + "---\n" + unrelatedConfigMapYAML)},
	}
	bundle, err := policies.Load(fsys, ".")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if bundle.Len() != 1 {
		t.Errorf("Len = %d, want 1 (ConfigMap should be ignored)", bundle.Len())
	}
}

func TestLoad_SeverityNormalization(t *testing.T) {
	cases := map[string]types.Severity{
		"critical": types.SeverityCritical,
		"High":     types.SeverityHigh,
		"moderate": types.SeverityModerate,
		"LOW":      types.SeverityLow,
		"info":     types.SeverityInfo,
		"":         types.SeverityNotRated,
		"bogus":    types.SeverityNotRated,
	}
	for annotation, want := range cases {
		annotation, want := annotation, want
		t.Run(annotation, func(t *testing.T) {
			yaml := `apiVersion: admissionregistration.k8s.io/v1
kind: ValidatingAdmissionPolicy
metadata:
  name: p
  annotations:
    security.cenroq.io/severity: "` + annotation + `"
spec:
  failurePolicy: Fail
  matchConstraints:
    resourceRules:
      - apiGroups: [""]
        apiVersions: ["v1"]
        operations: ["CREATE"]
        resources: ["pods"]
  validations:
    - expression: "true"
`
			bundle, err := policies.Load(fstest.MapFS{"p.yaml": {Data: []byte(yaml)}}, ".")
			if err != nil {
				t.Fatalf("Load: %v", err)
			}
			p, _ := bundle.Get("p")
			got := p.Parsed(scanaccess.Token{}).Severity
			if got != want {
				t.Errorf("Severity(%q) = %q, want %q", annotation, got, want)
			}
		})
	}
}

func TestLoad_IterateOrder(t *testing.T) {
	// Filenames sort alphabetically, so iteration order should follow the sorted file list.
	fsys := fstest.MapFS{
		"01-first.yaml": {Data: []byte(renamePolicy(policyHighSeverityYAML, "alpha-policy"))},
		"02-second.yaml": {Data: []byte(renamePolicy(policyHighSeverityYAML, "beta-policy"))},
	}
	bundle, err := policies.Load(fsys, ".")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	var got []string
	for p := range bundle.Iterate() {
		got = append(got, p.ID)
	}
	want := []string{"alpha-policy", "beta-policy"}
	if len(got) != len(want) || got[0] != want[0] || got[1] != want[1] {
		t.Errorf("Iterate order = %v, want %v", got, want)
	}
}

func TestLoadDir(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "policies.yaml"), []byte(policyHighSeverityYAML), 0o644); err != nil {
		t.Fatal(err)
	}
	bundle, err := policies.LoadDir(dir)
	if err != nil {
		t.Fatalf("LoadDir: %v", err)
	}
	if bundle.Len() != 1 {
		t.Errorf("Len = %d, want 1", bundle.Len())
	}
}

func renamePolicy(yaml, newName string) string {
	return string(bytes.Replace([]byte(yaml), []byte("name: test-policy"), []byte("name: "+newName), 1))
}

const policyWithAllAnnotationsYAML = `apiVersion: admissionregistration.k8s.io/v1
kind: ValidatingAdmissionPolicy
metadata:
  name: annotated-policy
  annotations:
    security.cenroq.io/displayName: Privileged Containers Not Allowed
    security.cenroq.io/description: Containers must not run with privileged=true.
    security.cenroq.io/category: Pod Security
spec:
  failurePolicy: Fail
  matchConstraints:
    resourceRules:
      - apiGroups: [""]
        apiVersions: ["v1"]
        operations: ["CREATE"]
        resources: ["pods"]
  validations:
    - expression: "true"
`

const policyWithKyvernoAnnotationsYAML = `apiVersion: admissionregistration.k8s.io/v1
kind: ValidatingAdmissionPolicy
metadata:
  name: kyverno-annotated-policy
  annotations:
    policies.kyverno.io/title: Block hostPath Volumes
    policies.kyverno.io/description: hostPath volumes leak host filesystem state.
    policies.kyverno.io/category: Pod Security
spec:
  failurePolicy: Fail
  matchConstraints:
    resourceRules:
      - apiGroups: [""]
        apiVersions: ["v1"]
        operations: ["CREATE"]
        resources: ["pods"]
  validations:
    - expression: "true"
`

const policyWithNoAnnotationsYAML = `apiVersion: admissionregistration.k8s.io/v1
kind: ValidatingAdmissionPolicy
metadata:
  name: bare-policy
spec:
  failurePolicy: Fail
  matchConstraints:
    resourceRules:
      - apiGroups: [""]
        apiVersions: ["v1"]
        operations: ["CREATE"]
        resources: ["pods"]
  validations:
    - expression: "true"
`

func TestPolicyMetadata_CenroqAnnotations(t *testing.T) {
	bundle, err := policies.Load(fstest.MapFS{"p.yaml": {Data: []byte(policyWithAllAnnotationsYAML)}}, ".")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	p, _ := bundle.Get("annotated-policy")
	if got := p.Title(); got != "Privileged Containers Not Allowed" {
		t.Errorf("Title() = %q, want cenroq displayName", got)
	}
	if got := p.Description(); got != "Containers must not run with privileged=true." {
		t.Errorf("Description() = %q, want cenroq description", got)
	}
	if got := p.Category(); got != "Pod Security" {
		t.Errorf("Category() = %q, want cenroq category", got)
	}
}

func TestPolicyMetadata_KyvernoFallback(t *testing.T) {
	bundle, err := policies.Load(fstest.MapFS{"p.yaml": {Data: []byte(policyWithKyvernoAnnotationsYAML)}}, ".")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	p, _ := bundle.Get("kyverno-annotated-policy")
	if got := p.Title(); got != "Block hostPath Volumes" {
		t.Errorf("Title() = %q, want kyverno title fallback", got)
	}
	if got := p.Description(); got != "hostPath volumes leak host filesystem state." {
		t.Errorf("Description() = %q, want kyverno description fallback", got)
	}
	if got := p.Category(); got != "Pod Security" {
		t.Errorf("Category() = %q, want kyverno category fallback", got)
	}
}

func TestPolicyMetadata_FallbacksWhenAbsent(t *testing.T) {
	bundle, err := policies.Load(fstest.MapFS{"p.yaml": {Data: []byte(policyWithNoAnnotationsYAML)}}, ".")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	p, _ := bundle.Get("bare-policy")
	if got := p.Title(); got != "bare-policy" {
		t.Errorf("Title() = %q, want fallback to ID", got)
	}
	if got := p.Description(); got != "" {
		t.Errorf("Description() = %q, want empty string when unset", got)
	}
	if got := p.Category(); got != "" {
		t.Errorf("Category() = %q, want empty string when unset", got)
	}
}

func TestBundleMetadata_FromBundleJSON(t *testing.T) {
	fsys := fstest.MapFS{
		"policies.yaml": {Data: []byte(policyHighSeverityYAML)},
		"bundle.json": {Data: []byte(`{
  "name": "pod-security-admission",
  "description": "Pod Security Admission policies.",
  "version": "v1.36.0"
}`)},
	}
	bundle, err := policies.Load(fsys, ".")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if got := bundle.Name(); got != "pod-security-admission" {
		t.Errorf("Name() = %q", got)
	}
	if got := bundle.Description(); got != "Pod Security Admission policies." {
		t.Errorf("Description() = %q", got)
	}
	if got := bundle.Version(); got != "v1.36.0" {
		t.Errorf("Version() = %q", got)
	}
}

func TestBundleMetadata_EmptyWhenBundleJSONAbsent(t *testing.T) {
	bundle, err := policies.Load(fstest.MapFS{"p.yaml": {Data: []byte(policyHighSeverityYAML)}}, ".")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if got := bundle.Name(); got != "" {
		t.Errorf("Name() = %q, want empty without bundle.json", got)
	}
	if got := bundle.Description(); got != "" {
		t.Errorf("Description() = %q, want empty without bundle.json", got)
	}
	if got := bundle.Version(); got != "" {
		t.Errorf("Version() = %q, want empty without bundle.json", got)
	}
}

func TestBundleMetadata_MalformedJSONIsError(t *testing.T) {
	fsys := fstest.MapFS{
		"policies.yaml": {Data: []byte(policyHighSeverityYAML)},
		"bundle.json":   {Data: []byte(`{"name": "broken`)},
	}
	if _, err := policies.Load(fsys, "."); err == nil {
		t.Fatal("Load on malformed bundle.json = nil, want error")
	}
}

func TestBundleLabelsAndSources_Populated(t *testing.T) {
	fsys := fstest.MapFS{
		"policies.yaml": {Data: []byte(policyHighSeverityYAML)},
		"bundle.json": {Data: []byte(`{
  "name": "pod-security-admission",
  "version": "v1.36.0",
  "labels": {
    "audit":   "pss.security.cenroq.io/audit",
    "enforce": "pss.security.cenroq.io/enforce",
    "warn":    "pss.security.cenroq.io/warn"
  },
  "sources": [
    "https://github.com/cenroq/kubernetes-security-policies/releases/download/vap_pod-security-admission@v1.36.0/pod-security-admission.tar.gz"
  ]
}`)},
	}
	bundle, err := policies.Load(fsys, ".")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	labels := bundle.Labels()
	if labels["audit"] != "pss.security.cenroq.io/audit" || labels["enforce"] != "pss.security.cenroq.io/enforce" || labels["warn"] != "pss.security.cenroq.io/warn" {
		t.Errorf("Labels() = %v, want audit/enforce/warn keys", labels)
	}
	sources := bundle.Sources()
	if len(sources) != 1 || !strings.HasSuffix(sources[0], "pod-security-admission.tar.gz") {
		t.Errorf("Sources() = %v, want one .tar.gz URL", sources)
	}
}

func TestBundleLabelsAndSources_NilWhenAbsent(t *testing.T) {
	bundle, err := policies.Load(fstest.MapFS{"p.yaml": {Data: []byte(policyHighSeverityYAML)}}, ".")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if got := bundle.Labels(); got != nil {
		t.Errorf("Labels() = %v, want nil without bundle.json", got)
	}
	if got := bundle.Sources(); got != nil {
		t.Errorf("Sources() = %v, want nil without bundle.json", got)
	}
}

func TestBundleLabelsAndSources_DefensiveCopy(t *testing.T) {
	fsys := fstest.MapFS{
		"policies.yaml": {Data: []byte(policyHighSeverityYAML)},
		"bundle.json": {Data: []byte(`{
  "name": "b",
  "labels": {"audit": "k1"},
  "sources": ["s1"]
}`)},
	}
	bundle, err := policies.Load(fsys, ".")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	// Mutate the returned copies; subsequent reads must reflect the original.
	bundle.Labels()["audit"] = "tampered"
	bundle.Sources()[0] = "tampered"
	if got := bundle.Labels()["audit"]; got != "k1" {
		t.Errorf("Labels() mutation leaked back: got %q, want k1", got)
	}
	if got := bundle.Sources()[0]; got != "s1" {
		t.Errorf("Sources() mutation leaked back: got %q, want s1", got)
	}
}

func vapTargeting(resources ...string) *admissionregistrationv1.ValidatingAdmissionPolicy {
	return &admissionregistrationv1.ValidatingAdmissionPolicy{
		Spec: admissionregistrationv1.ValidatingAdmissionPolicySpec{
			MatchConstraints: &admissionregistrationv1.MatchResources{
				ResourceRules: []admissionregistrationv1.NamedRuleWithOperations{
					{RuleWithOperations: admissionregistrationv1.RuleWithOperations{Rule: admissionregistrationv1.Rule{Resources: resources}}},
				},
			},
		},
	}
}

func TestPolicyTargetsResources_Func(t *testing.T) {
	cases := []struct {
		name      string
		policy    *admissionregistrationv1.ValidatingAdmissionPolicy
		resources []string
		want      bool
	}{
		{"exact", vapTargeting("pods"), []string{"pods"}, true},
		{"miss", vapTargeting("deployments"), []string{"pods"}, false},
		{"base of subresource", vapTargeting("pods/status"), []string{"pods"}, true},
		{"subresource request not covered by base", vapTargeting("pods"), []string{"pods/status"}, false},
		{"wildcard", vapTargeting("*"), []string{"pods"}, true},
		{"group wildcard", vapTargeting("*/*"), []string{"configmaps"}, true},
		{"case insensitive", vapTargeting("Pods"), []string{"PODS"}, true},
		{"any of several", vapTargeting("configmaps"), []string{"pods", "configmaps"}, true},
		{"empty resources", vapTargeting("pods"), nil, false},
		{"nil vap", nil, []string{"pods"}, false},
		{"nil match constraints", &admissionregistrationv1.ValidatingAdmissionPolicy{}, []string{"pods"}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := policies.PolicyTargetsResources(tc.policy, tc.resources); got != tc.want {
				t.Fatalf("PolicyTargetsResources() = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestPolicyResources_Func(t *testing.T) {
	if got := strings.Join(policies.PolicyResources(vapTargeting("pods/status", "pods", "configmaps")), ","); got != "configmaps,pods" {
		t.Fatalf("PolicyResources() = %q, want configmaps,pods", got)
	}
	if got := strings.Join(policies.PolicyResources(vapTargeting("*/*")), ","); got != "*" {
		t.Fatalf("PolicyResources(wildcard) = %q, want *", got)
	}
	if got := policies.PolicyResources(nil); got != nil {
		t.Fatalf("PolicyResources(nil) = %v, want nil", got)
	}
}

func vapWithRule(groups, versions, resources []string) *admissionregistrationv1.ValidatingAdmissionPolicy {
	return &admissionregistrationv1.ValidatingAdmissionPolicy{
		Spec: admissionregistrationv1.ValidatingAdmissionPolicySpec{
			MatchConstraints: &admissionregistrationv1.MatchResources{
				ResourceRules: []admissionregistrationv1.NamedRuleWithOperations{
					{RuleWithOperations: admissionregistrationv1.RuleWithOperations{Rule: admissionregistrationv1.Rule{
						APIGroups:   groups,
						APIVersions: versions,
						Resources:   resources,
					}}},
				},
			},
		},
	}
}

func gvr(group, version, resource string) types.GVR {
	return types.GVR{Group: group, Version: version, Resource: resource}
}

func TestPolicyTargetsGVRs_Func(t *testing.T) {
	netpol := vapWithRule([]string{"networking.k8s.io"}, []string{"v1"}, []string{"networkpolicies"})
	calico := vapWithRule([]string{"projectcalico.org"}, []string{"v3"}, []string{"networkpolicies"})
	core := vapWithRule([]string{""}, []string{"v1"}, []string{"services"})
	subres := vapWithRule([]string{""}, []string{"v1"}, []string{"pods/status"})
	anyGroup := vapWithRule(nil, []string{"v1"}, []string{"networkpolicies"})
	wildcard := vapWithRule([]string{"*"}, []string{"*"}, []string{"*"})

	cases := []struct {
		name string
		vap  *admissionregistrationv1.ValidatingAdmissionPolicy
		gvrs []types.GVR
		want bool
	}{
		{"exact group+resource", netpol, []types.GVR{gvr("networking.k8s.io", "v1", "networkpolicies")}, true},
		{"group distinguishes calico from k8s", netpol, []types.GVR{gvr("projectcalico.org", "v3", "networkpolicies")}, false},
		{"calico matches its own group", calico, []types.GVR{gvr("projectcalico.org", "v3", "networkpolicies")}, true},
		{"core group exact", core, []types.GVR{gvr("", "v1", "services")}, true},
		{"core not matched by named-group request", core, []types.GVR{gvr("networking.k8s.io", "v1", "services")}, false},
		{"resource mismatch", netpol, []types.GVR{gvr("networking.k8s.io", "v1", "services")}, false},
		{"empty rule apiGroups matches any group", anyGroup, []types.GVR{gvr("networking.k8s.io", "v1", "networkpolicies")}, true},
		{"subresource base matches", subres, []types.GVR{gvr("", "v1", "pods")}, true},
		{"version ignored: empty request still matches", netpol, []types.GVR{gvr("networking.k8s.io", "", "networkpolicies")}, true},
		{"version ignored: star request still matches", netpol, []types.GVR{gvr("networking.k8s.io", "*", "networkpolicies")}, true},
		{"version ignored: concrete mismatch still matches", netpol, []types.GVR{gvr("networking.k8s.io", "v2", "networkpolicies")}, true},
		{"request group star matches any", netpol, []types.GVR{gvr("*", "v1", "networkpolicies")}, true},
		{"policy wildcard rule matches any gvr", wildcard, []types.GVR{gvr("anything.io", "v9", "widgets")}, true},
		{"any of several", netpol, []types.GVR{gvr("", "v1", "services"), gvr("networking.k8s.io", "v1", "networkpolicies")}, true},
		{"empty resource ignored", netpol, []types.GVR{gvr("networking.k8s.io", "v1", "")}, false},
		{"empty gvrs", netpol, nil, false},
		{"nil vap", nil, []types.GVR{gvr("", "v1", "services")}, false},
		{"nil match constraints", &admissionregistrationv1.ValidatingAdmissionPolicy{}, []types.GVR{gvr("", "v1", "services")}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := policies.PolicyTargetsGVRs(tc.vap, tc.gvrs); got != tc.want {
				t.Fatalf("PolicyTargetsGVRs() = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestPolicy_TargetsGVR_Method(t *testing.T) {
	// policyHighSeverityYAML targets core (apiGroups [""]) v1 pods.
	bundle, err := policies.Load(fstest.MapFS{"p.yaml": {Data: []byte(policyHighSeverityYAML)}}, ".")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	p, ok := bundle.Get("test-policy")
	if !ok {
		t.Fatal("test-policy missing")
	}
	if !p.TargetsGVR(types.GVR{Group: "", Version: "v1", Resource: "pods"}) {
		t.Errorf("test-policy should target core/v1/pods")
	}
	if p.TargetsGVR(types.GVR{Group: "apps", Version: "v1", Resource: "deployments"}) {
		t.Errorf("test-policy should not target apps/v1/deployments")
	}
	if p.TargetsGVR() {
		t.Errorf("TargetsGVR() with no args must be false")
	}

	var nilPolicy *policies.Policy
	if nilPolicy.TargetsGVR(types.GVR{Resource: "pods"}) {
		t.Errorf("nil *Policy must not target anything")
	}
}

func TestPolicyMethods_ResourcesAndTargets(t *testing.T) {
	fsys := fstest.MapFS{
		"all.yaml": {Data: []byte(policyHighSeverityYAML + "---\n" + deploymentPolicyYAML)},
	}
	bundle, err := policies.Load(fsys, ".")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	pods, _ := bundle.Get("test-policy")
	if pods == nil {
		t.Fatal("test-policy missing")
	}
	if !pods.TargetsResources("pods") {
		t.Errorf("test-policy should target pods")
	}
	if pods.TargetsResources("deployments") {
		t.Errorf("test-policy should not target deployments")
	}
	if got := strings.Join(pods.Resources(), ","); got != "pods" {
		t.Errorf("test-policy Resources() = %q, want pods", got)
	}

	// Nil-receiver and nil-VAP safety.
	var nilPolicy *policies.Policy
	if nilPolicy.TargetsResources("pods") {
		t.Errorf("nil *Policy must not target anything")
	}
	if nilPolicy.Resources() != nil {
		t.Errorf("nil *Policy Resources() must be nil")
	}
}

func TestBundleFilterByResources(t *testing.T) {
	fsys := fstest.MapFS{
		"all.yaml":    {Data: []byte(policyHighSeverityYAML + "---\n" + bindingForTestPolicyYAML + "---\n" + deploymentPolicyYAML)},
		"bundle.json": {Data: []byte(`{"name":"b","version":"1.0.0","sources":["s1"]}`)},
	}
	bundle, err := policies.Load(fsys, ".")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if bundle.Len() != 2 {
		t.Fatalf("precondition: Len = %d, want 2", bundle.Len())
	}

	filtered := bundle.FilterByResources("pods")
	if filtered.Len() != 1 {
		t.Fatalf("FilterByResources(pods) Len = %d, want 1", filtered.Len())
	}
	if _, ok := filtered.Get("test-policy"); !ok {
		t.Errorf("expected test-policy retained")
	}
	if _, ok := filtered.Get("deploy-policy"); ok {
		t.Errorf("expected deploy-policy filtered out")
	}
	// Bindings ride along with the kept policy.
	kept, _ := filtered.Get("test-policy")
	if !bytes.Contains(kept.BindingYAML, []byte("test-binding")) {
		t.Errorf("kept policy lost its binding YAML")
	}
	// Bundle metadata is carried over.
	if filtered.Name() != "b" || filtered.Version() != "1.0.0" {
		t.Errorf("metadata not carried: name=%q version=%q", filtered.Name(), filtered.Version())
	}
	if got := strings.Join(filtered.Sources(), ","); got != "s1" {
		t.Errorf("sources not carried: %q", got)
	}
	// The receiver is unchanged.
	if bundle.Len() != 2 {
		t.Errorf("FilterByResources mutated the receiver: Len = %d, want 2", bundle.Len())
	}

	// No resources -> structural copy with every policy.
	if all := bundle.FilterByResources(); all.Len() != 2 {
		t.Errorf("FilterByResources() Len = %d, want 2", all.Len())
	}
	// Multiple resources keep both.
	if both := bundle.FilterByResources("pods", "deployments"); both.Len() != 2 {
		t.Errorf("FilterByResources(pods,deployments) Len = %d, want 2", both.Len())
	}
	// Unmatched resource yields an empty bundle.
	if none := bundle.FilterByResources("services"); none.Len() != 0 {
		t.Errorf("FilterByResources(services) Len = %d, want 0", none.Len())
	}
}
