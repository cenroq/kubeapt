// Copyright by cenroq AG
// Contact: info@cenroq.com

package scanner_test

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/cenroq/kubeapt/v2/pkg/policies"
	"github.com/cenroq/kubeapt/v2/pkg/scanner"
	"github.com/cenroq/kubeapt/v2/pkg/types"
)

const policyForbidsNameYAML = `apiVersion: admissionregistration.k8s.io/v1
kind: ValidatingAdmissionPolicy
metadata:
  name: forbid-bad-name
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
      message: "pod name 'forbidden' is not allowed"
`

const policyWithNarrowBindingYAML = policyForbidsNameYAML + `---
apiVersion: admissionregistration.k8s.io/v1
kind: ValidatingAdmissionPolicyBinding
metadata:
  name: forbid-bad-name--prod-only
spec:
  policyName: forbid-bad-name
  matchResources:
    namespaceSelector:
      matchLabels:
        env: prod
  validationActions: [Deny]
`

const policyBadCELYAML = `apiVersion: admissionregistration.k8s.io/v1
kind: ValidatingAdmissionPolicy
metadata:
  name: bad-cel
spec:
  failurePolicy: Fail
  matchConstraints:
    resourceRules:
      - apiGroups: [""]
        apiVersions: ["v1"]
        operations: ["CREATE"]
        resources: ["pods"]
  validations:
    - expression: "this is not valid cel @"
      message: "should not matter"
`

func mustLoad(t *testing.T, yaml string) *policies.Bundle {
	t.Helper()
	bundle, err := policies.Load(fstest.MapFS{"p.yaml": {Data: []byte(yaml)}}, ".")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	return bundle
}

func pod(name string) types.Manifest {
	return types.Manifest{
		"apiVersion": "v1",
		"kind":       "Pod",
		"metadata": map[string]any{
			"name":      name,
			"namespace": "default",
		},
	}
}

func TestNew_NilBundle(t *testing.T) {
	if _, err := scanner.New(nil); err == nil {
		t.Fatal("New(nil) = nil error, want error")
	}
}

func TestScan_CompliantAndNonCompliant(t *testing.T) {
	sc, err := scanner.New(mustLoad(t, policyForbidsNameYAML))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	res, err := sc.Scan(context.Background(), []types.Manifest{pod("forbidden"), pod("ok")})
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if len(res.Findings) != 1 {
		t.Fatalf("Findings = %d, want 1", len(res.Findings))
	}
	f := res.Findings[0]
	if f.PolicyID != "forbid-bad-name" {
		t.Errorf("PolicyID = %q, want forbid-bad-name", f.PolicyID)
	}
	if f.Severity != types.SeverityHigh {
		t.Errorf("Severity = %q, want High", f.Severity)
	}
	if f.Resource.Name != "forbidden" || f.Resource.Kind != "Pod" {
		t.Errorf("Resource = %+v, want Pod/forbidden", f.Resource)
	}
	if f.Message == "" {
		t.Error("Message empty, want CEL message")
	}
	if len(f.Actions) == 0 {
		t.Error("Actions empty; implicit binding should default to Deny")
	}
	if len(res.ScanErrors) != 0 {
		t.Errorf("ScanErrors = %d, want 0", len(res.ScanErrors))
	}
}

func TestScan_DoesNotMutateInput(t *testing.T) {
	sc, _ := scanner.New(mustLoad(t, policyForbidsNameYAML))
	// A Role kind triggers RBAC normalization (which mutates the resource).
	in := []types.Manifest{
		{
			"apiVersion": "rbac.authorization.k8s.io/v1",
			"kind":       "Role",
			"metadata":   map[string]any{"name": "r", "namespace": "default"},
			// rules absent — the normalizer would add an empty slice.
		},
	}
	if _, err := sc.Scan(context.Background(), in); err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if _, present := in[0]["rules"]; present {
		t.Errorf("input manifest was mutated (rules field appeared); Scan should deep-copy")
	}
}

func TestScan_ContextCancelled(t *testing.T) {
	sc, _ := scanner.New(mustLoad(t, policyForbidsNameYAML))
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := sc.Scan(ctx, []types.Manifest{pod("forbidden")})
	if err == nil {
		t.Fatal("Scan with cancelled ctx = nil error, want context.Canceled")
	}
	if err != context.Canceled {
		t.Errorf("err = %v, want context.Canceled", err)
	}
}

func TestScan_IgnoreBindingsByDefault(t *testing.T) {
	// Bundle ships a narrow binding (namespace env=prod). Pod has no labels.
	// With default (ignore bindings) the implicit binding is used and the
	// policy fires anyway.
	sc, err := scanner.New(mustLoad(t, policyWithNarrowBindingYAML))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	res, err := sc.Scan(context.Background(), []types.Manifest{pod("forbidden")})
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if len(res.Findings) != 1 {
		t.Fatalf("Findings = %d, want 1 (default ignore-bindings should match everything)", len(res.Findings))
	}
}

func TestScan_RespectBindings(t *testing.T) {
	// Same bundle, opt into respect-bindings: namespace selector requires env=prod,
	// the Pod has no namespace label data, so MatchesBinding returns "match all"
	// when namespace data is unknown. We assert the scan still produces a finding —
	// the WithRespectBindings option must not crash and must use the bundle's bindings
	// instead of the implicit one (verified by checking Actions reflect the binding).
	sc, err := scanner.New(mustLoad(t, policyWithNarrowBindingYAML), scanner.WithRespectBindings())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	res, err := sc.Scan(context.Background(), []types.Manifest{pod("forbidden")})
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	// In respect-bindings mode, when namespace labels are unknown, the matcher
	// errs on the side of "match everything." So a finding still appears, and
	// its Actions come from the bundle's binding (Deny in the fixture).
	if len(res.Findings) != 1 {
		t.Fatalf("Findings = %d, want 1", len(res.Findings))
	}
	if len(res.Findings[0].Actions) == 0 || res.Findings[0].Actions[0] != "Deny" {
		t.Errorf("Actions = %v, want [Deny] from bundle binding", res.Findings[0].Actions)
	}
}

func TestScan_BadCELProducesScanError(t *testing.T) {
	sc, _ := scanner.New(mustLoad(t, policyBadCELYAML))
	res, err := sc.Scan(context.Background(), []types.Manifest{pod("anything")})
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if len(res.ScanErrors) == 0 {
		t.Fatal("ScanErrors empty, want CEL compile error")
	}
	se := res.ScanErrors[0]
	if se.PolicyID != "bad-cel" {
		t.Errorf("ScanError.PolicyID = %q, want bad-cel", se.PolicyID)
	}
	if se.Err == nil {
		t.Error("ScanError.Err = nil, want non-nil")
	}
}

func TestScan_NonMatchingResourceProducesNothing(t *testing.T) {
	// Policy matches pods; provide a Service.
	sc, _ := scanner.New(mustLoad(t, policyForbidsNameYAML))
	svc := types.Manifest{
		"apiVersion": "v1",
		"kind":       "Service",
		"metadata":   map[string]any{"name": "forbidden", "namespace": "default"},
	}
	res, err := sc.Scan(context.Background(), []types.Manifest{svc})
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if len(res.Findings) != 0 {
		t.Errorf("Findings = %d, want 0 (Service should not match Pod-only policy)", len(res.Findings))
	}
}

// Fixture policies for exercising the WithPolicyResources GVR filter.
const netpolPolicyYAML = `apiVersion: admissionregistration.k8s.io/v1
kind: ValidatingAdmissionPolicy
metadata:
  name: forbid-netpol
  annotations:
    security.cenroq.io/severity: high
spec:
  failurePolicy: Fail
  matchConstraints:
    resourceRules:
      - apiGroups: ["networking.k8s.io"]
        apiVersions: ["v1"]
        operations: ["CREATE"]
        resources: ["networkpolicies"]
  validations:
    - expression: "false"
      message: "networkpolicy flagged"
`

const calicoNetpolPolicyYAML = `apiVersion: admissionregistration.k8s.io/v1
kind: ValidatingAdmissionPolicy
metadata:
  name: forbid-calico-netpol
spec:
  failurePolicy: Fail
  matchConstraints:
    resourceRules:
      - apiGroups: ["projectcalico.org"]
        apiVersions: ["v3"]
        operations: ["CREATE"]
        resources: ["networkpolicies"]
  validations:
    - expression: "false"
      message: "calico networkpolicy flagged"
`

const servicePolicyYAML = `apiVersion: admissionregistration.k8s.io/v1
kind: ValidatingAdmissionPolicy
metadata:
  name: forbid-service
  annotations:
    security.cenroq.io/severity: moderate
spec:
  failurePolicy: Fail
  matchConstraints:
    resourceRules:
      - apiGroups: [""]
        apiVersions: ["v1"]
        operations: ["CREATE"]
        resources: ["services"]
  validations:
    - expression: "false"
      message: "service flagged"
`

func manifest(apiVersion, kind, name string) types.Manifest {
	return types.Manifest{
		"apiVersion": apiVersion,
		"kind":       kind,
		"metadata":   map[string]any{"name": name, "namespace": "default"},
	}
}

func firedPolicies(res *types.Result) map[string]bool {
	fired := make(map[string]bool)
	for _, f := range res.Findings {
		fired[f.PolicyID] = true
	}
	return fired
}

func TestScan_WithPolicyResources_FiltersByGVR(t *testing.T) {
	// Mixed bundle: a Pod policy, a NetworkPolicy policy, and a Service policy.
	bundle := mustLoad(t, policyForbidsNameYAML+"---\n"+netpolPolicyYAML+"---\n"+servicePolicyYAML)
	sc, err := scanner.New(bundle, scanner.WithPolicyResources([]scanner.GVR{
		{Group: "networking.k8s.io", Version: "v1", Resource: "networkpolicies"},
		{Group: "", Version: "v1", Resource: "services"},
	}))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	manifests := []types.Manifest{
		pod("forbidden"), // would violate the Pod policy, but it is filtered out
		manifest("networking.k8s.io/v1", "NetworkPolicy", "np"),
		manifest("v1", "Service", "svc"),
	}
	res, err := sc.Scan(context.Background(), manifests)
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	fired := firedPolicies(res)
	if fired["forbid-bad-name"] {
		t.Errorf("Pod policy fired, but pods were not in the policy-resources filter")
	}
	if !fired["forbid-netpol"] {
		t.Errorf("NetworkPolicy policy should have fired")
	}
	if !fired["forbid-service"] {
		t.Errorf("Service policy should have fired")
	}
	// A policy filtered out by WithPolicyResources reports no outcome at all,
	// not even a pass.
	assertEvaluationsConsistent(t, res)
	assertEvaluationKeys(t, res, []evaluationKey{
		{"forbid-netpol", "forbid-netpol--implicit", "np", types.OutcomeFail, 1},
		{"forbid-service", "forbid-service--implicit", "svc", types.OutcomeFail, 1},
	})
}

func TestScan_WithPolicyResources_DistinguishesGroup(t *testing.T) {
	// Two policies target the "networkpolicies" resource but in different groups.
	bundle := mustLoad(t, netpolPolicyYAML+"---\n"+calicoNetpolPolicyYAML)
	sc, err := scanner.New(bundle, scanner.WithPolicyResources([]scanner.GVR{
		{Group: "networking.k8s.io", Version: "v1", Resource: "networkpolicies"},
	}))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	manifests := []types.Manifest{
		manifest("networking.k8s.io/v1", "NetworkPolicy", "k8s-np"),
		manifest("projectcalico.org/v3", "NetworkPolicy", "calico-np"),
	}
	res, err := sc.Scan(context.Background(), manifests)
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	fired := firedPolicies(res)
	if !fired["forbid-netpol"] {
		t.Errorf("networking.k8s.io NetworkPolicy policy should have fired")
	}
	if fired["forbid-calico-netpol"] {
		t.Errorf("projectcalico.org policy should have been filtered out by group")
	}
}

func TestScan_WithPolicyResources_EmptyIsNoOp(t *testing.T) {
	sc, err := scanner.New(mustLoad(t, policyForbidsNameYAML), scanner.WithPolicyResources(nil))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	res, err := sc.Scan(context.Background(), []types.Manifest{pod("forbidden")})
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if len(res.Findings) != 1 {
		t.Fatalf("Findings = %d, want 1 (empty filter must not filter anything)", len(res.Findings))
	}
}

const policyTwoViolationsYAML = `apiVersion: admissionregistration.k8s.io/v1
kind: ValidatingAdmissionPolicy
metadata:
  name: two-violations
  annotations:
    # The legacy key on purpose: severity must still resolve through the
    # security.kubeapt.io fallback.
    security.kubeapt.io/severity: low
spec:
  failurePolicy: Fail
  matchConstraints:
    resourceRules:
      - apiGroups: [""]
        apiVersions: ["v1"]
        operations: ["CREATE"]
        resources: ["pods"]
  validations:
    - expression: "false"
      message: "first"
    - expression: "false"
      message: "second"
`

// Three bindings for one policy: two that match every pod with different
// actions, and one whose object selector matches only pods labelled app=web.
const policyPerBindingYAML = policyForbidsNameYAML + `---
apiVersion: admissionregistration.k8s.io/v1
kind: ValidatingAdmissionPolicyBinding
metadata:
  name: forbid-bad-name--all
spec:
  policyName: forbid-bad-name
  validationActions: [Deny]
---
apiVersion: admissionregistration.k8s.io/v1
kind: ValidatingAdmissionPolicyBinding
metadata:
  name: forbid-bad-name--audit
spec:
  policyName: forbid-bad-name
  validationActions: [Audit]
---
apiVersion: admissionregistration.k8s.io/v1
kind: ValidatingAdmissionPolicyBinding
metadata:
  name: forbid-bad-name--web-only
spec:
  policyName: forbid-bad-name
  matchResources:
    objectSelector:
      matchLabels:
        app: web
  validationActions: [Deny]
`

func labelledPod(name string, labels map[string]any) types.Manifest {
	m := pod(name)
	m["metadata"].(map[string]any)["labels"] = labels
	return m
}

func mustScan(t *testing.T, yaml string, manifests []types.Manifest, opts ...scanner.Option) *types.Result {
	t.Helper()
	sc, err := scanner.New(mustLoad(t, yaml), opts...)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	res, err := sc.Scan(context.Background(), manifests)
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	assertEvaluationsConsistent(t, res)
	return res
}

// assertEvaluationsConsistent checks the rules Evaluations promises callers:
// each outcome carries only its own fields, the fail entries' violations are
// exactly the Findings in the same order, and the error entries are exactly
// the ScanErrors in the same order.
func assertEvaluationsConsistent(t *testing.T, res *types.Result) {
	t.Helper()
	var findings []types.Finding
	var scanErrors []types.ScanError
	for i, e := range res.Evaluations {
		switch e.Outcome {
		case types.OutcomePass:
			if len(e.Violations) != 0 || e.Error != "" {
				t.Errorf("Evaluations[%d] pass carries violations %v / error %q", i, e.Violations, e.Error)
			}
		case types.OutcomeFail:
			if len(e.Violations) == 0 || e.Error != "" {
				t.Errorf("Evaluations[%d] fail has %d violations / error %q", i, len(e.Violations), e.Error)
			}
			for _, v := range e.Violations {
				findings = append(findings, types.Finding{
					PolicyID: e.PolicyID, FindingID: e.FindingID, Resource: e.Resource, Severity: e.Severity,
					Message: v.Message, Path: v.Path, Actions: v.Actions,
				})
			}
		case types.OutcomeError:
			if len(e.Violations) != 0 || e.Error == "" {
				t.Errorf("Evaluations[%d] error has violations %v / error %q", i, e.Violations, e.Error)
			}
			scanErrors = append(scanErrors, types.ScanError{PolicyID: e.PolicyID, Resource: e.Resource, Err: errors.New(e.Error)})
		default:
			t.Errorf("Evaluations[%d] has unknown outcome %q", i, e.Outcome)
		}
	}

	if len(findings) != len(res.Findings) {
		t.Fatalf("fail violations add up to %d, Findings has %d", len(findings), len(res.Findings))
	}
	for i, want := range res.Findings {
		got := findings[i]
		if got.PolicyID != want.PolicyID || got.FindingID != want.FindingID || got.Resource != want.Resource ||
			got.Severity != want.Severity || got.Message != want.Message || got.Path != want.Path || !slices.Equal(got.Actions, want.Actions) {
			t.Errorf("violation %d = %+v, Finding = %+v", i, got, want)
		}
	}

	if len(scanErrors) != len(res.ScanErrors) {
		t.Fatalf("error entries add up to %d, ScanErrors has %d", len(scanErrors), len(res.ScanErrors))
	}
	for i, want := range res.ScanErrors {
		got := scanErrors[i]
		if got.PolicyID != want.PolicyID || got.Resource != want.Resource || got.Err.Error() != want.Err.Error() {
			t.Errorf("error entry %d = %+v, ScanError = %+v", i, got, want)
		}
	}
}

// evaluationKey is the part of an Evaluation that identifies it and its
// verdict, for comparing a whole result at once.
type evaluationKey struct {
	Policy, Binding, Object string
	Outcome                 types.Outcome
	Violations              int
}

func evaluationKeys(res *types.Result) []evaluationKey {
	keys := make([]evaluationKey, len(res.Evaluations))
	for i, e := range res.Evaluations {
		keys[i] = evaluationKey{e.PolicyID, e.Binding, e.Resource.Name, e.Outcome, len(e.Violations)}
	}
	return keys
}

func assertEvaluationKeys(t *testing.T, res *types.Result, want []evaluationKey) {
	t.Helper()
	if got := evaluationKeys(res); !slices.Equal(got, want) {
		t.Errorf("Evaluations =\n  %+v\nwant\n  %+v", got, want)
	}
}

func TestScan_EvaluationsPassAndFail(t *testing.T) {
	res := mustScan(t, policyForbidsNameYAML, []types.Manifest{pod("forbidden"), pod("ok")})

	assertEvaluationKeys(t, res, []evaluationKey{
		{"forbid-bad-name", "forbid-bad-name--implicit", "forbidden", types.OutcomeFail, 1},
		{"forbid-bad-name", "forbid-bad-name--implicit", "ok", types.OutcomePass, 0},
	})

	fail, pass := res.Evaluations[0], res.Evaluations[1]
	wantRef := types.ResourceRef{APIVersion: "v1", Kind: "Pod", Namespace: "default", Name: "forbidden"}
	if fail.Resource != wantRef {
		t.Errorf("Resource = %+v, want %+v", fail.Resource, wantRef)
	}
	if fail.Severity != types.SeverityHigh || pass.Severity != types.SeverityHigh {
		t.Errorf("Severity = %q / %q, want High on both", fail.Severity, pass.Severity)
	}
	v := fail.Violations[0]
	if v.Message != "pod name 'forbidden' is not allowed" || !slices.Equal(v.Actions, []string{"Deny"}) {
		t.Errorf("Violation = %+v", v)
	}
	if pass.Violations != nil {
		t.Errorf("pass Violations = %v, want nil", pass.Violations)
	}

	// The Evaluation must not share Actions with the Finding it mirrors.
	res.Findings[0].Actions[0] = "Mutated"
	if fail.Violations[0].Actions[0] != "Deny" {
		t.Errorf("editing Findings[0].Actions changed the Evaluation: %v", fail.Violations[0].Actions)
	}
}

func TestScan_EvaluationsError(t *testing.T) {
	res := mustScan(t, policyBadCELYAML, []types.Manifest{pod("anything")})

	assertEvaluationKeys(t, res, []evaluationKey{
		{"bad-cel", "bad-cel--implicit", "anything", types.OutcomeError, 0},
	})
	e := res.Evaluations[0]
	if e.Error != res.ScanErrors[0].Err.Error() {
		t.Errorf("Error = %q, want the ScanError text %q", e.Error, res.ScanErrors[0].Err.Error())
	}
	if e.Severity != types.SeverityNotRated {
		t.Errorf("Severity = %q, want Not Rated", e.Severity)
	}
}

// Two failing validations are one evaluation with two violations, and two
// Findings.
func TestScan_EvaluationsMultipleViolations(t *testing.T) {
	res := mustScan(t, policyTwoViolationsYAML, []types.Manifest{pod("p")})

	assertEvaluationKeys(t, res, []evaluationKey{
		{"two-violations", "two-violations--implicit", "p", types.OutcomeFail, 2},
	})
	if len(res.Findings) != 2 {
		t.Fatalf("Findings = %d, want 2", len(res.Findings))
	}
	got := []string{res.Evaluations[0].Violations[0].Message, res.Evaluations[0].Violations[1].Message}
	if !slices.Equal(got, []string{"first", "second"}) {
		t.Errorf("violation messages = %v, want [first second]", got)
	}
	if res.Evaluations[0].Severity != types.SeverityLow {
		t.Errorf("Severity = %q, want Low", res.Evaluations[0].Severity)
	}
}

// Every binding that matches an object gets its own entry, in binding order
// and then manifest order; a binding that does not match gets none.
func TestScan_EvaluationsPerBinding(t *testing.T) {
	manifests := []types.Manifest{pod("forbidden"), pod("ok"), labelledPod("web", map[string]any{"app": "web"})}
	res := mustScan(t, policyPerBindingYAML, manifests, scanner.WithRespectBindings())

	const policy = "forbid-bad-name"
	assertEvaluationKeys(t, res, []evaluationKey{
		{policy, policy + "--all", "forbidden", types.OutcomeFail, 1},
		{policy, policy + "--all", "ok", types.OutcomePass, 0},
		{policy, policy + "--all", "web", types.OutcomePass, 0},
		{policy, policy + "--audit", "forbidden", types.OutcomeFail, 1},
		{policy, policy + "--audit", "ok", types.OutcomePass, 0},
		{policy, policy + "--audit", "web", types.OutcomePass, 0},
		{policy, policy + "--web-only", "web", types.OutcomePass, 0},
	})

	// Each fail carries the actions of the binding it was evaluated under.
	if got := res.Evaluations[0].Violations[0].Actions; !slices.Equal(got, []string{"Deny"}) {
		t.Errorf("--all actions = %v, want [Deny]", got)
	}
	if got := res.Evaluations[3].Violations[0].Actions; !slices.Equal(got, []string{"Audit"}) {
		t.Errorf("--audit actions = %v, want [Audit]", got)
	}
}

func TestScan_EvaluationsNotApplicable(t *testing.T) {
	t.Run("object does not match the policy", func(t *testing.T) {
		svc := manifest("v1", "Service", "forbidden")
		res := mustScan(t, policyForbidsNameYAML, []types.Manifest{svc})
		if len(res.Evaluations) != 0 {
			t.Errorf("Evaluations = %+v, want none", res.Evaluations)
		}
	})
	t.Run("policy has no binding", func(t *testing.T) {
		res := mustScan(t, policyForbidsNameYAML, []types.Manifest{pod("forbidden")}, scanner.WithRespectBindings())
		if len(res.Evaluations) != 0 {
			t.Errorf("Evaluations = %+v, want none", res.Evaluations)
		}
	})
}

// A bundle producing every outcome, plus pairs that do not apply, still keeps
// all the rules mustScan checks.
func TestScan_EvaluationsMixedBundle(t *testing.T) {
	bundle := policyForbidsNameYAML + "---\n" + policyBadCELYAML + "---\n" + policyTwoViolationsYAML + "---\n" + servicePolicyYAML
	manifests := []types.Manifest{pod("forbidden"), pod("ok"), manifest("v1", "Service", "svc")}
	res := mustScan(t, bundle, manifests)

	assertEvaluationKeys(t, res, []evaluationKey{
		{"forbid-bad-name", "forbid-bad-name--implicit", "forbidden", types.OutcomeFail, 1},
		{"forbid-bad-name", "forbid-bad-name--implicit", "ok", types.OutcomePass, 0},
		{"bad-cel", "bad-cel--implicit", "forbidden", types.OutcomeError, 0},
		{"bad-cel", "bad-cel--implicit", "ok", types.OutcomeError, 0},
		{"two-violations", "two-violations--implicit", "forbidden", types.OutcomeFail, 2},
		{"two-violations", "two-violations--implicit", "ok", types.OutcomeFail, 2},
		{"forbid-service", "forbid-service--implicit", "svc", types.OutcomeFail, 1},
	})
	if len(res.Findings) != 6 || len(res.ScanErrors) != 2 {
		t.Errorf("Findings = %d, ScanErrors = %d; want 6 and 2", len(res.Findings), len(res.ScanErrors))
	}
}

// Every entry of a policy carries its finding id, whatever the outcome:
// cenroq.io/finding first, the deprecated kubeapt.io/uuid as a fallback, and ""
// for a policy with neither. PolicyID stays the policy's name.
func TestScan_FindingID(t *testing.T) {
	withFinding := strings.Replace(policyForbidsNameYAML,
		"annotations:\n", "annotations:\n    cenroq.io/finding: \"oq-0276\"\n", 1)
	badCELWithFinding := strings.Replace(policyBadCELYAML,
		"name: bad-cel\n", "name: bad-cel\n  annotations:\n    cenroq.io/finding: \" oq-0277 \"\n", 1)
	legacyUUID := strings.Replace(policyTwoViolationsYAML,
		"annotations:\n", "annotations:\n    kubeapt.io/uuid: \"23ef68db\"\n", 1)
	bundle := withFinding + "---\n" + badCELWithFinding + "---\n" + legacyUUID + "---\n" + servicePolicyYAML
	manifests := []types.Manifest{pod("forbidden"), pod("ok"), manifest("v1", "Service", "svc")}
	res := mustScan(t, bundle, manifests)

	want := map[string]string{
		"forbid-bad-name": "oq-0276",
		"bad-cel":         "oq-0277",
		"two-violations":  "23ef68db",
		"forbid-service":  "",
	}
	outcomes := map[types.Outcome]bool{}
	for i, e := range res.Evaluations {
		id, ok := want[e.PolicyID]
		if !ok {
			t.Fatalf("Evaluations[%d] has unexpected policy %q", i, e.PolicyID)
		}
		if e.FindingID != id {
			t.Errorf("Evaluations[%d] (%s, %s) FindingID = %q, want %q", i, e.PolicyID, e.Outcome, e.FindingID, id)
		}
		outcomes[e.Outcome] = true
	}
	for _, o := range []types.Outcome{types.OutcomePass, types.OutcomeFail, types.OutcomeError} {
		if !outcomes[o] {
			t.Errorf("no %s evaluation; the test must cover every outcome", o)
		}
	}
	if len(res.Findings) == 0 {
		t.Fatal("no Findings")
	}
	for i, f := range res.Findings {
		if f.FindingID != want[f.PolicyID] {
			t.Errorf("Findings[%d] (%s) FindingID = %q, want %q", i, f.PolicyID, f.FindingID, want[f.PolicyID])
		}
	}
	if got := policies.DocsURL(res.Evaluations[0].FindingID); got != policies.DocsBaseURL+"/oq-0276" {
		t.Errorf("DocsURL = %q", got)
	}
}
