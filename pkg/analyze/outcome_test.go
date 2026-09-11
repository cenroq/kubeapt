// Copyright by cenroq AG
// Contact: info@cenroq.com

package analyze_test

import (
	"errors"
	"testing"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime/schema"

	"github.com/cenroq/kubeapt/v2/pkg/analyze"
)

func probe(t *testing.T, expect analyze.Expectation) analyze.Probe {
	t.Helper()
	return analyze.Probe{
		ID:     "privileged-pod",
		Expect: expect,
		Object: object(t, `{"apiVersion":"v1","kind":"Pod","metadata":{"name":"probe"},"spec":{"containers":[{"name":"app","securityContext":{"privileged":true}}]}}`),
	}
}

// This matrix is the specification. If the implementation disagrees with it,
// the implementation is wrong.
func TestVerdictFor(t *testing.T) {
	tests := []struct {
		expect  analyze.Expectation
		outcome analyze.Outcome
		want    analyze.Verdict
	}{
		{analyze.ExpectBlocked, analyze.OutcomeBlocked, analyze.VerdictPass},
		{analyze.ExpectBlocked, analyze.OutcomeAdmitted, analyze.VerdictFail},
		{analyze.ExpectBlocked, analyze.OutcomeMutated, analyze.VerdictWarn},
		{analyze.ExpectBlocked, analyze.OutcomeInconclusive, analyze.VerdictInconclusive},
		{analyze.ExpectBlocked, analyze.OutcomeSkipped, analyze.VerdictInconclusive},
		{analyze.ExpectBlocked, analyze.OutcomeError, analyze.VerdictInconclusive},

		{analyze.ExpectAllowed, analyze.OutcomeBlocked, analyze.VerdictWarn},
		{analyze.ExpectAllowed, analyze.OutcomeAdmitted, analyze.VerdictPass},
		{analyze.ExpectAllowed, analyze.OutcomeMutated, analyze.VerdictPass},
		{analyze.ExpectAllowed, analyze.OutcomeInconclusive, analyze.VerdictInconclusive},
		{analyze.ExpectAllowed, analyze.OutcomeSkipped, analyze.VerdictInconclusive},
		{analyze.ExpectAllowed, analyze.OutcomeError, analyze.VerdictInconclusive},
	}
	for _, tc := range tests {
		if got := analyze.VerdictFor(tc.expect, tc.outcome); got != tc.want {
			t.Errorf("VerdictFor(%s, %s) = %s, want %s", tc.expect, tc.outcome, got, tc.want)
		}
	}
}

// An inconclusive run must never read as a pass. A cluster where every probe
// was RBAC-denied is untested, not hardened.
func TestInconclusiveIsNeverAPass(t *testing.T) {
	for _, outcome := range []analyze.Outcome{analyze.OutcomeInconclusive, analyze.OutcomeSkipped, analyze.OutcomeError} {
		for _, expect := range []analyze.Expectation{analyze.ExpectBlocked, analyze.ExpectAllowed} {
			if got := analyze.VerdictFor(expect, outcome); got == analyze.VerdictPass {
				t.Errorf("VerdictFor(%s, %s) = Pass", expect, outcome)
			}
		}
	}
}

func TestClassifyAdmitted(t *testing.T) {
	p := probe(t, analyze.ExpectBlocked)
	returned := object(t, `{"apiVersion":"v1","kind":"Pod","metadata":{"name":"probe","uid":"x"},"spec":{"containers":[{"name":"app","securityContext":{"privileged":true},"imagePullPolicy":"Always"}]}}`)

	got := analyze.Classify(p, "default", p.Object, returned, nil)
	if got.Outcome != analyze.OutcomeAdmitted {
		t.Fatalf("outcome = %s, want Admitted (mutations: %v)", got.Outcome, got.Mutations)
	}
	if got.Verdict != analyze.VerdictFail {
		t.Fatalf("verdict = %s, want Fail", got.Verdict)
	}
	if got.Namespace != "default" {
		t.Errorf("namespace = %q", got.Namespace)
	}
	if got.SubmittedName != "probe" {
		t.Errorf("submitted name = %q", got.SubmittedName)
	}
}

func TestClassifyMutated(t *testing.T) {
	p := probe(t, analyze.ExpectBlocked)
	returned := object(t, `{"apiVersion":"v1","kind":"Pod","metadata":{"name":"probe"},"spec":{"containers":[{"name":"app","securityContext":{"privileged":false}}]}}`)

	got := analyze.Classify(p, "default", p.Object, returned, nil)
	if got.Outcome != analyze.OutcomeMutated {
		t.Fatalf("outcome = %s, want Mutated", got.Outcome)
	}
	if got.Verdict != analyze.VerdictWarn {
		t.Fatalf("verdict = %s, want Warn", got.Verdict)
	}
	if len(got.Mutations) != 1 || got.Mutations[0] != "spec.containers[0].securityContext.privileged" {
		t.Fatalf("mutations = %v", got.Mutations)
	}
}

func TestClassifyBlockedAttributesTheEnforcer(t *testing.T) {
	p := probe(t, analyze.ExpectBlocked)
	err := apierrors.NewForbidden(
		schema.GroupResource{Resource: "pods"}, "probe",
		errors.New(`violates PodSecurity "restricted:latest": privileged`),
	)

	got := analyze.Classify(p, "default", p.Object, nil, err)
	if got.Outcome != analyze.OutcomeBlocked {
		t.Fatalf("outcome = %s, want Blocked", got.Outcome)
	}
	if got.Verdict != analyze.VerdictPass {
		t.Fatalf("verdict = %s, want Pass", got.Verdict)
	}
	if got.Enforcer.Type != analyze.EnforcerPSA || got.Enforcer.Name != "restricted:latest" {
		t.Fatalf("enforcer = %+v", got.Enforcer)
	}
}

// Quota is accounting, not admission control. Counting it as a block would
// report the cluster as defending against a technique it never evaluated.
func TestClassifyQuotaDenialIsInconclusiveNotBlocked(t *testing.T) {
	p := probe(t, analyze.ExpectBlocked)
	err := apierrors.NewForbidden(
		schema.GroupResource{Resource: "pods"}, "probe",
		errors.New("exceeded quota: compute-quota, requested: requests.cpu=1"),
	)

	got := analyze.Classify(p, "default", p.Object, nil, err)
	if got.Outcome != analyze.OutcomeInconclusive {
		t.Fatalf("outcome = %s, want Inconclusive", got.Outcome)
	}
	if got.Reason != analyze.ReasonQuota {
		t.Fatalf("reason = %s, want quota", got.Reason)
	}
	if got.Verdict == analyze.VerdictPass {
		t.Fatal("quota denial must not read as a pass")
	}
}

func TestClassifyInvalidIsABlock(t *testing.T) {
	p := probe(t, analyze.ExpectBlocked)
	err := apierrors.NewInvalid(
		schema.GroupKind{Kind: "Pod"}, "probe",
		nil,
	)

	got := analyze.Classify(p, "default", p.Object, nil, err)
	if got.Outcome != analyze.OutcomeBlocked {
		t.Fatalf("outcome = %s, want Blocked", got.Outcome)
	}
}

func TestClassifyMissingNamespace(t *testing.T) {
	p := probe(t, analyze.ExpectBlocked)
	err := apierrors.NewNotFound(schema.GroupResource{Resource: "namespaces"}, "gone")

	got := analyze.Classify(p, "gone", p.Object, nil, err)
	if got.Outcome != analyze.OutcomeInconclusive {
		t.Fatalf("outcome = %s, want Inconclusive", got.Outcome)
	}
	if got.Reason != analyze.ReasonNamespaceMissing {
		t.Fatalf("reason = %s", got.Reason)
	}
}

func TestClassifyTransportError(t *testing.T) {
	p := probe(t, analyze.ExpectBlocked)

	got := analyze.Classify(p, "default", p.Object, nil, errors.New("connection refused"))
	if got.Outcome != analyze.OutcomeError {
		t.Fatalf("outcome = %s, want Error", got.Outcome)
	}
	if got.Reason != analyze.ReasonRequestFailed {
		t.Fatalf("reason = %s", got.Reason)
	}
	if got.Detail != "connection refused" {
		t.Fatalf("detail = %q", got.Detail)
	}
}

func TestClassifyRecordsRenamedSubmission(t *testing.T) {
	p := probe(t, analyze.ExpectBlocked)
	submitted := p.Object.DeepCopy()
	submitted.SetName("probe-kubeapt-a1b2c3")

	got := analyze.Classify(p, "default", submitted, submitted, nil)
	if got.SubmittedName != "probe-kubeapt-a1b2c3" {
		t.Fatalf("submitted name = %q", got.SubmittedName)
	}
}

func TestSkippedAndInconclusiveHelpers(t *testing.T) {
	p := probe(t, analyze.ExpectBlocked)

	skipped := analyze.SkippedResult(p, "default", "no matches for kind")
	if skipped.Outcome != analyze.OutcomeSkipped || skipped.Verdict != analyze.VerdictInconclusive {
		t.Errorf("skipped = %+v", skipped)
	}
	if skipped.Reason != analyze.ReasonKindNotServed {
		t.Errorf("skipped reason = %s", skipped.Reason)
	}

	rbac := analyze.InconclusiveResult(p, "default", analyze.ReasonRBAC, "cannot create pods")
	if rbac.Outcome != analyze.OutcomeInconclusive || rbac.Verdict != analyze.VerdictInconclusive {
		t.Errorf("rbac = %+v", rbac)
	}

	failed := analyze.ErrorResult(p, "default", "timeout")
	if failed.Outcome != analyze.OutcomeError || failed.Verdict != analyze.VerdictInconclusive {
		t.Errorf("error = %+v", failed)
	}
}

func TestSummarize(t *testing.T) {
	results := []analyze.Result{
		{Verdict: analyze.VerdictPass, Outcome: analyze.OutcomeBlocked},
		{Verdict: analyze.VerdictPass, Outcome: analyze.OutcomeBlocked},
		{Verdict: analyze.VerdictFail, Outcome: analyze.OutcomeAdmitted},
		{Verdict: analyze.VerdictWarn, Outcome: analyze.OutcomeMutated},
		{Verdict: analyze.VerdictInconclusive, Outcome: analyze.OutcomeSkipped},
	}

	got := analyze.Summarize(results)
	if got.Total != 5 || got.Pass != 2 || got.Fail != 1 || got.Warn != 1 || got.Inconclusive != 1 {
		t.Fatalf("summary = %+v", got)
	}
	if got.ByOutcome[analyze.OutcomeBlocked] != 2 {
		t.Errorf("ByOutcome[Blocked] = %d", got.ByOutcome[analyze.OutcomeBlocked])
	}
	if !got.HasFailures() {
		t.Error("HasFailures() = false")
	}
}

func TestSummarizeNoFailures(t *testing.T) {
	got := analyze.Summarize([]analyze.Result{
		{Verdict: analyze.VerdictPass},
		{Verdict: analyze.VerdictWarn},
		{Verdict: analyze.VerdictInconclusive},
	})
	if got.HasFailures() {
		t.Error("HasFailures() = true without any Fail verdict")
	}
}

func TestSummarizeEmpty(t *testing.T) {
	got := analyze.Summarize(nil)
	if got.Total != 0 || got.HasFailures() {
		t.Fatalf("summary = %+v", got)
	}
	if got.ByOutcome == nil {
		t.Error("ByOutcome should be non-nil so callers can index it")
	}
}

// Guards the contract that Classify never panics on a partially populated
// response, which is what a proxy or an aggregated API server can return.
func TestClassifyNilReturnedWithoutError(t *testing.T) {
	p := probe(t, analyze.ExpectBlocked)
	got := analyze.Classify(p, "default", p.Object, nil, nil)
	if got.Outcome != analyze.OutcomeAdmitted {
		t.Fatalf("outcome = %s", got.Outcome)
	}
}
