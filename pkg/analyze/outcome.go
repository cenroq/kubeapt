// Copyright by cenroq AG
// Contact: info@cenroq.com

package analyze

import (
	"errors"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

// Outcome is what the API server did with a probe.
type Outcome string

const (
	// OutcomeBlocked means admission rejected the object.
	OutcomeBlocked Outcome = "Blocked"
	// OutcomeAdmitted means the object was accepted exactly as authored.
	OutcomeAdmitted Outcome = "Admitted"
	// OutcomeMutated means the object was accepted but a field the probe set
	// was changed, most likely by a mutating webhook.
	OutcomeMutated Outcome = "Mutated"
	// OutcomeInconclusive means something prevented a verdict: the caller
	// lacks RBAC, quota rejected the object, or the namespace is missing.
	OutcomeInconclusive Outcome = "Inconclusive"
	// OutcomeSkipped means the cluster does not serve the probe's kind.
	OutcomeSkipped Outcome = "Skipped"
	// OutcomeError means the request itself failed.
	OutcomeError Outcome = "Error"
)

// Verdict is the security reading of an Outcome given what the probe expected.
type Verdict string

const (
	VerdictPass         Verdict = "Pass"
	VerdictFail         Verdict = "Fail"
	VerdictWarn         Verdict = "Warn"
	VerdictInconclusive Verdict = "Inconclusive"
)

// Reason explains an Inconclusive, Skipped, or Error outcome.
type Reason string

const (
	ReasonNone Reason = ""
	// ReasonRBAC means the caller may not create the resource. This is the
	// single most important reason to track: an RBAC refusal looks exactly
	// like an admission refusal over the wire, and reporting it as a block
	// would claim a cluster is defended when it is merely inaccessible.
	ReasonRBAC Reason = "rbac"
	// ReasonQuota means quota or LimitRanger rejected the object, which says
	// nothing about whether a security control would have.
	ReasonQuota Reason = "quota"
	// ReasonNamespaceMissing means the target namespace does not exist.
	ReasonNamespaceMissing Reason = "namespace-missing"
	// ReasonKindNotServed means the cluster does not serve the probe's kind,
	// usually a probe for an operator that is not installed.
	ReasonKindNotServed Reason = "kind-not-served"
	// ReasonRequestFailed means the request errored for a transport reason.
	ReasonRequestFailed Reason = "request-failed"
)

// Result is one probe's outcome in one namespace.
type Result struct {
	Probe     Probe
	Namespace string
	Outcome   Outcome
	Verdict   Verdict
	Enforcer  Enforcer
	Reason    Reason
	Detail    string
	// Mutations lists the paths the server changed, when Outcome is Mutated.
	Mutations []string
	// SubmittedName is the name the object was actually sent under. It differs
	// from the manifest when a collision forced a rename.
	SubmittedName string
}

// VerdictFor maps an outcome to its security reading.
//
// The one rule that must not be relaxed: Inconclusive, Skipped, and Error never
// become a pass. A run where every probe was RBAC-denied describes a cluster
// that is untested, not one that is hardened.
func VerdictFor(expect Expectation, outcome Outcome) Verdict {
	switch outcome {
	case OutcomeBlocked:
		if expect == ExpectAllowed {
			// A benign object being rejected is over-blocking: not a
			// security hole, but a real operational finding.
			return VerdictWarn
		}
		return VerdictPass
	case OutcomeAdmitted:
		if expect == ExpectAllowed {
			return VerdictPass
		}
		return VerdictFail
	case OutcomeMutated:
		if expect == ExpectAllowed {
			return VerdictPass
		}
		// Neutralised rather than rejected. Worth surfacing, because the
		// mutation may be partial and it depends on the webhook staying up.
		return VerdictWarn
	default:
		return VerdictInconclusive
	}
}

// Classify turns the API server's response to a dry-run create into a Result.
//
// submitted is the object as it went over the wire, which may differ from
// p.Object when a name collision forced a rename. returned and err are exactly
// what the create call produced; a non-nil err is data, not a failure.
func Classify(p Probe, namespace string, submitted, returned *unstructured.Unstructured, err error) Result {
	result := Result{
		Probe:     p,
		Namespace: namespace,
	}
	if submitted != nil {
		result.SubmittedName = submitted.GetName()
	}

	switch {
	case err == nil:
		result.Mutations = DiffSetPaths(submitted, returned)
		if len(result.Mutations) > 0 {
			result.Outcome = OutcomeMutated
		} else {
			result.Outcome = OutcomeAdmitted
		}

	case apierrors.IsForbidden(err), apierrors.IsInvalid(err):
		message := apiMessage(err)
		enforcer := Attribute(message)
		result.Enforcer = enforcer
		if enforcer.Resource() {
			// Quota and LimitRanger are accounting, not admission control.
			// Counting them as a block would be a false pass.
			result.Outcome = OutcomeInconclusive
			result.Reason = ReasonQuota
			result.Detail = message
		} else {
			result.Outcome = OutcomeBlocked
		}

	case apierrors.IsNotFound(err):
		// A create can only 404 when the namespace it targets is gone.
		result.Outcome = OutcomeInconclusive
		result.Reason = ReasonNamespaceMissing
		result.Detail = apiMessage(err)

	default:
		result.Outcome = OutcomeError
		result.Reason = ReasonRequestFailed
		result.Detail = apiMessage(err)
	}

	result.Verdict = VerdictFor(p.Expect, result.Outcome)
	return result
}

// SkippedResult records a probe whose kind the cluster does not serve.
func SkippedResult(p Probe, namespace, detail string) Result {
	return Result{
		Probe:     p,
		Namespace: namespace,
		Outcome:   OutcomeSkipped,
		Verdict:   VerdictInconclusive,
		Reason:    ReasonKindNotServed,
		Detail:    detail,
	}
}

// InconclusiveResult records a probe that was never submitted, most often
// because the RBAC preflight said the caller may not create the resource.
func InconclusiveResult(p Probe, namespace string, reason Reason, detail string) Result {
	return Result{
		Probe:     p,
		Namespace: namespace,
		Outcome:   OutcomeInconclusive,
		Verdict:   VerdictInconclusive,
		Reason:    reason,
		Detail:    detail,
	}
}

// ErrorResult records a probe whose request could not be made at all.
func ErrorResult(p Probe, namespace, detail string) Result {
	return Result{
		Probe:     p,
		Namespace: namespace,
		Outcome:   OutcomeError,
		Verdict:   VerdictInconclusive,
		Reason:    ReasonRequestFailed,
		Detail:    detail,
	}
}

func apiMessage(err error) string {
	if err == nil {
		return ""
	}
	var status apierrors.APIStatus
	if errors.As(err, &status) {
		if s := status.Status(); s.Message != "" {
			return s.Message
		}
	}
	return err.Error()
}

// Summary counts results by verdict and outcome for the report footer.
type Summary struct {
	Total        int
	Pass         int
	Fail         int
	Warn         int
	Inconclusive int
	ByOutcome    map[Outcome]int
}

// Summarize tallies a result set.
func Summarize(results []Result) Summary {
	summary := Summary{ByOutcome: map[Outcome]int{}}
	for _, r := range results {
		summary.Total++
		summary.ByOutcome[r.Outcome]++
		switch r.Verdict {
		case VerdictPass:
			summary.Pass++
		case VerdictFail:
			summary.Fail++
		case VerdictWarn:
			summary.Warn++
		default:
			summary.Inconclusive++
		}
	}
	return summary
}

// HasFailures reports whether any probe that should have been blocked was
// admitted. This is what --pipeline keys its exit code on.
func (s Summary) HasFailures() bool { return s.Fail > 0 }
