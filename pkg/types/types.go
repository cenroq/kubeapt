// Copyright by cenroq AG
// Contact: info@cenroq.com

// Package types defines the shared primitives exposed by kubeapt's scanner API.
package types

// Manifest is a parsed Kubernetes manifest as a map alias.
type Manifest = map[string]any

// Severity is kubeapt's native severity scale from policy annotations.
type Severity string

// Severity constants match kubeapt's normalized severity annotation values.
const (
	SeverityCritical Severity = "Critical"
	SeverityHigh     Severity = "High"
	SeverityModerate Severity = "Moderate"
	SeverityLow      Severity = "Low"
	SeverityInfo     Severity = "Info"
	SeverityNotRated Severity = "Not Rated"
)

// ResourceRef identifies a single Kubernetes resource scanned by Scanner.Scan.
type ResourceRef struct {
	APIVersion string
	Kind       string
	Namespace  string
	Name       string
	UID        string
}

// GVR identifies a resource by group, version, and plural resource.
type GVR struct {
	Group    string
	Version  string
	Resource string
}

// Finding is a single rule violation produced by the scanner.
type Finding struct {
	PolicyID string
	// FindingID is the policy's catalogue id; see Evaluation.FindingID.
	FindingID string
	Resource  ResourceRef
	Severity  Severity
	Message   string
	Path      string
	Actions   []string
}

// ScanError reports a non-fatal failure for one policy-resource pair.
type ScanError struct {
	PolicyID string
	Resource ResourceRef
	Err      error
}

// Outcome is the verdict of one policy evaluated against one object.
type Outcome string

// Outcome constants are the wire values of Evaluation.Outcome.
const (
	// OutcomePass means the object satisfied every validation of the policy.
	OutcomePass Outcome = "pass"
	// OutcomeFail means at least one validation rejected the object.
	OutcomeFail Outcome = "fail"
	// OutcomeError means the policy could not be evaluated against the object.
	OutcomeError Outcome = "error"
)

// Violation is one failed validation inside a fail Evaluation. It carries the
// same content as the Finding reported for it.
type Violation struct {
	Message string
	Path    string
	Actions []string
}

// Evaluation is one policy evaluated against one object it applies to.
//
// It deliberately holds no copy of the manifest: on a real cluster the list
// holds roughly every policy times every object it applies to, so each entry
// stays small and names its object by ResourceRef only.
type Evaluation struct {
	// PolicyID is the name of the ValidatingAdmissionPolicy.
	PolicyID string
	// FindingID is the policy's catalogue id from its cenroq.io/finding
	// annotation (or the deprecated kubeapt.io/uuid), such as "oq-0276", or ""
	// when the policy carries none. policies.DocsURL turns it into the
	// policy's page.
	FindingID string
	// Binding is the name of the binding the policy was evaluated under. It is
	// "<policy>--implicit" unless the scanner was built WithRespectBindings.
	Binding  string
	Resource ResourceRef
	Severity Severity
	Outcome  Outcome
	// Violations is set only when Outcome is OutcomeFail.
	Violations []Violation
	// Error is set only when Outcome is OutcomeError. It is the same text as
	// the matching ScanError's Err.
	Error string
}

// Result is the aggregate output of a single Scanner.Scan call.
//
// Evaluations has exactly one entry per (policy, binding, object) the policy
// applies to; a policy that does not apply to an object has no entry for it.
// The fail entries' Violations add up to len(Findings) and the error entries
// add up to len(ScanErrors). All three lists are ordered by policy, then
// binding, then the order of the manifests passed to Scan.
type Result struct {
	Findings    []Finding
	ScanErrors  []ScanError
	Evaluations []Evaluation
}
