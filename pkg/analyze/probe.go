// Copyright by cenroq AG
// Contact: info@cenroq.com

// Package analyze models the result of submitting a deliberately dangerous
// object to a live Kubernetes API server with dryRun=All, so a cluster's
// admission posture can be measured rather than inferred.
//
// The package is pure: no filesystem, no network, no cluster, no logger. It
// takes an object plus whatever the API server said about it and returns a
// typed verdict. Everything that talks to a cluster lives in
// internal/kubernetes and everything that touches disk or a terminal lives in
// internal/cli. That split is the reason the attribution parser and the
// outcome matrix can be tested exhaustively without a cluster, which matters
// because those two pieces are where a wrong answer would be most dangerous:
// they decide whether a cluster is reported as defended.
//
// The probe catalogue is deliberately not modelled here. Probes are arbitrary
// manifests shipped in a bundle, so this package treats any object as a probe
// and reads its intent from annotations.
package analyze

import (
	"fmt"
	"path/filepath"
	"strings"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"

	"github.com/cenroq/kubeapt/v2/pkg/policies"
	"github.com/cenroq/kubeapt/v2/pkg/types"
)

// Annotation keys carrying probe intent. The descriptive metadata reuses the
// security.cenroq.io/* vocabulary that policies use (with the legacy
// security.kubeapt.io/* spelling as a fallback), so a probe bundle and a
// policy bundle are annotated the same way.
const (
	AnnotationProbeID     = "analyze.kubeapt.io/id"
	AnnotationProbeExpect = "analyze.kubeapt.io/expect"
)

// AnnotationFinding is the finding id a deny manifest shares with the policy
// that should reject it. It is the only cenroq annotation the shipped probe
// corpus carries, so it is how a result names its policy.
const AnnotationFinding = policies.AnnotationFinding

// Expectation records what a correctly configured cluster should do with a probe.
type Expectation string

const (
	// ExpectBlocked is the default: admission should reject the object.
	ExpectBlocked Expectation = "blocked"
	// ExpectAllowed marks a benign control probe. Rejecting it means the
	// cluster is over-blocking, which is a real operational finding even
	// though nothing dangerous got through.
	ExpectAllowed Expectation = "allowed"
)

// Probe is a single dangerous object to submit, plus the metadata describing
// what it tests and what should happen to it.
type Probe struct {
	ID          string
	DisplayName string
	Description string
	Category    string
	Severity    types.Severity
	Expect      Expectation
	SourceFile  string

	// FindingID is the finding id shared with the policy this probe tests,
	// such as "oq-0276", read from cenroq.io/finding. Empty for probe sets
	// that do not stamp one.
	FindingID string

	// DeprecatedID reports that FindingID was read from the deprecated
	// kubeapt.io/uuid annotation, which future policy sets no longer carry.
	DeprecatedID bool

	// DeprecatedAnnotations reports that some of the probe's own metadata was
	// read from a deprecated security.kubeapt.io annotation.
	DeprecatedAnnotations bool

	// Policy is the policy this probe's finding id resolves to, when the
	// caller supplied an index to resolve it against. Probe manifests carry
	// only the id, so display metadata comes from the policy, not the probe.
	Policy *PolicyRef

	// Unsupported, when set, explains why this probe cannot be exercised by a
	// dry-run create. Such a probe is still reported -- as Skipped, never as a
	// pass -- because an untested technique is not a defended one.
	Unsupported string

	// Object is the manifest to submit, with kubeapt's own annotations
	// removed. It is a deep copy, so building a Probe never mutates the
	// caller's loaded manifest.
	Object *unstructured.Unstructured
}

// NewProbe reads probe metadata off obj's annotations and returns a Probe
// carrying a sanitised copy of it.
//
// sourceFile is used only to derive an ID when the manifest does not declare
// one; it may be empty.
func NewProbe(obj *unstructured.Unstructured, sourceFile string) (Probe, error) {
	if obj == nil || len(obj.Object) == 0 {
		return Probe{}, fmt.Errorf("analyze: probe is empty")
	}
	gvk := obj.GroupVersionKind()
	if gvk.Empty() {
		return Probe{}, fmt.Errorf("analyze: probe is missing apiVersion or kind")
	}

	annotations := obj.GetAnnotations()

	expect, err := parseExpectation(annotations[AnnotationProbeExpect])
	if err != nil {
		return Probe{}, err
	}

	sanitised := obj.DeepCopy()
	stripProbeAnnotations(sanitised)

	findingID, deprecatedID := policies.FindingID(annotations)

	return Probe{
		ID:          probeID(annotations[AnnotationProbeID], sourceFile, obj),
		DisplayName: displayName(annotations, obj),
		Description: policies.DescriptionFromAnnotations(annotations),
		Category:    policies.CategoryFromAnnotations(annotations),
		// Severity never falls back to the Kyverno key; see
		// policies.SeverityFromAnnotations for why.
		Severity:              policies.SeverityFromAnnotations(annotations),
		Expect:                expect,
		SourceFile:            sourceFile,
		FindingID:             findingID,
		DeprecatedID:          deprecatedID,
		DeprecatedAnnotations: policies.UsesLegacyAnnotations(annotations),
		Object:                sanitised,
	}, nil
}

// DocsURL returns the catalogue page for the policy this probe tests, or ""
// when the probe carries no finding id.
func (p Probe) DocsURL() string { return policies.DocsURL(p.FindingID) }

// Title returns the best available human label for the probe: the policy's
// display name when the finding id resolved, else the probe's own.
//
// The policy wins because a shipped deny manifest carries no descriptive
// annotations at all, so Probe.DisplayName has already fallen back to
// "Kind name" -- a label that names the fixture rather than the weakness it
// tests.
func (p Probe) Title() string {
	if p.Policy != nil && p.Policy.DisplayName != "" {
		return p.Policy.DisplayName
	}
	return p.DisplayName
}

// Summary returns the best available description: the probe's own when it has
// one, else the policy's. Same reasoning as Title.
func (p Probe) Summary() string {
	if p.Description != "" {
		return p.Description
	}
	if p.Policy != nil {
		return p.Policy.Description
	}
	return ""
}

// parseExpectation rejects an unrecognised value rather than defaulting it. A
// typo like "blocke" would otherwise silently invert a probe's meaning, turning
// a real finding into a pass.
func parseExpectation(raw string) (Expectation, error) {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "":
		return ExpectBlocked, nil
	case string(ExpectBlocked):
		return ExpectBlocked, nil
	case string(ExpectAllowed):
		return ExpectAllowed, nil
	default:
		return "", fmt.Errorf("analyze: invalid %s value %q, expected blocked or allowed", AnnotationProbeExpect, raw)
	}
}

func probeID(annotated, sourceFile string, obj *unstructured.Unstructured) string {
	if id := strings.TrimSpace(annotated); id != "" {
		return id
	}
	if sourceFile != "" {
		base := filepath.Base(sourceFile)
		if stem := strings.TrimSuffix(base, filepath.Ext(base)); stem != "" {
			return stem
		}
	}
	kind := strings.ToLower(obj.GetKind())
	if name := obj.GetName(); name != "" {
		return kind + "-" + name
	}
	return kind
}

func displayName(annotations map[string]string, obj *unstructured.Unstructured) string {
	if name := policies.DisplayNameFromAnnotations(annotations); name != "" {
		return name
	}
	if name := obj.GetName(); name != "" {
		return fmt.Sprintf("%s %s", obj.GetKind(), name)
	}
	return obj.GetKind()
}

// stripProbeAnnotations removes kubeapt's own annotations from the object that
// goes over the wire. A policy is free to match on annotations, and a probe
// carrying "security.cenroq.io/severity: Critical" would be a different object
// from the dangerous one the bundle author meant to test.
func stripProbeAnnotations(obj *unstructured.Unstructured) {
	annotations := obj.GetAnnotations()
	if len(annotations) == 0 {
		return
	}
	remaining := make(map[string]string, len(annotations))
	for key, value := range annotations {
		if isProbeAnnotation(key) {
			continue
		}
		remaining[key] = value
	}
	if len(remaining) == 0 {
		// SetAnnotations(map{}) leaves an empty annotations block behind.
		unstructured.RemoveNestedField(obj.Object, "metadata", "annotations")
		return
	}
	obj.SetAnnotations(remaining)
}

// isProbeAnnotation reports whether a key is kubeapt's or cenroq's own
// bookkeeping rather than part of the object under test.
//
// The matches are deliberately narrow, which is why cenroq.io/finding and the
// security.cenroq.io metadata keys are matched exactly rather than by prefix:
// security.cenroq.io/ is also the namespace of the per-policy enforce, warn and
// audit labels, which a probe may carry as part of what it tests. Probes in
// the shipped corpus violate their policy *through* annotations -- an apparmor
// probe carries container.apparmor.security.beta.kubernetes.io/main and an
// ingress probe carries nginx.ingress.kubernetes.io/server-snippet -- so
// stripping anything broader would send a compliant object and report a false
// pass.
func isProbeAnnotation(key string) bool {
	if _, ok := cenroqMetadataAnnotations[key]; ok {
		return true
	}
	return key == AnnotationFinding ||
		strings.HasPrefix(key, "analyze.kubeapt.io/") ||
		strings.HasPrefix(key, "security.kubeapt.io/") ||
		strings.HasPrefix(key, "kubeapt.io/")
}

// cenroqMetadataAnnotations are the security.cenroq.io keys that describe a
// probe rather than form part of it.
var cenroqMetadataAnnotations = map[string]struct{}{
	policies.AnnotationSeverity:    {},
	policies.AnnotationDisplayName: {},
	policies.AnnotationDescription: {},
	policies.AnnotationCategory:    {},
	policies.AnnotationResource:    {},
	policies.AnnotationRemediation: {},
	policies.AnnotationProduct:     {},
}
