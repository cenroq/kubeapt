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
// security.kubeapt.io/* vocabulary that policies already use, so a probe
// bundle and a policy bundle are annotated the same way.
const (
	AnnotationProbeID     = "analyze.kubeapt.io/id"
	AnnotationProbeExpect = "analyze.kubeapt.io/expect"
)

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

	return Probe{
		ID:          probeID(annotations[AnnotationProbeID], sourceFile, obj),
		DisplayName: displayName(annotations, obj),
		Description: policies.LookupAnnotation(annotations, policies.AnnotationDescription, policies.KyvernoAnnotationDescription),
		Category:    policies.LookupAnnotation(annotations, policies.AnnotationCategory, policies.KyvernoAnnotationCategory),
		// Severity deliberately reads only the kubeapt key. Kyverno's scale
		// spells the middle rung "medium", which NormalizeSeverity does not
		// know, so accepting the Kyverno key here would quietly report a
		// medium-severity probe as Not Rated. Title, description and category
		// are plain strings with no such mismatch, so they do fall back.
		Severity:   policies.NormalizeSeverity(annotations[policies.AnnotationSeverity]),
		Expect:     expect,
		SourceFile: sourceFile,
		Object:     sanitised,
	}, nil
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
	if name := policies.LookupAnnotation(annotations, policies.AnnotationDisplayName, policies.KyvernoAnnotationTitle); name != "" {
		return name
	}
	if name := obj.GetName(); name != "" {
		return fmt.Sprintf("%s %s", obj.GetKind(), name)
	}
	return obj.GetKind()
}

// stripProbeAnnotations removes kubeapt's own annotations from the object that
// goes over the wire. A policy is free to match on annotations, and a probe
// carrying "security.kubeapt.io/severity: Critical" would be a different object
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

func isProbeAnnotation(key string) bool {
	return strings.HasPrefix(key, "analyze.kubeapt.io/") ||
		strings.HasPrefix(key, "security.kubeapt.io/")
}
