// Copyright by cenroq AG
// Contact: info@cenroq.com

// Package scanner evaluates a loaded policies.Bundle against a slice of
// in-memory Kubernetes manifests and returns structured findings, plus the
// outcome (pass, fail or error) of every policy for every object it applies to.
//
// The scanner is the only public entrypoint kubeapt exposes for embedding
// the policy engine into another Go program. It does not talk to the
// Kubernetes API; callers are expected to bring their own parsed manifests.
package scanner

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"

	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/cenroq/kubeapt/v2/internal/kubernetes"
	"github.com/cenroq/kubeapt/v2/internal/scanaccess"
	"github.com/cenroq/kubeapt/v2/pkg/policies"
	"github.com/cenroq/kubeapt/v2/pkg/types"
)

// Scanner evaluates a sealed policies.Bundle against caller-supplied manifests.
type Scanner struct {
	bundle          *policies.Bundle
	respectBindings bool
	policyResources []types.GVR
}

// Option configures a Scanner at construction time.
type Option func(*Scanner)

// GVR re-exports types.GVR for callers importing only the scanner.
type GVR = types.GVR

// WithRespectBindings evaluates policies only against their loaded bindings.
func WithRespectBindings() Option {
	return func(s *Scanner) {
		s.respectBindings = true
	}
}

// WithPolicyResources limits the scan to policies targeting the given GVRs.
func WithPolicyResources(resources []GVR) Option {
	return func(s *Scanner) {
		for _, gvr := range resources {
			if strings.TrimSpace(gvr.Resource) == "" {
				continue
			}
			s.policyResources = append(s.policyResources, gvr)
		}
	}
}

// New constructs a Scanner for the given bundle.
func New(bundle *policies.Bundle, opts ...Option) (*Scanner, error) {
	if bundle == nil {
		return nil, errors.New("scanner: nil bundle")
	}
	s := &Scanner{bundle: bundle}
	for _, opt := range opts {
		opt(s)
	}
	return s, nil
}

// Scan evaluates every policy against every manifest, returning aggregated results.
//
// Findings and ScanErrors report violations and evaluation failures.
// Evaluations additionally records one entry per (policy, binding, manifest)
// the policy applies to, including the ones that passed, so a caller can tell
// "checked and compliant" apart from "never applied".
func (s *Scanner) Scan(ctx context.Context, manifests []types.Manifest) (*types.Result, error) {
	if ctx == nil {
		ctx = context.Background()
	}

	working := deepCopyManifests(manifests)
	kubernetes.NormalizeResourcesForCEL(working)

	result := &types.Result{}
	for policy := range s.bundle.Iterate() {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if len(s.policyResources) > 0 && !policy.TargetsGVR(s.policyResources...) {
			continue
		}
		parsed := policy.Parsed(scanaccess.Token{})
		if parsed == nil || parsed.VAP == nil {
			continue
		}

		bindings := s.effectiveBindings(parsed)
		if len(bindings) == 0 {
			continue
		}
		findingID := policy.FindingID()

		for _, binding := range bindings {
			if err := ctx.Err(); err != nil {
				return nil, err
			}
			for _, manifest := range working {
				if err := ctx.Err(); err != nil {
					return nil, err
				}
				s.evaluate(policy.ID, findingID, parsed, binding, manifest, result)
			}
		}
	}
	return result, nil
}

func (s *Scanner) effectiveBindings(parsed *scanaccess.Parsed) []*admissionregistrationv1.ValidatingAdmissionPolicyBinding {
	if s.respectBindings {
		return parsed.Bindings
	}
	return []*admissionregistrationv1.ValidatingAdmissionPolicyBinding{implicitBinding(parsed.VAP.Name)}
}

func implicitBinding(policyName string) *admissionregistrationv1.ValidatingAdmissionPolicyBinding {
	return &admissionregistrationv1.ValidatingAdmissionPolicyBinding{
		ObjectMeta: metav1.ObjectMeta{Name: policyName + "--implicit"},
		Spec: admissionregistrationv1.ValidatingAdmissionPolicyBindingSpec{
			PolicyName: policyName,
		},
	}
}

func (s *Scanner) evaluate(
	policyID, findingID string,
	parsed *scanaccess.Parsed,
	binding *admissionregistrationv1.ValidatingAdmissionPolicyBinding,
	manifest types.Manifest,
	result *types.Result,
) {
	ref := resourceRefFromManifest(manifest)

	if !kubernetes.MatchesPolicy(parsed.VAP, manifest, nil, false, false) {
		return
	}
	if s.respectBindings {
		if !kubernetes.MatchesBinding(binding, manifest, nil, false, false, false) {
			return
		}
	}

	// From here on the policy applies to the object, so exactly one
	// Evaluation is recorded whatever the outcome.
	evaluation := types.Evaluation{
		PolicyID:  policyID,
		FindingID: findingID,
		Binding:   binding.Name,
		Resource:  ref,
		Severity:  parsed.Severity,
	}

	eval, err := kubernetes.EvaluateValidations(parsed.VAP, binding, manifest, ref.Namespace, nil)
	if err != nil {
		wrapped := fmt.Errorf("scanner: evaluate policy %s against %s: %w", policyID, formatRef(ref), err)
		result.ScanErrors = append(result.ScanErrors, types.ScanError{
			PolicyID: policyID,
			Resource: ref,
			Err:      wrapped,
		})
		evaluation.Outcome = types.OutcomeError
		evaluation.Error = wrapped.Error()
		result.Evaluations = append(result.Evaluations, evaluation)
		return
	}
	if eval.Compliant {
		evaluation.Outcome = types.OutcomePass
		result.Evaluations = append(result.Evaluations, evaluation)
		return
	}

	evaluation.Outcome = types.OutcomeFail
	evaluation.Violations = make([]types.Violation, 0, len(eval.Violations))
	for _, v := range eval.Violations {
		result.Findings = append(result.Findings, types.Finding{
			PolicyID:  policyID,
			FindingID: findingID,
			Resource:  ref,
			Severity:  parsed.Severity,
			Message:   v.Message,
			Path:      v.Path,
			Actions:   v.Actions,
		})
		// Actions gets its own backing array so a caller editing a Finding
		// cannot silently change the Evaluation, or the other way round.
		evaluation.Violations = append(evaluation.Violations, types.Violation{
			Message: v.Message,
			Path:    v.Path,
			Actions: slices.Clone(v.Actions),
		})
	}
	result.Evaluations = append(result.Evaluations, evaluation)
}

func resourceRefFromManifest(m types.Manifest) types.ResourceRef {
	return types.ResourceRef{
		APIVersion: stringField(m, "apiVersion"),
		Kind:       stringField(m, "kind"),
		Namespace:  kubernetes.MetadataString(m, "namespace"),
		Name:       kubernetes.MetadataString(m, "name"),
		UID:        kubernetes.MetadataString(m, "uid"),
	}
}

func stringField(m types.Manifest, key string) string {
	if v, ok := m[key].(string); ok {
		return v
	}
	return ""
}

func formatRef(ref types.ResourceRef) string {
	ns := ref.Namespace
	if ns == "" {
		ns = "<cluster>"
	}
	return fmt.Sprintf("%s %s/%s", ref.Kind, ns, ref.Name)
}

func deepCopyManifests(in []types.Manifest) []types.Manifest {
	out := make([]types.Manifest, len(in))
	for i, m := range in {
		out[i] = deepCopyMap(m)
	}
	return out
}

func deepCopyMap(m map[string]any) map[string]any {
	if m == nil {
		return nil
	}
	out := make(map[string]any, len(m))
	for k, v := range m {
		out[k] = deepCopyValue(v)
	}
	return out
}

func deepCopyValue(v any) any {
	switch x := v.(type) {
	case map[string]any:
		return deepCopyMap(x)
	case []any:
		out := make([]any, len(x))
		for i, item := range x {
			out[i] = deepCopyValue(item)
		}
		return out
	default:
		return v
	}
}
