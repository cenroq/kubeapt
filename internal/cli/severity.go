// Copyright by cenroq AG
// Contact: info@cenroq.com

package cli

import (
	"fmt"

	"github.com/fatih/color"
	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"

	"github.com/cenroq/kubeapt/v2/internal/logging"
	"github.com/cenroq/kubeapt/v2/pkg/policies"
	"github.com/cenroq/kubeapt/v2/pkg/types"
)

const (
	severityCritical = string(types.SeverityCritical)
	severityHigh     = string(types.SeverityHigh)
	severityModerate = string(types.SeverityModerate)
	severityLow      = string(types.SeverityLow)
	severityInfo     = string(types.SeverityInfo)
	severityNotRated = string(types.SeverityNotRated)
)

func normalizeSeverity(raw string) string {
	return string(policies.NormalizeSeverity(raw))
}

func severityRank(s string) int {
	switch s {
	case severityCritical:
		return 0
	case severityHigh:
		return 1
	case severityModerate:
		return 2
	case severityLow:
		return 3
	case severityInfo:
		return 4
	default:
		return 5
	}
}

func severityColor(severity string) *color.Color {
	switch severity {
	case severityCritical:
		return color.New(color.FgHiRed, color.Bold)
	case severityHigh:
		return color.New(color.FgRed, color.Bold)
	case severityModerate:
		return color.New(color.FgYellow)
	case severityLow:
		return color.New(color.FgCyan)
	case severityInfo:
		return color.New(color.FgWhite)
	default:
		return color.New(color.FgHiBlack)
	}
}

// Annotation families named in the deprecation warnings.
const (
	cenroqAnnotationFamily = "security.cenroq.io/*"
	legacyAnnotationFamily = "security.kubeapt.io/*"
)

// logDeprecatedPolicyAnnotations logs once, not per policy, when policy
// metadata is still read from the deprecated security.kubeapt.io annotations.
//
// It logs at debug level only. Every policy set published so far (up to
// cenroq-best-practices v0.4.0) carries the old keys, so a warning would fire on
// every run with nothing for the user to do. Raise it to a warning once the
// published policy sets carry security.cenroq.io.
func logDeprecatedPolicyAnnotations(items []admissionregistrationv1.ValidatingAdmissionPolicy) {
	if note := deprecatedPolicyAnnotationsNote(items); note != "" {
		logging.Debugf("%s", note)
	}
}

// deprecatedPolicyAnnotationsNote is the line logDeprecatedPolicyAnnotations
// logs, or "" when no policy reads the deprecated annotations.
func deprecatedPolicyAnnotationsNote(items []admissionregistrationv1.ValidatingAdmissionPolicy) string {
	deprecated := 0
	for _, policy := range items {
		if policies.UsesLegacyAnnotations(policy.Annotations) {
			deprecated++
		}
	}
	if deprecated == 0 {
		return ""
	}
	return fmt.Sprintf("%d policy(ies) take their metadata from the deprecated %s annotations; newer policy sets use %s",
		deprecated, legacyAnnotationFamily, cenroqAnnotationFamily)
}

// policySeverityMap reads each policy's severity, security.cenroq.io first and
// the legacy security.kubeapt.io key as a fallback.
func policySeverityMap(items []admissionregistrationv1.ValidatingAdmissionPolicy) map[string]string {
	out := make(map[string]string, len(items))
	for _, policy := range items {
		out[policy.Name] = normalizeSeverity(policies.LookupAnnotation(policy.Annotations, policies.AnnotationSeverity, policies.LegacyAnnotationSeverity))
	}
	return out
}
