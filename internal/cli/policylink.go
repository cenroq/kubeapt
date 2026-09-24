// Copyright by cenroq AG
// Contact: info@cenroq.com

package cli

import (
	"strings"

	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
)

const (
	// policyAnnotationUUID carries the policy's cenroq catalogue identifier. It
	// is read verbatim; nothing is derived or hashed from it.
	policyAnnotationUUID = "kubeapt.io/uuid"

	policyDocsBaseURL = "https://cenroq.com/open-source/policies"
)

// policyDocsURL returns the cenroq page for a policy uuid, or "" when unset.
func policyDocsURL(uuid string) string {
	uuid = strings.TrimSpace(uuid)
	if uuid == "" {
		return ""
	}
	return policyDocsBaseURL + "/" + uuid
}

// policyURLFromAnnotations reads kubeapt.io/uuid off a policy's annotations.
func policyURLFromAnnotations(meta map[string]string) string {
	if meta == nil {
		return ""
	}
	return policyDocsURL(meta[policyAnnotationUUID])
}

// policyURLMap maps metadata.name to a docs URL, omitting policies without a uuid.
func policyURLMap(policies []admissionregistrationv1.ValidatingAdmissionPolicy) map[string]string {
	out := make(map[string]string, len(policies))
	for _, policy := range policies {
		if url := policyURLFromAnnotations(policy.Annotations); url != "" {
			out[policy.Name] = url
		}
	}
	return out
}
