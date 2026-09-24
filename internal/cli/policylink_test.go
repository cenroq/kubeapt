// Copyright by cenroq AG
// Contact: info@cenroq.com

package cli

import (
	"testing"

	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const testPolicyUUID = "7f1d4c0e-2b6a-4f8d-9c3e-5a1b2c3d4e5f"

func TestPolicyDocsURL(t *testing.T) {
	cases := map[string]string{
		testPolicyUUID:       policyDocsBaseURL + "/" + testPolicyUUID,
		" " + testPolicyUUID: policyDocsBaseURL + "/" + testPolicyUUID,
		"":                   "",
		"   ":                "",
	}
	for in, want := range cases {
		if got := policyDocsURL(in); got != want {
			t.Errorf("policyDocsURL(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestPolicyURLFromAnnotations(t *testing.T) {
	if got := policyURLFromAnnotations(nil); got != "" {
		t.Errorf("nil annotations = %q, want empty", got)
	}
	if got := policyURLFromAnnotations(map[string]string{policyAnnotationSeverity: "high"}); got != "" {
		t.Errorf("missing uuid annotation = %q, want empty", got)
	}
	if got := policyURLFromAnnotations(map[string]string{policyAnnotationUUID: "  "}); got != "" {
		t.Errorf("blank uuid annotation = %q, want empty", got)
	}
	want := policyDocsBaseURL + "/" + testPolicyUUID
	if got := policyURLFromAnnotations(map[string]string{policyAnnotationUUID: testPolicyUUID}); got != want {
		t.Errorf("uuid annotation = %q, want %q", got, want)
	}
}

func TestPolicyURLMapOmitsPoliciesWithoutUUID(t *testing.T) {
	policies := []admissionregistrationv1.ValidatingAdmissionPolicy{
		{ObjectMeta: metav1.ObjectMeta{
			Name:        "hostpid",
			Annotations: map[string]string{policyAnnotationUUID: testPolicyUUID},
		}},
		{ObjectMeta: metav1.ObjectMeta{Name: "no-annotations"}},
		{ObjectMeta: metav1.ObjectMeta{
			Name:        "blank-uuid",
			Annotations: map[string]string{policyAnnotationUUID: ""},
		}},
	}
	urls := policyURLMap(policies)
	if len(urls) != 1 {
		t.Fatalf("urls = %v, want only hostpid", urls)
	}
	if urls["hostpid"] != policyDocsBaseURL+"/"+testPolicyUUID {
		t.Errorf("hostpid url = %q", urls["hostpid"])
	}
	if _, ok := urls["no-annotations"]; ok {
		t.Errorf("policy without annotations must be absent from the map")
	}
}
