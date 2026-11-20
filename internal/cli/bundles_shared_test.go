// Copyright by cenroq AG
// Contact: info@cenroq.com

package cli

import (
	"reflect"
	"testing"

	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

func bundleObject(kind, name string) *unstructured.Unstructured {
	obj := &unstructured.Unstructured{}
	obj.SetAPIVersion("admissionregistration.k8s.io/v1")
	obj.SetKind(kind)
	obj.SetName(name)
	return obj
}

func clusterBinding(name, policy string) admissionregistrationv1.ValidatingAdmissionPolicyBinding {
	return admissionregistrationv1.ValidatingAdmissionPolicyBinding{
		ObjectMeta: metav1.ObjectMeta{Name: name},
		Spec:       admissionregistrationv1.ValidatingAdmissionPolicyBindingSpec{PolicyName: policy},
	}
}

func objectNames(resources []*unstructured.Unstructured) []string {
	names := make([]string, 0, len(resources))
	for _, resource := range resources {
		names = append(names, resource.GetKind()+"/"+resource.GetName())
	}
	return names
}

// Uninstalling one bundle must not delete a policy another installed bundle's
// binding still points at; the API server would silently stop enforcing it.
func TestWithoutSharedPoliciesKeepsPoliciesBoundElsewhere(t *testing.T) {
	resources := []*unstructured.Unstructured{
		bundleObject("ValidatingAdmissionPolicy", "container-privileged"),
		bundleObject("ValidatingAdmissionPolicy", "service-nodeport"),
		bundleObject("ValidatingAdmissionPolicyBinding", "cenroq-best-practices--v0.4.0--container-privileged-namespace-enforce"),
		bundleObject("ValidatingAdmissionPolicyBinding", "cenroq-best-practices--v0.4.0--service-nodeport-namespace-enforce"),
	}
	cluster := []admissionregistrationv1.ValidatingAdmissionPolicyBinding{
		clusterBinding("cenroq-best-practices--v0.4.0--container-privileged-namespace-enforce", "container-privileged"),
		clusterBinding("cenroq-best-practices--v0.4.0--service-nodeport-namespace-enforce", "service-nodeport"),
		clusterBinding("pod-security-admission--v1.37.1--container-privileged-namespace-enforce", "container-privileged"),
	}

	got, kept := withoutSharedPolicies(resources, cluster)

	wantNames := []string{
		"ValidatingAdmissionPolicy/service-nodeport",
		"ValidatingAdmissionPolicyBinding/cenroq-best-practices--v0.4.0--container-privileged-namespace-enforce",
		"ValidatingAdmissionPolicyBinding/cenroq-best-practices--v0.4.0--service-nodeport-namespace-enforce",
	}
	if names := objectNames(got); !reflect.DeepEqual(names, wantNames) {
		t.Fatalf("resources to delete = %v, want %v", names, wantNames)
	}
	wantKept := map[string][]string{
		"container-privileged": {"pod-security-admission--v1.37.1--container-privileged-namespace-enforce"},
	}
	if !reflect.DeepEqual(kept, wantKept) {
		t.Fatalf("kept = %v, want %v", kept, wantKept)
	}
}

// With nothing else bound, uninstall removes everything it installed, exactly
// as before.
func TestWithoutSharedPoliciesRemovesEverythingWhenUnshared(t *testing.T) {
	resources := []*unstructured.Unstructured{
		bundleObject("ValidatingAdmissionPolicy", "container-privileged"),
		bundleObject("ValidatingAdmissionPolicyBinding", "own-binding"),
	}
	cluster := []admissionregistrationv1.ValidatingAdmissionPolicyBinding{
		clusterBinding("own-binding", "container-privileged"),
		clusterBinding("unrelated", "some-other-policy"),
	}

	got, kept := withoutSharedPolicies(resources, cluster)

	if len(got) != len(resources) {
		t.Fatalf("resources to delete = %v, want all %d", objectNames(got), len(resources))
	}
	if len(kept) != 0 {
		t.Fatalf("kept = %v, want none", kept)
	}
}
