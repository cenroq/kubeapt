// Copyright by cenroq AG
// Contact: info@cenroq.com

package kubernetes

import (
	"context"
	"errors"
	"testing"

	authorizationv1 "k8s.io/api/authorization/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	dynamicfake "k8s.io/client-go/dynamic/fake"
	kubefake "k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"
)

func testResourceClient(t *testing.T) *ResourceClient {
	t.Helper()

	mapper := meta.NewDefaultRESTMapper([]schema.GroupVersion{
		{Group: "", Version: "v1"},
		{Group: "rbac.authorization.k8s.io", Version: "v1"},
	})
	mapper.Add(schema.GroupVersionKind{Version: "v1", Kind: "Pod"}, meta.RESTScopeNamespace)
	mapper.Add(schema.GroupVersionKind{
		Group: "rbac.authorization.k8s.io", Version: "v1", Kind: "ClusterRole",
	}, meta.RESTScopeRoot)

	return &ResourceClient{
		dynamic: dynamicfake.NewSimpleDynamicClient(runtime.NewScheme()),
		mapper:  mapper,
		auth:    kubefake.NewSimpleClientset(),
		access:  map[string]bool{},
	}
}

func pod(namespace string) *unstructured.Unstructured {
	obj := &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": "v1",
		"kind":       "Pod",
		"metadata":   map[string]any{"name": "probe"},
	}}
	if namespace != "" {
		obj.SetNamespace(namespace)
	}
	return obj
}

func TestResolveNamespacedUsesObjectNamespace(t *testing.T) {
	client := testResourceClient(t)

	target, err := client.Resolve(pod("team-a"), "")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if !target.Namespaced {
		t.Fatal("Namespaced = false for a Pod")
	}
	if target.Namespace != "team-a" {
		t.Fatalf("Namespace = %q, want team-a", target.Namespace)
	}
}

func TestResolveOverrideBeatsObjectNamespace(t *testing.T) {
	client := testResourceClient(t)
	obj := pod("team-a")

	target, err := client.Resolve(obj, "team-b")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if target.Namespace != "team-b" {
		t.Fatalf("Namespace = %q, want team-b", target.Namespace)
	}
	if obj.GetNamespace() != "team-b" {
		t.Fatalf("namespace not written back onto the object: %q", obj.GetNamespace())
	}
}

func TestResolveFallsBackToActiveNamespace(t *testing.T) {
	client := testResourceClient(t)

	previous := activeNamespace
	activeNamespace = "from-kubeconfig"
	t.Cleanup(func() { activeNamespace = previous })

	target, err := client.Resolve(pod(""), "")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if target.Namespace != "from-kubeconfig" {
		t.Fatalf("Namespace = %q, want from-kubeconfig", target.Namespace)
	}
}

func TestResolveFallsBackToDefault(t *testing.T) {
	client := testResourceClient(t)

	previous := activeNamespace
	activeNamespace = ""
	t.Cleanup(func() { activeNamespace = previous })

	target, err := client.Resolve(pod(""), "")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if target.Namespace != "default" {
		t.Fatalf("Namespace = %q, want default", target.Namespace)
	}
}

// A cluster-scoped probe runs once, so an override must not smuggle a namespace
// onto it and turn one probe into one probe per namespace.
func TestResolveClusterScopedIgnoresNamespace(t *testing.T) {
	client := testResourceClient(t)
	obj := &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": "rbac.authorization.k8s.io/v1",
		"kind":       "ClusterRole",
		"metadata":   map[string]any{"name": "wildcard"},
	}}

	target, err := client.Resolve(obj, "team-b")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if target.Namespaced {
		t.Fatal("Namespaced = true for a ClusterRole")
	}
	if target.Namespace != "" {
		t.Fatalf("Namespace = %q, want empty", target.Namespace)
	}
	if obj.GetNamespace() != "" {
		t.Fatalf("namespace written onto a cluster-scoped object: %q", obj.GetNamespace())
	}
}

func TestResolveUnknownKindIsSkippable(t *testing.T) {
	client := testResourceClient(t)
	obj := &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": "example.com/v1",
		"kind":       "NotInstalled",
		"metadata":   map[string]any{"name": "x"},
	}}

	_, err := client.Resolve(obj, "")
	if !errors.Is(err, ErrKindNotServed) {
		t.Fatalf("err = %v, want ErrKindNotServed", err)
	}
	// The RESTMapper's own wording names the kind, which is the useful part.
	if got := err.Error(); got == ErrKindNotServed.Error() {
		t.Fatal("original mapper detail was discarded")
	}
}

func TestResolveMissingTypeMeta(t *testing.T) {
	client := testResourceClient(t)
	obj := &unstructured.Unstructured{Object: map[string]any{
		"metadata": map[string]any{"name": "x"},
	}}

	if _, err := client.Resolve(obj, ""); err == nil {
		t.Fatal("expected an error for a missing apiVersion and kind")
	}
}

func TestCanCreate(t *testing.T) {
	client := testResourceClient(t)
	fake := client.auth.(*kubefake.Clientset)

	reviews := 0
	fake.PrependReactor("create", "selfsubjectaccessreviews", func(action k8stesting.Action) (bool, runtime.Object, error) {
		reviews++
		review := action.(k8stesting.CreateAction).GetObject().(*authorizationv1.SelfSubjectAccessReview)
		review.Status.Allowed = review.Spec.ResourceAttributes.Namespace != "locked"
		return true, review, nil
	})

	open, err := client.Resolve(pod("open"), "")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	locked, err := client.Resolve(pod("locked"), "")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}

	allowed, err := client.CanCreate(context.Background(), open)
	if err != nil || !allowed {
		t.Fatalf("CanCreate(open) = %v, %v", allowed, err)
	}
	allowed, err = client.CanCreate(context.Background(), locked)
	if err != nil || allowed {
		t.Fatalf("CanCreate(locked) = %v, %v", allowed, err)
	}
	if reviews != 2 {
		t.Fatalf("issued %d reviews, want 2", reviews)
	}

	// Repeating the same question must not cost another round trip: with
	// --all-namespaces this is asked once per probe per namespace.
	if _, err := client.CanCreate(context.Background(), open); err != nil {
		t.Fatalf("CanCreate: %v", err)
	}
	if reviews != 2 {
		t.Fatalf("memoisation failed: %d reviews", reviews)
	}
}

func TestCanCreateWithoutMapping(t *testing.T) {
	client := testResourceClient(t)
	if _, err := client.CanCreate(context.Background(), Target{}); err == nil {
		t.Fatal("expected an error for a target with no REST mapping")
	}
}
