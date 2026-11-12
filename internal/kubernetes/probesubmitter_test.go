// Copyright by cenroq AG
// Contact: info@cenroq.com

package kubernetes

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"sync"
	"testing"

	authorizationv1 "k8s.io/api/authorization/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	dynamicfake "k8s.io/client-go/dynamic/fake"
	kubefake "k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"

	"github.com/cenroq/kubeapt/v2/pkg/analyze"
)

var _ analyze.Submitter = ProbeSubmitter{}

func TestProbeSubmitterResolveNamespaced(t *testing.T) {
	submitter := NewProbeSubmitter(testResourceClient(t))
	obj := pod("team-a")

	target, err := submitter.Resolve(obj, "team-b")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if !target.Namespaced() || target.Namespace() != "team-b" || target.Resource() != "pods" {
		t.Fatalf("target = namespaced %v, namespace %q, resource %q", target.Namespaced(), target.Namespace(), target.Resource())
	}
	if obj.GetNamespace() != "team-b" {
		t.Fatalf("namespace not written back onto the object: %q", obj.GetNamespace())
	}
}

func TestProbeSubmitterResolveClusterScoped(t *testing.T) {
	submitter := NewProbeSubmitter(testResourceClient(t))
	obj := &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": "rbac.authorization.k8s.io/v1",
		"kind":       "ClusterRole",
		"metadata":   map[string]any{"name": "wildcard"},
	}}

	target, err := submitter.Resolve(obj, "team-b")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if target.Namespaced() || target.Namespace() != "" || target.Resource() != "clusterroles" {
		t.Fatalf("target = namespaced %v, namespace %q, resource %q", target.Namespaced(), target.Namespace(), target.Resource())
	}
}

// The runner only knows analyze's sentinel, so the adapter must translate the
// kubernetes one or every missing CRD would abort as an error instead of a skip.
func TestProbeSubmitterTranslatesKindNotServed(t *testing.T) {
	submitter := NewProbeSubmitter(testResourceClient(t))
	obj := &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": "example.com/v1",
		"kind":       "NotInstalled",
		"metadata":   map[string]any{"name": "x"},
	}}

	_, err := submitter.Resolve(obj, "")
	if !errors.Is(err, analyze.ErrKindNotServed) {
		t.Fatalf("err = %v, want analyze.ErrKindNotServed", err)
	}
	if !strings.Contains(err.Error(), "NotInstalled") {
		t.Errorf("mapper detail was discarded: %v", err)
	}
}

func TestProbeSubmitterPassesThroughOtherResolveErrors(t *testing.T) {
	submitter := NewProbeSubmitter(testResourceClient(t))
	_, err := submitter.Resolve(&unstructured.Unstructured{Object: map[string]any{}}, "")
	if err == nil {
		t.Fatal("expected an error for an object with no apiVersion or kind")
	}
	if errors.Is(err, analyze.ErrKindNotServed) {
		t.Fatal("a malformed object must not read as an unserved kind")
	}
}

func TestProbeSubmitterCanCreate(t *testing.T) {
	client := testResourceClient(t)
	client.auth.(*kubefake.Clientset).PrependReactor("create", "selfsubjectaccessreviews", func(action k8stesting.Action) (bool, runtime.Object, error) {
		review := action.(k8stesting.CreateAction).GetObject().(*authorizationv1.SelfSubjectAccessReview)
		review.Status.Allowed = review.Spec.ResourceAttributes.Namespace != "locked"
		return true, review, nil
	})
	submitter := NewProbeSubmitter(client)

	for namespace, want := range map[string]bool{"open": true, "locked": false} {
		target, err := submitter.Resolve(pod(""), namespace)
		if err != nil {
			t.Fatalf("Resolve: %v", err)
		}
		allowed, err := submitter.CanCreate(context.Background(), target)
		if err != nil || allowed != want {
			t.Errorf("CanCreate(%s) = %v, %v; want %v", namespace, allowed, err, want)
		}
	}
}

type foreignTarget struct{ analyze.Target }

func TestProbeSubmitterCanCreateRejectsForeignTarget(t *testing.T) {
	submitter := NewProbeSubmitter(testResourceClient(t))
	if _, err := submitter.CanCreate(context.Background(), foreignTarget{}); err == nil {
		t.Fatal("expected an error for a target this submitter did not produce")
	}
}

func TestProbeTargetResourceWithoutMapping(t *testing.T) {
	if got := (probeTarget{}).Resource(); got != "" {
		t.Fatalf("Resource() = %q, want empty", got)
	}
}

// Nothing analyze submits may ever be persisted. This pins the request options
// that make that true.
func TestProbeTargetDryRunCreateIsDryRun(t *testing.T) {
	client := testResourceClient(t)
	fake := client.dynamic.(*dynamicfake.FakeDynamicClient)
	target, err := NewProbeSubmitter(client).Resolve(pod(""), "team-a")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}

	obj := pod("team-a")
	if _, err := target.DryRunCreate(context.Background(), obj); err != nil {
		t.Fatalf("DryRunCreate: %v", err)
	}

	actions := fake.Actions()
	if len(actions) != 1 {
		t.Fatalf("recorded %d actions, want 1", len(actions))
	}
	create, ok := actions[0].(k8stesting.CreateActionImpl)
	if !ok {
		t.Fatalf("action = %T, want CreateActionImpl", actions[0])
	}
	if !reflect.DeepEqual(create.CreateOptions.DryRun, []string{metav1.DryRunAll}) {
		t.Errorf("DryRun = %v, want [All]", create.CreateOptions.DryRun)
	}
	if create.CreateOptions.FieldManager != "kubeapt" {
		t.Errorf("FieldManager = %q", create.CreateOptions.FieldManager)
	}
	if create.GetNamespace() != "team-a" || create.GetResource().Resource != "pods" {
		t.Errorf("created %s in %q", create.GetResource().Resource, create.GetNamespace())
	}
}

// The adapter and the runner together: an admission denial is a pass with its
// enforcer named, and a name collision is retried under a fresh name.
func TestRunnerThroughProbeSubmitter(t *testing.T) {
	client := testResourceClient(t)
	client.auth.(*kubefake.Clientset).PrependReactor("create", "selfsubjectaccessreviews", func(action k8stesting.Action) (bool, runtime.Object, error) {
		review := action.(k8stesting.CreateAction).GetObject().(*authorizationv1.SelfSubjectAccessReview)
		review.Status.Allowed = true
		return true, review, nil
	})

	var mu sync.Mutex
	var submitted []string
	client.dynamic.(*dynamicfake.FakeDynamicClient).PrependReactor("create", "pods", func(action k8stesting.Action) (bool, runtime.Object, error) {
		obj := action.(k8stesting.CreateAction).GetObject().(*unstructured.Unstructured)
		mu.Lock()
		submitted = append(submitted, obj.GetName())
		mu.Unlock()
		switch obj.GetName() {
		case "hostpid":
			return true, nil, apierrors.NewForbidden(schema.GroupResource{Resource: "pods"}, obj.GetName(),
				fmt.Errorf(`violates PodSecurity "restricted:latest": host namespaces (hostPID=true)`))
		case "existing":
			return true, nil, apierrors.NewAlreadyExists(schema.GroupResource{Resource: "pods"}, obj.GetName())
		}
		return true, obj, nil
	})

	probe := func(name string) analyze.Probe {
		obj := pod("")
		obj.SetName(name)
		return analyze.Probe{ID: name, Expect: analyze.ExpectBlocked, Object: obj}
	}
	results := analyze.NewRunner(NewProbeSubmitter(client)).Run(context.Background(),
		[]analyze.Probe{probe("hostpid"), probe("existing")}, []string{"team-a"})

	byID := map[string]analyze.Result{}
	for _, r := range results {
		byID[r.Probe.ID] = r
	}
	blocked := byID["hostpid"]
	if blocked.Verdict != analyze.VerdictPass || blocked.Enforcer.Type != analyze.EnforcerPSA || blocked.Namespace != "team-a" {
		t.Errorf("hostpid = %+v", blocked)
	}
	// The retry under a fresh name is admitted, so the probe fails.
	retried := byID["existing"]
	if retried.Verdict != analyze.VerdictFail || !strings.HasPrefix(retried.SubmittedName, "existing-kubeapt-") {
		t.Errorf("existing = verdict %q submitted as %q", retried.Verdict, retried.SubmittedName)
	}
	if len(submitted) != 3 {
		t.Errorf("submissions = %v, want hostpid, existing and its retry", submitted)
	}
}
