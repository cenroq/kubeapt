// Copyright by cenroq AG
// Contact: info@cenroq.com

package kubernetes

import (
	"context"
	"errors"
	"fmt"
	"sync"

	authorizationv1 "k8s.io/api/authorization/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/client-go/discovery"
	"k8s.io/client-go/dynamic"
	kubeclient "k8s.io/client-go/kubernetes"
	"k8s.io/client-go/restmapper"
)

// ErrKindNotServed reports that the connected cluster does not serve the kind a
// caller asked for. It is returned instead of the raw RESTMapper error so that
// callers walking a list of manifests can skip an unknown kind rather than
// abort, which matters when a manifest set targets a CRD that may not be
// installed.
var ErrKindNotServed = errors.New("kubernetes: cluster does not serve this kind")

// ResourceClient pairs a dynamic client with a discovery-backed RESTMapper so
// arbitrary manifests can be addressed without compiled-in type knowledge.
//
// Construction performs a full discovery round trip, so callers should build
// one client and reuse it across every object rather than constructing per
// resource.
type ResourceClient struct {
	dynamic dynamic.Interface
	mapper  meta.RESTMapper
	auth    kubeclient.Interface

	accessMu sync.Mutex
	access   map[string]bool
}

// NewResourceClient builds a ResourceClient from the ambient kubeconfig.
func NewResourceClient() (*ResourceClient, error) {
	config, err := RESTConfig()
	if err != nil {
		return nil, err
	}
	dynamicClient, err := dynamic.NewForConfig(config)
	if err != nil {
		return nil, err
	}
	discoveryClient, err := discovery.NewDiscoveryClientForConfig(config)
	if err != nil {
		return nil, err
	}
	groupResources, err := restmapper.GetAPIGroupResources(discoveryClient)
	if err != nil {
		return nil, err
	}
	clientset, err := kubeclient.NewForConfig(config)
	if err != nil {
		return nil, err
	}
	return &ResourceClient{
		dynamic: dynamicClient,
		mapper:  restmapper.NewDiscoveryRESTMapper(groupResources),
		auth:    clientset,
		access:  map[string]bool{},
	}, nil
}

// Target is a resolved destination for a single object: the scope-correct
// dynamic client plus the mapping that decided it.
type Target struct {
	Client     dynamic.ResourceInterface
	Mapping    *meta.RESTMapping
	Namespace  string // empty for cluster-scoped resources
	Namespaced bool
}

// Resolve maps obj to a scope-correct client.
//
// For a namespaced resource the namespace is taken from namespaceOverride when
// set, then from the object, then from the active kubeconfig context, and
// finally "default". The chosen namespace is written back onto obj so the
// object that goes over the wire carries the namespace it was sent to. Cluster
// scoped resources ignore namespaceOverride entirely.
//
// A kind the cluster does not serve yields ErrKindNotServed.
func (c *ResourceClient) Resolve(obj *unstructured.Unstructured, namespaceOverride string) (Target, error) {
	gvk := obj.GroupVersionKind()
	if gvk.Empty() {
		return Target{}, fmt.Errorf("resource is missing apiVersion or kind")
	}
	mapping, err := c.mapper.RESTMapping(gvk.GroupKind(), gvk.Version)
	if err != nil {
		if meta.IsNoMatchError(err) {
			// Wrap rather than replace: the RESTMapper message names the kind
			// and version, which is the useful part of the diagnosis.
			return Target{}, fmt.Errorf("%w: %v", ErrKindNotServed, err)
		}
		return Target{}, err
	}

	if mapping.Scope.Name() != meta.RESTScopeNameNamespace {
		return Target{
			Client:     c.dynamic.Resource(mapping.Resource),
			Mapping:    mapping,
			Namespaced: false,
		}, nil
	}

	namespaceName := namespaceOverride
	if namespaceName == "" {
		namespaceName = obj.GetNamespace()
	}
	if namespaceName == "" {
		namespaceName = ActiveNamespace()
	}
	if namespaceName == "" {
		namespaceName = "default"
	}
	obj.SetNamespace(namespaceName)

	return Target{
		Client:     c.dynamic.Resource(mapping.Resource).Namespace(namespaceName),
		Mapping:    mapping,
		Namespace:  namespaceName,
		Namespaced: true,
	}, nil
}

// DryRunCreate submits obj with dryRun=All and returns the object exactly as it
// would have been persisted, including everything admission and defaulting did
// to it. Nothing is written.
//
// A rejection comes back as an error, which for a caller measuring admission
// posture is the interesting result rather than a failure.
func (t Target) DryRunCreate(ctx context.Context, obj *unstructured.Unstructured) (*unstructured.Unstructured, error) {
	return t.Client.Create(ctx, obj, metav1.CreateOptions{
		DryRun:       []string{metav1.DryRunAll},
		FieldManager: "kubeapt",
	})
}

// CanCreate reports whether the caller is allowed to create the target's
// resource, answered by the API server via SelfSubjectAccessReview.
//
// This exists because an RBAC refusal and an admission refusal are both
// StatusReasonForbidden and are not reliably distinguishable from the error
// text. Asking first means an inaccessible cluster is reported as untested
// rather than as defended, which is the difference between a useful report and
// a dangerous one. Answers are memoised per resource and namespace.
func (c *ResourceClient) CanCreate(ctx context.Context, target Target) (bool, error) {
	if target.Mapping == nil {
		return false, fmt.Errorf("kubernetes: target has no REST mapping")
	}
	gvr := target.Mapping.Resource
	key := gvr.String() + "|" + target.Namespace

	c.accessMu.Lock()
	allowed, cached := c.access[key]
	c.accessMu.Unlock()
	if cached {
		return allowed, nil
	}

	review := &authorizationv1.SelfSubjectAccessReview{
		Spec: authorizationv1.SelfSubjectAccessReviewSpec{
			ResourceAttributes: &authorizationv1.ResourceAttributes{
				Namespace: target.Namespace,
				Verb:      "create",
				Group:     gvr.Group,
				Version:   gvr.Version,
				Resource:  gvr.Resource,
			},
		},
	}
	result, err := c.auth.AuthorizationV1().SelfSubjectAccessReviews().Create(ctx, review, metav1.CreateOptions{})
	if err != nil {
		return false, err
	}

	c.accessMu.Lock()
	c.access[key] = result.Status.Allowed
	c.accessMu.Unlock()
	return result.Status.Allowed, nil
}
