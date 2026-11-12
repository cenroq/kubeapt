// Copyright by cenroq AG
// Contact: info@cenroq.com

package kubernetes

import (
	"context"
	"fmt"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"

	"github.com/cenroq/kubeapt/v2/pkg/analyze"
)

// ProbeSubmitter adapts a ResourceClient to analyze.Submitter, which is the
// only seam pkg/analyze exposes to a cluster. The adapter lives here rather
// than in pkg/analyze so the public package keeps its dependency on client-go
// out of its API: an embedding tool can drive the runner with a client of its
// own without ever importing kubeapt's.
type ProbeSubmitter struct {
	client *ResourceClient
}

// NewProbeSubmitter wraps c for use with analyze.NewRunner.
func NewProbeSubmitter(c *ResourceClient) ProbeSubmitter {
	return ProbeSubmitter{client: c}
}

// Resolve maps obj to a target, translating a not-served kind into the error
// the runner recognises.
func (s ProbeSubmitter) Resolve(obj *unstructured.Unstructured, namespaceOverride string) (analyze.Target, error) {
	target, err := s.client.Resolve(obj, namespaceOverride)
	if err != nil {
		if IsKindNotServed(err) {
			// Re-wrap so errors.Is finds the analyze sentinel while the
			// RESTMapper's message, which names the kind and version, survives.
			return nil, fmt.Errorf("%w: %v", analyze.ErrKindNotServed, err)
		}
		return nil, err
	}
	return probeTarget{target: target}, nil
}

// CanCreate answers the RBAC preflight for a target this submitter produced.
func (s ProbeSubmitter) CanCreate(ctx context.Context, target analyze.Target) (bool, error) {
	concrete, ok := target.(probeTarget)
	if !ok {
		return false, fmt.Errorf("kubernetes: target was not produced by this submitter")
	}
	return s.client.CanCreate(ctx, concrete.target)
}

// probeTarget exposes a Target through the accessor interface analyze expects.
// Target's fields cannot serve as the methods directly, because a field and a
// method cannot share a name.
type probeTarget struct {
	target Target
}

func (p probeTarget) Namespace() string { return p.target.Namespace }
func (p probeTarget) Namespaced() bool  { return p.target.Namespaced }

func (p probeTarget) Resource() string {
	if p.target.Mapping == nil {
		return ""
	}
	return p.target.Mapping.Resource.Resource
}

func (p probeTarget) DryRunCreate(ctx context.Context, obj *unstructured.Unstructured) (*unstructured.Unstructured, error) {
	return p.target.DryRunCreate(ctx, obj)
}
