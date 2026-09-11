// Copyright by cenroq AG
// Contact: info@cenroq.com

package analyze

import (
	"encoding/json"
	"fmt"
	"reflect"
	"sort"

	"k8s.io/apimachinery/pkg/api/resource"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

// DiffSetPaths reports which of the fields the submitted object actually set
// were changed by the API server.
//
// The comparison is one-directional on purpose. A dry-run response is fully
// defaulted, so the returned object always carries fields the manifest never
// mentioned (imagePullPolicy, terminationMessagePath, an injected service
// account volume, and so on). Diffing the two objects symmetrically would mark
// every probe as mutated. Defaulting only ever *adds* fields, so asking the
// narrower question — "did the server change something I set?" — isolates real
// mutation without needing a curated list of security-relevant paths.
//
// Resource quantities are compared by value rather than spelling, because the
// API server canonicalises them: a manifest asking for "1000m" comes back as
// "1". Without that, every probe carrying a resources block would report as
// mutated and the Mutated outcome would stop meaning anything.
func DiffSetPaths(submitted, returned *unstructured.Unstructured) []string {
	if submitted == nil || returned == nil {
		return nil
	}
	var changed []string
	diffMap("", submitted.Object, returned.Object, &changed)
	sort.Strings(changed)
	return changed
}

func diffMap(prefix string, want, got map[string]any, changed *[]string) {
	for key, wantValue := range want {
		path := key
		if prefix != "" {
			path = prefix + "." + key
		}
		if ignoredPath(path) {
			continue
		}
		gotValue, ok := got[key]
		if !ok {
			*changed = append(*changed, path)
			continue
		}
		diffValue(path, wantValue, gotValue, changed)
	}
}

func diffValue(path string, want, got any, changed *[]string) {
	switch typed := want.(type) {
	case map[string]any:
		gotMap, ok := got.(map[string]any)
		if !ok {
			*changed = append(*changed, path)
			return
		}
		diffMap(path, typed, gotMap, changed)
	case []any:
		gotSlice, ok := got.([]any)
		if !ok {
			*changed = append(*changed, path)
			return
		}
		if len(gotSlice) < len(typed) {
			// The server dropped entries; report the slice itself rather
			// than a misleading per-index list.
			*changed = append(*changed, path)
			return
		}
		for i := range typed {
			diffValue(fmt.Sprintf("%s[%d]", path, i), typed[i], gotSlice[i], changed)
		}
	default:
		if !equalScalar(want, got) {
			*changed = append(*changed, path)
		}
	}
}

// ignoredPath drops fields whose divergence is never a mutation. status is
// server-owned, and a manifest round-tripped through `kubectl get` carries a
// null creationTimestamp that the server always replaces.
func ignoredPath(path string) bool {
	switch path {
	case "status", "metadata.creationTimestamp", "metadata.managedFields", "metadata.uid",
		"metadata.resourceVersion", "metadata.generation", "metadata.selfLink":
		return true
	}
	return false
}

// equalScalar compares two leaf values, treating all numeric encodings as
// equivalent.
//
// This matters more than it looks. Probe manifests are decoded with
// encoding/json, which yields float64 for every number, while the dynamic
// client decodes responses into int64. Without this normalisation a plain
// `containerPort: 8080` would be reported as mutated on every single probe.
func equalScalar(want, got any) bool {
	if wantNum, ok := numericValue(want); ok {
		gotNum, ok := numericValue(got)
		return ok && wantNum == gotNum
	}
	if reflect.DeepEqual(want, got) {
		return true
	}
	return equalQuantity(want, got)
}

// equalQuantity reports whether two differing strings denote the same resource
// quantity, which is how the API server rewrites "1000m" to "1".
//
// It is only consulted for strings that are not already equal, so the only way
// it can mask a genuine mutation is if a non-quantity field were rewritten
// between two spellings of the same number.
func equalQuantity(want, got any) bool {
	wantStr, ok := want.(string)
	if !ok {
		return false
	}
	gotStr, ok := got.(string)
	if !ok {
		return false
	}
	wantQty, err := resource.ParseQuantity(wantStr)
	if err != nil {
		return false
	}
	gotQty, err := resource.ParseQuantity(gotStr)
	if err != nil {
		return false
	}
	return wantQty.Cmp(gotQty) == 0
}

func numericValue(v any) (float64, bool) {
	switch n := v.(type) {
	case int:
		return float64(n), true
	case int32:
		return float64(n), true
	case int64:
		return float64(n), true
	case float32:
		return float64(n), true
	case float64:
		return n, true
	case json.Number:
		f, err := n.Float64()
		return f, err == nil
	}
	return 0, false
}
