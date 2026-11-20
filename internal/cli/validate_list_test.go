// Copyright by cenroq AG
// Contact: info@cenroq.com

package cli

import (
	"strings"
	"testing"
)

func decodedKinds(t *testing.T, manifest string) []string {
	t.Helper()
	resources, err := decodeResources(strings.NewReader(manifest))
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	kinds := make([]string, 0, len(resources))
	for _, obj := range resources {
		kind, _ := obj["kind"].(string)
		name, _ := obj["metadata"].(map[string]interface{})["name"].(string)
		kinds = append(kinds, kind+"/"+name)
	}
	return kinds
}

// kubectl apply creates every item of a List, so validate has to evaluate the
// items rather than one object of kind List that no policy matches.
func TestDecodeResourcesExpandsLists(t *testing.T) {
	tests := []struct {
		name     string
		manifest string
		want     string
	}{
		{
			name: "v1 List",
			manifest: `
apiVersion: v1
kind: List
items:
- apiVersion: v1
  kind: Pod
  metadata: {name: privileged}
- apiVersion: v1
  kind: ConfigMap
  metadata: {name: settings}
`,
			want: "Pod/privileged,ConfigMap/settings",
		},
		{
			name: "typed list next to a plain document",
			manifest: `
apiVersion: v1
kind: PodList
items:
- apiVersion: v1
  kind: Pod
  metadata: {name: a}
---
apiVersion: v1
kind: Service
metadata: {name: b}
`,
			want: "Pod/a,Service/b",
		},
		{
			name: "nested list",
			manifest: `
apiVersion: v1
kind: List
items:
- apiVersion: v1
  kind: List
  items:
  - apiVersion: v1
    kind: Pod
    metadata: {name: inner}
`,
			want: "Pod/inner",
		},
		{
			name: "items without apiVersion or kind are skipped",
			manifest: `
apiVersion: v1
kind: List
items:
- metadata: {name: no-kind}
- apiVersion: v1
  kind: Pod
  metadata: {name: kept}
`,
			want: "Pod/kept",
		},
		{
			name: "a List kind without items is kept as is",
			manifest: `
apiVersion: example.com/v1
kind: AllowList
metadata: {name: registry}
`,
			want: "AllowList/registry",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := strings.Join(decodedKinds(t, tt.manifest), ","); got != tt.want {
				t.Fatalf("got %s, want %s", got, tt.want)
			}
		})
	}
}
