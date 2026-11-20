// Copyright by cenroq AG
// Contact: info@cenroq.com

package kubernetes

import (
	"strings"
	"testing"
)

// A policy file's resourceRules are joined into a request path, so values that
// could walk out of the list endpoint must be refused before any URL is built.
// The clientset is nil: rejection has to happen before discovery is touched.
func TestDraftURLsRejectsNonSegmentValues(t *testing.T) {
	tests := []struct {
		name        string
		apiGroups   []string
		apiVersions []string
		resources   []string
		field       string
	}{
		{"group walks to node proxy", []string{"../api/v1/nodes/kind-control-plane/proxy"}, []string{"."}, []string{"pods"}, "apiGroups"},
		{"group is dot-dot", []string{".."}, []string{"v1"}, []string{"pods"}, "apiGroups"},
		{"version is dot", []string{""}, []string{"."}, []string{"pods"}, "apiVersions"},
		{"version contains slash", []string{"apps"}, []string{"v1/../../api"}, []string{"deployments"}, "apiVersions"},
		{"resource contains slash", []string{""}, []string{"v1"}, []string{"namespaces/kube-system/services"}, "resources"},
		{"resource is percent-encoded", []string{""}, []string{"v1"}, []string{"%2e%2e"}, "resources"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			urls, err := draftURLs(nil, tt.apiGroups, tt.apiVersions, tt.resources)
			if err == nil {
				t.Fatalf("expected an error, got urls %v", urls)
			}
			if !strings.Contains(err.Error(), tt.field) {
				t.Fatalf("error %q does not name the offending field %s", err, tt.field)
			}
		})
	}
}

// Real ValidatingAdmissionPolicy rules must keep producing the same URLs.
func TestDraftURLsAcceptsValidSegments(t *testing.T) {
	tests := []struct {
		name        string
		apiGroups   []string
		apiVersions []string
		resources   []string
		want        []string
	}{
		{"core group", []string{""}, []string{"v1"}, []string{"pods"}, []string{"/api/v1/pods"}},
		{"named group", []string{"rbac.authorization.k8s.io"}, []string{"v1"}, []string{"clusterroles"}, []string{"/apis/rbac.authorization.k8s.io/v1/clusterroles"}},
		{"several groups", []string{"apps", "batch"}, []string{"v1"}, []string{"deployments"}, []string{"/apis/apps/v1/deployments", "/apis/batch/v1/deployments"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := draftURLs(nil, tt.apiGroups, tt.apiVersions, tt.resources)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if strings.Join(got, ",") != strings.Join(tt.want, ",") {
				t.Fatalf("got %v, want %v", got, tt.want)
			}
		})
	}
}
