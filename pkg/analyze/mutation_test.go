// Copyright by cenroq AG
// Contact: info@cenroq.com

package analyze_test

import (
	"encoding/json"
	"reflect"
	"testing"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"

	"github.com/cenroq/kubeapt/v2/pkg/analyze"
)

func object(t *testing.T, raw string) *unstructured.Unstructured {
	t.Helper()
	var obj map[string]any
	if err := json.Unmarshal([]byte(raw), &obj); err != nil {
		t.Fatalf("decode fixture: %v", err)
	}
	return &unstructured.Unstructured{Object: obj}
}

// The single most important test in this file. A dry-run response is fully
// defaulted, so if DiffSetPaths compared the objects symmetrically every probe
// would report as mutated and the Mutated outcome would be meaningless.
func TestDiffSetPathsIgnoresServerDefaulting(t *testing.T) {
	submitted := object(t, `{
	  "apiVersion": "v1",
	  "kind": "Pod",
	  "metadata": {"name": "probe", "namespace": "default"},
	  "spec": {
	    "containers": [{"name": "app", "image": "nginx", "securityContext": {"privileged": true}}]
	  }
	}`)
	returned := object(t, `{
	  "apiVersion": "v1",
	  "kind": "Pod",
	  "metadata": {
	    "name": "probe",
	    "namespace": "default",
	    "uid": "9f1c2f2e-0000-0000-0000-000000000000",
	    "resourceVersion": "12345",
	    "creationTimestamp": "2026-08-14T10:00:00Z"
	  },
	  "spec": {
	    "containers": [{
	      "name": "app",
	      "image": "nginx",
	      "securityContext": {"privileged": true},
	      "imagePullPolicy": "IfNotPresent",
	      "terminationMessagePath": "/dev/termination-log",
	      "terminationMessagePolicy": "File",
	      "resources": {},
	      "volumeMounts": [{"name": "kube-api-access-abcde", "mountPath": "/var/run/secrets/kubernetes.io/serviceaccount"}]
	    }],
	    "dnsPolicy": "ClusterFirst",
	    "restartPolicy": "Always",
	    "schedulerName": "default-scheduler",
	    "securityContext": {},
	    "serviceAccount": "default",
	    "serviceAccountName": "default",
	    "terminationGracePeriodSeconds": 30,
	    "volumes": [{"name": "kube-api-access-abcde"}]
	  },
	  "status": {"phase": "Pending"}
	}`)

	if got := analyze.DiffSetPaths(submitted, returned); len(got) != 0 {
		t.Fatalf("defaulting reported as mutation: %v", got)
	}
}

// Probe manifests decode through encoding/json (float64) while the dynamic
// client decodes responses into int64. Without numeric normalisation every
// probe carrying a port or a replica count would report as mutated.
func TestDiffSetPathsNormalisesNumericEncodings(t *testing.T) {
	submitted := &unstructured.Unstructured{Object: map[string]any{
		"spec": map[string]any{
			"replicas": float64(3),
			"ports":    []any{map[string]any{"containerPort": float64(8080)}},
		},
	}}
	returned := &unstructured.Unstructured{Object: map[string]any{
		"spec": map[string]any{
			"replicas": int64(3),
			"ports":    []any{map[string]any{"containerPort": int64(8080)}},
		},
	}}

	if got := analyze.DiffSetPaths(submitted, returned); len(got) != 0 {
		t.Fatalf("numeric encoding difference reported as mutation: %v", got)
	}
}

// The API server canonicalises quantities, so "1000m" comes back as "1". Any
// probe carrying a resources block would otherwise always report as mutated.
func TestDiffSetPathsTreatsEquivalentQuantitiesAsUnchanged(t *testing.T) {
	tests := [][2]string{
		{"1000m", "1"},
		{"1024Mi", "1Gi"},
		{"0.5", "500m"},
		{"1e3", "1k"},
	}
	for _, tc := range tests {
		submitted := object(t, `{"spec":{"containers":[{"resources":{"requests":{"cpu":"`+tc[0]+`"}}}]}}`)
		returned := object(t, `{"spec":{"containers":[{"resources":{"requests":{"cpu":"`+tc[1]+`"}}}]}}`)
		if got := analyze.DiffSetPaths(submitted, returned); len(got) != 0 {
			t.Errorf("%q vs %q reported as mutation: %v", tc[0], tc[1], got)
		}
	}
}

func TestDiffSetPathsDetectsChangedQuantity(t *testing.T) {
	submitted := object(t, `{"spec":{"containers":[{"resources":{"limits":{"memory":"1Gi"}}}]}}`)
	returned := object(t, `{"spec":{"containers":[{"resources":{"limits":{"memory":"512Mi"}}}]}}`)

	want := []string{"spec.containers[0].resources.limits.memory"}
	if got := analyze.DiffSetPaths(submitted, returned); !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v, want %v", got, want)
	}
}

// Quantity comparison must not swallow ordinary string changes.
func TestDiffSetPathsQuantityComparisonDoesNotMaskStringChanges(t *testing.T) {
	submitted := object(t, `{"spec":{"containers":[{"image":"busybox:1.36","name":"app"}]}}`)
	returned := object(t, `{"spec":{"containers":[{"image":"evil:latest","name":"app"}]}}`)

	want := []string{"spec.containers[0].image"}
	if got := analyze.DiffSetPaths(submitted, returned); !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v, want %v", got, want)
	}
}

func TestDiffSetPathsDetectsChangedValue(t *testing.T) {
	submitted := object(t, `{"spec":{"containers":[{"name":"app","securityContext":{"privileged":true}}]}}`)
	returned := object(t, `{"spec":{"containers":[{"name":"app","securityContext":{"privileged":false}}]}}`)

	want := []string{"spec.containers[0].securityContext.privileged"}
	if got := analyze.DiffSetPaths(submitted, returned); !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v, want %v", got, want)
	}
}

func TestDiffSetPathsDetectsRemovedField(t *testing.T) {
	submitted := object(t, `{"spec":{"hostNetwork":true,"hostPID":true}}`)
	returned := object(t, `{"spec":{"hostNetwork":true}}`)

	want := []string{"spec.hostPID"}
	if got := analyze.DiffSetPaths(submitted, returned); !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v, want %v", got, want)
	}
}

func TestDiffSetPathsDetectsTruncatedSlice(t *testing.T) {
	submitted := object(t, `{"spec":{"volumes":[{"name":"a","hostPath":{"path":"/"}},{"name":"b"}]}}`)
	returned := object(t, `{"spec":{"volumes":[{"name":"a","hostPath":{"path":"/"}}]}}`)

	want := []string{"spec.volumes"}
	if got := analyze.DiffSetPaths(submitted, returned); !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v, want %v", got, want)
	}
}

// A server that appends to a slice the probe set has not changed what the probe
// set, so the extra entry is defaulting and must not register.
func TestDiffSetPathsAllowsAppendedSliceEntries(t *testing.T) {
	submitted := object(t, `{"spec":{"volumes":[{"name":"data","hostPath":{"path":"/"}}]}}`)
	returned := object(t, `{"spec":{"volumes":[{"name":"data","hostPath":{"path":"/"}},{"name":"kube-api-access-abcde"}]}}`)

	if got := analyze.DiffSetPaths(submitted, returned); len(got) != 0 {
		t.Fatalf("appended slice entry reported as mutation: %v", got)
	}
}

func TestDiffSetPathsDetectsTypeChange(t *testing.T) {
	submitted := object(t, `{"spec":{"securityContext":{"runAsUser":0}}}`)
	returned := object(t, `{"spec":{"securityContext":"replaced"}}`)

	want := []string{"spec.securityContext"}
	if got := analyze.DiffSetPaths(submitted, returned); !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v, want %v", got, want)
	}
}

func TestDiffSetPathsReportsMultiplePathsSorted(t *testing.T) {
	submitted := object(t, `{"spec":{"hostPID":true,"hostIPC":true,"hostNetwork":true}}`)
	returned := object(t, `{"spec":{"hostPID":false,"hostIPC":false,"hostNetwork":false}}`)

	want := []string{"spec.hostIPC", "spec.hostNetwork", "spec.hostPID"}
	if got := analyze.DiffSetPaths(submitted, returned); !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v, want %v", got, want)
	}
}

func TestDiffSetPathsNilInputs(t *testing.T) {
	obj := object(t, `{"spec":{"a":1}}`)
	if got := analyze.DiffSetPaths(nil, obj); got != nil {
		t.Errorf("nil submitted: got %v", got)
	}
	if got := analyze.DiffSetPaths(obj, nil); got != nil {
		t.Errorf("nil returned: got %v", got)
	}
}
