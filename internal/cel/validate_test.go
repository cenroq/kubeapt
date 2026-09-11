// Copyright by cenroq AG
// Contact: info@cenroq.com

package cel

import (
	"context"
	"strings"
	"testing"

	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
)

func check(t *testing.T, expr string, object map[string]any) bool {
	t.Helper()
	got, err := Check(context.Background(), expr, object)
	if err != nil {
		t.Fatalf("Check(%q): %v", expr, err)
	}
	return got
}

func apiService(insecure any) map[string]any {
	spec := map[string]any{"group": "metrics.k8s.io", "version": "v1beta1"}
	if insecure != nil {
		spec["insecureSkipTLSVerify"] = insecure
	}
	return map[string]any{
		"apiVersion": "apiregistration.k8s.io/v1",
		"kind":       "APIService",
		"metadata":   map[string]any{"name": "v1beta1.metrics.k8s.io"},
		"spec":       spec,
	}
}

// The reported bug, verbatim. Before the environment came from upstream this
// failed to compile with "unsupported syntax '.?'", which aborted the whole
// run: one policy using optional syntax meant no report at all.
func TestOptionalSyntaxFromReportedBug(t *testing.T) {
	const expr = "object.spec.?insecureSkipTLSVerify.orValue(false) != true"

	if got := check(t, expr, apiService(true)); got {
		t.Error("insecureSkipTLSVerify: true should violate the policy")
	}
	if got := check(t, expr, apiService(false)); !got {
		t.Error("insecureSkipTLSVerify: false should satisfy the policy")
	}
	if got := check(t, expr, apiService(nil)); !got {
		t.Error("absent insecureSkipTLSVerify should satisfy the policy via orValue")
	}
}

// The other optional shapes the cenroq bundle actually ships, so a regression in
// optional support is caught in the forms real policies use rather than only the
// simplest one.
func TestOptionalSyntaxBundleShapes(t *testing.T) {
	webhook := map[string]any{
		"apiVersion": "admissionregistration.k8s.io/v1",
		"kind":       "ValidatingWebhookConfiguration",
		"webhooks": []any{
			map[string]any{"name": "a.example.com", "failurePolicy": "Fail"},
			map[string]any{"name": "b.example.com"},
		},
	}
	const expr = "object.webhooks.all(w, w.?failurePolicy.orValue('Fail') != 'Ignore')"
	if got := check(t, expr, webhook); !got {
		t.Error("a webhook with no failurePolicy should default to Fail and pass")
	}

	policy := map[string]any{
		"apiVersion": "kyverno.io/v1",
		"kind":       "ClusterPolicy",
		"spec":       map[string]any{},
	}
	const enforcing = "!(object.spec.?validationFailureAction.orValue('Enforce') in ['Audit', 'audit'])"
	if got := check(t, enforcing, policy); !got {
		t.Error("absent validationFailureAction should default to Enforce")
	}
}

// An optional select propagates through the selects that follow it, so
// a chain like object.spec.?mtls.mode.orValue(default) is guarded at every hop,
// not just the first.
// The plainer reading - that only `.?mtls` is guarded and a bare `.mode` on a
// present-but-empty parent would error - is wrong, and it is worth a test
// because policies in the cenroq bundle rely on the real behaviour.
func TestChainedOptionalPropagatesThroughTheWholeChain(t *testing.T) {
	const expr = "object.spec.?mtls.mode.orValue('') in ['DISABLE', 'PERMISSIVE']"

	cases := []struct {
		name string
		spec map[string]any
		want bool
	}{
		{"mode present", map[string]any{"mtls": map[string]any{"mode": "DISABLE"}}, true},
		{"mtls present, mode absent", map[string]any{"mtls": map[string]any{}}, false},
		{"mtls absent", map[string]any{}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := Check(context.Background(), expr, map[string]any{"spec": tc.spec})
			if err != nil {
				t.Fatalf("optional chain should not error: %v", err)
			}
			if got != tc.want {
				t.Errorf("got %v, want %v", got, tc.want)
			}
		})
	}
}

// One case per Kubernetes CEL library that the hand-built environment omitted.
// No bundle uses these yet, which is exactly why they need pinning: without a
// test, dropping one would only surface as a user's policy failing to compile.
func TestKubernetesLibrariesAreRegistered(t *testing.T) {
	object := map[string]any{"spec": map[string]any{}}
	tests := []struct {
		name string
		expr string
	}{
		{"quantity", `quantity("1Gi").isLessThan(quantity("2Gi"))`},
		{"isQuantity", `isQuantity("500m")`},
		{"ip", `ip("192.168.0.1").family() == 4`},
		{"isIP", `isIP("10.0.0.1")`},
		{"cidr", `cidr("192.168.0.0/16").containsIP(ip("192.168.0.1"))`},
		{"isCIDR", `isCIDR("10.0.0.0/8")`},
		{"url", `url("https://example.com/x").getHostname() == "example.com"`},
		{"isURL", `isURL("https://example.com")`},
		{"format", `format.dns1123Label().validate("my-label") == optional.none()`},
		{"semver", `semver("1.2.3").isGreaterThan(semver("1.2.2"))`},
		{"sets", `sets.contains([1, 2, 3], [2])`},
		{"lists", `[1, 2, 3].indexOf(2) == 1`},
		{"strings", `"Hello".lowerAscii() == "hello"`},
		{"regex", `"abc123".find("[0-9]+") == "123"`},
		{"twoVarComprehensions", `[1, 2, 3].transformList(i, v, v * 2) == [2, 4, 6]`},
		{"optionalTypes", `optional.of(1).orValue(2) == 1`},
		{"crossTypeNumericComparison", `1 < 1.5`},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := check(t, tc.expr, object); !got {
				t.Errorf("%s evaluated false", tc.expr)
			}
		})
	}
}

// request and namespaceObject are typed upstream, and kubeapt previously passed
// request as a literal nil. These expressions could not work at all before.
func TestTypedRequestAndNamespaceVariables(t *testing.T) {
	evaluator, err := Compile(nil, []admissionregistrationv1.Validation{
		{Expression: `request.operation == 'CREATE'`},
		{Expression: `request.kind.kind == 'Pod'`},
		{Expression: `request.dryRun == true`},
		{Expression: `namespaceObject.metadata.labels['env'] == 'prod'`},
		{Expression: `request.resource.resource == 'pods'`},
	}, Options{})
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}

	results, err := evaluator.Evaluate(context.Background(), Input{
		Object: map[string]any{
			"apiVersion": "v1",
			"kind":       "Pod",
			"metadata":   map[string]any{"name": "demo", "namespace": "prod-ns"},
		},
		Namespace:       "prod-ns",
		NamespaceLabels: map[string]string{"env": "prod"},
	})
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	for i, result := range results {
		if result.Err != nil {
			t.Errorf("validation %d: %v", i, result.Err)
			continue
		}
		if !result.Allowed {
			t.Errorf("validation %d evaluated false", i)
		}
	}
}

// A cluster-scoped resource has no namespace, and upstream expects null rather
// than an empty Namespace object.
func TestNamespaceObjectIsNullWhenClusterScoped(t *testing.T) {
	object := map[string]any{
		"apiVersion": "rbac.authorization.k8s.io/v1",
		"kind":       "ClusterRole",
		"metadata":   map[string]any{"name": "demo"},
	}
	if got := check(t, "namespaceObject == null", object); !got {
		t.Error("expected namespaceObject to be null for a cluster-scoped resource")
	}
}

// spec.variables compose lazily upstream, and a variable that fails to compile
// must fail only the validations that read it.
func TestVariableComposition(t *testing.T) {
	evaluator, err := Compile(
		[]admissionregistrationv1.Variable{
			{Name: "containers", Expression: "object.spec.containers"},
			{Name: "privileged", Expression: "variables.containers.exists(c, c.securityContext.privileged)"},
		},
		[]admissionregistrationv1.Validation{{Expression: "!variables.privileged"}},
		Options{},
	)
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}

	pod := func(privileged bool) map[string]any {
		return map[string]any{
			"apiVersion": "v1",
			"kind":       "Pod",
			"metadata":   map[string]any{"name": "demo"},
			"spec": map[string]any{"containers": []any{
				map[string]any{"name": "app", "securityContext": map[string]any{"privileged": privileged}},
			}},
		}
	}

	for _, tc := range []struct {
		privileged bool
		want       bool
	}{{false, true}, {true, false}} {
		results, err := evaluator.Evaluate(context.Background(), Input{Object: pod(tc.privileged)})
		if err != nil {
			t.Fatalf("Evaluate: %v", err)
		}
		if results[0].Err != nil {
			t.Fatalf("validation error: %v", results[0].Err)
		}
		if results[0].Allowed != tc.want {
			t.Errorf("privileged=%v: got %v, want %v", tc.privileged, results[0].Allowed, tc.want)
		}
	}
}

// Bundle policies are third-party downloads. Before the upstream environment
// they ran with no cost budget at all, so a pathological expression could spin
// indefinitely instead of erroring.
func TestCostLimitRejectsRunawayExpression(t *testing.T) {
	const list = `[1,2,3,4,5,6,7,8,9,10]`
	const expr = `size(` + list + `.map(a, ` + list + `.map(b, ` + list + `.map(c, ` +
		list + `.map(d, ` + list + `.map(e, string(a)+string(b)+string(c)+string(d)+string(e))))))) > 0`

	_, err := Check(context.Background(), expr, map[string]any{"spec": map[string]any{}})
	if err == nil {
		t.Fatal("expected the cost budget to reject a runaway expression")
	}
	if !strings.Contains(strings.ToLower(err.Error()), "cost") {
		t.Errorf("expected a cost-related error, got: %v", err)
	}
}

// A non-boolean validation is rejected at compile time, because upstream
// declares bool as the required return type.
func TestNonBooleanValidationIsRejected(t *testing.T) {
	if _, err := Compile(nil, []admissionregistrationv1.Validation{{Expression: "1 + 2"}}, Options{}); err == nil {
		t.Fatal("expected a non-boolean validation to fail compilation")
	}
}

func TestInvalidExpressionIsRejected(t *testing.T) {
	if _, err := Compile(nil, []admissionregistrationv1.Validation{{Expression: "1 +"}}, Options{}); err == nil {
		t.Fatal("expected a malformed expression to fail compilation")
	}
}

// authorizer must be declared even though kubeapt binds none, so that a policy
// mentioning it still compiles. It has to fail loudly at evaluation rather than
// returning a permissive answer, which would be the dangerous outcome.
func TestAuthorizerCompilesButFailsWithoutABinding(t *testing.T) {
	evaluator, err := Compile(nil, []admissionregistrationv1.Validation{
		{Expression: `authorizer.group('').resource('pods').check('create').allowed()`},
	}, Options{HasAuthorizer: true})
	if err != nil {
		t.Fatalf("expected the expression to compile with HasAuthorizer: %v", err)
	}

	results, err := evaluator.Evaluate(context.Background(), Input{
		Object: map[string]any{"apiVersion": "v1", "kind": "Pod", "metadata": map[string]any{"name": "demo"}},
	})
	if err == nil && results[0].Err == nil {
		t.Fatal("expected an unbound authorizer to produce an error, not a verdict")
	}
}

// Compile is cached, and the cache is what keeps validate from recompiling every
// policy once per resource. Identical inputs must return the same evaluator, and
// differing inputs must not collide.
func TestCompileCaches(t *testing.T) {
	validations := []admissionregistrationv1.Validation{{Expression: "has(object.metadata.name)"}}

	first, err := Compile(nil, validations, Options{})
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	second, err := Compile(nil, validations, Options{})
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	if first != second {
		t.Error("expected identical inputs to return the cached evaluator")
	}

	other, err := Compile(nil, []admissionregistrationv1.Validation{{Expression: "has(object.kind)"}}, Options{})
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	if first == other {
		t.Error("expected different expressions to compile separately")
	}
}

// The NUL separator exists so no combination of names and expressions can forge
// a boundary and be mistaken for a different policy.
func TestFingerprintDistinguishesAdjacentFields(t *testing.T) {
	a := fingerprint(
		[]admissionregistrationv1.Variable{{Name: "ab", Expression: "1"}},
		nil, Options{})
	b := fingerprint(
		[]admissionregistrationv1.Variable{{Name: "a", Expression: "b1"}},
		nil, Options{})
	if a == b {
		t.Error("fingerprint collided across a name/expression boundary")
	}

	withOpts := fingerprint(nil, nil, Options{HasParams: true})
	if withOpts == fingerprint(nil, nil, Options{}) {
		t.Error("fingerprint ignored Options")
	}
}
