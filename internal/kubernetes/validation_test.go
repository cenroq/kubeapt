package kubernetes

import (
    "testing"

    admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
    metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestEvaluateValidations(t *testing.T) {
    policy := &admissionregistrationv1.ValidatingAdmissionPolicy{
        ObjectMeta: metav1.ObjectMeta{Name: "policy1"},
        Spec: admissionregistrationv1.ValidatingAdmissionPolicySpec{
            Variables: []admissionregistrationv1.Variable{{
                Name:       "foo",
                Expression: "'bar'",
            }},
            Validations: []admissionregistrationv1.Validation{{
                Expression: "variables.foo == 'bar'",
            }, {
                Expression: "object.metadata.name == 'ok'",
            }},
        },
    }

    binding := &admissionregistrationv1.ValidatingAdmissionPolicyBinding{
        ObjectMeta: metav1.ObjectMeta{Name: "binding1"},
        Spec:       admissionregistrationv1.ValidatingAdmissionPolicyBindingSpec{PolicyName: "policy1"},
    }

    resourceOK := map[string]interface{}{
        "apiVersion": "v1",
        "kind":       "Pod",
        "metadata": map[string]interface{}{
            "name":      "ok",
            "namespace": "ns1",
        },
    }

    result, err := EvaluateValidations(policy, binding, resourceOK, "ns1", nil)
    if err != nil {
        t.Fatalf("unexpected error: %v", err)
    }
    if !result.Compliant || len(result.Violations) != 0 {
        t.Fatalf("expected compliant result, got %+v", result)
    }

    resourceBad := map[string]interface{}{
        "apiVersion": "v1",
        "kind":       "Pod",
        "metadata": map[string]interface{}{
            "name":      "bad",
            "namespace": "ns1",
        },
    }
    result, err = EvaluateValidations(policy, binding, resourceBad, "ns1", nil)
    if err != nil {
        t.Fatalf("unexpected error: %v", err)
    }
    if result.Compliant || len(result.Violations) != 1 {
        t.Fatalf("expected non-compliant with one violation, got %+v", result)
    }
    if result.Violations[0].Message == "" {
        t.Fatalf("expected violation message to be set")
    }
    if len(result.Violations[0].Actions) != 1 || result.Violations[0].Actions[0] != string(admissionregistrationv1.Deny) {
        t.Fatalf("expected default deny action, got %v", result.Violations[0].Actions)
    }
}

// namespaceObject is now a typed corev1.Namespace built inside internal/cel
// rather than a hand-assembled map, so this asserts the property that actually
// matters to a policy: the namespace labels reach the expression.
func TestEvaluateValidationsExposesNamespaceLabels(t *testing.T) {
    policy := &admissionregistrationv1.ValidatingAdmissionPolicy{
        ObjectMeta: metav1.ObjectMeta{Name: "ns-labels"},
        Spec: admissionregistrationv1.ValidatingAdmissionPolicySpec{
            Validations: []admissionregistrationv1.Validation{
                {Expression: "namespaceObject.metadata.labels['env'] == 'prod'"},
            },
        },
    }
    binding := &admissionregistrationv1.ValidatingAdmissionPolicyBinding{
        ObjectMeta: metav1.ObjectMeta{Name: "ns-labels-binding"},
    }
    resource := map[string]interface{}{
        "apiVersion": "v1",
        "kind":       "Pod",
        "metadata":   map[string]interface{}{"name": "demo", "namespace": "ns1"},
    }

    result, err := EvaluateValidations(policy, binding, resource, "ns1", map[string]string{"env": "prod"})
    if err != nil {
        t.Fatalf("unexpected error: %v", err)
    }
    if !result.Compliant {
        t.Fatalf("expected the namespace label to be visible, got violations %v", result.Violations)
    }
}

// The reported bug, through the full evaluation path: optional syntax used to
// abort the whole run rather than yielding a verdict.
func TestEvaluateValidationsSupportsOptionalSyntax(t *testing.T) {
    policy := &admissionregistrationv1.ValidatingAdmissionPolicy{
        ObjectMeta: metav1.ObjectMeta{Name: "apiservice-tls"},
        Spec: admissionregistrationv1.ValidatingAdmissionPolicySpec{
            Validations: []admissionregistrationv1.Validation{
                {
                    Expression: "object.spec.?insecureSkipTLSVerify.orValue(false) != true",
                    Message:    "APIService must not skip TLS verification",
                },
            },
        },
    }
    binding := &admissionregistrationv1.ValidatingAdmissionPolicyBinding{
        ObjectMeta: metav1.ObjectMeta{Name: "apiservice-tls--implicit"},
    }
    apiService := func(insecure bool) map[string]interface{} {
        return map[string]interface{}{
            "apiVersion": "apiregistration.k8s.io/v1",
            "kind":       "APIService",
            "metadata":   map[string]interface{}{"name": "v1beta1.metrics.k8s.io"},
            "spec":       map[string]interface{}{"insecureSkipTLSVerify": insecure},
        }
    }

    result, err := EvaluateValidations(policy, binding, apiService(false), "", nil)
    if err != nil {
        t.Fatalf("unexpected error: %v", err)
    }
    if !result.Compliant {
        t.Fatalf("expected compliance, got %v", result.Violations)
    }

    result, err = EvaluateValidations(policy, binding, apiService(true), "", nil)
    if err != nil {
        t.Fatalf("unexpected error: %v", err)
    }
    if result.Compliant {
        t.Fatal("expected insecureSkipTLSVerify: true to violate the policy")
    }
    if result.Violations[0].Message != "APIService must not skip TLS verification" {
        t.Fatalf("unexpected message: %q", result.Violations[0].Message)
    }
}
