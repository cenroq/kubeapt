// Copyright by cenroq AG
// Contact: info@cenroq.com

package kubernetes

import (
	"context"
	"fmt"

	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"

	"github.com/cenroq/kubeapt/v2/internal/cel"
)

type ValidationViolation struct {
	Message string
	Path    string
	Actions []string
}

type ValidationResult struct {
	Compliant  bool
	Violations []ValidationViolation
}

func EvaluateValidations(policy *admissionregistrationv1.ValidatingAdmissionPolicy, binding *admissionregistrationv1.ValidatingAdmissionPolicyBinding, resource map[string]interface{}, namespace string, namespaceLabels map[string]string) (ValidationResult, error) {
	resultData := ValidationResult{Compliant: true}
	normalizeResourceForCEL(resource)

	if len(policy.Spec.Validations) == 0 {
		return resultData, nil
	}

	// authorizer is always declared even though kubeapt binds no Authorizer
	// here. Declaring it costs nothing and lets a policy that mentions
	// authorizer compile; leaving it out would fail the whole policy at compile
	// time over an expression that may never be reached.
	evaluator, err := cel.Compile(policy.Spec.Variables, policy.Spec.Validations, cel.Options{
		HasParams:     policy.Spec.ParamKind != nil,
		HasAuthorizer: true,
	})
	if err != nil {
		return resultData, fmt.Errorf("cel compilation failed for policy %s: %w", policy.Name, err)
	}

	results, err := evaluator.Evaluate(context.TODO(), cel.Input{
		Object:          resource,
		Namespace:       namespace,
		NamespaceLabels: namespaceLabels,
	})
	if err != nil {
		return resultData, fmt.Errorf("cel evaluation failed for policy %s binding %s: %w", policy.Name, binding.Name, err)
	}

	for idx, result := range results {
		if result.Err != nil {
			return resultData, fmt.Errorf("cel evaluation failed for policy %s binding %s validation %d: %w", policy.Name, binding.Name, idx, result.Err)
		}
		if result.Allowed {
			continue
		}

		message := policy.Spec.Validations[idx].Message
		if message == "" {
			message = policy.Spec.Validations[idx].Expression
		}

		resultData.Compliant = false
		actions := binding.Spec.ValidationActions
		if len(actions) == 0 {
			actions = []admissionregistrationv1.ValidationAction{admissionregistrationv1.Deny}
		}
		resultData.Violations = append(resultData.Violations, ValidationViolation{
			Message: message,
			Actions: actionsToStrings(actions),
		})
	}

	return resultData, nil
}

func actionsToStrings(actions []admissionregistrationv1.ValidationAction) []string {
	result := make([]string, len(actions))
	for i, action := range actions {
		result[i] = string(action)
	}
	return result
}
