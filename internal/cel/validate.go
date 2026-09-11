// Copyright by cenroq AG
// Contact: info@cenroq.com

// Package cel evaluates ValidatingAdmissionPolicy expressions the way the
// Kubernetes API server evaluates them.
//
// Everything here defers to k8s.io/apiserver rather than reimplementing it. The
// environment, the variable declarations and their types, the lazy composition
// of spec.variables, and the runtime cost budget all come from the same code a
// cluster runs, so an expression that compiles here compiles there and an
// expression that fails here would have failed there too. That correspondence
// is the whole point: kubeapt's claim is that it reports what the cluster would
// do, and a private approximation of the API server's CEL environment cannot
// support that claim.
package cel

import (
	"context"
	"errors"
	"fmt"

	celgo "github.com/google/cel-go/cel"

	admissionv1 "k8s.io/api/admission/v1"
	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	authenticationv1 "k8s.io/api/authentication/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apiserver/pkg/admission"
	plugincel "k8s.io/apiserver/pkg/admission/plugin/cel"
	celconfig "k8s.io/apiserver/pkg/apis/cel"
	"k8s.io/apiserver/pkg/authentication/user"
	"k8s.io/apiserver/pkg/authorization/authorizer"
	"k8s.io/apiserver/pkg/cel/environment"
)

// ErrNonBooleanResult is returned when a validation expression yields something
// other than a boolean. Compilation already requires a bool return type, so
// this only fires if evaluation produces an unknown or an error value.
var ErrNonBooleanResult = errors.New("expression did not return a boolean")

// evaluatingUser is the identity kubeapt presents to authorizer expressions and
// in request.userInfo.
//
// kubeapt evaluates policies offline, so there is no real requester to report.
// A named synthetic user is better than an empty one: a policy that branches on
// request.userInfo gets a stable, obviously-not-real answer rather than a blank
// that might look like a legitimate anonymous request.
const evaluatingUser = "system:serviceaccount:kubeapt:kubeapt"

// namedExpression and boolExpression are kubeapt's copies of the accessor types
// in k8s.io/apiserver/pkg/admission/plugin/policy/validating.
//
// Copying two four-line structs is worth it here. That package transitively
// pulls in the whole admission-plugin runtime - 1062 packages against
// plugin/cel's 477, including gRPC and OpenTelemetry - and importing it purely
// for these declarations added 36MB to the binary. The interfaces they satisfy
// (plugincel.NamedExpressionAccessor and plugincel.ExpressionAccessor) are two
// and three methods respectively and are what the compiler actually consumes,
// so nothing about fidelity depends on the structs themselves coming from
// upstream. The compile-time assertions below fail if that stops being true.
type namedExpression struct {
	name       string
	expression string
}

var _ plugincel.NamedExpressionAccessor = &namedExpression{}

func (e *namedExpression) GetName() string       { return e.name }
func (e *namedExpression) GetExpression() string { return e.expression }
func (e *namedExpression) ReturnTypes() []*celgo.Type {
	return []*celgo.Type{celgo.AnyType, celgo.DynType}
}

type boolExpression struct {
	expression string
}

var _ plugincel.ExpressionAccessor = &boolExpression{}

func (e *boolExpression) GetExpression() string      { return e.expression }
func (e *boolExpression) ReturnTypes() []*celgo.Type { return []*celgo.Type{celgo.BoolType} }

// Evaluator holds the compiled variables and validations of one policy.
//
// It is safe for concurrent use and is cached across resources; see
// evaluatorCache.
type Evaluator struct {
	conditions plugincel.ConditionEvaluator
	count      int
}

// Input is one resource to evaluate a policy against.
type Input struct {
	// Object is the resource under test, as decoded YAML.
	Object map[string]any
	// Namespace is the namespace to report and to build namespaceObject from.
	// Empty means cluster-scoped, and namespaceObject evaluates to null.
	Namespace string
	// NamespaceLabels populates namespaceObject.metadata.labels, which is what
	// Pod Security style policies read.
	NamespaceLabels map[string]string
	// Params binds spec.paramKind for policies that declare one. Requires
	// Options.HasParams at compile time.
	Params runtime.Object
	// Authorizer answers authorizer.* expressions. Requires
	// Options.HasAuthorizer at compile time. A nil Authorizer with
	// HasAuthorizer set compiles, but the expressions error at evaluation
	// rather than silently returning a permissive answer.
	Authorizer authorizer.Authorizer
}

// Result is the outcome of a single validation expression.
type Result struct {
	// Allowed reports whether the expression held. Only meaningful when Err is
	// nil.
	Allowed bool
	// Err is the per-expression failure. Upstream evaluates each validation
	// independently, so one broken expression does not suppress the verdicts of
	// the others; a caller that treats any error as fatal throws that away.
	Err error
}

// Compile prepares a policy's variables and validations for evaluation.
//
// Compiled policies are cached by expression content, so calling this once per
// resource is cheap and callers do not have to manage the lifetime themselves.
func Compile(variables []admissionregistrationv1.Variable, validations []admissionregistrationv1.Validation, opts Options) (*Evaluator, error) {
	key := fingerprint(variables, validations, opts)
	if cached, ok := evaluatorCache.Load(key); ok {
		return cached.(*Evaluator), nil
	}

	evaluator, err := compile(variables, validations, opts)
	if err != nil {
		return nil, err
	}
	actual, _ := evaluatorCache.LoadOrStore(key, evaluator)
	return actual.(*Evaluator), nil
}

func compile(variables []admissionregistrationv1.Variable, validations []admissionregistrationv1.Validation, opts Options) (*Evaluator, error) {
	compiler, err := plugincel.NewCompositedCompiler(baseEnv())
	if err != nil {
		return nil, fmt.Errorf("build CEL compiler: %w", err)
	}
	declarations := opts.declarations()

	named := make([]plugincel.NamedExpressionAccessor, 0, len(variables))
	for i := range variables {
		named = append(named, &namedExpression{
			name:       variables[i].Name,
			expression: variables[i].Expression,
		})
	}
	// Variables compile into the compiler's composition state rather than into
	// the returned evaluator, and a variable that fails to compile surfaces
	// when an expression reads it. That is upstream's behaviour and it is the
	// better one: a broken variable should fail the validations that use it,
	// not every validation in the policy.
	compiler.CompileAndStoreVariables(named, declarations, environment.StoredExpressions)

	expressions := make([]plugincel.ExpressionAccessor, 0, len(validations))
	for i := range validations {
		expressions = append(expressions, &boolExpression{expression: validations[i].Expression})
	}
	conditions := compiler.CompileCondition(expressions, declarations, environment.StoredExpressions)
	if errs := conditions.CompilationErrors(); len(errs) > 0 {
		return nil, errors.Join(errs...)
	}
	return &Evaluator{conditions: conditions, count: len(expressions)}, nil
}

// Evaluate runs every compiled validation against one resource and returns a
// Result per validation, in declaration order.
//
// The returned error covers failures to evaluate the policy at all - a
// malformed object, a broken activation. A failure in a single expression is
// reported in that expression's Result.Err instead.
func (e *Evaluator) Evaluate(ctx context.Context, in Input) ([]Result, error) {
	if e.count == 0 {
		return nil, nil
	}

	object := &unstructured.Unstructured{Object: in.Object}
	gvk := object.GroupVersionKind()
	gvr, _ := meta.UnsafeGuessKindToResource(gvk)
	namespace := in.Namespace
	if namespace == "" {
		namespace = object.GetNamespace()
	}

	userInfo := &user.DefaultInfo{
		Name:   evaluatingUser,
		Groups: []string{user.AllAuthenticated},
	}
	attributes := admission.NewAttributesRecord(
		object, nil, gvk, namespace, object.GetName(), gvr, "",
		admission.Create, nil, true, userInfo,
	)
	versioned := &admission.VersionedAttributes{
		Attributes:      attributes,
		VersionedObject: object,
		VersionedKind:   gvk,
	}

	results, _, err := e.conditions.ForInput(
		ctx,
		versioned,
		admissionRequest(gvk, gvr, object.GetName(), namespace),
		plugincel.OptionalVariableBindings{
			VersionedParams: in.Params,
			Authorizer:      in.Authorizer,
		},
		namespaceObject(namespace, in.NamespaceLabels),
		celconfig.RuntimeCELCostBudget,
	)
	if err != nil {
		return nil, err
	}

	out := make([]Result, len(results))
	for i, result := range results {
		switch {
		case result.Error != nil:
			out[i] = Result{Err: result.Error}
		case result.EvalResult == nil:
			out[i] = Result{Err: ErrNonBooleanResult}
		default:
			held, ok := result.EvalResult.Value().(bool)
			if !ok {
				out[i] = Result{Err: ErrNonBooleanResult}
				continue
			}
			out[i] = Result{Allowed: held}
		}
	}
	return out, nil
}

// admissionRequest synthesises the request a policy sees in `request`.
//
// kubeapt evaluates offline, so there is no observed admission request to pass
// through; it is constructed from the object under test. CREATE with dryRun set
// is the honest description of what kubeapt is asking - "would this object be
// admitted if someone created it now" - and it matches the operation most
// policies scope themselves to.
func admissionRequest(gvk schema.GroupVersionKind, gvr schema.GroupVersionResource, name, namespace string) *admissionv1.AdmissionRequest {
	kind := metav1.GroupVersionKind{Group: gvk.Group, Version: gvk.Version, Kind: gvk.Kind}
	resource := metav1.GroupVersionResource{Group: gvr.Group, Version: gvr.Version, Resource: gvr.Resource}
	dryRun := true
	return &admissionv1.AdmissionRequest{
		UID:             types.UID("kubeapt"),
		Kind:            kind,
		Resource:        resource,
		RequestKind:     &kind,
		RequestResource: &resource,
		Name:            name,
		Namespace:       namespace,
		Operation:       admissionv1.Create,
		UserInfo: authenticationv1.UserInfo{
			Username: evaluatingUser,
			Groups:   []string{user.AllAuthenticated},
		},
		DryRun: &dryRun,
	}
}

// namespaceObject builds the typed Namespace behind `namespaceObject`. A
// cluster-scoped resource has none, and upstream expects nil rather than an
// empty object in that case.
func namespaceObject(name string, labels map[string]string) *corev1.Namespace {
	if name == "" {
		return nil
	}
	return &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{Name: name, Labels: labels},
	}
}

// Check evaluates a single boolean expression against one object.
//
// It runs the full policy path rather than a simplified one, so there is only
// ever one CEL environment in this package and a convenience helper cannot
// quietly disagree with the real evaluator.
func Check(ctx context.Context, expr string, object map[string]any) (bool, error) {
	evaluator, err := Compile(nil, []admissionregistrationv1.Validation{{Expression: expr}}, Options{})
	if err != nil {
		return false, err
	}
	results, err := evaluator.Evaluate(ctx, Input{Object: object})
	if err != nil {
		return false, err
	}
	if len(results) != 1 {
		return false, fmt.Errorf("expected 1 result, got %d", len(results))
	}
	if results[0].Err != nil {
		return false, results[0].Err
	}
	return results[0].Allowed, nil
}
