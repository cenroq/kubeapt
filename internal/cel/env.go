// Copyright by cenroq AG
// Contact: info@cenroq.com

package cel

import (
	"strings"
	"sync"

	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	"k8s.io/apimachinery/pkg/util/version"
	plugincel "k8s.io/apiserver/pkg/admission/plugin/cel"
	"k8s.io/apiserver/pkg/cel/environment"
)

// compatibilityMinor pins the Kubernetes minor release whose CEL feature set
// kubeapt models. It tracks the k8s.io/* versions in go.mod and should be
// bumped with them.
//
// StoredExpressions (the mode every compile below uses) is compatible with all
// known versions regardless, so this figure decides very little in practice.
// It is written down so the version kubeapt claims to model is a stated fact
// rather than an accident of whichever module version last resolved.
const compatibilityMinor = 36

var (
	baseEnvOnce sync.Once
	baseEnvSet  *environment.EnvSet
)

// baseEnv returns the API server's own CEL environment for admission policies.
//
// This package used to build the environment by hand, and it failed the only
// way a hand-written copy of someone else's list can: it drifted. Options were
// added one bug report at a time - ext.Strings in the first commit,
// ext.TwoVarComprehensions later - so everything nobody had filed a bug about
// was simply absent. Optional types, quantity, ip, cidr, url, authz, format,
// semver and sets were all missing, which meant kubeapt rejected expressions
// that every real cluster accepts. Deferring to upstream is the only version of
// this that stays correct as Kubernetes keeps adding functions.
//
// MustBaseEnvSet memoises internally; the sync.Once only avoids the repeated
// lookup, and makes the sharing explicit for the concurrent callers below.
func baseEnv() *environment.EnvSet {
	baseEnvOnce.Do(func() {
		baseEnvSet = environment.MustBaseEnvSet(version.MajorMinor(1, compatibilityMinor))
	})
	return baseEnvSet
}

// Options selects the optional variables a policy's expressions may reference.
// They mirror upstream's OptionalVariableDeclarations: declaring a variable a
// policy does not use is harmless, but a policy that references one which was
// not declared fails to compile.
type Options struct {
	HasParams     bool
	HasAuthorizer bool
}

func (o Options) declarations() plugincel.OptionalVariableDeclarations {
	return plugincel.OptionalVariableDeclarations{
		HasParams:     o.HasParams,
		HasAuthorizer: o.HasAuthorizer,
	}
}

// evaluatorCache memoises compiled policies.
//
// Compiling is expensive out of proportion to how it reads: every
// CompositedCompiler builds eight CEL environments, one per combination of the
// optional variable declarations. validate evaluates each policy against every
// selected resource in every selected namespace, so without this the compile
// cost is multiplied by the size of the cluster rather than paid once per
// policy.
//
// Entries are read concurrently from the worker pools in internal/cli/validate
// and internal/kubernetes/psa_compliance. A compiled Evaluator is safe to share:
// cel-go programs are immutable once built, and ForInput derives a fresh
// composition context per call rather than mutating the evaluator.
var evaluatorCache sync.Map // fingerprint -> *Evaluator

// fingerprint identifies a policy by the expressions it will compile to.
//
// The separator is NUL because it cannot appear in a CEL expression or a
// variable name, so no combination of inputs can forge a boundary and collide
// with a different policy. Hashing would be shorter but would trade an
// impossible collision for an improbable one, at no real saving.
func fingerprint(variables []admissionregistrationv1.Variable, validations []admissionregistrationv1.Validation, opts Options) string {
	var b strings.Builder
	if opts.HasParams {
		b.WriteString("p")
	}
	if opts.HasAuthorizer {
		b.WriteString("a")
	}
	for i := range variables {
		b.WriteByte(0)
		b.WriteString(variables[i].Name)
		b.WriteByte(0)
		b.WriteString(variables[i].Expression)
	}
	b.WriteByte(0)
	b.WriteByte(0)
	for i := range validations {
		b.WriteByte(0)
		b.WriteString(validations[i].Expression)
	}
	return b.String()
}
