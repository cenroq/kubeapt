// Copyright by cenroq AG
// Contact: info@cenroq.com

package convert

import (
	"fmt"
	"regexp"

	"github.com/cenroq/kubeapt/v2/pkg/kyverno"
)

// KyvernoCELExtension names a function Kyverno adds to its CEL environment.
// The Kubernetes API server's environment does not declare it, so a converted
// ValidatingAdmissionPolicy that calls it fails type-checking at admission
// time.
type KyvernoCELExtension struct {
	// Name is the call as it appears in an expression, such as "resource.Get".
	Name string
	// Level is LevelError when the function is certainly absent upstream, and
	// LevelWarn when a cluster might have an equivalent enabled.
	Level Level
	// Hint is one lowercase clause suggesting what to do instead.
	Hint string
}

// KyvernoCELExtensions is the detection table, in report order.
//
// Detection is table-based rather than compile-based, and deliberately so. The
// obvious alternative - compile each expression against a
// ValidatingAdmissionPolicy-equivalent cel-go environment and treat any failure
// as a portability finding - needs the declarations in
// k8s.io/apiserver/pkg/cel/library (quantity, format, url, authorizer, sets,
// ip, cidr, semver, and more).
//
// The dependency objection this comment used to record is now obsolete on both
// counts. kubeapt does depend on k8s.io/apiserver: internal/cel builds its
// environment from it, so those declarations are available here for the asking.
// And the stated cost was wrong - importing pkg/cel/environment and
// pkg/admission/plugin/cel pulls in neither etcd nor gRPC, and measured at
// +2.9MB on the binary. (pkg/admission/plugin/policy/validating is the package
// that does pull the whole admission runtime, 1062 packages against
// plugin/cel's 477. Avoid that one.) internal/cel also no longer declares a
// "resource" variable, so its environment is no longer disqualified as an
// oracle on that ground either.
//
// The table still stands, for reasons that have nothing to do with
// dependencies. A compile failure is not the same thing as non-portability: a
// typo, a type error, or a variable Kyverno supplies under another name would
// all be reported as portability findings, and a false positive on valid input
// is worse than missing an exotic extension. The per-extension Hint below is
// also the actual value here, and "undeclared reference to 'resource'" cannot
// replace "fetch the data into a paramKind instead". Doing it properly would
// mean modelling Kyverno's environment and diffing the two, which relocates the
// hand-maintenance to a place with no upstream to track rather than removing
// it. So this table trades recall for precision on purpose.
//
// The better use of the dependency, if someone wants one, is the inverse:
// compile the ValidatingAdmissionPolicy that convert emits and refuse to output
// one that will not load on a cluster. That checks kubeapt's own output rather
// than classifying user input, so it has no false-positive problem.
var KyvernoCELExtensions = []KyvernoCELExtension{
	{Name: "resource.Get", Level: LevelError, Hint: "a ValidatingAdmissionPolicy can only see the request, so fetch the data into a paramKind instead"},
	{Name: "resource.List", Level: LevelError, Hint: "a ValidatingAdmissionPolicy can only see the request, so fetch the data into a paramKind instead"},
	{Name: "resource.Post", Level: LevelError, Hint: "a ValidatingAdmissionPolicy cannot call the api server"},
	{Name: "http.Get", Level: LevelError, Hint: "a ValidatingAdmissionPolicy cannot make network calls"},
	{Name: "http.Post", Level: LevelError, Hint: "a ValidatingAdmissionPolicy cannot make network calls"},
	{Name: "http.Client", Level: LevelError, Hint: "a ValidatingAdmissionPolicy cannot make network calls"},
	{Name: "globalContext.Get", Level: LevelError, Hint: "global context entries are a kyverno feature with no upstream equivalent"},
	{Name: "image.GetMetadata", Level: LevelError, Hint: "registry lookups are a kyverno feature with no upstream equivalent"},
	{Name: "image", Level: LevelError, Hint: "parse the image reference with string functions instead"},
	{Name: "isImage", Level: LevelError, Hint: "parse the image reference with string functions instead"},
	{Name: "parseServiceAccount", Level: LevelError, Hint: "match on request.userInfo.username instead"},
	{Name: "x509.decode", Level: LevelError, Hint: "certificate decoding has no upstream equivalent"},
	{Name: "json.unmarshal", Level: LevelError, Hint: "no upstream equivalent"},
	{Name: "yaml.parse", Level: LevelError, Hint: "no upstream equivalent"},
	{Name: "time.now", Level: LevelError, Hint: "an admission decision that depends on the clock is not reproducible upstream"},
	{Name: "time.truncate", Level: LevelError, Hint: "no upstream equivalent"},
	{Name: "time.toCron", Level: LevelError, Hint: "no upstream equivalent"},
	{Name: "md5", Level: LevelError, Hint: "no upstream equivalent"},
	{Name: "sha1", Level: LevelError, Hint: "no upstream equivalent"},
	{Name: "sha256", Level: LevelError, Hint: "no upstream equivalent"},
	{Name: "random", Level: LevelError, Hint: "an admission decision that depends on randomness is not reproducible upstream"},
	{Name: "listObjToMap", Level: LevelError, Hint: "rewrite with a CEL comprehension"},
	{Name: "math.round", Level: LevelWarn, Hint: "cel-go's math extension provides this, so some clusters may accept it"},
}

// extensionPatterns holds one compiled matcher per table entry, in table order.
var extensionPatterns = compileExtensionPatterns()

func compileExtensionPatterns() []*regexp.Regexp {
	out := make([]*regexp.Regexp, len(KyvernoCELExtensions))
	for i, extension := range KyvernoCELExtensions {
		// The leading guard keeps myhttp.Get and foo.image from matching, and
		// the trailing "(" keeps resource.GetOwner from matching resource.Get.
		out[i] = regexp.MustCompile(`(^|[^\w.])` + regexp.QuoteMeta(extension.Name) + `\s*\(`)
	}
	return out
}

// SpecCELFinding locates one Kyverno-only extension inside a policy spec.
type SpecCELFinding struct {
	// Field is the JSON path of the expression, such as
	// "spec.validations[0].expression".
	Field     string
	Extension KyvernoCELExtension
}

// DetectKyvernoCELExtensions returns the Kyverno-only extensions expr calls, in
// table order with no duplicates. String literals are ignored, so a message
// mentioning http.Get does not register as a call.
func DetectKyvernoCELExtensions(expr string) []KyvernoCELExtension {
	if expr == "" {
		return nil
	}
	code := stripCELStringLiterals(expr)

	var found []KyvernoCELExtension
	for i, pattern := range extensionPatterns {
		if pattern.MatchString(code) {
			found = append(found, KyvernoCELExtensions[i])
		}
	}
	return found
}

// DetectInSpec scans every CEL expression in a Kyverno spec and returns its
// findings in document order.
func DetectInSpec(spec kyverno.ValidatingPolicySpec) []SpecCELFinding {
	var findings []SpecCELFinding

	collect := func(field, expr string) {
		for _, extension := range DetectKyvernoCELExtensions(expr) {
			findings = append(findings, SpecCELFinding{Field: field, Extension: extension})
		}
	}

	for i, condition := range spec.MatchConditions {
		collect(fmt.Sprintf("spec.matchConditions[%d].expression", i), condition.Expression)
	}
	for i, variable := range spec.Variables {
		collect(fmt.Sprintf("spec.variables[%d].expression", i), variable.Expression)
	}
	for i, validation := range spec.Validations {
		collect(fmt.Sprintf("spec.validations[%d].expression", i), validation.Expression)
		collect(fmt.Sprintf("spec.validations[%d].messageExpression", i), validation.MessageExpression)
	}
	for i, annotation := range spec.AuditAnnotations {
		collect(fmt.Sprintf("spec.auditAnnotations[%d].valueExpression", i), annotation.ValueExpression)
	}

	return findings
}

// stripCELStringLiterals blanks the contents of every string literal, keeping
// the input's length so nothing outside a literal shifts. It handles single and
// double quotes, their triple-quoted forms, and the r-prefixed raw variants, in
// which a backslash is not an escape.
func stripCELStringLiterals(expr string) string {
	out := []byte(expr)
	i := 0

	for i < len(out) {
		raw := false
		if out[i] == 'r' || out[i] == 'R' {
			if next := i + 1; next < len(out) && (out[next] == '\'' || out[next] == '"') {
				raw = true
				i = next
			}
		}

		quote := out[i]
		if quote != '\'' && quote != '"' {
			i++
			continue
		}

		width := 1
		if hasRunAt(out, i, quote, 3) {
			width = 3
		}

		i += width
		for i < len(out) {
			if !raw && out[i] == '\\' && i+1 < len(out) {
				out[i] = ' '
				out[i+1] = ' '
				i += 2
				continue
			}
			if hasRunAt(out, i, quote, width) {
				i += width
				break
			}
			out[i] = ' '
			i++
		}
	}

	return string(out)
}

// hasRunAt reports whether out has n consecutive copies of c starting at i.
func hasRunAt(out []byte, i int, c byte, n int) bool {
	if i+n > len(out) {
		return false
	}
	for offset := 0; offset < n; offset++ {
		if out[i+offset] != c {
			return false
		}
	}
	return true
}
