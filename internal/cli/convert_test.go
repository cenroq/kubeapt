// Copyright by cenroq AG
// Contact: info@cenroq.com

package cli

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spf13/cobra"

	"github.com/cenroq/kubeapt/v2/pkg/kyverno"
)

const (
	convertFixtureVAPYAML = `apiVersion: admissionregistration.k8s.io/v1
kind: ValidatingAdmissionPolicy
metadata:
  name: no-latest-tag
  annotations:
    security.cenroq.io/severity: Critical
spec:
  matchConstraints:
    resourceRules:
      - apiGroups: [""]
        apiVersions: ["v1"]
        operations: ["CREATE"]
        resources: ["pods"]
  validations:
    - expression: "!object.spec.containers.exists(c, c.image.endsWith(':latest'))"
      message: containers must not use the latest tag
`

	convertFixtureBindingYAML = `apiVersion: admissionregistration.k8s.io/v1
kind: ValidatingAdmissionPolicyBinding
metadata:
  name: no-latest-tag-prod
spec:
  policyName: no-latest-tag
  validationActions: [Deny]
  matchResources:
    namespaceSelector:
      matchLabels:
        env: prod
`

	convertFixtureKyvernoYAML = `apiVersion: policies.kyverno.io/v1
kind: ValidatingPolicy
metadata:
  name: check-labels
spec:
  validationActions: [Audit]
  matchConstraints:
    resourceRules:
      - apiGroups: [""]
        apiVersions: ["v1"]
        operations: ["CREATE"]
        resources: ["pods"]
  validations:
    - expression: "'environment' in object.metadata.labels"
      message: label environment is required
`

	convertFixtureParamKindYAML = `apiVersion: admissionregistration.k8s.io/v1
kind: ValidatingAdmissionPolicy
metadata:
  name: parameterized
spec:
  paramKind:
    apiVersion: rules.example.com/v1
    kind: ReplicaLimit
  matchConstraints:
    resourceRules:
      - apiGroups: ["apps"]
        apiVersions: ["v1"]
        operations: ["CREATE"]
        resources: ["deployments"]
  validations:
    - expression: "object.spec.replicas <= params.maxReplicas"
`

	convertFixtureLegacyYAML = `apiVersion: kyverno.io/v1
kind: ClusterPolicy
metadata:
  name: require-labels
spec:
  rules:
    - name: check-team
      match:
        any:
          - resources:
              kinds: [Pod]
`
)

// writeConvertFixture writes content into dir and returns its full path.
func writeConvertFixture(t *testing.T, dir, name, content string) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
	return path
}

// runConvertCmd executes the convert command with args, returning stdout and
// stderr. It goes through Execute so PreRunE wires the logging writers, which
// is required because logging.Init is sync.Once guarded and its writers are
// package globals: calling runConvert directly would leave them pointing at
// whatever the previous test set.
func runConvertCmd(t *testing.T, args ...string) (stdout, stderr string, err error) {
	t.Helper()
	var out, errOut bytes.Buffer
	cmd := ConvertCmd()
	cmd.SetOut(&out)
	cmd.SetErr(&errOut)
	cmd.SetArgs(args)
	cmd.SilenceUsage = true
	cmd.SilenceErrors = true
	err = cmd.Execute()
	return out.String(), errOut.String(), err
}

func TestConvertFlagValidation(t *testing.T) {
	dir := t.TempDir()
	writeConvertFixture(t, dir, "policies.yaml", convertFixtureVAPYAML)

	cases := []struct {
		name string
		args []string
		want string
	}{
		{name: "missing target", args: []string{"-p", dir}, want: "--to is required"},
		{name: "unknown target", args: []string{"--to", "sideways", "-p", dir}, want: "invalid target sideways"},
		{name: "no source", args: []string{"--to", "kyverno"}, want: "specify a source"},
		{name: "bad format", args: []string{"--to", "kyverno", "-p", dir, "-f", "xml"}, want: "invalid format xml"},
		{name: "bad kyverno version", args: []string{"--to", "kyverno", "-p", dir, "--kyverno-api-version", "v2"}, want: "invalid kyverno api version v2"},
		{name: "bad action", args: []string{"--to", "kyverno", "-p", dir, "--validation-actions", "Deny,Bogus"}, want: "invalid validation action Bogus"},
		{name: "empty actions", args: []string{"--to", "kyverno", "-p", dir, "--validation-actions", " , "}, want: "requires at least one of"},
		{name: "bundle with policies", args: []string{"--to", "kyverno", "--bundle", "b", "-p", dir}, want: "--bundle cannot be combined"},
		{name: "bundle version alone", args: []string{"--to", "kyverno", "-p", dir, "--bundle-version", "1.0.0"}, want: "--bundle-version requires --bundle"},
		{name: "policy name with policies", args: []string{"--to", "kyverno", "-P", "x", "-p", dir}, want: "--policy-name cannot be combined with --policies"},
		{name: "policy name with bindings", args: []string{"--to", "kyverno", "-P", "x", "-b", dir}, want: "--policy-name cannot be combined with --bindings"},
		{name: "cluster with policies", args: []string{"--to", "kyverno", "--cluster", "-p", dir}, want: "--cluster cannot be combined"},
		{name: "bindings with vap target", args: []string{"--to", "vap", "-p", dir, "-b", dir}, want: "--bindings is only used with --to kyverno"},
		{name: "cluster with vap target", args: []string{"--to", "vap", "--cluster"}, want: "--cluster reads ValidatingAdmissionPolicies"},
		{name: "namespace with vap target", args: []string{"--to", "vap", "-p", dir, "-n", "prod"}, want: "--namespace is only used with --to kyverno"},
		{name: "kyverno version with vap target", args: []string{"--to", "vap", "-p", dir, "--kyverno-api-version", "v1alpha1"}, want: "--kyverno-api-version is only used with --to kyverno"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, _, err := runConvertCmd(t, tc.args...)
			if err == nil {
				t.Fatalf("expected an error containing %q", tc.want)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("got error %q, want it to contain %q", err.Error(), tc.want)
			}
		})
	}
}

func TestConvertToKyvernoWritesParsableManifests(t *testing.T) {
	dir := t.TempDir()
	writeConvertFixture(t, dir, "policies.yaml", convertFixtureVAPYAML)
	writeConvertFixture(t, dir, "bindings.yaml", convertFixtureBindingYAML)

	stdout, _, err := runConvertCmd(t, "--to", "kyverno", "-p", dir, "-b", dir)
	if err != nil {
		t.Fatalf("convert: %v", err)
	}

	policies, err := kyverno.DecodeValidatingPolicies(strings.NewReader(stdout))
	if err != nil {
		t.Fatalf("stdout is not a valid kyverno stream: %v\n%s", err, stdout)
	}
	if len(policies) != 1 {
		t.Fatalf("got %d policies, want 1:\n%s", len(policies), stdout)
	}
	if policies[0].Name != "no-latest-tag" {
		t.Errorf("got name %s, want no-latest-tag", policies[0].Name)
	}
	if len(policies[0].Spec.ValidationActions) != 1 || string(policies[0].Spec.ValidationActions[0]) != "Deny" {
		t.Errorf("got validationActions %v, want [Deny]", policies[0].Spec.ValidationActions)
	}
	if policies[0].Spec.MatchConstraints.NamespaceSelector == nil {
		t.Errorf("the binding's namespaceSelector was not folded in:\n%s", stdout)
	}
	if strings.Contains(stdout, "status:") || strings.Contains(stdout, "creationTimestamp:") {
		t.Errorf("output carries placeholder fields:\n%s", stdout)
	}
}

func TestConvertToVAPEmitsAPolicyAndBinding(t *testing.T) {
	dir := t.TempDir()
	writeConvertFixture(t, dir, "kyverno.yaml", convertFixtureKyvernoYAML)

	stdout, _, err := runConvertCmd(t, "--to", "vap", "-p", dir)
	if err != nil {
		t.Fatalf("convert: %v", err)
	}

	if !strings.Contains(stdout, "kind: ValidatingAdmissionPolicy\n") {
		t.Errorf("no policy in output:\n%s", stdout)
	}
	if !strings.Contains(stdout, "kind: ValidatingAdmissionPolicyBinding") {
		t.Errorf("no binding in output:\n%s", stdout)
	}
	if !strings.Contains(stdout, "name: check-labels-binding") {
		t.Errorf("binding is not named after the policy:\n%s", stdout)
	}
	if !strings.Contains(stdout, "- Audit") {
		t.Errorf("validationActions did not move to the binding:\n%s", stdout)
	}

	// The output must load back through the loaders the rest of the CLI uses.
	path := writeConvertFixture(t, t.TempDir(), "out.yaml", stdout)
	policies, bindings, err := loadVAPSource(&cobra.Command{}, convertRequest{policyPath: path})
	if err != nil {
		t.Fatalf("output does not load as ValidatingAdmissionPolicies: %v", err)
	}
	if len(policies) != 1 || len(bindings) != 1 {
		t.Errorf("got %d policies and %d bindings, want 1 and 1", len(policies), len(bindings))
	}
	if bindings[0].Spec.PolicyName != policies[0].Name {
		t.Errorf("binding points at %s but the policy is %s", bindings[0].Spec.PolicyName, policies[0].Name)
	}
}

func TestConvertSeparatesDocumentsWithOneMarker(t *testing.T) {
	dir := t.TempDir()
	writeConvertFixture(t, dir, "kyverno.yaml", convertFixtureKyvernoYAML)

	stdout, _, err := runConvertCmd(t, "--to", "vap", "-p", dir)
	if err != nil {
		t.Fatalf("convert: %v", err)
	}
	if got := strings.Count(stdout, "\n---\n"); got != 1 {
		t.Errorf("got %d document separators, want 1:\n%s", got, stdout)
	}
	if strings.HasPrefix(stdout, "---") {
		t.Errorf("the first document must not be preceded by a separator:\n%s", stdout)
	}
}

func TestConvertOutputToFile(t *testing.T) {
	dir := t.TempDir()
	writeConvertFixture(t, dir, "policies.yaml", convertFixtureVAPYAML)
	target := filepath.Join(t.TempDir(), "converted.yaml")

	stdout, _, err := runConvertCmd(t, "--to", "kyverno", "-p", dir, "--output", target)
	if err != nil {
		t.Fatalf("convert: %v", err)
	}
	if strings.TrimSpace(stdout) != "" {
		t.Errorf("stdout should be empty when --output names a file, got:\n%s", stdout)
	}

	data, err := os.ReadFile(target)
	if err != nil {
		t.Fatalf("read output: %v", err)
	}
	if !strings.Contains(string(data), "kind: ValidatingPolicy") {
		t.Errorf("output file does not hold the manifest:\n%s", data)
	}
}

func TestConvertOutputToDirectory(t *testing.T) {
	source := t.TempDir()
	writeConvertFixture(t, source, "kyverno.yaml", convertFixtureKyvernoYAML)
	target := t.TempDir()

	if _, _, err := runConvertCmd(t, "--to", "vap", "-p", source, "--output", target); err != nil {
		t.Fatalf("convert: %v", err)
	}

	policies, err := os.ReadFile(filepath.Join(target, "policies.yaml"))
	if err != nil {
		t.Fatalf("read policies.yaml: %v", err)
	}
	if !strings.Contains(string(policies), "kind: ValidatingAdmissionPolicy") {
		t.Errorf("policies.yaml is wrong:\n%s", policies)
	}
	if strings.Contains(string(policies), "kind: ValidatingAdmissionPolicyBinding") {
		t.Errorf("bindings leaked into policies.yaml:\n%s", policies)
	}

	bindings, err := os.ReadFile(filepath.Join(target, "bindings.yaml"))
	if err != nil {
		t.Fatalf("read bindings.yaml: %v", err)
	}
	if !strings.Contains(string(bindings), "kind: ValidatingAdmissionPolicyBinding") {
		t.Errorf("bindings.yaml is wrong:\n%s", bindings)
	}
}

func TestConvertOutputToDirectoryOmitsBindingsForKyverno(t *testing.T) {
	source := t.TempDir()
	writeConvertFixture(t, source, "policies.yaml", convertFixtureVAPYAML)
	target := t.TempDir()

	if _, _, err := runConvertCmd(t, "--to", "kyverno", "-p", source, "--output", target); err != nil {
		t.Fatalf("convert: %v", err)
	}
	if _, err := os.Stat(filepath.Join(target, "policies.yaml")); err != nil {
		t.Fatalf("policies.yaml missing: %v", err)
	}
	if _, err := os.Stat(filepath.Join(target, "bindings.yaml")); !os.IsNotExist(err) {
		t.Error("kyverno has no bindings, so bindings.yaml should not be written")
	}
}

func TestConvertJSONFormat(t *testing.T) {
	dir := t.TempDir()
	writeConvertFixture(t, dir, "policies.yaml", convertFixtureVAPYAML)

	stdout, _, err := runConvertCmd(t, "--to", "kyverno", "-p", dir, "-f", "json")
	if err != nil {
		t.Fatalf("convert: %v", err)
	}

	var documents []map[string]any
	if err := json.Unmarshal([]byte(stdout), &documents); err != nil {
		t.Fatalf("stdout is not valid json: %v\n%s", err, stdout)
	}
	if len(documents) != 1 {
		t.Fatalf("got %d documents, want 1", len(documents))
	}
	if documents[0]["apiVersion"] != kyverno.APIVersionV1 {
		t.Errorf("got apiVersion %v, want %s", documents[0]["apiVersion"], kyverno.APIVersionV1)
	}
	if documents[0]["kind"] != kyverno.KindValidatingPolicy {
		t.Errorf("got kind %v, want %s", documents[0]["kind"], kyverno.KindValidatingPolicy)
	}
}

func TestConvertKyvernoAPIVersionV1Alpha1(t *testing.T) {
	dir := t.TempDir()
	writeConvertFixture(t, dir, "policies.yaml", `apiVersion: admissionregistration.k8s.io/v1
kind: ValidatingAdmissionPolicy
metadata:
  name: with-conditions
spec:
  matchConstraints:
    resourceRules:
      - apiGroups: [""]
        apiVersions: ["v1"]
        operations: ["CREATE"]
        resources: ["pods"]
  matchConditions:
    - name: skip-system
      expression: "object.metadata.namespace != 'kube-system'"
  validations:
    - expression: "true"
`)

	stdout, _, err := runConvertCmd(t, "--to", "kyverno", "-p", dir, "--kyverno-api-version", "v1alpha1")
	if err != nil {
		t.Fatalf("convert: %v", err)
	}
	if !strings.Contains(stdout, kyverno.APIVersionV1Alpha1) {
		t.Errorf("apiVersion was not pinned:\n%s", stdout)
	}
	if !strings.Contains(stdout, "conditions:") || strings.Contains(stdout, "matchConditions:") {
		t.Errorf("v1alpha1 output must spell the field conditions:\n%s", stdout)
	}
}

func TestConvertNamespacedTarget(t *testing.T) {
	dir := t.TempDir()
	writeConvertFixture(t, dir, "policies.yaml", convertFixtureVAPYAML)

	stdout, _, err := runConvertCmd(t, "--to", "kyverno", "-p", dir, "-n", "production")
	if err != nil {
		t.Fatalf("convert: %v", err)
	}
	if !strings.Contains(stdout, "kind: NamespacedValidatingPolicy") {
		t.Errorf("want a NamespacedValidatingPolicy:\n%s", stdout)
	}
	if !strings.Contains(stdout, "namespace: production") {
		t.Errorf("want the namespace set:\n%s", stdout)
	}
}

func TestConvertNoProvenance(t *testing.T) {
	dir := t.TempDir()
	writeConvertFixture(t, dir, "policies.yaml", convertFixtureVAPYAML)

	with, _, err := runConvertCmd(t, "--to", "kyverno", "-p", dir)
	if err != nil {
		t.Fatalf("convert: %v", err)
	}
	if !strings.Contains(with, "convert.kubeapt.io/source") {
		t.Errorf("provenance should be written by default:\n%s", with)
	}

	without, _, err := runConvertCmd(t, "--to", "kyverno", "-p", dir, "--no-provenance")
	if err != nil {
		t.Fatalf("convert: %v", err)
	}
	if strings.Contains(without, "convert.kubeapt.io/") {
		t.Errorf("--no-provenance did not suppress the annotations:\n%s", without)
	}
}

func TestConvertStrict(t *testing.T) {
	dir := t.TempDir()
	writeConvertFixture(t, dir, "policies.yaml", convertFixtureParamKindYAML)

	stdout, _, err := runConvertCmd(t, "--to", "kyverno", "-p", dir)
	if err != nil {
		t.Fatalf("without --strict a lossy conversion should still succeed: %v", err)
	}
	if !strings.Contains(stdout, "kind: ValidatingPolicy") {
		t.Errorf("the document should still be emitted:\n%s", stdout)
	}

	target := filepath.Join(t.TempDir(), "out.yaml")
	_, _, err = runConvertCmd(t, "--to", "kyverno", "-p", dir, "--strict", "--output", target)
	if err == nil {
		t.Fatal("--strict should fail when the conversion changes behaviour")
	}
	if !strings.Contains(err.Error(), "change policy behaviour") {
		t.Errorf("got error %q, want it to mention the behaviour change", err.Error())
	}
	// Output is still written under --strict so the result can be reviewed.
	data, readErr := os.ReadFile(target)
	if readErr != nil {
		t.Fatalf("--strict should still write its output: %v", readErr)
	}
	if !strings.Contains(string(data), "kind: ValidatingPolicy") {
		t.Errorf("output file is empty or wrong:\n%s", data)
	}
}

func TestConvertRejectsLegacyClusterPolicy(t *testing.T) {
	dir := t.TempDir()
	writeConvertFixture(t, dir, "legacy.yaml", convertFixtureLegacyYAML)

	_, _, err := runConvertCmd(t, "--to", "vap", "-p", dir)
	if err == nil {
		t.Fatal("expected an error for a legacy ClusterPolicy")
	}
	if !strings.Contains(err.Error(), "ClusterPolicy") {
		t.Errorf("got error %q, want it to name the kind", err.Error())
	}
}

func TestConvertMissingSourcePath(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "absent.yaml")
	_, _, err := runConvertCmd(t, "--to", "kyverno", "-p", missing)
	if err == nil {
		t.Fatal("expected an error for a missing path")
	}
	if !strings.Contains(err.Error(), "absent.yaml") {
		t.Errorf("got error %q, want it to name the path", err.Error())
	}
}

func TestConvertEmptySource(t *testing.T) {
	_, _, err := runConvertCmd(t, "--to", "kyverno", "-p", t.TempDir())
	if err == nil {
		t.Fatal("expected an error for a source holding no policies")
	}
	if !strings.Contains(err.Error(), "no ValidatingAdmissionPolicy documents") {
		t.Errorf("got error %q, want it to say nothing was found", err.Error())
	}
}

func TestConvertFromBundle(t *testing.T) {
	setHome(t)
	seedInstalledBundle(t)

	stdout, _, err := runConvertCmd(t, "--to", "kyverno", "--bundle", testBundleName)
	if err != nil {
		t.Fatalf("convert: %v", err)
	}

	policies, err := kyverno.DecodeValidatingPolicies(strings.NewReader(stdout))
	if err != nil {
		t.Fatalf("stdout is not a valid kyverno stream: %v\n%s", err, stdout)
	}
	if len(policies) != 1 || policies[0].Name != "p" {
		t.Fatalf("got %d policies from the bundle:\n%s", len(policies), stdout)
	}
	if policies[0].Annotations[convertSourceAnnotation] != "ValidatingAdmissionPolicy/p" {
		t.Errorf("provenance not recorded: %v", policies[0].Annotations)
	}
}

func TestConvertFromMissingBundle(t *testing.T) {
	setHome(t)

	_, _, err := runConvertCmd(t, "--to", "kyverno", "--bundle", "absent-bundle")
	if err == nil {
		t.Fatal("expected an error for a bundle that is not installed")
	}
	if !strings.Contains(err.Error(), "is not installed") {
		t.Errorf("got error %q, want it to explain the bundle is not installed", err.Error())
	}
}

// convertSourceAnnotation is convert.AnnotationConvertSource, spelled out so
// this test asserts on the wire format rather than on the constant.
const convertSourceAnnotation = "convert.kubeapt.io/source"
