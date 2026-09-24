package cli

import (
    "bytes"
    "encoding/json"
    "os"
    "path/filepath"
    "reflect"
    "strings"
    "testing"

    "github.com/jedib0t/go-pretty/v6/table"
    admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
    metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

    "github.com/cenroq/kubeapt/v2/pkg/types"
)

func TestParseNamespaces(t *testing.T) {
    got := parseNamespaces("a, b, ,c")
    want := []string{"a", "b", "c"}
    if !reflect.DeepEqual(got, want) {
        t.Fatalf("expected %v, got %v", want, got)
    }
}

func TestManifestHelpers(t *testing.T) {
    if !isManifestFile("demo.YAML") {
        t.Fatalf("expected YAML to be recognized")
    }
    if isManifestFile("demo.txt") {
        t.Fatalf("expected txt to be ignored")
    }

    dir := t.TempDir()
    valid := filepath.Join(dir, "a.yaml")
    invalid := filepath.Join(dir, "b.txt")
    if err := os.WriteFile(valid, []byte("x"), 0o644); err != nil {
        t.Fatalf("write valid: %v", err)
    }
    if err := os.WriteFile(invalid, []byte("x"), 0o644); err != nil {
        t.Fatalf("write invalid: %v", err)
    }

    files, err := collectFiles(dir)
    if err != nil {
        t.Fatalf("collectFiles error: %v", err)
    }
    if len(files) != 1 || files[0] != valid {
        t.Fatalf("unexpected files: %v", files)
    }
}

func TestResourceDisplayAndKey(t *testing.T) {
    obj := map[string]interface{}{
        "kind": "Pod",
        "metadata": map[string]interface{}{
            "name":      "demo",
            "namespace": "ns1",
            "uid":       "u1",
        },
    }
    kind, name := resourceDisplayName(obj)
    if kind != "Pod" || name != "ns1/demo" {
        t.Fatalf("unexpected display name: %s %s", kind, name)
    }
    if key := resourceKey(obj); key != "Pod/ns1/demo/u1" {
        t.Fatalf("unexpected key: %s", key)
    }
}

func TestBindingModeAndSeverity(t *testing.T) {
    binding := &admissionregistrationv1.ValidatingAdmissionPolicyBinding{}
    if got := bindingMode(binding); got != string(admissionregistrationv1.Deny) {
        t.Fatalf("expected default deny, got %q", got)
    }

    binding.Spec.ValidationActions = []admissionregistrationv1.ValidationAction{admissionregistrationv1.Audit, admissionregistrationv1.Warn}
    if got := bindingMode(binding); got != "Audit,Warn" {
        t.Fatalf("unexpected mode: %q", got)
    }

    if label, _ := violationSeverityLabel("high"); label != "HIGH" {
        t.Fatalf("expected HIGH label, got %q", label)
    }
    if label, _ := violationSeverityLabel("Critical"); label != "CRITICAL" {
        t.Fatalf("expected CRITICAL label, got %q", label)
    }
    if label, _ := violationSeverityLabel(""); label != "NOT RATED" {
        t.Fatalf("expected NOT RATED label, got %q", label)
    }
}

func TestUniqueViolationFields(t *testing.T) {
    violations := []violationDetail{
        {Policy: "p1"},
        {Policy: "p2"},
        {Policy: "p1"},
        {Policy: ""},
    }
    got := uniqueViolationFields(violations, func(v violationDetail) string { return v.Policy })
    want := []string{"p1", "p2"}
    if !reflect.DeepEqual(got, want) {
        t.Fatalf("expected %v, got %v", want, got)
    }
}

func TestPSALabelHelpers(t *testing.T) {
    labels := map[string]string{
        "pod-security.kubernetes.io/enforce": "baseline",
        "pss.security.cenroq.io/warn":       "restricted",
        "other":                              "ignore",
    }
    converted := convertPSALabels(labels)
    if converted["enforce"] != "baseline" || converted["warn"] != "restricted" {
        t.Fatalf("unexpected PSA labels: %v", converted)
    }

    modes := map[string]string{"enforce": "baseline"}
    if got := formatPSAMode(modes, map[string]bool{"enforce": true}, "enforce", true); got != "baseline (cenroq)" {
        t.Fatalf("unexpected PSA mode format: %s", got)
    }
}

func TestHighestResourceSeverity(t *testing.T) {
    // A resource carrying multiple violations is bucketed under the most
    // severe one, so per-namespace severity columns sum to NonCompliant.
    got := highestResourceSeverity([]violationDetail{
        {Severity: "low"},
        {Severity: "Critical"},
        {Severity: "moderate"},
    })
    if got != severityCritical {
        t.Fatalf("expected %q, got %q", severityCritical, got)
    }

    // No violations at all → defaults to Not Rated so the bucket is never empty.
    if got := highestResourceSeverity(nil); got != severityNotRated {
        t.Fatalf("expected %q for empty input, got %q", severityNotRated, got)
    }

    // Unrecognized strings normalize to Not Rated rather than disappearing.
    if got := highestResourceSeverity([]violationDetail{{Severity: "bogus"}}); got != severityNotRated {
        t.Fatalf("expected %q for unknown severity, got %q", severityNotRated, got)
    }
}

func TestVisibleSeverityColumnsHidesZeros(t *testing.T) {
    reports := []namespaceReport{
        {Namespace: "ns1", SeverityCounts: map[string]int{severityHigh: 2, severityLow: 1}},
        {Namespace: "ns2", SeverityCounts: map[string]int{severityHigh: 3}},
    }
    visible, totals := visibleSeverityColumns(reports)
    // Only High and Low should appear; Critical/Moderate/Info/Not Rated stay hidden.
    want := []string{severityHigh, severityLow}
    if !reflect.DeepEqual(visible, want) {
        t.Fatalf("visible severities = %v, want %v", visible, want)
    }
    if totals[severityHigh] != 5 || totals[severityLow] != 1 {
        t.Fatalf("totals = %v, want High=5 Low=1", totals)
    }
}

func TestPrintNamespaceTableShowsSeverityColumns(t *testing.T) {
    reports := []namespaceReport{
        {Namespace: "prod-api", Total: 24, Compliant: 19, NonCompliant: 5,
            SeverityCounts: map[string]int{severityCritical: 2, severityHigh: 3}},
        {Namespace: "prod-web", Total: 18, Compliant: 18, NonCompliant: 0},
    }
    var buf bytes.Buffer
    printNamespaceTable(reports, &buf, table.StyleDefault)
    out := buf.String()
    // go-pretty uppercases header text; row values keep their case.
    upperOut := strings.ToUpper(out)
    for _, want := range []string{severityCritical, severityHigh} {
        if !strings.Contains(upperOut, strings.ToUpper(want)) {
            t.Errorf("table missing header %q\noutput:\n%s", want, out)
        }
    }
    for _, want := range []string{"prod-api", "Totals"} {
        if !strings.Contains(out, want) {
            t.Errorf("table missing %q\noutput:\n%s", want, out)
        }
    }
    // Moderate/Low/Info/Not Rated have zero totals and must not appear as headers.
    for _, hidden := range []string{severityModerate, severityLow, severityInfo, severityNotRated} {
        if strings.Contains(upperOut, strings.ToUpper(hidden)) {
            t.Errorf("table should hide zero-count column %q\noutput:\n%s", hidden, out)
        }
    }
}

func TestViolationLogsIncludeLinkOnlyWhenURLSet(t *testing.T) {
    url := policyDocsBaseURL + "/" + testPolicyUUID
    linked := violationDetail{Policy: "p1", Binding: "b1", Severity: severityCritical,
        Resource: "Pod ns/a", Message: "boom", URL: url}
    bare := violationDetail{Policy: "p2", Binding: "b2", Severity: severityLow,
        Resource: "Pod ns/b", Message: "meh"}

    cases := []struct {
        name   string
        render func(w *bytes.Buffer, violations []violationDetail)
    }{
        {"policy", func(w *bytes.Buffer, v []violationDetail) {
            printViolationLogs([]*bindingReport{{Policy: "p", Violations: v}}, w, false)
        }},
        {"namespace", func(w *bytes.Buffer, v []violationDetail) {
            printNamespaceViolationLogs([]namespaceReport{{Namespace: "ns", Violations: v}}, w, false)
        }},
        {"resource", func(w *bytes.Buffer, v []violationDetail) {
            printResourceViolationLogs([]resourceReport{{Kind: "Pod", Resource: "a", Violations: v}}, w, false)
        }},
    }

    for _, tc := range cases {
        t.Run(tc.name, func(t *testing.T) {
            var withURL bytes.Buffer
            tc.render(&withURL, []violationDetail{linked})
            if !strings.Contains(withURL.String(), url) {
                t.Errorf("expected link %q in output:\n%s", url, withURL.String())
            }

            var withoutURL bytes.Buffer
            tc.render(&withoutURL, []violationDetail{bare})
            if strings.Contains(withoutURL.String(), "Link") {
                t.Errorf("violation without a uuid must not render a link:\n%s", withoutURL.String())
            }
            if strings.Contains(withoutURL.String(), policyDocsBaseURL) {
                t.Errorf("no fallback URL expected:\n%s", withoutURL.String())
            }
        })
    }
}

func TestPrintSummaryTablesHyperlinksPolicyOnlyWithColor(t *testing.T) {
    url := policyDocsBaseURL + "/" + testPolicyUUID
    reports := []*bindingReport{
        {Policy: "hostpid", Severity: severityCritical, Total: 3, NonCompliant: 3, URL: url},
        {Policy: "hostipc", Severity: severityHigh, Total: 2, Compliant: 2},
    }

    var colored bytes.Buffer
    printSummaryTables(reports, true, &colored, table.StyleDefault, true)
    if !strings.Contains(colored.String(), "\x1b]8;;"+url) {
        t.Errorf("expected OSC 8 hyperlink for hostpid:\n%q", colored.String())
    }
    if strings.Count(colored.String(), "\x1b]8;;"+policyDocsBaseURL) != 1 {
        t.Errorf("only the policy carrying a uuid should be hyperlinked:\n%q", colored.String())
    }

    var plain bytes.Buffer
    printSummaryTables(reports, true, &plain, table.StyleDefault, false)
    if strings.Contains(plain.String(), "\x1b]8") {
        t.Errorf("useColor=false must not emit escape sequences:\n%q", plain.String())
    }
    if !strings.Contains(plain.String(), "hostpid") {
        t.Errorf("policy name missing from plain output:\n%s", plain.String())
    }
}

func TestBuildNamespaceJSONReportMirrorsSeverity(t *testing.T) {
    reports := []namespaceReport{
        {Namespace: "ns1", Total: 5, Compliant: 3, NonCompliant: 2,
            SeverityCounts: map[string]int{severityHigh: 1, severityLow: 1}},
        {Namespace: "ns2", Total: 4, Compliant: 4},
    }
    payload := buildNamespaceJSONReport("summary", reports, nil)
    if payload.SeverityTotals[severityHigh] != 1 || payload.SeverityTotals[severityLow] != 1 {
        t.Errorf("SeverityTotals = %v, want High=1 Low=1", payload.SeverityTotals)
    }
    encoded, err := json.Marshal(payload)
    if err != nil {
        t.Fatalf("marshal: %v", err)
    }
    if !strings.Contains(string(encoded), `"severityCounts"`) {
        t.Errorf("expected per-namespace severityCounts in JSON, got %s", encoded)
    }
    if !strings.Contains(string(encoded), `"severityTotals"`) {
        t.Errorf("expected top-level severityTotals in JSON, got %s", encoded)
    }
}

func TestParseResourceFilter(t *testing.T) {
    got := parseResourceFilter("Pods, deployments ,,pods, ")
    want := []string{"pods", "deployments"}
    if !reflect.DeepEqual(got, want) {
        t.Fatalf("parseResourceFilter() = %v, want %v", got, want)
    }
    if got := parseResourceFilter("   "); got != nil {
        t.Fatalf("expected nil for blank input, got %v", got)
    }
    if got := parseResourceFilter(""); got != nil {
        t.Fatalf("expected nil for empty input, got %v", got)
    }
}

func TestFilterPoliciesByResource(t *testing.T) {
    policy := func(name, resource string) admissionregistrationv1.ValidatingAdmissionPolicy {
        return admissionregistrationv1.ValidatingAdmissionPolicy{
            ObjectMeta: metav1.ObjectMeta{Name: name},
            Spec: admissionregistrationv1.ValidatingAdmissionPolicySpec{
                MatchConstraints: &admissionregistrationv1.MatchResources{
                    ResourceRules: []admissionregistrationv1.NamedRuleWithOperations{
                        {RuleWithOperations: admissionregistrationv1.RuleWithOperations{Rule: admissionregistrationv1.Rule{Resources: []string{resource}}}},
                    },
                },
            },
        }
    }
    binding := func(name, policyName string) admissionregistrationv1.ValidatingAdmissionPolicyBinding {
        return admissionregistrationv1.ValidatingAdmissionPolicyBinding{
            ObjectMeta: metav1.ObjectMeta{Name: name},
            Spec: admissionregistrationv1.ValidatingAdmissionPolicyBindingSpec{PolicyName: policyName},
        }
    }
    policyNames := func(ps []admissionregistrationv1.ValidatingAdmissionPolicy) []string {
        out := make([]string, len(ps))
        for i, p := range ps {
            out[i] = p.Name
        }
        return out
    }
    bindingNames := func(bs []admissionregistrationv1.ValidatingAdmissionPolicyBinding) []string {
        out := make([]string, len(bs))
        for i, b := range bs {
            out[i] = b.Name
        }
        return out
    }

    policies := []admissionregistrationv1.ValidatingAdmissionPolicy{
        policy("pods-policy", "pods"),
        policy("deploy-policy", "deployments"),
    }
    bindings := []admissionregistrationv1.ValidatingAdmissionPolicyBinding{
        binding("b-pods", "pods-policy"),
        binding("b-deploy", "deploy-policy"),
        binding("b-pods-2", "pods-policy"),
    }

    gotPolicies, gotBindings := filterPoliciesByResource(policies, bindings, []string{"pods"})
    if !reflect.DeepEqual(policyNames(gotPolicies), []string{"pods-policy"}) {
        t.Fatalf("expected only pods-policy, got %v", policyNames(gotPolicies))
    }
    if !reflect.DeepEqual(bindingNames(gotBindings), []string{"b-pods", "b-pods-2"}) {
        t.Fatalf("expected bindings targeting pods-policy only, got %v", bindingNames(gotBindings))
    }

    // Empty filter returns the inputs unchanged.
    samePolicies, sameBindings := filterPoliciesByResource(policies, bindings, nil)
    if len(samePolicies) != 2 || len(sameBindings) != 3 {
        t.Fatalf("expected inputs unchanged for empty filter, got %d policies %d bindings", len(samePolicies), len(sameBindings))
    }

    // No matching policy yields empty results (the caller turns this into an error).
    emptyPolicies, _ := filterPoliciesByResource(policies, bindings, []string{"services"})
    if len(emptyPolicies) != 0 {
        t.Fatalf("expected no policies for unmatched resource, got %v", policyNames(emptyPolicies))
    }
}

func TestPolicyResourceFlagParsing(t *testing.T) {
    cmd := ValidateCmd(func() string { return "info" })
    if err := cmd.ParseFlags([]string{"--policyresource", "pods", "--all-namespaces"}); err != nil {
        t.Fatalf("ParseFlags error: %v", err)
    }
    got, err := cmd.Flags().GetString("policyresource")
    if err != nil {
        t.Fatalf("GetString: %v", err)
    }
    if got != "pods" {
        t.Fatalf("policyresource = %q, want pods", got)
    }
    all, err := cmd.Flags().GetBool("all-namespaces")
    if err != nil {
        t.Fatalf("GetBool all-namespaces: %v", err)
    }
    if !all {
        t.Fatalf("expected --all-namespaces to parse alongside --policyresource")
    }
}

func TestParseGVRFilter(t *testing.T) {
    got := parseGVRFilter("networking.k8s.io/v1/networkpolicies, /v1/services , projectcalico.org/networkpolicies, pods,, networking.k8s.io/v1/networkpolicies")
    want := []types.GVR{
        {Group: "networking.k8s.io", Version: "v1", Resource: "networkpolicies"},
        {Group: "", Version: "v1", Resource: "services"},
        {Group: "projectcalico.org", Version: "*", Resource: "networkpolicies"},
        {Group: "*", Version: "*", Resource: "pods"},
    }
    if !reflect.DeepEqual(got, want) {
        t.Fatalf("parseGVRFilter() = %#v, want %#v", got, want)
    }
    if got := parseGVRFilter("   "); got != nil {
        t.Fatalf("expected nil for blank input, got %v", got)
    }
    if got := parseGVRFilter(""); got != nil {
        t.Fatalf("expected nil for empty input, got %v", got)
    }
}

func TestFilterPoliciesByGVR(t *testing.T) {
    policy := func(name, group, resource string) admissionregistrationv1.ValidatingAdmissionPolicy {
        return admissionregistrationv1.ValidatingAdmissionPolicy{
            ObjectMeta: metav1.ObjectMeta{Name: name},
            Spec: admissionregistrationv1.ValidatingAdmissionPolicySpec{
                MatchConstraints: &admissionregistrationv1.MatchResources{
                    ResourceRules: []admissionregistrationv1.NamedRuleWithOperations{
                        {RuleWithOperations: admissionregistrationv1.RuleWithOperations{Rule: admissionregistrationv1.Rule{
                            APIGroups: []string{group},
                            Resources: []string{resource},
                        }}},
                    },
                },
            },
        }
    }
    binding := func(name, policyName string) admissionregistrationv1.ValidatingAdmissionPolicyBinding {
        return admissionregistrationv1.ValidatingAdmissionPolicyBinding{
            ObjectMeta: metav1.ObjectMeta{Name: name},
            Spec: admissionregistrationv1.ValidatingAdmissionPolicyBindingSpec{PolicyName: policyName},
        }
    }
    names := func(ps []admissionregistrationv1.ValidatingAdmissionPolicy) []string {
        out := make([]string, len(ps))
        for i, p := range ps {
            out[i] = p.Name
        }
        return out
    }

    policies := []admissionregistrationv1.ValidatingAdmissionPolicy{
        policy("k8s-netpol", "networking.k8s.io", "networkpolicies"),
        policy("calico-netpol", "projectcalico.org", "networkpolicies"),
    }
    bindings := []admissionregistrationv1.ValidatingAdmissionPolicyBinding{
        binding("b-k8s", "k8s-netpol"),
        binding("b-calico", "calico-netpol"),
    }

    // Group discriminates: only the networking.k8s.io policy and its binding survive.
    gotPolicies, gotBindings := filterPoliciesByGVR(policies, bindings, []types.GVR{
        {Group: "networking.k8s.io", Version: "v1", Resource: "networkpolicies"},
    })
    if !reflect.DeepEqual(names(gotPolicies), []string{"k8s-netpol"}) {
        t.Fatalf("expected only k8s-netpol, got %v", names(gotPolicies))
    }
    if len(gotBindings) != 1 || gotBindings[0].Name != "b-k8s" {
        t.Fatalf("expected only b-k8s binding, got %v", gotBindings)
    }

    // Empty filter returns inputs unchanged.
    samePolicies, sameBindings := filterPoliciesByGVR(policies, bindings, nil)
    if len(samePolicies) != 2 || len(sameBindings) != 2 {
        t.Fatalf("expected inputs unchanged for empty filter, got %d policies %d bindings", len(samePolicies), len(sameBindings))
    }

    // No match yields empty results (the caller turns this into an error).
    emptyPolicies, _ := filterPoliciesByGVR(policies, bindings, []types.GVR{{Group: "", Version: "v1", Resource: "services"}})
    if len(emptyPolicies) != 0 {
        t.Fatalf("expected no policies for unmatched GVR, got %v", names(emptyPolicies))
    }
}

func TestPolicyResourcesFlagMutualExclusion(t *testing.T) {
    cmd := ValidateCmd(func() string { return "info" })
    if err := cmd.ParseFlags([]string{"--policyresource", "pods", "--policy-resources", "/v1/pods"}); err != nil {
        t.Fatalf("ParseFlags error: %v", err)
    }
    err := runValidate(cmd, nil)
    if err == nil || !strings.Contains(err.Error(), "cannot be combined") {
        t.Fatalf("expected mutual-exclusion error, got %v", err)
    }
}
