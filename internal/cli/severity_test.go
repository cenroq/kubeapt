// Copyright by cenroq AG
// Contact: info@cenroq.com

package cli

import (
	"encoding/json"
	"strings"
	"testing"

	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestNormalizeSeverity(t *testing.T) {
	cases := map[string]string{
		"Critical":  severityCritical,
		"critical":  severityCritical,
		"HIGH":      severityHigh,
		"moderate":  severityModerate,
		"Low":       severityLow,
		"info":      severityInfo,
		"":          severityNotRated,
		"bogus":     severityNotRated,
		"medium":    severityNotRated,
		"  High  ": severityHigh,
	}
	for input, want := range cases {
		if got := normalizeSeverity(input); got != want {
			t.Errorf("normalizeSeverity(%q) = %q, want %q", input, got, want)
		}
	}
}

func TestSeverityRankOrdering(t *testing.T) {
	order := []string{severityCritical, severityHigh, severityModerate, severityLow, severityInfo, severityNotRated}
	for i := 1; i < len(order); i++ {
		if severityRank(order[i-1]) >= severityRank(order[i]) {
			t.Fatalf("expected %s to rank before %s", order[i-1], order[i])
		}
	}
}

func TestPolicySeverityMap(t *testing.T) {
	policies := []admissionregistrationv1.ValidatingAdmissionPolicy{
		{
			ObjectMeta: metav1.ObjectMeta{
				Name:        "p-high",
				Annotations: map[string]string{policyAnnotationSeverity: "High"},
			},
		},
		{
			ObjectMeta: metav1.ObjectMeta{
				Name: "p-missing",
			},
		},
	}
	m := policySeverityMap(policies)
	if m["p-high"] != severityHigh {
		t.Errorf("expected High for p-high, got %q", m["p-high"])
	}
	if m["p-missing"] != severityNotRated {
		t.Errorf("expected Not Rated for p-missing, got %q", m["p-missing"])
	}
}

func TestSortViolationsBySeverity(t *testing.T) {
	violations := []violationDetail{
		{Policy: "a", Severity: severityLow},
		{Policy: "b", Severity: severityCritical},
		{Policy: "c", Severity: severityInfo},
		{Policy: "d", Severity: severityHigh},
		{Policy: "e", Severity: severityNotRated},
		{Policy: "f", Severity: severityModerate},
	}
	sortViolationsBySeverity(violations)
	want := []string{severityCritical, severityHigh, severityModerate, severityLow, severityInfo, severityNotRated}
	for i, sev := range want {
		if violations[i].Severity != sev {
			t.Fatalf("position %d: expected %s, got %s", i, sev, violations[i].Severity)
		}
	}
}

func TestImplicitBindingsForPolicies(t *testing.T) {
	policies := []admissionregistrationv1.ValidatingAdmissionPolicy{
		{ObjectMeta: metav1.ObjectMeta{Name: "p1"}},
		{ObjectMeta: metav1.ObjectMeta{Name: "p2"}},
	}
	bindings := implicitBindingsForPolicies(policies)
	if len(bindings) != 2 {
		t.Fatalf("expected 2 implicit bindings, got %d", len(bindings))
	}
	if bindings[0].Spec.PolicyName != "p1" || bindings[1].Spec.PolicyName != "p2" {
		t.Fatalf("unexpected policy names: %+v", bindings)
	}
}

func TestBuildPolicyJSONReportFlatViolations(t *testing.T) {
	reports := []*bindingReport{
		{
			Policy:   "p1",
			Severity: severityLow,
			Total:    1,
			NonCompliant: 1,
			URL:      policyDocsBaseURL + "/" + testPolicyUUID,
			Violations: []violationDetail{
				{Policy: "p1", Severity: severityLow, Resource: "r1", Message: "low msg",
					URL: policyDocsBaseURL + "/" + testPolicyUUID},
			},
		},
		{
			Policy:   "p2",
			Severity: severityCritical,
			Total:    1,
			NonCompliant: 1,
			Violations: []violationDetail{
				{Policy: "p2", Severity: severityCritical, Resource: "r2", Message: "critical msg"},
			},
		},
	}

	all := buildPolicyJSONReport("all", reports, nil, nil)
	encoded, err := json.Marshal(all)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if !strings.Contains(string(encoded), `"url":"`+policyDocsBaseURL+`/`+testPolicyUUID+`"`) {
		t.Fatalf("expected policy url in JSON, got %s", encoded)
	}
	// p2 carries no uuid, so exactly one binding and one violation expose "url".
	if got := strings.Count(string(encoded), `"url"`); got != 2 {
		t.Fatalf(`expected "url" twice (one binding, one violation), got %d in %s`, got, encoded)
	}
	if len(all.Violations) != 2 {
		t.Fatalf("expected 2 flat violations, got %d", len(all.Violations))
	}
	if all.Violations[0].Severity != severityCritical || all.Violations[1].Severity != severityLow {
		t.Fatalf("flat violations not sorted by severity: %+v", all.Violations)
	}
	for _, br := range all.Data {
		if br.Violations != nil {
			t.Fatalf("per-binding violations should be cleared in JSON output")
		}
	}

	summary := buildPolicyJSONReport("summary", reports, nil, nil)
	if summary.Violations != nil {
		t.Fatalf("summary mode should not include flat violations")
	}
}

func TestBuildNamespaceJSONReportSortsViolations(t *testing.T) {
	reports := []namespaceReport{
		{
			Namespace: "ns1",
			Violations: []violationDetail{
				{Severity: severityLow, Policy: "a"},
				{Severity: severityCritical, Policy: "b"},
			},
		},
	}
	out := buildNamespaceJSONReport("all", reports, nil)
	if len(out.Namespaces) != 1 {
		t.Fatalf("expected 1 namespace")
	}
	got := out.Namespaces[0].Violations
	if got[0].Severity != severityCritical || got[1].Severity != severityLow {
		t.Fatalf("namespace violations not sorted: %+v", got)
	}
}

func TestBuildResourceJSONReportSortsViolations(t *testing.T) {
	reports := []resourceReport{
		{
			Kind:     "Pod",
			Resource: "ns/r",
			Violations: []violationDetail{
				{Severity: severityInfo, Policy: "a"},
				{Severity: severityHigh, Policy: "b"},
			},
		},
	}
	out := buildResourceJSONReport("all", reports)
	got := out.Resources[0].Violations
	if got[0].Severity != severityHigh || got[1].Severity != severityInfo {
		t.Fatalf("resource violations not sorted: %+v", got)
	}
}
