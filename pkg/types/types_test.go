// Copyright by cenroq AG
// Contact: info@cenroq.com

package types_test

import (
	"testing"

	"github.com/cenroq/kubeapt/v2/pkg/types"
)

// TestManifestIsAlias asserts Manifest is a type alias for map.
func TestManifestIsAlias(t *testing.T) {
	// Single-value interchange in both directions.
	var asAlias types.Manifest = map[string]any{"kind": "Pod"}
	var asMap map[string]any = types.Manifest{"kind": "Pod"}
	_ = asAlias
	_ = asMap

	// Slice-of-Manifest interchanges with slice-of-map without conversion.
	var asAliasSlice []types.Manifest = []map[string]any{{"kind": "Pod"}}
	var asMapSlice []map[string]any = []types.Manifest{{"kind": "Pod"}}
	_ = asAliasSlice
	_ = asMapSlice

	// Function-parameter interchange — proves a function declared with one
	// signature accepts the other directly.
	takesMap := func(_ map[string]any) {}
	takesManifest := func(_ types.Manifest) {}
	takesMap(types.Manifest{})
	takesManifest(map[string]any{})
}

// TestSeverityConstantValues pins the wire values of Severity constants.
func TestSeverityConstantValues(t *testing.T) {
	cases := map[types.Severity]string{
		types.SeverityCritical: "Critical",
		types.SeverityHigh:     "High",
		types.SeverityModerate: "Moderate",
		types.SeverityLow:      "Low",
		types.SeverityInfo:     "Info",
		types.SeverityNotRated: "Not Rated",
	}
	for sev, want := range cases {
		if string(sev) != want {
			t.Errorf("Severity = %q, want %q", string(sev), want)
		}
	}
}

// TestOutcomeConstantValues pins the wire values of Outcome constants.
func TestOutcomeConstantValues(t *testing.T) {
	cases := map[types.Outcome]string{
		types.OutcomePass:  "pass",
		types.OutcomeFail:  "fail",
		types.OutcomeError: "error",
	}
	for outcome, want := range cases {
		if string(outcome) != want {
			t.Errorf("Outcome = %q, want %q", string(outcome), want)
		}
	}
}
