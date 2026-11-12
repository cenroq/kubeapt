// Copyright by cenroq AG
// Contact: info@cenroq.com

package convert_test

import (
	"reflect"
	"strings"
	"testing"

	"github.com/cenroq/kubeapt/v2/pkg/convert"
	"github.com/cenroq/kubeapt/v2/pkg/policies"
	"github.com/cenroq/kubeapt/v2/pkg/types"
)

func TestSeverityToKyverno(t *testing.T) {
	cases := []struct {
		raw       string
		wantValue string
		wantLossy bool
		wantOK    bool
	}{
		{raw: "Critical", wantValue: "high", wantLossy: true, wantOK: true},
		{raw: "critical", wantValue: "high", wantLossy: true, wantOK: true},
		{raw: "High", wantValue: "high", wantOK: true},
		{raw: "Moderate", wantValue: "medium", wantOK: true},
		{raw: " low ", wantValue: "low", wantOK: true},
		{raw: "Info", wantValue: "low", wantLossy: true, wantOK: true},
		{raw: "Not Rated"},
		{raw: ""},
		{raw: "bogus"},
	}

	for _, tc := range cases {
		t.Run(tc.raw, func(t *testing.T) {
			value, lossy, ok := convert.SeverityToKyverno(tc.raw)
			if value != tc.wantValue || lossy != tc.wantLossy || ok != tc.wantOK {
				t.Errorf("got (%q, %v, %v), want (%q, %v, %v)",
					value, lossy, ok, tc.wantValue, tc.wantLossy, tc.wantOK)
			}
		})
	}
}

func TestSeverityFromKyverno(t *testing.T) {
	cases := []struct {
		raw  string
		want types.Severity
		ok   bool
	}{
		{raw: "critical", want: types.SeverityCritical, ok: true},
		{raw: "High", want: types.SeverityHigh, ok: true},
		{raw: "medium", want: types.SeverityModerate, ok: true},
		{raw: " low", want: types.SeverityLow, ok: true},
		{raw: "info", want: types.SeverityNotRated},
		{raw: "", want: types.SeverityNotRated},
	}

	for _, tc := range cases {
		t.Run(tc.raw, func(t *testing.T) {
			got, ok := convert.SeverityFromKyverno(tc.raw)
			if got != tc.want || ok != tc.ok {
				t.Errorf("got (%q, %v), want (%q, %v)", got, ok, tc.want, tc.ok)
			}
		})
	}
}

func TestBridgeAnnotationsDualEmits(t *testing.T) {
	in := map[string]string{
		policies.AnnotationDisplayName: "Require Labels",
		policies.AnnotationDescription: "every pod needs an environment label",
		policies.AnnotationCategory:    "Best Practices",
		policies.AnnotationSeverity:    "Critical",
	}

	got, rep := convert.BridgeAnnotations(in, true)

	want := map[string]string{
		policies.AnnotationDisplayName:        "Require Labels",
		policies.AnnotationDescription:        "every pod needs an environment label",
		policies.AnnotationCategory:           "Best Practices",
		policies.AnnotationSeverity:           "Critical",
		policies.KyvernoAnnotationTitle:       "Require Labels",
		policies.KyvernoAnnotationDescription: "every pod needs an environment label",
		policies.KyvernoAnnotationCategory:    "Best Practices",
		policies.KyvernoAnnotationSeverity:    "high",
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %v\nwant %v", got, want)
	}
	if rep.Count(convert.LevelInfo) != 1 {
		t.Errorf("Critical -> high should record one lossy note, got %d", rep.Count(convert.LevelInfo))
	}
}

func TestBridgeAnnotationsFromKyverno(t *testing.T) {
	in := map[string]string{
		policies.KyvernoAnnotationTitle:       "Check Labels",
		policies.KyvernoAnnotationDescription: "labels are required",
		policies.KyvernoAnnotationCategory:    "Other",
		policies.KyvernoAnnotationSeverity:    "medium",
	}

	got, _ := convert.BridgeAnnotations(in, true)

	if got[policies.AnnotationDisplayName] != "Check Labels" {
		t.Errorf("title did not map to displayName: %v", got)
	}
	if got[policies.AnnotationSeverity] != string(types.SeverityModerate) {
		t.Errorf("got severity %q, want Moderate", got[policies.AnnotationSeverity])
	}
	if got[policies.KyvernoAnnotationSeverity] != "medium" {
		t.Errorf("kyverno severity not preserved: %v", got)
	}
}

func TestBridgeAnnotationsPrefersCenroqKey(t *testing.T) {
	in := map[string]string{
		policies.AnnotationDisplayName:  "cenroq wins",
		policies.KyvernoAnnotationTitle: "kyverno loses",
	}
	got, _ := convert.BridgeAnnotations(in, true)
	if got[policies.AnnotationDisplayName] != "cenroq wins" || got[policies.KyvernoAnnotationTitle] != "cenroq wins" {
		t.Errorf("cenroq key should win on both sides: %v", got)
	}
}

// TestBridgeAnnotationsRoundTripsCritical is the case dual-emit exists to
// protect: Kyverno cannot express Critical, so deriving it back from the
// Kyverno key alone would silently downgrade the policy to High.
func TestBridgeAnnotationsRoundTripsCritical(t *testing.T) {
	in := map[string]string{policies.AnnotationSeverity: "Critical"}

	once, _ := convert.BridgeAnnotations(in, true)
	twice, _ := convert.BridgeAnnotations(once, true)

	if twice[policies.AnnotationSeverity] != "Critical" {
		t.Errorf("Critical did not survive the round trip: %v", twice)
	}
	if !reflect.DeepEqual(once, twice) {
		t.Errorf("BridgeAnnotations is not idempotent:\n once: %v\ntwice: %v", once, twice)
	}
}

func TestBridgeAnnotationsKeepsUnrecognizedSeverityVerbatim(t *testing.T) {
	in := map[string]string{policies.AnnotationSeverity: "showstopper"}
	got, _ := convert.BridgeAnnotations(in, true)

	if got[policies.AnnotationSeverity] != "showstopper" {
		t.Errorf("unrecognized severity not preserved: %v", got)
	}
	if _, ok := got[policies.KyvernoAnnotationSeverity]; ok {
		t.Errorf("unrecognized severity should not produce a kyverno value: %v", got)
	}
}

func TestBridgeAnnotationsUnmapped(t *testing.T) {
	in := map[string]string{
		policies.AnnotationRemediation:  "add the label",
		"team.example.com/owner":        "platform",
		policies.AnnotationDisplayName:  "Kept",
		convert.AnnotationConvertSource: "stale/provenance",
	}

	kept, _ := convert.BridgeAnnotations(in, true)
	if kept[policies.AnnotationRemediation] != "add the label" || kept["team.example.com/owner"] != "platform" {
		t.Errorf("unmapped keys should be copied through: %v", kept)
	}
	if _, ok := kept[convert.AnnotationConvertSource]; ok {
		t.Errorf("provenance must be authored fresh, not inherited: %v", kept)
	}

	dropped, _ := convert.BridgeAnnotations(in, false)
	if _, ok := dropped["team.example.com/owner"]; ok {
		t.Errorf("unmapped keys should be dropped: %v", dropped)
	}
	if dropped[policies.AnnotationDisplayName] != "Kept" {
		t.Errorf("bridged keys must survive keepUnmapped=false: %v", dropped)
	}
}

func TestBridgeAnnotationsEmptyIsNil(t *testing.T) {
	got, rep := convert.BridgeAnnotations(nil, true)
	if got != nil {
		t.Errorf("got %v, want nil", got)
	}
	if rep.Len() != 0 {
		t.Errorf("got %d notes, want 0", rep.Len())
	}
}

// legacyMetadata is a policy annotated the way policy sets were before the
// switch to security.cenroq.io.
func legacyMetadata() map[string]string {
	return map[string]string{
		policies.LegacyAnnotationDisplayName: "Require Labels",
		policies.LegacyAnnotationDescription: "every pod needs an environment label",
		policies.LegacyAnnotationCategory:    "Best Practices",
		policies.LegacyAnnotationSeverity:    "Critical",
		policies.LegacyAnnotationResource:    "pods",
		policies.LegacyAnnotationRemediation: "add the label",
		policies.LegacyAnnotationProduct:     "kubernetes",
		"team.example.com/owner":             "platform",
	}
}

// A conversion migrates the legacy keys: the output carries security.cenroq.io
// and Kyverno keys only, and one info note says so.
func TestBridgeAnnotationsMigratesLegacyKeys(t *testing.T) {
	got, rep := convert.BridgeAnnotations(legacyMetadata(), true)

	want := map[string]string{
		policies.AnnotationDisplayName:        "Require Labels",
		policies.AnnotationDescription:        "every pod needs an environment label",
		policies.AnnotationCategory:           "Best Practices",
		policies.AnnotationSeverity:           "Critical",
		policies.AnnotationResource:           "pods",
		policies.AnnotationRemediation:        "add the label",
		policies.AnnotationProduct:            "kubernetes",
		policies.KyvernoAnnotationTitle:       "Require Labels",
		policies.KyvernoAnnotationDescription: "every pod needs an environment label",
		policies.KyvernoAnnotationCategory:    "Best Practices",
		policies.KyvernoAnnotationSeverity:    "high",
		"team.example.com/owner":              "platform",
	}
	if len(got) != len(want) {
		t.Fatalf("got %d annotations, want %d:\n%v", len(got), len(want), got)
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("%s = %q, want %q", k, got[k], v)
		}
	}

	var migrated int
	for _, note := range rep.Notes {
		if strings.Contains(note.Message, "migrated deprecated security.kubeapt.io") {
			migrated++
		}
	}
	if migrated != 1 {
		t.Errorf("migration notes = %d, want exactly 1: %+v", migrated, rep.Notes)
	}
}

// resource, remediation and product have no Kyverno equivalent, so like any
// other unmapped key they are dropped when keepUnmapped is false, legacy or not.
func TestBridgeAnnotationsLegacyUnmappedDropped(t *testing.T) {
	got, _ := convert.BridgeAnnotations(legacyMetadata(), false)
	for _, k := range []string{policies.AnnotationResource, policies.AnnotationRemediation, policies.AnnotationProduct,
		policies.LegacyAnnotationResource, policies.LegacyAnnotationRemediation, policies.LegacyAnnotationProduct} {
		if _, ok := got[k]; ok {
			t.Errorf("%s survived keepUnmapped=false: %v", k, got)
		}
	}
	if got[policies.AnnotationDisplayName] != "Require Labels" {
		t.Errorf("bridged legacy displayName lost: %v", got)
	}
}

// When a document carries both spellings, security.cenroq.io wins everywhere
// and no migration is reported, because nothing was read from a legacy key.
func TestBridgeAnnotationsCenroqBeatsLegacy(t *testing.T) {
	in := legacyMetadata()
	in[policies.AnnotationDisplayName] = "New Title"
	in[policies.AnnotationDescription] = "new description"
	in[policies.AnnotationCategory] = "New Category"
	in[policies.AnnotationSeverity] = "Low"
	in[policies.AnnotationResource] = "deployments"
	in[policies.AnnotationRemediation] = "new fix"
	in[policies.AnnotationProduct] = "openshift"

	got, rep := convert.BridgeAnnotations(in, true)
	checks := map[string]string{
		policies.AnnotationDisplayName:     "New Title",
		policies.KyvernoAnnotationTitle:    "New Title",
		policies.AnnotationSeverity:        "Low",
		policies.KyvernoAnnotationSeverity: "low",
		policies.AnnotationResource:        "deployments",
		policies.AnnotationRemediation:     "new fix",
		policies.AnnotationProduct:         "openshift",
	}
	for k, v := range checks {
		if got[k] != v {
			t.Errorf("%s = %q, want %q", k, got[k], v)
		}
	}
	for k := range got {
		if strings.HasPrefix(k, "security.kubeapt.io/") {
			t.Errorf("legacy key %s leaked into the output", k)
		}
	}
	if len(rep.Notes) != 0 {
		t.Errorf("notes = %+v, want none", rep.Notes)
	}
}

// Converting already-migrated output again changes nothing.
func TestBridgeAnnotationsMigrationIsIdempotent(t *testing.T) {
	once, _ := convert.BridgeAnnotations(legacyMetadata(), true)
	twice, rep := convert.BridgeAnnotations(once, true)
	if len(once) != len(twice) {
		t.Fatalf("second pass changed the key set:\n%v\n%v", once, twice)
	}
	for k, v := range once {
		if twice[k] != v {
			t.Errorf("%s = %q after second pass, want %q", k, twice[k], v)
		}
	}
	// Critical still has no Kyverno equivalent, so that note recurs; the
	// migration note must not, because nothing legacy is left to migrate.
	for _, note := range rep.Notes {
		if strings.Contains(note.Message, "migrated deprecated") {
			t.Errorf("second pass reported a migration: %+v", note)
		}
	}
}

// An unrecognized cenroq severity cannot be mapped, so an existing Kyverno
// severity is carried over rather than dropped.
func TestBridgeAnnotationsUnrecognizedSeverityKeepsKyvernoValue(t *testing.T) {
	got, _ := convert.BridgeAnnotations(map[string]string{
		policies.AnnotationSeverity:        "showstopper",
		policies.KyvernoAnnotationSeverity: "medium",
	}, false)
	if got[policies.AnnotationSeverity] != "showstopper" || got[policies.KyvernoAnnotationSeverity] != "medium" {
		t.Errorf("got %v, want both values kept verbatim", got)
	}
}
