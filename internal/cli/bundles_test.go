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
	"github.com/spf13/cobra"
	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
)

func TestValidateBundleSegment(t *testing.T) {
	if err := validateBundleSegment("bundle", ""); err == nil {
		t.Fatalf("expected error for empty value")
	}
	if err := validateBundleSegment("bundle", "../bad"); err == nil {
		t.Fatalf("expected error for path traversal")
	}
	if err := validateBundleSegment("bundle", "good-name"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestBundleIndexHelpers(t *testing.T) {
	bundles := []bundleIndexEntry{{Name: "demo", LatestVersion: "1.2.3", Versions: []string{"1.0.0", "1.2.3"}}}

	if v, err := resolveBundleVersionFromIndex(bundles, "demo", ""); err != nil || v != "1.2.3" {
		t.Fatalf("unexpected result: %v %v", v, err)
	}
	if _, err := resolveBundleVersionFromIndex(bundles, "missing", ""); err == nil {
		t.Fatalf("expected error for missing bundle")
	}

	if entry, ok := findBundleIndexEntry(bundles, "demo"); !ok || entry.Name != "demo" {
		t.Fatalf("expected to find bundle entry")
	}
	if bundleVersionInIndex(bundles[0], "9.9.9") {
		t.Fatalf("expected version to be missing")
	}
}

func TestBundleURLAndSourceHelpers(t *testing.T) {
	if got := bundleJSONURL("demo", "1.0.0"); got == "" {
		t.Fatalf("expected bundle URL to be built")
	}

	source, err := selectBundleSource([]string{"file.txt", "archive.tar.gz"})
	if err != nil || source != "archive.tar.gz" {
		t.Fatalf("unexpected source selection: %v %v", source, err)
	}

	base, err := basenameFromURL("https://example.com/path/archive.tar.gz")
	if err != nil || base != "archive.tar.gz" {
		t.Fatalf("unexpected basename: %v %v", base, err)
	}
}

func TestPathHelpers(t *testing.T) {
	if got := pathBase("/a/b/c.tar.gz"); got != "c.tar.gz" {
		t.Fatalf("unexpected path base: %s", got)
	}

	dir := t.TempDir()
	if _, err := safeJoin(dir, "../evil"); err == nil {
		t.Fatalf("expected error for unsafe join")
	}
	if got, err := safeJoin(dir, "nested/file.txt"); err != nil || got != filepath.Join(dir, "nested/file.txt") {
		t.Fatalf("unexpected safe join: %v %v", got, err)
	}
}

func TestBundleBindingMode(t *testing.T) {
	binding := &admissionregistrationv1.ValidatingAdmissionPolicyBinding{}
	if got := bundleBindingMode(binding); got != string(admissionregistrationv1.Deny) {
		t.Fatalf("expected default deny, got %q", got)
	}
	binding.Spec.ValidationActions = []admissionregistrationv1.ValidationAction{admissionregistrationv1.Audit}
	if got := bundleBindingMode(binding); got != "Audit" {
		t.Fatalf("unexpected binding mode: %q", got)
	}
}

func TestVerifySHA256(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "file.txt")
	if err := os.WriteFile(target, []byte("hello"), 0o644); err != nil {
		t.Fatalf("failed to write target: %v", err)
	}

	checksum := filepath.Join(dir, "file.txt.sha256")
	// precomputed sha256 for "hello"
	if err := os.WriteFile(checksum, []byte("2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"), 0o644); err != nil {
		t.Fatalf("failed to write checksum: %v", err)
	}

	if err := verifySHA256(target, checksum); err != nil {
		t.Fatalf("unexpected checksum error: %v", err)
	}
}

func TestLocalBundleIndexSetsLatest(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	versions := []string{"0.9.0", "1.0.0"}
	for _, v := range versions {
		path := filepath.Join(home, ".config", "kubeapt", "bundles", "telekom", v)
		if err := os.MkdirAll(path, 0o755); err != nil {
			t.Fatalf("failed to create version dir: %v", err)
		}
	}

	bundles, err := localBundleIndex()
	if err != nil {
		t.Fatalf("localBundleIndex error: %v", err)
	}
	if len(bundles) != 1 {
		t.Fatalf("expected 1 bundle, got %d", len(bundles))
	}
	got := bundles[0]
	if got.LatestVersion != "1.0.0" {
		t.Fatalf("expected latest version 1.0.0, got %s", got.LatestVersion)
	}
	if !got.LocalOnly {
		t.Fatalf("expected LocalOnly to be true for local bundle")
	}
}

func TestMergeBundleIndexesAddsLocalOnly(t *testing.T) {
	remote := []bundleIndexEntry{{
		Name:          "demo",
		LatestVersion: "1.0.0",
		Versions:      []string{"1.0.0"},
	}}
	local := []bundleIndexEntry{
		{
			Name:     "demo",
			Versions: []string{"0.9.0"},
		},
		{
			Name:     "telekom",
			Versions: []string{"0.1.0"},
		},
	}

	merged := mergeBundleIndexes(remote, local)

	var demo bundleIndexEntry
	var telekom bundleIndexEntry
	for _, b := range merged {
		switch b.Name {
		case "demo":
			demo = b
		case "telekom":
			telekom = b
		}
	}

	if telekom.Name != "telekom" {
		t.Fatalf("expected telekom bundle to be present")
	}
	if telekom.LatestVersion != "0.1.0" {
		t.Fatalf("expected telekom latest 0.1.0, got %s", telekom.LatestVersion)
	}
	if !telekom.LocalOnly {
		t.Fatalf("expected telekom to be marked LocalOnly")
	}
	if demo.Name != "demo" || len(demo.Versions) != 2 {
		t.Fatalf("expected demo bundle to have merged versions, got %+v", demo)
	}
	if demo.LatestVersion != "1.0.0" {
		t.Fatalf("expected demo latest to remain 1.0.0, got %s", demo.LatestVersion)
	}
	if demo.LocalOnly {
		t.Fatalf("expected demo to not be marked LocalOnly")
	}
}

func TestMarkBundleOrigins(t *testing.T) {
	bundles := []bundleIndexEntry{
		{Name: "demo", LocalOnly: true},
		{Name: "telekom", LocalOnly: true},
	}
	remote := []bundleIndexEntry{
		{Name: "demo"},
	}

	got := markBundleOrigins(bundles, remote, true)

	if got[0].LocalOnly {
		t.Fatalf("expected demo to be remote")
	}
	if !got[1].LocalOnly {
		t.Fatalf("expected telekom to stay local-only")
	}
}

func TestEnsureBundleVersionAvailablePrefersLocalWhenMissingInIndex(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	versionDir := filepath.Join(home, ".config", "kubeapt", "bundles", "custom", "v1.2.3")
	if err := os.MkdirAll(versionDir, 0o755); err != nil {
		t.Fatalf("failed creating custom bundle: %v", err)
	}

	cmd := &cobra.Command{}
	got, err := ensureBundleVersionAvailable(cmd, "custom", "")
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if got != "v1.2.3" {
		t.Fatalf("expected to pick local version v1.2.3, got %s", got)
	}
}

func TestDeprecatedBundleIndex(t *testing.T) {
	data := []byte(`[
		{"name":"cenroq-best-practices","latest-version":"v0.1.1","versions":["v0.1.1"]},
		{"name":"pod-security-admission","latest-version":"v1.36.0-cenroq","versions":["v1.36.0-cenroq"]},
		{"name":"pod-security-admission","latest-version":"v1.36.0","deprecated":1782856800,"versions":["v1.36.0","v1.35.0"]}
	]`)
	var index []bundleIndexEntry
	if err := json.Unmarshal(data, &index); err != nil {
		t.Fatalf("unmarshal index: %v", err)
	}

	// The deprecated timestamp is parsed onto the entry.
	var depTS int64
	for _, b := range index {
		if b.Name == "pod-security-admission" && b.Deprecated != 0 {
			depTS = b.Deprecated
		}
	}
	if depTS != 1782856800 {
		t.Fatalf("expected deprecated timestamp to be parsed, got %d", depTS)
	}

	// Merge keeps the current + deprecated duplicates as two separate rows.
	merged := mergeBundleIndexes(index, nil)
	psaRows := 0
	for _, b := range merged {
		if b.Name == "pod-security-admission" {
			psaRows++
		}
	}
	if psaRows != 2 {
		t.Fatalf("expected current + deprecated pod-security-admission rows, got %d", psaRows)
	}

	// Lookups prefer the current (non-deprecated) entry...
	entry, ok := findBundleIndexEntry(index, "pod-security-admission")
	if !ok || entry.Deprecated != 0 || entry.LatestVersion != "v1.36.0-cenroq" {
		t.Fatalf("expected current entry preferred, got %+v (ok=%v)", entry, ok)
	}
	if v, err := resolveBundleVersionFromIndex(merged, "pod-security-admission", ""); err != nil || v != "v1.36.0-cenroq" {
		t.Fatalf("expected latest to resolve to current v1.36.0-cenroq, got %v %v", v, err)
	}

	// ...but a still-published deprecated version stays discoverable for download.
	if !indexHasBundleVersion(index, "pod-security-admission", "v1.35.0") {
		t.Fatalf("expected deprecated version v1.35.0 to be downloadable")
	}
	if indexHasBundleVersion(index, "pod-security-admission", "v9.9.9") {
		t.Fatalf("did not expect unknown version to be found")
	}
}

// The rule between the current and the deprecated block is what tells a reader
// where the superseded bundles start.
func TestRenderBundleTableSeparatesDeprecatedBlock(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	bundles := []bundleIndexEntry{
		{Name: "cenroq-best-practices", LatestVersion: "v0.3.0", Versions: []string{"v0.3.0"}},
		{Name: "telekom", LatestVersion: "v5.0.0", Versions: []string{"v5.0.0"}, LocalOnly: true},
		{Name: "kolteq-best-practices", LatestVersion: "v0.1.1", Versions: []string{"v0.1.1"}, Deprecated: 1782856800},
	}

	var buf bytes.Buffer
	if err := renderBundleTable(bundles, nil, &buf, table.StyleDefault); err != nil {
		t.Fatalf("renderBundleTable: %v", err)
	}
	out := buf.String()

	lines := strings.Split(strings.TrimSpace(out), "\n")
	var ruleAfter, lastCurrent, firstDeprecated int
	ruleAfter = -1
	for i, line := range lines {
		switch {
		case strings.Contains(line, "telekom"):
			lastCurrent = i
		case strings.Contains(line, "kolteq-best-practices"):
			if firstDeprecated == 0 {
				firstDeprecated = i
			}
		}
	}
	// Exactly one rule sits strictly between the last current row and the
	// first deprecated one.
	for i := lastCurrent + 1; i < firstDeprecated; i++ {
		if isTableRule(lines[i]) {
			ruleAfter = i
		}
	}
	if ruleAfter == -1 {
		t.Fatalf("no rule between the current and deprecated rows:\n%s", out)
	}
}

// A listing that is entirely deprecated must not open with a doubled rule.
func TestRenderBundleTableNoLeadingSeparator(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	bundles := []bundleIndexEntry{
		{Name: "kolteq-best-practices", LatestVersion: "v0.1.1", Versions: []string{"v0.1.1"}, Deprecated: 1782856800},
		{Name: "old-thing", LatestVersion: "v1.0.0", Versions: []string{"v1.0.0"}, Deprecated: 1782856800},
	}

	var buf bytes.Buffer
	if err := renderBundleTable(bundles, nil, &buf, table.StyleDefault); err != nil {
		t.Fatalf("renderBundleTable: %v", err)
	}
	lines := strings.Split(strings.TrimSpace(buf.String()), "\n")

	var headerRow int
	for i, line := range lines {
		if strings.Contains(line, "BUNDLE") {
			headerRow = i
			break
		}
	}
	// One rule closes the header; a second would be the suppressed separator.
	if isTableRule(lines[headerRow+1]) && isTableRule(lines[headerRow+2]) {
		t.Fatalf("separator was emitted directly under the header:\n%s", buf.String())
	}
}

// With nothing deprecated the table carries no extra rule at all.
func TestRenderBundleTableNoSeparatorWhenNoneDeprecated(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	bundles := []bundleIndexEntry{
		{Name: "a-bundle", LatestVersion: "v1", Versions: []string{"v1"}},
		{Name: "b-bundle", LatestVersion: "v1", Versions: []string{"v1"}},
	}

	var buf bytes.Buffer
	if err := renderBundleTable(bundles, nil, &buf, table.StyleDefault); err != nil {
		t.Fatalf("renderBundleTable: %v", err)
	}
	rules := 0
	for _, line := range strings.Split(strings.TrimSpace(buf.String()), "\n") {
		if isTableRule(line) {
			rules++
		}
	}
	// StyleDefault draws a rule above the header, below it, and at the foot.
	if rules != 3 {
		t.Fatalf("rules = %d, want 3 (no deprecated separator):\n%s", rules, buf.String())
	}
}

// isTableRule reports whether a rendered line is a horizontal rule rather than
// a data row.
func isTableRule(line string) bool {
	trimmed := strings.TrimSpace(line)
	if trimmed == "" {
		return false
	}
	return strings.IndexFunc(trimmed, func(r rune) bool {
		return r != '-' && r != '+' && r != '\u2500' && r != '\u251c' && r != '\u2524' &&
			r != '\u252c' && r != '\u2534' && r != '\u253c' && r != '\u256d' && r != '\u256e' &&
			r != '\u256f' && r != '\u2570' && r != ' '
	}) == -1
}

func TestSortBundleEntriesForDisplayPutsDeprecatedLast(t *testing.T) {
	const older = int64(1700000000)
	const newer = int64(1782856800)
	entries := []bundleIndexEntry{
		{Name: "pod-security-admission", Deprecated: newer},
		{Name: "aaa-legacy", Deprecated: older},
		{Name: "pod-security-admission"},
		{Name: "cenroq-best-practices"},
	}

	sortBundleEntriesForDisplay(entries)

	var got []string
	for _, entry := range entries {
		label := entry.Name
		if entry.Deprecated != 0 {
			label += " (deprecated)"
		}
		got = append(got, label)
	}
	want := []string{
		"cenroq-best-practices",
		"pod-security-admission",
		"aaa-legacy (deprecated)",
		"pod-security-admission (deprecated)",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("order = %v, want %v", got, want)
	}
}

// The merge path pairs a deprecated entry with the current one of the same
// name by adjacency, so it must keep the name-first order.
func TestSortBundleEntriesKeepsDeprecatedBesideItsCurrent(t *testing.T) {
	entries := []bundleIndexEntry{
		{Name: "pod-security-admission", Deprecated: 1782856800},
		{Name: "zzz-other"},
		{Name: "pod-security-admission"},
	}

	sortBundleEntries(entries)

	if entries[0].Name != "pod-security-admission" || entries[0].Deprecated != 0 {
		t.Fatalf("entry 0 = %+v, want the current pod-security-admission", entries[0])
	}
	if entries[1].Name != "pod-security-admission" || entries[1].Deprecated == 0 {
		t.Fatalf("entry 1 = %+v, want its deprecated duplicate", entries[1])
	}
}

func TestMergeBundleIndexesDeprecatedLocalDownloads(t *testing.T) {
	const depTS = int64(1782856800)
	remote := []bundleIndexEntry{
		{Name: "cenroq-best-practices", LatestVersion: "v0.1.1", Versions: []string{"v0.1.1"}},
		{Name: "pod-security-admission", LatestVersion: "v1.36.0-cenroq", Versions: []string{"v1.36.0-cenroq"}},
		{Name: "legacy-best-practices", LatestVersion: "v0.1.1", Versions: []string{"v0.1.1", "v0.1.0"}, Deprecated: depTS},
		{Name: "pod-security-admission", LatestVersion: "v1.36.0", Versions: []string{"v1.36.0", "v1.35.0", "v1.34.0"}, Deprecated: depTS},
	}
	// Everything downloaded locally belongs to the deprecated (legacy) lineage.
	local := []bundleIndexEntry{
		{Name: "legacy-best-practices", Versions: []string{"v0.1.0", "v0.1.1"}},
		{Name: "pod-security-admission", Versions: []string{"v1.34.0", "v1.36.0"}},
		{Name: "telekom", Versions: []string{"v5.0.0"}},
	}

	merged := mergeBundleIndexes(remote, local)

	rows := map[string]int{}
	for _, b := range merged {
		rows[b.Name]++
	}
	// A deprecated-only bundle that is also downloaded locally must not duplicate.
	if rows["legacy-best-practices"] != 1 {
		t.Fatalf("expected legacy-best-practices to appear once, got %d", rows["legacy-best-practices"])
	}
	if rows["pod-security-admission"] != 2 {
		t.Fatalf("expected pod-security-admission current + deprecated rows, got %d", rows["pod-security-admission"])
	}
	if rows["telekom"] != 1 {
		t.Fatalf("expected telekom local-only row, got %d", rows["telekom"])
	}

	for _, b := range merged {
		// The current entry must not be polluted with deprecated-lineage versions.
		if b.Name == "pod-security-admission" && b.Deprecated == 0 {
			if len(b.Versions) != 1 || b.Versions[0] != "v1.36.0-cenroq" {
				t.Fatalf("current pod-security-admission should list only v1.36.0-cenroq, got %v", b.Versions)
			}
		}
		if b.Name == "telekom" && !b.LocalOnly {
			t.Fatalf("expected telekom to be marked local-only")
		}
	}
}

// The Downloaded and Installed columns line up one mark per listed version.
func TestRenderBundleTableMarksDownloadedAndInstalled(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	if err := os.MkdirAll(filepath.Join(home, ".config", "kubeapt", "bundles", "cenroq-best-practices", "v0.2.0"), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	bundles := []bundleIndexEntry{
		{Name: "cenroq-best-practices", LatestVersion: "v0.3.0", Versions: []string{"v0.3.0", "v0.2.0"}},
		{Name: "unversioned"},
	}
	installed := map[string]map[string]struct{}{"cenroq-best-practices": {"v0.3.0": {}}}

	var buf bytes.Buffer
	if err := renderBundleTable(bundles, installed, &buf, table.StyleDefault); err != nil {
		t.Fatalf("renderBundleTable: %v", err)
	}
	lines := strings.Split(buf.String(), "\n")
	// row finds the line whose cell in column col reads value. Columns are
	// "", Bundle, Origin, Latest, Deprecated, Versions, Downloaded, Installed, "".
	row := func(col int, value string) []string {
		for _, line := range lines {
			if cells := strings.Split(line, "|"); len(cells) == 9 && strings.TrimSpace(cells[col]) == value {
				return cells
			}
		}
		t.Fatalf("no row with %q in column %d:\n%s", value, col, buf.String())
		return nil
	}
	latest, older := row(5, "v0.3.0"), row(5, "v0.2.0")
	if strings.TrimSpace(latest[6]) != "" || strings.TrimSpace(latest[7]) != "x" {
		t.Errorf("v0.3.0 downloaded/installed = %q/%q, want \"\"/x", latest[6], latest[7])
	}
	if strings.TrimSpace(older[6]) != "x" || strings.TrimSpace(older[7]) != "" {
		t.Errorf("v0.2.0 downloaded/installed = %q/%q, want x/\"\"", older[6], older[7])
	}
	if unversioned := row(1, "unversioned"); strings.TrimSpace(unversioned[3]) != "-" || strings.TrimSpace(unversioned[5]) != "-" {
		t.Errorf("unversioned latest/versions = %q/%q, want -/-", unversioned[3], unversioned[5])
	}
}

func TestRenderBundleTableReturnsVersionLookupError(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	bundlesDir := filepath.Join(home, ".config", "kubeapt", "bundles")
	if err := os.MkdirAll(bundlesDir, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	// A regular file where the bundle's directory belongs cannot be listed.
	if err := os.WriteFile(filepath.Join(bundlesDir, "broken"), []byte("x"), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	err := renderBundleTable([]bundleIndexEntry{{Name: "broken"}}, nil, &bytes.Buffer{}, table.StyleDefault)
	if err == nil {
		t.Fatal("expected the version lookup error to be returned")
	}
}

// Two deprecated generations of one bundle list oldest first, so the order is
// stable across runs.
func TestSortBundleEntriesForDisplayOrdersDeprecatedGenerations(t *testing.T) {
	entries := []bundleIndexEntry{
		{Name: "legacy", Deprecated: 1782856800},
		{Name: "legacy", Deprecated: 1700000000},
	}
	sortBundleEntriesForDisplay(entries)
	if entries[0].Deprecated != 1700000000 {
		t.Fatalf("order = %d, %d; want the older deprecation first", entries[0].Deprecated, entries[1].Deprecated)
	}
}
