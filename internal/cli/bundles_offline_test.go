// Copyright by cenroq AG
// Contact: info@cenroq.com

package cli

import (
	"archive/tar"
	"compress/gzip"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spf13/cobra"

	"github.com/cenroq/kubeapt/v2/internal/config"
)

const (
	testBundleName    = "test-bundle"
	testBundleVersion = "1.0.0"
	// Real bundle.json files carry a display name, not the bundle's directory
	// name, so the fixture does too.
	testBundleDisplayName = "Test Bundle"

	fixturePoliciesYAML = "apiVersion: admissionregistration.k8s.io/v1\nkind: ValidatingAdmissionPolicy\nmetadata:\n  name: p\n"
	fixtureBindingsYAML = "apiVersion: admissionregistration.k8s.io/v1\nkind: ValidatingAdmissionPolicyBinding\nmetadata:\n  name: b\nspec:\n  policyName: p\n"
)

// seedInstalledBundle writes a fixture bundle and returns its version dir.
func seedInstalledBundle(t *testing.T) string {
	t.Helper()
	versionDir, err := config.BundleVersionDir(testBundleName, testBundleVersion)
	if err != nil {
		t.Fatalf("BundleVersionDir: %v", err)
	}
	if err := os.MkdirAll(versionDir, 0o755); err != nil {
		t.Fatalf("mkdir bundle: %v", err)
	}

	manifest := bundleManifest{Name: testBundleDisplayName, Version: testBundleVersion, Description: "fixture"}
	manifestBytes, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	writes := map[string][]byte{
		"bundle.json":   manifestBytes,
		"policies.yaml": []byte(fixturePoliciesYAML),
		"bindings.yaml": []byte(fixtureBindingsYAML),
	}
	for name, data := range writes {
		if err := os.WriteFile(filepath.Join(versionDir, name), data, 0o644); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
	}
	return versionDir
}

func TestBundleExportImportRoundTrip(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	versionDir := seedInstalledBundle(t)

	outDir := t.TempDir()
	archivePath := filepath.Join(outDir, "bundle.tar.gz")
	if err := runBundleExport(&cobra.Command{}, testBundleName, testBundleVersion, archivePath); err != nil {
		t.Fatalf("runBundleExport: %v", err)
	}
	if _, err := os.Stat(archivePath); err != nil {
		t.Errorf("archive not written: %v", err)
	}
	if _, err := os.Stat(archivePath + ".sha256"); err != nil {
		t.Errorf("sha256 sidecar not written: %v", err)
	}
	// Like a release archive, everything sits below the bundle's name.
	for _, name := range tarEntryNames(t, archivePath) {
		if !strings.HasPrefix(name, testBundleName+"/") {
			t.Errorf("archive entry %q is not below %s/", name, testBundleName)
		}
	}

	// Wipe the installed bundle so import can rebuild it from the archive.
	if err := os.RemoveAll(versionDir); err != nil {
		t.Fatal(err)
	}

	if err := runBundleImport(&cobra.Command{}, archivePath, "", false); err != nil {
		t.Fatalf("runBundleImport: %v", err)
	}

	// Verify the round-tripped files match what was seeded.
	for name, want := range map[string]string{
		"policies.yaml": fixturePoliciesYAML,
		"bindings.yaml": fixtureBindingsYAML,
	} {
		got, err := os.ReadFile(filepath.Join(versionDir, name))
		if err != nil {
			t.Errorf("read %s: %v", name, err)
			continue
		}
		if string(got) != want {
			t.Errorf("%s mismatch after round-trip:\n got: %q\nwant: %q", name, got, want)
		}
	}
}

func TestBundleImport_RejectsTamperedArchive(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	versionDir := seedInstalledBundle(t)
	outDir := t.TempDir()
	archivePath := filepath.Join(outDir, "bundle.tar.gz")
	if err := runBundleExport(&cobra.Command{}, testBundleName, testBundleVersion, archivePath); err != nil {
		t.Fatalf("runBundleExport: %v", err)
	}

	// Corrupt the archive bytes without touching the sidecar.
	data, err := os.ReadFile(archivePath)
	if err != nil {
		t.Fatal(err)
	}
	data[len(data)-10] ^= 0xFF
	if err := os.WriteFile(archivePath, data, 0o644); err != nil {
		t.Fatal(err)
	}

	if err := os.RemoveAll(versionDir); err != nil {
		t.Fatal(err)
	}

	err = runBundleImport(&cobra.Command{}, archivePath, "", false)
	if err == nil {
		t.Fatal("runBundleImport on tampered archive = nil, want error")
	}
	if !strings.Contains(err.Error(), "checksum") {
		t.Errorf("err = %v, want checksum-related error", err)
	}
}

func TestBundleImport_RequiresChecksum(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	seedInstalledBundle(t)
	outDir := t.TempDir()
	archivePath := filepath.Join(outDir, "bundle.tar.gz")
	if err := runBundleExport(&cobra.Command{}, testBundleName, testBundleVersion, archivePath); err != nil {
		t.Fatalf("runBundleExport: %v", err)
	}
	// Remove the sidecar so the import has no checksum source.
	if err := os.Remove(archivePath + ".sha256"); err != nil {
		t.Fatal(err)
	}

	err := runBundleImport(&cobra.Command{}, archivePath, "", true)
	if err == nil {
		t.Fatal("runBundleImport without checksum = nil, want error")
	}
	if !strings.Contains(err.Error(), "checksum") {
		t.Errorf("err = %v, want checksum-related error", err)
	}
}

func TestBundleImport_RefusesOverwriteWithoutForce(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	seedInstalledBundle(t)
	outDir := t.TempDir()
	archivePath := filepath.Join(outDir, "bundle.tar.gz")
	if err := runBundleExport(&cobra.Command{}, testBundleName, testBundleVersion, archivePath); err != nil {
		t.Fatalf("runBundleExport: %v", err)
	}

	// Bundle is still installed on disk; import without --force must refuse.
	err := runBundleImport(&cobra.Command{}, archivePath, "", false)
	if err == nil {
		t.Fatal("runBundleImport over existing = nil, want error")
	}
	if !strings.Contains(err.Error(), "--force") {
		t.Errorf("err = %v, want '--force' hint", err)
	}

	// With --force the import should succeed.
	if err := runBundleImport(&cobra.Command{}, archivePath, "", true); err != nil {
		t.Errorf("runBundleImport --force: %v", err)
	}
}

type tarEntry struct {
	name string
	data string // a directory when empty and name ends in "/"
}

// writeBundleArchive writes a .tar.gz of entries plus its .sha256 sidecar.
func writeBundleArchive(t *testing.T, path string, entries []tarEntry) {
	t.Helper()
	out, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	gz := gzip.NewWriter(out)
	tw := tar.NewWriter(gz)
	for _, e := range entries {
		hdr := &tar.Header{Name: e.name, Mode: 0o644, Size: int64(len(e.data)), Typeflag: tar.TypeReg}
		if strings.HasSuffix(e.name, "/") {
			hdr = &tar.Header{Name: e.name, Mode: 0o755, Typeflag: tar.TypeDir}
		}
		if err := tw.WriteHeader(hdr); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write([]byte(e.data)); err != nil {
			t.Fatal(err)
		}
	}
	for _, c := range []io.Closer{tw, gz, out} {
		if err := c.Close(); err != nil {
			t.Fatal(err)
		}
	}
	if err := writeSHA256Sidecar(path, path+".sha256"); err != nil {
		t.Fatal(err)
	}
}

func tarEntryNames(t *testing.T, path string) []string {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	gz, err := gzip.NewReader(f)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	tr := tar.NewReader(gz)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			return names
		}
		if err != nil {
			t.Fatal(err)
		}
		names = append(names, hdr.Name)
	}
}

func manifestJSON(t *testing.T, name, version string) string {
	t.Helper()
	data, err := json.Marshal(bundleManifest{Name: name, Version: version})
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

// A release archive is rooted at the bundle's name, while its bundle.json
// carries the display name. The bundle must install under the root name, the
// one --bundle and `bundles download` use, with its probes.
func TestBundleImport_ReleaseArchiveInstallsUnderRootName(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	const root = "cenroq-best-practices/"
	archivePath := filepath.Join(t.TempDir(), "cenroq-best-practices_v0.4.0.tar.gz")
	writeBundleArchive(t, archivePath, []tarEntry{
		{name: root},
		{name: root + "README.md", data: "readme"},
		{name: root + "bindings.yaml", data: fixtureBindingsYAML},
		{name: root + "policies.yaml", data: fixturePoliciesYAML},
		{name: root + "probes/"},
		{name: root + "probes/deny.yaml", data: "kind: Pod\n"},
		{name: root + "bundle.json", data: manifestJSON(t, "cenroq Best Practices", "v0.4.0")},
	})

	if err := runBundleImport(&cobra.Command{}, archivePath, "", false); err != nil {
		t.Fatalf("runBundleImport: %v", err)
	}

	versionDir, err := config.BundleVersionDir("cenroq-best-practices", "v0.4.0")
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"bundle.json", "policies.yaml", "bindings.yaml", "probes/deny.yaml"} {
		if _, err := os.Stat(filepath.Join(versionDir, name)); err != nil {
			t.Errorf("%s not installed: %v", name, err)
		}
	}
	versions, err := config.BundleVersions("cenroq-best-practices")
	if err != nil || len(versions) != 1 || versions[0] != "v0.4.0" {
		t.Errorf("BundleVersions = %v, %v; want [v0.4.0]", versions, err)
	}
	displayDir, err := config.BundleDir("cenroq Best Practices")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(displayDir); !os.IsNotExist(err) {
		t.Errorf("bundle also installed under its display name %s (stat err %v)", displayDir, err)
	}
}

// Archives exported by older kubeapt releases have no root directory; they
// still install under bundle.json's name, as before.
func TestBundleImport_FlatArchiveUsesManifestName(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	archivePath := filepath.Join(t.TempDir(), "legacy.tar.gz")
	writeBundleArchive(t, archivePath, []tarEntry{
		{name: "bundle.json", data: manifestJSON(t, "legacy-bundle", "1.0.0")},
		{name: "policies.yaml", data: fixturePoliciesYAML},
		{name: "bindings.yaml", data: fixtureBindingsYAML},
	})

	if err := runBundleImport(&cobra.Command{}, archivePath, "", false); err != nil {
		t.Fatalf("runBundleImport: %v", err)
	}
	versionDir, err := config.BundleVersionDir("legacy-bundle", "1.0.0")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(versionDir, "policies.yaml")); err != nil {
		t.Errorf("policies.yaml not installed under legacy-bundle: %v", err)
	}
}

// A name or version of "." or ".." would put the install dir, and with
// --force the directory import removes first, outside the bundles dir.
func TestBundleImport_RejectsDotSegments(t *testing.T) {
	tests := []struct{ name, version string }{
		{"..", "1.0.0"},
		{"legacy-bundle", ".."},
		{".", "1.0.0"},
		{"legacy-bundle", "."},
	}
	for _, tc := range tests {
		t.Run(tc.name+"@"+tc.version, func(t *testing.T) {
			home := t.TempDir()
			t.Setenv("HOME", home)
			archivePath := filepath.Join(t.TempDir(), "evil.tar.gz")
			writeBundleArchive(t, archivePath, []tarEntry{
				{name: "bundle.json", data: manifestJSON(t, tc.name, tc.version)},
				{name: "policies.yaml", data: fixturePoliciesYAML},
				{name: "bindings.yaml", data: fixtureBindingsYAML},
			})
			err := runBundleImport(&cobra.Command{}, archivePath, "", true)
			if err == nil || !strings.Contains(err.Error(), "invalid path elements") {
				t.Fatalf("runBundleImport = %v, want an invalid path elements error", err)
			}
			if _, statErr := os.Stat(home); statErr != nil {
				t.Fatalf("home removed: %v", statErr)
			}
		})
	}
}

func TestValidateBundleSegmentTable(t *testing.T) {
	for _, ok := range []string{"cenroq-best-practices", "v0.4.0", "Pod Security Admission", "1.0.0"} {
		if err := validateBundleSegment("x", ok); err != nil {
			t.Errorf("validateBundleSegment(%q) = %v, want nil", ok, err)
		}
	}
	for _, bad := range []string{"", ".", "..", "a/b", `a\b`, "../x"} {
		if err := validateBundleSegment("x", bad); err == nil {
			t.Errorf("validateBundleSegment(%q) = nil, want error", bad)
		}
	}
}
