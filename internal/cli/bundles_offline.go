// Copyright by cenroq AG
// Contact: info@cenroq.com

package cli

import (
	"archive/tar"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"

	"github.com/cenroq/kubeapt/v2/internal/config"
	"github.com/cenroq/kubeapt/v2/internal/logging"
)

func newBundleImportCmd() *cobra.Command {
	var from string
	var checksum string
	var force bool
	cmd := &cobra.Command{
		Use:   "import",
		Short: "Install a policy bundle from a local tarball (offline / air-gapped)",
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runBundleImport(cmd, from, checksum, force)
		},
	}
	cmd.Flags().StringVar(&from, "from", "", "Path to a bundle archive (.tar.gz). Required.")
	cmd.Flags().StringVar(&checksum, "checksum", "", "Expected SHA-256 of the archive (hex). Overrides any sidecar file.")
	cmd.Flags().BoolVar(&force, "force", false, "Overwrite an existing bundle version on disk")
	_ = cmd.MarkFlagRequired("from")
	return cmd
}

func newBundleExportCmd() *cobra.Command {
	var version string
	var output string
	cmd := &cobra.Command{
		Use:   "export <bundle-name>",
		Short: "Export an installed bundle as a portable .tar.gz for offline / air-gapped transfer",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runBundleExport(cmd, args[0], version, output)
		},
	}
	cmd.Flags().StringVar(&version, "version", "", "Bundle version to export (defaults to the latest installed)")
	cmd.Flags().StringVar(&output, "output", "", "Output path (defaults to <bundle>-<version>.tar.gz in the current directory)")
	return cmd
}

func runBundleImport(cmd *cobra.Command, from, checksum string, force bool) error {
	if strings.TrimSpace(from) == "" {
		return errors.New("--from is required")
	}
	info, err := os.Stat(from)
	if err != nil {
		return fmt.Errorf("read archive %s: %w", from, err)
	}
	if info.IsDir() {
		return fmt.Errorf("--from must point at a .tar.gz file, got directory %s", from)
	}

	if err := verifyArchiveChecksum(from, checksum); err != nil {
		return err
	}

	manifest, err := readBundleManifestFromArchive(from)
	if err != nil {
		return err
	}
	bundleName, err := importBundleName(from, manifest)
	if err != nil {
		return err
	}
	bundleVersion := strings.TrimSpace(manifest.Version)
	if err := validateBundleSegment("bundle name", bundleName); err != nil {
		return fmt.Errorf("archive bundle.json: %w", err)
	}
	if err := validateBundleSegment("bundle version", bundleVersion); err != nil {
		return fmt.Errorf("archive bundle.json: %w", err)
	}

	dest, err := config.BundleVersionDir(bundleName, bundleVersion)
	if err != nil {
		return err
	}
	if _, statErr := os.Stat(dest); statErr == nil {
		if !force {
			return fmt.Errorf("bundle %s version %s already installed at %s; pass --force to overwrite", bundleName, bundleVersion, dest)
		}
		if err := os.RemoveAll(dest); err != nil {
			return fmt.Errorf("remove existing bundle dir %s: %w", dest, err)
		}
	} else if !errors.Is(statErr, os.ErrNotExist) {
		return statErr
	}

	if err := os.MkdirAll(filepath.Dir(dest), 0o755); err != nil {
		return err
	}
	staging, err := os.MkdirTemp(filepath.Dir(dest), ".kubeapt-import-*")
	if err != nil {
		return fmt.Errorf("create staging dir: %w", err)
	}
	stagingCleanup := true
	defer func() {
		if stagingCleanup {
			_ = os.RemoveAll(staging)
		}
	}()

	if err := extractTarGzStripRoot(from, staging); err != nil {
		return fmt.Errorf("extract archive: %w", err)
	}
	for _, required := range []string{"bundle.json", "policies.yaml", "bindings.yaml"} {
		if _, err := os.Stat(filepath.Join(staging, required)); err != nil {
			return fmt.Errorf("archive missing required file %s: %w", required, err)
		}
	}

	if err := os.Rename(staging, dest); err != nil {
		return fmt.Errorf("install bundle into %s: %w", dest, err)
	}
	stagingCleanup = false

	logging.Infof("Imported bundle %s %s into %s", bundleName, bundleVersion, dest)
	return nil
}

func runBundleExport(cmd *cobra.Command, bundleName, version, output string) error {
	if err := validateBundleSegment("bundle name", bundleName); err != nil {
		return err
	}
	version = strings.TrimSpace(version)
	if version == "" {
		versions, err := config.BundleVersions(bundleName)
		if err != nil {
			return err
		}
		if len(versions) == 0 {
			dir, dErr := config.BundleDir(bundleName)
			if dErr != nil {
				return dErr
			}
			return fmt.Errorf("bundle %s is not installed under %s", bundleName, dir)
		}
		version = versions[len(versions)-1]
	} else if err := validateBundleSegment("bundle version", version); err != nil {
		return err
	}

	sourceDir, err := config.BundleVersionDir(bundleName, version)
	if err != nil {
		return err
	}
	for _, required := range []string{"bundle.json", "policies.yaml", "bindings.yaml"} {
		if _, err := os.Stat(filepath.Join(sourceDir, required)); err != nil {
			return fmt.Errorf("bundle %s %s missing %s: %w", bundleName, version, required, err)
		}
	}

	if strings.TrimSpace(output) == "" {
		output = fmt.Sprintf("%s-%s.tar.gz", bundleName, version)
	}
	if outDir := filepath.Dir(output); outDir != "" && outDir != "." {
		if err := os.MkdirAll(outDir, 0o755); err != nil {
			return err
		}
	}

	if err := packBundleArchive(sourceDir, bundleName, output); err != nil {
		return fmt.Errorf("pack archive %s: %w", output, err)
	}
	checksumPath := output + ".sha256"
	if err := writeSHA256Sidecar(output, checksumPath); err != nil {
		return fmt.Errorf("write checksum %s: %w", checksumPath, err)
	}

	logging.Infof("Exported bundle %s %s to %s (+ %s)", bundleName, version, output, checksumPath)
	return nil
}

// verifyArchiveChecksum checks the archive against explicit or sidecar checksum.
func verifyArchiveChecksum(archivePath, explicit string) error {
	actual, err := sha256File(archivePath)
	if err != nil {
		return err
	}
	if explicit = strings.TrimSpace(explicit); explicit != "" {
		if !strings.EqualFold(strings.ToLower(explicit), actual) {
			return fmt.Errorf("checksum mismatch for %s (expected %s, got %s)", archivePath, explicit, actual)
		}
		return nil
	}
	sidecar := archivePath + ".sha256"
	if _, err := os.Stat(sidecar); err == nil {
		return verifySHA256(archivePath, sidecar)
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return fmt.Errorf("no checksum provided for %s: pass --checksum or place a %s sidecar", archivePath, sidecar)
}

func sha256File(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	hasher := sha256.New()
	if _, err := io.Copy(hasher, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(hasher.Sum(nil)), nil
}

// importBundleName returns the name a bundle archive installs under, the one
// `bundles download` and --bundle use (cenroq-best-practices).
//
// Release archives and the ones `bundles export` writes keep every file below
// a single root directory with that name. bundle.json's name is the display
// name ("cenroq Best Practices"), so it is only the fallback, for flat archives
// written by kubeapt releases before the export gained its root directory.
func importBundleName(archivePath string, manifest bundleManifest) (string, error) {
	root, err := detectTarRoot(archivePath)
	if err != nil {
		return "", fmt.Errorf("read archive %s: %w", archivePath, err)
	}
	if root != "" && validateBundleSegment("bundle name", root) == nil {
		return root, nil
	}
	return strings.TrimSpace(manifest.Name), nil
}

// readBundleManifestFromArchive parses bundle.json from the tarball without unpacking.
func readBundleManifestFromArchive(archivePath string) (bundleManifest, error) {
	f, err := os.Open(archivePath)
	if err != nil {
		return bundleManifest{}, err
	}
	defer f.Close()
	gz, err := gzip.NewReader(f)
	if err != nil {
		return bundleManifest{}, err
	}
	defer gz.Close()
	reader := tar.NewReader(gz)
	for {
		header, err := reader.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return bundleManifest{}, err
		}
		name := filepath.Base(header.Name)
		if name != "bundle.json" {
			continue
		}
		data, err := io.ReadAll(reader)
		if err != nil {
			return bundleManifest{}, err
		}
		var m bundleManifest
		if err := json.Unmarshal(data, &m); err != nil {
			return bundleManifest{}, fmt.Errorf("parse bundle.json: %w", err)
		}
		return m, nil
	}
	return bundleManifest{}, errors.New("archive does not contain bundle.json")
}

// packBundleArchive writes the bundle's files below a <bundleName>/ root
// directory, the layout of release archives, so that importing the archive
// installs it under the same name again.
func packBundleArchive(sourceDir, bundleName, output string) error {
	out, err := os.Create(output)
	if err != nil {
		return err
	}
	defer out.Close()
	gz := gzip.NewWriter(out)
	defer gz.Close()
	tw := tar.NewWriter(gz)
	defer tw.Close()

	// Fixed file list keeps the archive minimal and predictable.
	for _, name := range []string{"bundle.json", "policies.yaml", "bindings.yaml"} {
		path := filepath.Join(sourceDir, name)
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		hdr := &tar.Header{
			Name:     bundleName + "/" + name,
			Mode:     0o644,
			Size:     int64(len(data)),
			Typeflag: tar.TypeReg,
		}
		if err := tw.WriteHeader(hdr); err != nil {
			return err
		}
		if _, err := tw.Write(data); err != nil {
			return err
		}
	}
	return nil
}

func writeSHA256Sidecar(archivePath, sidecarPath string) error {
	hex, err := sha256File(archivePath)
	if err != nil {
		return err
	}
	line := fmt.Sprintf("%s  %s\n", hex, filepath.Base(archivePath))
	return os.WriteFile(sidecarPath, []byte(line), 0o644)
}
