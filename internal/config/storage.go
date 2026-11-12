// Copyright by cenroq AG
// Contact: info@cenroq.com

package config

import (
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"

	"github.com/cenroq/kubeapt/v2/internal/kubernetes"
)

const (
	bundlesDirName         = "bundles"
	policiesDirName        = "policies"
	bundlePoliciesFilename = "policies.yaml"
	bundleBindingsFilename = "bindings.yaml"
)

func KubeaptDir() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".config", "kubeapt"), nil
}

func BundlesDir() (string, error) {
	root, err := KubeaptDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(root, bundlesDirName), nil
}

func BundleDir(bundleName string) (string, error) {
	root, err := BundlesDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(root, bundleName), nil
}

func BundleVersionDir(bundleName, version string) (string, error) {
	root, err := BundleDir(bundleName)
	if err != nil {
		return "", err
	}
	return filepath.Join(root, version), nil
}

func BundlePoliciesPath(bundleName, version string) (string, error) {
	root, err := BundleVersionDir(bundleName, version)
	if err != nil {
		return "", err
	}
	return filepath.Join(root, bundlePoliciesFilename), nil
}

func BundleBindingsPath(bundleName, version string) (string, error) {
	root, err := BundleVersionDir(bundleName, version)
	if err != nil {
		return "", err
	}
	return filepath.Join(root, bundleBindingsFilename), nil
}

func BundleManifestPath(bundleName, version string) (string, error) {
	root, err := BundleVersionDir(bundleName, version)
	if err != nil {
		return "", err
	}
	return filepath.Join(root, "bundle.json"), nil
}

func BundleIndexPath() (string, error) {
	root, err := BundlesDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(root, "bundles.json"), nil
}

func PoliciesDir() (string, error) {
	root, err := KubeaptDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(root, policiesDirName), nil
}

func PoliciesIndexPath() (string, error) {
	root, err := PoliciesDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(root, "policies.json"), nil
}

func PolicyVersionDir(version string) (string, error) {
	root, err := PoliciesDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(root, version), nil
}

func PolicyVersions() ([]string, error) {
	path, err := PoliciesDir()
	if err != nil {
		return nil, err
	}
	entries, err := os.ReadDir(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var versions []string
	for _, entry := range entries {
		if entry.IsDir() {
			versions = append(versions, entry.Name())
		}
	}
	sort.Slice(versions, func(i, j int) bool {
		return compareVersions(versions[i], versions[j]) < 0
	})
	return versions, nil
}

func BundleVersions(bundleName string) ([]string, error) {
	path, err := BundleDir(bundleName)
	if err != nil {
		return nil, err
	}
	entries, err := os.ReadDir(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var versions []string
	for _, entry := range entries {
		if entry.IsDir() {
			versions = append(versions, entry.Name())
		}
	}
	sort.Slice(versions, func(i, j int) bool {
		return compareVersions(versions[i], versions[j]) < 0
	})
	return versions, nil
}

func LocateBundleFiles(bundleName, version string) (string, string, bool, error) {
	if version == "" {
		versions, err := BundleVersions(bundleName)
		if err != nil {
			return "", "", false, err
		}
		if len(versions) == 0 {
			return "", "", false, nil
		}
		version = versions[len(versions)-1]
	}

	policiesPath, err := BundlePoliciesPath(bundleName, version)
	if err != nil {
		return "", "", false, err
	}
	if _, err := os.Stat(policiesPath); err != nil {
		if os.IsNotExist(err) {
			return "", "", false, nil
		}
		return "", "", false, err
	}

	bindingsPath, err := BundleBindingsPath(bundleName, version)
	if err != nil {
		return "", "", false, err
	}
	if _, err := os.Stat(bindingsPath); err != nil {
		if os.IsNotExist(err) {
			return "", "", false, nil
		}
		return "", "", false, err
	}

	return policiesPath, bindingsPath, true, nil
}

func LoadPoliciesFromFilesWithProgress(files []string, onFile func()) ([]admissionregistrationv1.ValidatingAdmissionPolicy, error) {
	var policies []admissionregistrationv1.ValidatingAdmissionPolicy
	for _, file := range files {
		items, err := kubernetes.LoadValidatingAdmissionPolicies(file)
		if err != nil {
			return nil, err
		}
		policies = append(policies, items...)
		if onFile != nil {
			onFile()
		}
	}
	return policies, nil
}

func LoadBindingsFromFilesWithProgress(files []string, onFile func()) ([]admissionregistrationv1.ValidatingAdmissionPolicyBinding, error) {
	var bindings []admissionregistrationv1.ValidatingAdmissionPolicyBinding
	for _, file := range files {
		items, err := kubernetes.LoadValidatingAdmissionPolicyBindings(file)
		if err != nil {
			return nil, err
		}
		bindings = append(bindings, items...)
		if onFile != nil {
			onFile()
		}
	}
	return bindings, nil
}

func CollectManifestFilesRecursive(root string) ([]string, error) {
	info, err := os.Stat(root)
	if err != nil {
		return nil, err
	}
	if !info.IsDir() {
		return []string{root}, nil
	}
	var files []string
	err = filepath.WalkDir(root, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() {
			return nil
		}
		name := strings.ToLower(entry.Name())
		if !strings.HasSuffix(name, ".yaml") && !strings.HasSuffix(name, ".yml") && !strings.HasSuffix(name, ".json") {
			return nil
		}
		files = append(files, path)
		return nil
	})
	if err != nil {
		return nil, err
	}
	return files, nil
}

func compareVersions(a, b string) int {
	aParts, aOK := parseVersionParts(a)
	bParts, bOK := parseVersionParts(b)
	if !aOK || !bOK {
		return strings.Compare(a, b)
	}
	maxParts := len(aParts)
	if len(bParts) > maxParts {
		maxParts = len(bParts)
	}
	for i := 0; i < maxParts; i++ {
		aVal := 0
		if i < len(aParts) {
			aVal = aParts[i]
		}
		bVal := 0
		if i < len(bParts) {
			bVal = bParts[i]
		}
		if aVal == bVal {
			continue
		}
		if aVal < bVal {
			return -1
		}
		return 1
	}
	return strings.Compare(a, b)
}

func parseVersionParts(version string) ([]int, bool) {
	trimmed := strings.TrimSpace(version)
	trimmed = strings.TrimPrefix(trimmed, "v")
	trimmed = strings.TrimPrefix(trimmed, "V")
	for _, sep := range []string{"-", "+"} {
		if idx := strings.Index(trimmed, sep); idx >= 0 {
			trimmed = trimmed[:idx]
			break
		}
	}
	if trimmed == "" {
		return nil, false
	}
	rawParts := strings.Split(trimmed, ".")
	parts := make([]int, 0, len(rawParts))
	for _, raw := range rawParts {
		if raw == "" {
			return nil, false
		}
		val, err := strconv.Atoi(raw)
		if err != nil {
			return nil, false
		}
		parts = append(parts, val)
	}
	return parts, true
}
