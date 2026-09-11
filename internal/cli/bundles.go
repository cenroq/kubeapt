// Copyright by cenroq AG
// Contact: info@cenroq.com

package cli

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/jedib0t/go-pretty/v6/table"
	"github.com/spf13/cobra"
	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	utilyaml "k8s.io/apimachinery/pkg/util/yaml"
	"sigs.k8s.io/yaml"

	"github.com/cenroq/kubeapt/v2/internal/config"
	"github.com/cenroq/kubeapt/v2/internal/kubernetes"
	"github.com/cenroq/kubeapt/v2/internal/logging"
)

const (
	bundleIndexURL = "https://raw.githubusercontent.com/cenroq/kubernetes-security-policies/refs/heads/main/admission/ValidatingAdmissionPolicy/bundles/bundles.json"
)

type bundleIndexEntry struct {
	Name          string   `json:"name"`
	LatestVersion string   `json:"latest-version"`
	Versions      []string `json:"versions"`
	Deprecated    int64    `json:"deprecated,omitempty"`
	LocalOnly     bool     `json:"-"`
}

func BundleCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "bundles",
		Short: "Manage policy bundles",
		PersistentPreRunE: func(cmd *cobra.Command, _ []string) error {
			if err := logging.Init("", getLogLevel()); err != nil {
				return err
			}
			logging.SetOutputWriter(cmd.OutOrStdout())
			logging.SetReportWriter(cmd.OutOrStdout())
			return nil
		},
	}
	cmd.AddCommand(newBundleDownloadCmd())
	cmd.AddCommand(newBundleExportCmd())
	cmd.AddCommand(newBundleImportCmd())
	cmd.AddCommand(newBundleInstallCmd())
	cmd.AddCommand(newBundleListCmd())
	cmd.AddCommand(newBundleNamespaceLabelCmd("audit"))
	cmd.AddCommand(newBundleNamespaceLabelCmd("enforce"))
	cmd.AddCommand(newBundleNamespaceLabelCmd("warn"))
	cmd.AddCommand(newBundleRemoveCmd())
	cmd.AddCommand(newBundleShowCmd())
	cmd.AddCommand(newBundleUninstallCmd())
	return cmd
}

func newBundleDownloadCmd() *cobra.Command {
	var version string
	cmd := &cobra.Command{
		Use:   "download <bundle-name>",
		Short: "Download a policy bundle",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runBundleDownload(cmd, args[0], version)
		},
	}
	cmd.Flags().StringVar(&version, "version", "", "Bundle version to download (defaults to latest)")
	return cmd
}

func newBundleListCmd() *cobra.Command {
	var local bool
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List available policy bundles and versions",
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runBundleList(cmd, local)
		},
	}
	cmd.Flags().BoolVar(&local, "local", false, "List only locally downloaded bundles")
	return cmd
}

func newBundleInstallCmd() *cobra.Command {
	var version string
	var overwrite bool
	var dryRun bool
	cmd := &cobra.Command{
		Use:   "install <bundle-name>",
		Short: "Install a policy bundle into the cluster",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runBundleInstall(cmd, args[0], version, overwrite, dryRun)
		},
	}
	cmd.Flags().StringVar(&version, "version", "", "Bundle version to install (defaults to latest)")
	cmd.Flags().BoolVar(&overwrite, "overwrite", false, "Overwrite existing bindings")
	cmd.Flags().BoolVar(&dryRun, "dry-run", false, "Preview changes without applying them")
	return cmd
}

func newBundleRemoveCmd() *cobra.Command {
	var version string
	cmd := &cobra.Command{
		Use:   "remove <bundle-name>",
		Short: "Remove a policy bundle version from local storage",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runBundleRemove(args[0], version)
		},
	}
	cmd.Flags().StringVar(&version, "version", "", "Bundle version to remove (defaults to latest downloaded)")
	return cmd
}

func newBundleUninstallCmd() *cobra.Command {
	var version string
	var dryRun bool
	cmd := &cobra.Command{
		Use:   "uninstall <bundle-name>",
		Short: "Uninstall a policy bundle from the cluster",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runBundleUninstall(cmd, args[0], version, dryRun)
		},
	}
	cmd.Flags().StringVar(&version, "version", "", "Bundle version to uninstall (defaults to latest)")
	cmd.Flags().BoolVar(&dryRun, "dry-run", false, "Preview changes without applying them")
	return cmd
}

func newBundleShowCmd() *cobra.Command {
	var version string
	var format string
	cmd := &cobra.Command{
		Use:   "show <bundle-name>",
		Short: "Show policies and bindings for a bundle",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runBundleShow(cmd, args[0], version, format)
		},
	}
	cmd.Flags().StringVar(&version, "version", "", "Bundle version to show (defaults to latest)")
	cmd.Flags().StringVarP(&format, "format", "f", "table", "Output format: table, yaml, or json")
	return cmd
}

func newBundleNamespaceLabelCmd(mode string) *cobra.Command {
	cmd := &cobra.Command{
		Use:   fmt.Sprintf("%s <bundle-name>", mode),
		Short: fmt.Sprintf("Set the bundle %s label on a namespace", mode),
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runBundleNamespaceLabel(cmd, mode, args[0])
		},
	}
	cmd.Flags().StringP("namespace", "n", "", "Namespace to label")
	cmd.Flags().BoolP("all-namespaces", "A", false, "Apply the label to all namespaces")
	cmd.Flags().String("namespace-selector", "", "Label selector to choose namespaces (e.g. env=prod)")
	cmd.Flags().Bool("overwrite", false, "Overwrite an existing bundle label")
	cmd.Flags().Bool("remove", false, "Remove the bundle label instead of setting it")
	cmd.Flags().String("psa-level", "", "PSA level for pod-security-admission: baseline or restricted")
	return cmd
}

func runBundleNamespaceLabel(cmd *cobra.Command, mode, bundleArg string) error {
	bundleName := strings.TrimSpace(bundleArg)
	if err := validateBundleSegment("bundle name", bundleName); err != nil {
		return err
	}

	flags := cmd.Flags()
	namespace, err := flags.GetString("namespace")
	if err != nil {
		return err
	}
	allNamespaces, err := flags.GetBool("all-namespaces")
	if err != nil {
		return err
	}
	namespaceSelector, err := flags.GetString("namespace-selector")
	if err != nil {
		return err
	}
	if allNamespaces && namespace != "" {
		return fmt.Errorf("--all-namespaces cannot be used together with --namespace")
	}
	if namespaceSelector != "" {
		if allNamespaces || namespace != "" {
			return fmt.Errorf("--namespace-selector cannot be used together with --all-namespaces or --namespace")
		}
		namespaces, err := namespacesFromSelector(namespaceSelector)
		if err != nil {
			return err
		}
		if len(namespaces) == 0 {
			return fmt.Errorf("no namespaces matched selector %s", namespaceSelector)
		}
		allNamespaces = false
	}
	if !allNamespaces && namespace == "" {
		return fmt.Errorf("either --namespace or --all-namespaces must be specified")
	}
	overwrite, err := flags.GetBool("overwrite")
	if err != nil {
		return err
	}
	remove, err := flags.GetBool("remove")
	if err != nil {
		return err
	}
	psaLevelInput, err := flags.GetString("psa-level")
	if err != nil {
		return err
	}
	psaLevel := strings.ToLower(strings.TrimSpace(psaLevelInput))
	if psaLevel != "" && psaLevel != "baseline" && psaLevel != "restricted" {
		return fmt.Errorf("invalid psa level %s, expected baseline or restricted", psaLevel)
	}
	isPSA := bundleName == "pod-security-admission"
	if isPSA && psaLevel == "" && !remove {
		return fmt.Errorf("--psa-level is required when using bundle pod-security-admission")
	}
	if !isPSA && psaLevel != "" {
		return fmt.Errorf("--psa-level is only supported with bundle pod-security-admission")
	}

	clientset, err := kubernetes.NewClientset()
	if err != nil {
		return err
	}

	targetKey, err := bundleLabelKey(bundleName, mode)
	if err != nil {
		return err
	}

	namespaces := []string{namespace}
	if namespaceSelector != "" {
		namespaces, err = namespacesFromSelector(namespaceSelector)
		if err != nil {
			return err
		}
	}
	if allNamespaces {
		namespaceList, err := clientset.CoreV1().Namespaces().List(context.TODO(), metav1.ListOptions{})
		if err != nil {
			return err
		}
		namespaces = make([]string, 0, len(namespaceList.Items))
		for _, namespace := range namespaceList.Items {
			namespaces = append(namespaces, namespace.Name)
		}
	}

	if !overwrite && !remove {
		for _, namespaceName := range namespaces {
			namespaceObj, err := clientset.CoreV1().Namespaces().Get(context.TODO(), namespaceName, metav1.GetOptions{})
			if err != nil {
				return err
			}
			labels := namespaceObj.Labels
			if labels == nil {
				continue
			}
			if _, has := labels[targetKey]; has {
				return fmt.Errorf("namespace %s already has a bundle %s label; use --overwrite to update it", namespaceName, mode)
			}
		}
	}

	for _, namespaceName := range namespaces {
		namespaceObj, err := clientset.CoreV1().Namespaces().Get(context.TODO(), namespaceName, metav1.GetOptions{})
		if err != nil {
			return err
		}
		labels := namespaceObj.Labels
		if labels == nil {
			labels = make(map[string]string)
		}

		if remove {
			if _, ok := labels[targetKey]; !ok {
				if !allNamespaces {
					return fmt.Errorf("label %s is not set on namespace %s", targetKey, namespaceName)
				}
				continue
			}
			delete(labels, targetKey)
			namespaceObj.Labels = labels
			if _, err := clientset.CoreV1().Namespaces().Update(context.TODO(), namespaceObj, metav1.UpdateOptions{}); err != nil {
				return err
			}
			logging.Infof("Removed %s from namespace %s", targetKey, namespaceName)
			continue
		}

		if overwrite {
			delete(labels, targetKey)
		}
		labels[targetKey] = "enabled"
		if isPSA {
			labels[targetKey] = psaLevel
		}
		namespaceObj.Labels = labels
		if _, err := clientset.CoreV1().Namespaces().Update(context.TODO(), namespaceObj, metav1.UpdateOptions{}); err != nil {
			return err
		}
		logging.Infof("Set %s=%s on namespace %s", targetKey, labels[targetKey], namespaceName)
	}

	return nil
}

func bundleLabelKey(bundleName, mode string) (string, error) {
	manifest, err := latestBundleManifest(bundleName)
	if err != nil {
		return "", err
	}
	if manifest.Labels == nil {
		return "", fmt.Errorf("bundle %s does not define labels", bundleName)
	}
	key := strings.TrimSpace(manifest.Labels[mode])
	if key == "" {
		return "", fmt.Errorf("bundle %s does not define a %s label", bundleName, mode)
	}
	return key, nil
}

func latestBundleManifest(bundleName string) (bundleManifest, error) {
	versions, err := config.BundleVersions(bundleName)
	if err != nil {
		return bundleManifest{}, err
	}
	if len(versions) == 0 {
		return bundleManifest{}, fmt.Errorf("bundle %s is not downloaded; run `kubeapt bundles download %s`", bundleName, bundleName)
	}
	version := versions[len(versions)-1]
	path, err := config.BundleManifestPath(bundleName, version)
	if err != nil {
		return bundleManifest{}, err
	}
	return readBundleManifest(path)
}

type bundleManifest struct {
	Name        string            `json:"name"`
	Description string            `json:"description"`
	Version     string            `json:"version"`
	Labels      map[string]string `json:"labels"`
	Sources     []string          `json:"sources"`
}

func runBundleDownload(cmd *cobra.Command, bundleName, version string) error {
	if err := validateBundleSegment("bundle name", bundleName); err != nil {
		return err
	}
	bundles, err := fetchBundleIndex(cmd.Context(), bundleIndexURL)
	if err != nil {
		return err
	}
	if version != "" {
		if _, ok := findBundleIndexEntry(bundles, bundleName); !ok {
			return fmt.Errorf("bundle %s not found; run `kubeapt bundles list` to see available bundles", bundleName)
		}
		if !indexHasBundleVersion(bundles, bundleName, version) {
			return fmt.Errorf("bundle %s version %s not found; run `kubeapt bundles list` to see available versions", bundleName, version)
		}
	}
	resolvedVersion, err := resolveBundleVersionFromIndex(bundles, bundleName, version)
	if err != nil {
		return err
	}
	if err := validateBundleSegment("bundle version", resolvedVersion); err != nil {
		return err
	}

	dest, err := config.BundleVersionDir(bundleName, resolvedVersion)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(dest, 0o755); err != nil {
		return err
	}

	bundleURL := bundleJSONURL(bundleName, resolvedVersion)
	bundleJSONPath := filepath.Join(dest, "bundle.json")
	if err := downloadFileWithContext(cmd.Context(), bundleURL, bundleJSONPath); err != nil {
		return err
	}

	manifest, err := readBundleManifest(bundleJSONPath)
	if err != nil {
		return err
	}
	sourceURL, err := selectBundleSource(manifest.Sources)
	if err != nil {
		return err
	}

	sourceName, err := basenameFromURL(sourceURL)
	if err != nil {
		return err
	}
	sourcePath := filepath.Join(dest, sourceName)
	if err := downloadFileWithContext(cmd.Context(), sourceURL, sourcePath); err != nil {
		return err
	}

	shaURL := sourceURL + ".sha256"
	shaPath := filepath.Join(dest, sourceName+".sha256")
	if err := downloadFileWithContext(cmd.Context(), shaURL, shaPath); err != nil {
		return err
	}
	if err := verifySHA256(sourcePath, shaPath); err != nil {
		return err
	}

	if err := extractTarGzStripRoot(sourcePath, dest); err != nil {
		return err
	}

	logging.Infof("Downloaded bundle %s %s to %s", bundleName, resolvedVersion, dest)
	return nil
}

func runBundleList(cmd *cobra.Command, local bool) error {
	var bundles []bundleIndexEntry
	var err error
	var remoteBundles []bundleIndexEntry
	var remoteErr error
	if local {
		bundles, err = localBundleIndex()
		if err == nil {
			remoteBundles, remoteErr = fetchBundleIndex(cmd.Context(), bundleIndexURL)
		}
	} else {
		remoteBundles, err = fetchBundleIndex(cmd.Context(), bundleIndexURL)
		if err != nil {
			return err
		}
		localBundles, errLocal := localBundleIndex()
		if errLocal != nil {
			return errLocal
		}
		bundles = mergeBundleIndexes(remoteBundles, localBundles)
	}
	if err != nil {
		return err
	}

	bundles = markBundleOrigins(bundles, remoteBundles, remoteErr == nil)

	if len(bundles) == 0 {
		logging.Infof("No bundles found.")
		return nil
	}

	sortBundleEntries(bundles)

	installedIndex := map[string]map[string]struct{}{}
	if !local {
		index, err := installedBundleVersionIndex(cmd.Context())
		// Check if connection was refused
		if err != nil && errors.Is(err, kubernetes.ErrKubeconfigNotFound) {
			logging.Warnf("%v", err)
		} else if err != nil && strings.Contains(err.Error(), "connection refused") {
			logging.Warnf("Unable to connect to Kubernetes cluster to check installed bundles.")
		} else if err != nil {
			return err
		}
		installedIndex = index
	}

	t := table.NewWriter()
	t.SetOutputMirror(logging.Writer())
	t.SetStyle(table.StyleRounded)
	t.AppendHeader(table.Row{"Bundle", "Origin", "Latest", "Deprecated", "Versions", "Downloaded", "Installed"})
	for _, bundle := range bundles {
		origin := "remote"
		if bundle.LocalOnly {
			origin = "local-only"
		}
		latest := bundle.LatestVersion
		if latest == "" {
			latest = "-"
		}
		deprecated := "-"
		if bundle.Deprecated != 0 {
			deprecated = time.Unix(bundle.Deprecated, 0).UTC().Format("2006-01-02")
		}
		downloadedVersions, err := config.BundleVersions(bundle.Name)
		if err != nil {
			return err
		}
		downloadedSet := make(map[string]struct{}, len(downloadedVersions))
		for _, version := range downloadedVersions {
			downloadedSet[version] = struct{}{}
		}

		installedSet := installedIndex[bundle.Name]
		versions := "-"
		downloaded := ""
		installed := ""
		if len(bundle.Versions) > 0 {
			versionLines := make([]string, 0, len(bundle.Versions))
			downloadedLines := make([]string, 0, len(bundle.Versions))
			installedLines := make([]string, 0, len(bundle.Versions))
			for _, version := range bundle.Versions {
				versionLines = append(versionLines, version)
				if _, ok := downloadedSet[version]; ok {
					downloadedLines = append(downloadedLines, "x")
				} else {
					downloadedLines = append(downloadedLines, "")
				}
				if _, ok := installedSet[version]; ok {
					installedLines = append(installedLines, "x")
				} else {
					installedLines = append(installedLines, "")
				}
			}
			versions = strings.Join(versionLines, "\n")
			downloaded = strings.Join(downloadedLines, "\n")
			installed = strings.Join(installedLines, "\n")
		}
		t.AppendRow(table.Row{bundle.Name, origin, latest, deprecated, versions, downloaded, installed})
	}
	t.Render()
	logging.Newline()
	logging.Infof("Legend: x = version is downloaded/installed")

	return nil
}

func runBundleInstall(cmd *cobra.Command, bundleName, version string, overwrite, dryRun bool) error {
	resolved, err := ensureBundleVersionAvailable(cmd, bundleName, version)
	if err != nil {
		return err
	}
	installedIndex, err := installedBundleVersionIndex(cmd.Context())
	if err != nil {
		return err
	}
	if installedVersions, ok := installedIndex[bundleName]; ok && len(installedVersions) > 0 {
		if _, same := installedVersions[resolved]; !same || len(installedVersions) > 1 {
			list := make([]string, 0, len(installedVersions))
			for v := range installedVersions {
				list = append(list, v)
			}
			sort.Strings(list)
			return fmt.Errorf("bundle %s has installed version(s) %s; uninstall the current version(s) before installing %s", bundleName, strings.Join(list, ", "), resolved)
		}
		return fmt.Errorf("bundle %s version %s is already installed; uninstall it before reinstalling", bundleName, resolved)
	}
	if err := preflightBundleBindings(cmd.Context(), bundleName, resolved, overwrite); err != nil {
		return err
	}
	return deployBundleResources(cmd, bundleName, resolved, true, dryRun)
}

func runBundleRemove(bundleName, version string) error {
	if err := validateBundleSegment("bundle name", bundleName); err != nil {
		return err
	}
	if version != "" {
		if err := validateBundleSegment("bundle version", version); err != nil {
			return err
		}
		target, err := config.BundleVersionDir(bundleName, version)
		if err != nil {
			return err
		}
		if _, err := os.Stat(target); err != nil {
			if os.IsNotExist(err) {
				return fmt.Errorf("bundle %s version %s not found", bundleName, version)
			}
			return err
		}
		return os.RemoveAll(target)
	}

	versions, err := config.BundleVersions(bundleName)
	if err != nil {
		return err
	}
	if len(versions) == 0 {
		return fmt.Errorf("bundle %s not found", bundleName)
	}
	latest := versions[len(versions)-1]
	target, err := config.BundleVersionDir(bundleName, latest)
	if err != nil {
		return err
	}
	if _, err := os.Stat(target); err != nil {
		if os.IsNotExist(err) {
			return fmt.Errorf("bundle %s version %s not found", bundleName, latest)
		}
		return err
	}
	return os.RemoveAll(target)
}

func runBundleUninstall(cmd *cobra.Command, bundleName, version string, dryRun bool) error {
	resolved, err := ensureBundleVersionAvailable(cmd, bundleName, version)
	if err != nil {
		return err
	}
	return deployBundleResources(cmd, bundleName, resolved, false, dryRun)
}

func runBundleShow(cmd *cobra.Command, bundleName, version, format string) error {
	if err := validateBundleSegment("bundle name", bundleName); err != nil {
		return err
	}
	if version == "" {
		versions, err := config.BundleVersions(bundleName)
		if err != nil {
			return err
		}
		if len(versions) == 0 {
			root, err := config.BundleDir(bundleName)
			if err != nil {
				return err
			}
			return fmt.Errorf("bundle %s not found in %s. Run `kubeapt bundles download %s` to install", bundleName, root, bundleName)
		}
		version = versions[len(versions)-1]
	} else {
		if err := validateBundleSegment("bundle version", version); err != nil {
			return err
		}
	}

	format = strings.ToLower(strings.TrimSpace(format))
	if format == "" {
		format = "table"
	}
	if format != "table" && format != "yaml" && format != "json" {
		return fmt.Errorf("invalid format %s, expected table, yaml, or json", format)
	}

	dir, err := config.BundleVersionDir(bundleName, version)
	if err != nil {
		return err
	}
	policiesPath, err := config.BundlePoliciesPath(bundleName, version)
	if err != nil {
		return err
	}
	bindingsPath, err := config.BundleBindingsPath(bundleName, version)
	if err != nil {
		return err
	}
	if _, err := os.Stat(policiesPath); err != nil {
		if os.IsNotExist(err) {
			return fmt.Errorf("policies.yaml not found in %s", dir)
		}
		return err
	}
	if _, err := os.Stat(bindingsPath); err != nil {
		if os.IsNotExist(err) {
			return fmt.Errorf("bindings.yaml not found in %s", dir)
		}
		return err
	}

	out := logging.Writer()
	switch format {
	case "json":
		resources, err := loadUnstructuredResources([]string{policiesPath, bindingsPath})
		if err != nil {
			return err
		}
		if len(resources) == 0 {
			return fmt.Errorf("no resources found in %s", dir)
		}
		payload := make([]map[string]interface{}, 0, len(resources))
		for _, res := range resources {
			payload = append(payload, res.Object)
		}
		data, err := json.MarshalIndent(payload, "", "  ")
		if err != nil {
			return err
		}
		_, err = fmt.Fprintln(out, string(data))
		return err
	case "yaml":
		resources, err := loadUnstructuredResources([]string{policiesPath, bindingsPath})
		if err != nil {
			return err
		}
		if len(resources) == 0 {
			return fmt.Errorf("no resources found in %s", dir)
		}
		for i, res := range resources {
			if i > 0 {
				if _, err := fmt.Fprintln(out, "---"); err != nil {
					return err
				}
			}
			data, err := yaml.Marshal(res.Object)
			if err != nil {
				return err
			}
			data = bytes.TrimSpace(data)
			if _, err := out.Write(data); err != nil {
				return err
			}
			if _, err := fmt.Fprintln(out); err != nil {
				return err
			}
		}
	default:
		policies, err := kubernetes.LoadValidatingAdmissionPolicies(policiesPath)
		if err != nil {
			return err
		}
		bindings, err := kubernetes.LoadValidatingAdmissionPolicyBindings(bindingsPath)
		if err != nil {
			return err
		}

		policyNames := make([]string, 0, len(policies))
		policySet := make(map[string]struct{}, len(policies))
		for _, policy := range policies {
			name := strings.TrimSpace(policy.Name)
			if name == "" {
				continue
			}
			policyNames = append(policyNames, name)
			policySet[name] = struct{}{}
		}

		type bindingInfo struct {
			Name string
			Mode string
		}
		bindingMap := make(map[string][]bindingInfo)
		for _, binding := range bindings {
			policyName := strings.TrimSpace(binding.Spec.PolicyName)
			if policyName == "" {
				continue
			}
			info := bindingInfo{
				Name: strings.TrimSpace(binding.Name),
				Mode: bundleBindingMode(&binding),
			}
			bindingMap[policyName] = append(bindingMap[policyName], info)
			if _, ok := policySet[policyName]; !ok {
				policyNames = append(policyNames, policyName)
				policySet[policyName] = struct{}{}
			}
		}

		sort.Strings(policyNames)
		for name, infos := range bindingMap {
			sort.Slice(infos, func(i, j int) bool {
				return infos[i].Name < infos[j].Name
			})
			bindingMap[name] = infos
		}

		t := table.NewWriter()
		t.SetOutputMirror(out)
		t.SetStyle(table.StyleRounded)
		t.AppendHeader(table.Row{"Policy", "Bindings", "Mode"})
		for _, policyName := range policyNames {
			infos := bindingMap[policyName]
			if len(infos) == 0 {
				t.AppendRow(table.Row{policyName, "-", "-"})
				continue
			}
			bindingLines := make([]string, 0, len(infos))
			modeLines := make([]string, 0, len(infos))
			for _, info := range infos {
				bindingLines = append(bindingLines, info.Name)
				modeLines = append(modeLines, info.Mode)
			}
			t.AppendRow(table.Row{
				policyName,
				strings.Join(bindingLines, "\n"),
				strings.Join(modeLines, "\n"),
			})
		}
		t.Render()
	}

	return nil
}

func bundleBindingMode(binding *admissionregistrationv1.ValidatingAdmissionPolicyBinding) string {
	if binding == nil {
		return ""
	}
	actions := binding.Spec.ValidationActions
	if len(actions) == 0 {
		return string(admissionregistrationv1.Deny)
	}
	values := make([]string, 0, len(actions))
	for _, action := range actions {
		values = append(values, string(action))
	}
	return strings.Join(values, ",")
}

func fetchBundleIndex(ctx context.Context, url string) ([]bundleIndexEntry, error) {
	client := &http.Client{Timeout: 30 * time.Second}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "kubeapt")

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("bundle index request failed: %s", resp.Status)
	}

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	if err := syncBundleIndexCache(data); err != nil {
		return nil, err
	}

	var bundles []bundleIndexEntry
	if err := json.Unmarshal(data, &bundles); err != nil {
		return nil, err
	}
	return bundles, nil
}

func resolveBundleVersionFromIndex(bundles []bundleIndexEntry, bundleName, version string) (string, error) {
	if version != "" {
		return version, nil
	}
	bundle, ok := findBundleIndexEntry(bundles, bundleName)
	if !ok {
		return "", fmt.Errorf("bundle %s not found in index", bundleName)
	}
	if bundle.LatestVersion == "" {
		return "", fmt.Errorf("latest version for bundle %s not found", bundleName)
	}
	return bundle.LatestVersion, nil
}

// findBundleIndexEntry returns the entry for bundleName, preferring the current
// (non-deprecated) entry when the index also lists a deprecated duplicate.
func findBundleIndexEntry(bundles []bundleIndexEntry, bundleName string) (bundleIndexEntry, bool) {
	var deprecated *bundleIndexEntry
	for i := range bundles {
		if bundles[i].Name != bundleName {
			continue
		}
		if bundles[i].Deprecated == 0 {
			return bundles[i], true
		}
		if deprecated == nil {
			deprecated = &bundles[i]
		}
	}
	if deprecated != nil {
		return *deprecated, true
	}
	return bundleIndexEntry{}, false
}

func bundleVersionInIndex(bundle bundleIndexEntry, version string) bool {
	for _, v := range bundle.Versions {
		if v == version {
			return true
		}
	}
	return false
}

// indexHasBundleVersion reports whether version is offered by ANY index entry for
// bundleName — including deprecated duplicates, so still-published deprecated
// versions remain downloadable.
func indexHasBundleVersion(bundles []bundleIndexEntry, bundleName, version string) bool {
	for _, bundle := range bundles {
		if bundle.Name == bundleName && bundleVersionInIndex(bundle, version) {
			return true
		}
	}
	return false
}

func bundleJSONURL(bundleName, version string) string {
	return fmt.Sprintf("https://github.com/cenroq/kubernetes-security-policies/releases/download/vap_%s%%40%s/bundle.json", bundleName, version)
}

func syncBundleIndexCache(data []byte) error {
	path, err := config.BundleIndexPath()
	if err != nil {
		return err
	}
	if existing, err := os.ReadFile(path); err == nil {
		if bytes.Equal(existing, data) {
			return nil
		}
	} else if !os.IsNotExist(err) {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o644)
}

func readBundleManifest(path string) (bundleManifest, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return bundleManifest{}, fmt.Errorf("read bundle manifest %s: %w", path, err)
	}
	var manifest bundleManifest
	if err := json.Unmarshal(data, &manifest); err != nil {
		return bundleManifest{}, fmt.Errorf("parse bundle manifest %s: %w", path, err)
	}
	return manifest, nil
}

func selectBundleSource(sources []string) (string, error) {
	for _, source := range sources {
		if strings.HasSuffix(source, ".tar.gz") {
			return source, nil
		}
	}
	for _, source := range sources {
		if strings.Contains(source, ".tar.gz") {
			return source, nil
		}
	}
	return "", fmt.Errorf("no .tar.gz source found in bundle.json")
}

func basenameFromURL(raw string) (string, error) {
	parsed, err := url.Parse(raw)
	if err != nil {
		return "", err
	}
	base := pathBase(parsed.Path)
	if base == "" || base == "." || base == "/" {
		return "", fmt.Errorf("invalid source filename in %s", raw)
	}
	return base, nil
}

func pathBase(p string) string {
	if p == "" {
		return ""
	}
	return filepath.Base(strings.ReplaceAll(p, "/", string(filepath.Separator)))
}

func verifySHA256(targetPath, checksumPath string) error {
	data, err := os.ReadFile(checksumPath)
	if err != nil {
		return err
	}
	fields := strings.Fields(string(data))
	if len(fields) == 0 {
		return fmt.Errorf("checksum file %s is empty", checksumPath)
	}
	expected := strings.ToLower(fields[0])

	file, err := os.Open(targetPath)
	if err != nil {
		return err
	}
	defer file.Close()

	hasher := sha256.New()
	if _, err := io.Copy(hasher, file); err != nil {
		return err
	}
	actual := hex.EncodeToString(hasher.Sum(nil))
	if !strings.EqualFold(expected, actual) {
		return fmt.Errorf("checksum mismatch for %s", targetPath)
	}
	return nil
}

func downloadFileWithContext(ctx context.Context, url, dest string) error {
	client := &http.Client{Timeout: 60 * time.Second}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	req.Header.Set("User-Agent", "kubeapt")

	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("download failed: %s", resp.Status)
	}

	out, err := os.OpenFile(dest, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	defer out.Close()

	_, err = io.Copy(out, resp.Body)
	return err
}

func ensureBundleVersionAvailable(cmd *cobra.Command, bundleName, version string) (string, error) {
	if err := validateBundleSegment("bundle name", bundleName); err != nil {
		return "", err
	}
	if version != "" {
		if err := validateBundleSegment("bundle version", version); err != nil {
			return "", err
		}
		ok, err := bundleVersionExists(bundleName, version)
		if err != nil {
			return "", err
		}
		if ok {
			return version, nil
		}
		remoteIndex, errIndex := fetchBundleIndex(cmd.Context(), bundleIndexURL)
		if errIndex == nil {
			if _, ok := findBundleIndexEntry(remoteIndex, bundleName); ok && indexHasBundleVersion(remoteIndex, bundleName, version) {
				if err := runBundleDownload(cmd, bundleName, version); err != nil {
					return "", err
				}
				return version, nil
			}
		}
		return "", fmt.Errorf("bundle %s version %s is not available locally", bundleName, version)
	}

	localVersions, err := config.BundleVersions(bundleName)
	if err != nil {
		return "", err
	}

	bundles, indexErr := fetchBundleIndex(cmd.Context(), bundleIndexURL)
	if indexErr == nil {
		if latest, err := resolveBundleVersionFromIndex(bundles, bundleName, ""); err == nil {
			ok, errExists := bundleVersionExists(bundleName, latest)
			if errExists != nil {
				return "", errExists
			}
			if ok {
				return latest, nil
			}
			if err := runBundleDownload(cmd, bundleName, latest); err != nil {
				return "", err
			}
			return latest, nil
		}
	}

	if len(localVersions) > 0 {
		return localVersions[len(localVersions)-1], nil
	}

	if indexErr != nil {
		return "", fmt.Errorf("bundle %s not found locally and bundle index could not be fetched: %w", bundleName, indexErr)
	}
	root, err := config.BundleDir(bundleName)
	if err != nil {
		return "", err
	}
	return "", fmt.Errorf("bundle %s is not available; add it under %s or download it", bundleName, root)
}

// resolveInstalledBundleVersion picks the version of an installed bundle to
// use. An empty bundleVersion selects the newest installed one. Nothing is
// downloaded: a command that reads a bundle should not silently fetch it.
func resolveInstalledBundleVersion(bundleName, bundleVersion string) (string, error) {
	if err := validateBundleSegment("bundle name", bundleName); err != nil {
		return "", err
	}

	version := strings.TrimSpace(bundleVersion)
	if version != "" {
		if err := validateBundleSegment("bundle version", version); err != nil {
			return "", err
		}
	} else {
		versions, err := config.BundleVersions(bundleName)
		if err != nil {
			return "", err
		}
		if len(versions) == 0 {
			dir, err := config.BundleDir(bundleName)
			if err != nil {
				return "", err
			}
			return "", fmt.Errorf("bundle %s is not installed; place it under %s or run `kubeapt bundles import --from <archive>`", bundleName, dir)
		}
		version = versions[len(versions)-1]
	}

	ok, err := bundleVersionExists(bundleName, version)
	if err != nil {
		return "", err
	}
	if !ok {
		dir, err := config.BundleDir(bundleName)
		if err != nil {
			return "", err
		}
		return "", fmt.Errorf("bundle %s version %s is not found in %s", bundleName, version, dir)
	}
	return version, nil
}

// locateInstalledBundle resolves an installed bundle to its policies and
// bindings paths. An empty bundleVersion selects the newest installed version.
// Every failure explains which command would fix it.
func locateInstalledBundle(bundleName, bundleVersion string) (policiesPath, bindingsPath string, err error) {
	version, err := resolveInstalledBundleVersion(bundleName, bundleVersion)
	if err != nil {
		return "", "", err
	}

	policiesPath, bindingsPath, ok, err := config.LocateBundleFiles(bundleName, version)
	if err != nil {
		return "", "", err
	}
	if !ok {
		root, err := config.BundleVersionDir(bundleName, version)
		if err != nil {
			return "", "", err
		}
		downloadCmd := fmt.Sprintf("kubeapt bundles download %s --version %s", bundleName, version)
		if bundleVersion == "" {
			downloadCmd = fmt.Sprintf("kubeapt bundles download %s", bundleName)
		}
		return "", "", fmt.Errorf("policy bundle %s %s not found in %s. Run `%s` to install", bundleName, version, root, downloadCmd)
	}

	return policiesPath, bindingsPath, nil
}

func bundleVersionExists(bundleName, version string) (bool, error) {
	path, err := config.BundleVersionDir(bundleName, version)
	if err != nil {
		return false, err
	}
	info, err := os.Stat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return false, nil
		}
		return false, err
	}
	return info.IsDir(), nil
}

func deployBundleResources(cmd *cobra.Command, bundleName, version string, install bool, dryRun bool) error {
	dir, err := config.BundleVersionDir(bundleName, version)
	if err != nil {
		return err
	}
	policiesPath, err := config.BundlePoliciesPath(bundleName, version)
	if err != nil {
		return err
	}
	bindingsPath, err := config.BundleBindingsPath(bundleName, version)
	if err != nil {
		return err
	}
	if _, err := os.Stat(policiesPath); err != nil {
		if os.IsNotExist(err) {
			return fmt.Errorf("policies.yaml not found in %s", dir)
		}
		return err
	}
	if _, err := os.Stat(bindingsPath); err != nil {
		if os.IsNotExist(err) {
			return fmt.Errorf("bindings.yaml not found in %s", dir)
		}
		return err
	}
	resources, err := loadUnstructuredResources([]string{policiesPath, bindingsPath})
	if err != nil {
		return err
	}
	if install {
		if err := applyKustomizeResources(resources, nil, dryRun); err != nil {
			return err
		}
		if dryRun {
			logging.Infof("Dry run: install bundle %s %s", bundleName, version)
		} else {
			logging.Infof("Installed bundle %s %s", bundleName, version)
		}
		return nil
	}
	if err := deleteKustomizeResources(resources, nil, dryRun); err != nil {
		return err
	}
	if dryRun {
		logging.Infof("Dry run: uninstall bundle %s %s", bundleName, version)
	} else {
		logging.Infof("Uninstalled bundle %s %s", bundleName, version)
	}
	return nil
}

func preflightBundleBindings(ctx context.Context, bundleName, version string, overwrite bool) error {
	dir, err := config.BundleVersionDir(bundleName, version)
	if err != nil {
		return err
	}
	bindingsPath, err := config.BundleBindingsPath(bundleName, version)
	if err != nil {
		return err
	}
	if _, err := os.Stat(bindingsPath); err != nil {
		if os.IsNotExist(err) {
			return fmt.Errorf("bindings.yaml not found for bundle %s %s in %s", bundleName, version, dir)
		}
		return err
	}
	bindings, err := kubernetes.LoadValidatingAdmissionPolicyBindings(bindingsPath)
	if err != nil {
		return err
	}
	if len(bindings) == 0 {
		return nil
	}

	clientset, err := kubernetes.NewClientset()
	if err != nil {
		return err
	}

	var conflicts []string
	for _, binding := range bindings {
		name := strings.TrimSpace(binding.Name)
		if name == "" {
			continue
		}
		_, err := clientset.AdmissionregistrationV1().ValidatingAdmissionPolicyBindings().Get(ctx, name, metav1.GetOptions{})
		if err == nil {
			conflicts = append(conflicts, name)
			continue
		}
		if apierrors.IsNotFound(err) {
			continue
		}
		return err
	}

	if len(conflicts) > 0 && !overwrite {
		sort.Strings(conflicts)
		return fmt.Errorf("bindings already exist for bundle %s %s: %s; use --overwrite to replace", bundleName, version, strings.Join(conflicts, ", "))
	}

	return nil
}

func installedBundleVersionIndex(ctx context.Context) (map[string]map[string]struct{}, error) {
	clientset, err := kubernetes.NewClientset()
	if err != nil {
		return nil, err
	}

	bindingList, err := clientset.AdmissionregistrationV1().ValidatingAdmissionPolicyBindings().List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, err
	}

	index := make(map[string]map[string]struct{})
	for _, binding := range bindingList.Items {
		bundleName := binding.Labels["bundle"]
		if bundleName == "" {
			continue
		}
		version := binding.Annotations["policy-bundle.cenroq.io/version"]
		if version == "" {
			continue
		}
		versions, ok := index[bundleName]
		if !ok {
			versions = make(map[string]struct{})
			index[bundleName] = versions
		}
		versions[version] = struct{}{}
	}

	return index, nil
}

func localBundleIndex() ([]bundleIndexEntry, error) {
	root, err := config.BundlesDir()
	if err != nil {
		return nil, err
	}
	entries, err := os.ReadDir(root)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}

	var bundles []bundleIndexEntry
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		name := entry.Name()
		versions, err := config.BundleVersions(name)
		if err != nil {
			return nil, err
		}
		bundles = append(bundles, bundleIndexEntry{
			Name:          name,
			Versions:      versions,
			LatestVersion: latestVersion(versions),
			LocalOnly:     true,
		})
	}
	sort.Slice(bundles, func(i, j int) bool {
		return bundles[i].Name < bundles[j].Name
	})
	return bundles, nil
}

func mergeBundleIndexes(remote, local []bundleIndexEntry) []bundleIndexEntry {
	// Preserve every remote entry verbatim — a deprecated duplicate and its current
	// counterpart for the same name are both authoritative rows.
	merged := make([]*bundleIndexEntry, 0, len(remote)+len(local))
	byName := make(map[string][]*bundleIndexEntry, len(remote))
	for i := range remote {
		cp := remote[i]
		cp.Versions = append([]string(nil), remote[i].Versions...)
		cp.LocalOnly = false
		merged = append(merged, &cp)
		byName[cp.Name] = append(byName[cp.Name], &cp)
	}

	for _, l := range local {
		entries := byName[l.Name]
		if len(entries) == 0 {
			// A bundle that exists only locally becomes its own row.
			cp := l
			cp.Versions = append([]string(nil), l.Versions...)
			cp.LocalOnly = true
			if cp.LatestVersion == "" {
				cp.LatestVersion = latestVersion(cp.Versions)
			}
			merged = append(merged, &cp)
			byName[cp.Name] = append(byName[cp.Name], &cp)
			continue
		}
		// Attribute a downloaded version to the remote entry that offers it; only
		// versions no remote row lists (orphans) are added, to the current entry.
		target := entries[0]
		for _, e := range entries {
			if e.Deprecated == 0 {
				target = e
				break
			}
		}
		for _, v := range l.Versions {
			if versionCoveredByAny(entries, v) {
				continue
			}
			target.Versions = append(target.Versions, v)
		}
		sort.Strings(target.Versions)
		if target.LatestVersion == "" {
			target.LatestVersion = latestVersion(target.Versions)
		}
	}

	out := make([]bundleIndexEntry, 0, len(merged))
	for _, entry := range merged {
		if entry.LatestVersion == "" {
			entry.LatestVersion = latestVersion(entry.Versions)
		}
		out = append(out, *entry)
	}
	sortBundleEntries(out)
	return out
}

// versionCoveredByAny reports whether version is listed by any of the given entries.
func versionCoveredByAny(entries []*bundleIndexEntry, version string) bool {
	for _, e := range entries {
		if bundleVersionInIndex(*e, version) {
			return true
		}
	}
	return false
}

// sortBundleEntries orders by name, then places the current entry before its
// deprecated duplicate (Deprecated == 0 sorts first).
func sortBundleEntries(entries []bundleIndexEntry) {
	sort.Slice(entries, func(i, j int) bool {
		if entries[i].Name != entries[j].Name {
			return entries[i].Name < entries[j].Name
		}
		return entries[i].Deprecated < entries[j].Deprecated
	})
}

func markBundleOrigins(bundles, remote []bundleIndexEntry, remoteOK bool) []bundleIndexEntry {
	if !remoteOK {
		return bundles
	}
	remoteSet := make(map[string]struct{}, len(remote))
	hasCurrent := make(map[string]bool)
	deprecatedTS := make(map[string]int64)
	for _, b := range remote {
		remoteSet[b.Name] = struct{}{}
		if b.Deprecated == 0 {
			hasCurrent[b.Name] = true
		} else {
			deprecatedTS[b.Name] = b.Deprecated
		}
	}
	for i := range bundles {
		if _, ok := remoteSet[bundles[i].Name]; ok {
			bundles[i].LocalOnly = false
		} else {
			bundles[i].LocalOnly = true
		}
		// Surface deprecation for local entries when the remote index lists this
		// bundle only as deprecated (no current entry of the same name).
		if bundles[i].Deprecated == 0 && !hasCurrent[bundles[i].Name] {
			if ts, ok := deprecatedTS[bundles[i].Name]; ok {
				bundles[i].Deprecated = ts
			}
		}
	}
	return bundles
}

func validateBundleSegment(label, value string) error {
	if value == "" {
		return fmt.Errorf("%s cannot be empty", label)
	}
	if strings.ContainsAny(value, `/\`) {
		return fmt.Errorf("%s contains invalid path separators", label)
	}
	if value != filepath.Base(value) {
		return fmt.Errorf("%s contains invalid path elements", label)
	}
	return nil
}

func loadUnstructuredResources(files []string) ([]*unstructured.Unstructured, error) {
	var resources []*unstructured.Unstructured
	for _, path := range files {
		file, err := os.Open(path)
		if err != nil {
			return nil, err
		}
		decoder := utilyaml.NewYAMLOrJSONDecoder(file, 4096)
		for {
			var raw runtime.RawExtension
			if err := decoder.Decode(&raw); err != nil {
				if err == io.EOF {
					break
				}
				file.Close()
				return nil, err
			}
			if len(bytes.TrimSpace(raw.Raw)) == 0 {
				continue
			}
			var obj map[string]interface{}
			if err := json.Unmarshal(raw.Raw, &obj); err != nil {
				file.Close()
				return nil, err
			}
			if len(obj) == 0 {
				continue
			}
			resources = append(resources, &unstructured.Unstructured{Object: obj})
		}
		file.Close()
	}
	return resources, nil
}

func applyKustomizeResources(resources []*unstructured.Unstructured, onProgress func(), dryRun bool) error {
	client, err := kubernetes.NewResourceClient()
	if err != nil {
		return err
	}

	for _, resource := range resources {
		target, err := client.Resolve(resource, "")
		if err != nil {
			return err
		}
		name := resource.GetName()
		if name == "" {
			return fmt.Errorf("resource %s missing metadata.name", resource.GroupVersionKind().String())
		}
		payload, err := json.Marshal(resource.Object)
		if err != nil {
			return err
		}
		opts := metav1.PatchOptions{
			FieldManager: "kubeapt",
		}
		if dryRun {
			opts.DryRun = []string{metav1.DryRunAll}
		}
		_, err = target.Client.Patch(context.TODO(), name, types.ApplyPatchType, payload, opts)
		if err != nil {
			return err
		}
		if onProgress != nil {
			onProgress()
		}
	}
	return nil
}

func deleteKustomizeResources(resources []*unstructured.Unstructured, onProgress func(), dryRun bool) error {
	client, err := kubernetes.NewResourceClient()
	if err != nil {
		return err
	}

	for i := len(resources) - 1; i >= 0; i-- {
		resource := resources[i]
		target, err := client.Resolve(resource, "")
		if err != nil {
			return err
		}
		name := resource.GetName()
		if name == "" {
			return fmt.Errorf("resource %s missing metadata.name", resource.GroupVersionKind().String())
		}
		opts := metav1.DeleteOptions{}
		if dryRun {
			opts.DryRun = []string{metav1.DryRunAll}
		}
		err = target.Client.Delete(context.TODO(), name, opts)
		if apierrors.IsNotFound(err) {
			if onProgress != nil {
				onProgress()
			}
			continue
		}
		if err != nil {
			return err
		}
		if onProgress != nil {
			onProgress()
		}
	}
	return nil
}

func extractTarGzStripRoot(archivePath, dest string) error {
	stripRoot, err := detectTarRoot(archivePath)
	if err != nil {
		return err
	}

	file, err := os.Open(archivePath)
	if err != nil {
		return err
	}
	defer file.Close()

	gzipReader, err := gzip.NewReader(file)
	if err != nil {
		return err
	}
	defer gzipReader.Close()

	reader := tar.NewReader(gzipReader)
	for {
		header, err := reader.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}

		cleaned := path.Clean(header.Name)
		cleaned = strings.TrimPrefix(cleaned, "./")
		if cleaned == "." || cleaned == "" {
			continue
		}
		if stripRoot != "" {
			if cleaned == stripRoot {
				continue
			}
			prefix := stripRoot + "/"
			if strings.HasPrefix(cleaned, prefix) {
				cleaned = strings.TrimPrefix(cleaned, prefix)
			}
		}
		if cleaned == "" || cleaned == "." {
			continue
		}

		target, err := safeJoin(dest, cleaned)
		if err != nil {
			return err
		}

		switch header.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(target, os.FileMode(header.Mode)); err != nil {
				return err
			}
		case tar.TypeReg, tar.TypeRegA:
			if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
				return err
			}
			out, err := os.OpenFile(target, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, os.FileMode(header.Mode))
			if err != nil {
				return err
			}
			if _, err := io.Copy(out, reader); err != nil {
				out.Close()
				return err
			}
			if err := out.Close(); err != nil {
				return err
			}
		case tar.TypeSymlink, tar.TypeLink:
			return fmt.Errorf("unsupported archive entry %s", header.Name)
		default:
			continue
		}
	}

	return nil
}

func detectTarRoot(archivePath string) (string, error) {
	file, err := os.Open(archivePath)
	if err != nil {
		return "", err
	}
	defer file.Close()

	gzipReader, err := gzip.NewReader(file)
	if err != nil {
		return "", err
	}
	defer gzipReader.Close()

	reader := tar.NewReader(gzipReader)
	var root string
	for {
		header, err := reader.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return "", err
		}
		cleaned := path.Clean(header.Name)
		cleaned = strings.TrimPrefix(cleaned, "./")
		if cleaned == "." || cleaned == "" {
			continue
		}
		parts := strings.Split(cleaned, "/")
		if len(parts) == 0 || parts[0] == "" {
			continue
		}
		if root == "" {
			root = parts[0]
			continue
		}
		if root != parts[0] {
			return "", nil
		}
	}

	return root, nil
}

func safeJoin(base, target string) (string, error) {
	clean := filepath.Clean(target)
	if filepath.IsAbs(clean) {
		return "", fmt.Errorf("invalid archive path %s", target)
	}
	joined := filepath.Join(base, clean)
	rel, err := filepath.Rel(base, joined)
	if err != nil {
		return "", err
	}
	if strings.HasPrefix(rel, "..") {
		return "", fmt.Errorf("invalid archive path %s", target)
	}
	return joined, nil
}
