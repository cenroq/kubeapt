// Copyright by cenroq AG
// Contact: info@cenroq.com

package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/jedib0t/go-pretty/v6/table"
	"github.com/spf13/cobra"
	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	"sigs.k8s.io/yaml"

	"github.com/cenroq/kubeapt/v2/internal/config"
	"github.com/cenroq/kubeapt/v2/internal/kubernetes"
	"github.com/cenroq/kubeapt/v2/internal/logging"
	"github.com/cenroq/kubeapt/v2/pkg/policies"
)

const (
	policiesIndexURL = "https://raw.githubusercontent.com/cenroq/kubernetes-security-policies/refs/heads/main/admission/ValidatingAdmissionPolicy/policies/policies.json"
	policiesArchive  = "policies.tar.gz"

	policyAnnotationDisplayName = policies.AnnotationDisplayName
	policyAnnotationDescription = policies.AnnotationDescription
	policyAnnotationSeverity    = policies.AnnotationSeverity

	policyAnnotationResource    = "security.kubeapt.io/resource"
	policyAnnotationRemediation = "security.kubeapt.io/remediation"
	policyAnnotationProduct     = "security.kubeapt.io/product"
)

type policiesIndex struct {
	LatestVersion string              `json:"latest-version"`
	Versions      []string            `json:"versions"`
	Policies      []policiesIndexItem `json:"policies"`
}

type policiesIndexItem struct {
	Name string `json:"name"`
	File string `json:"file"`
}

type policySummary struct {
	Name        string `json:"name"`
	DisplayName string `json:"displayName"`
	Description string `json:"description"`
	Product     string `json:"product"`
}

type policyAnnotations struct {
	DisplayName string `json:"displayName"`
	Description string `json:"description"`
	Resource    string `json:"resource"`
	Severity    string `json:"severity"`
	Remediation string `json:"remediation"`
	Product     string `json:"product"`
	URL         string `json:"url,omitempty"`
}

func PoliciesCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "policies",
		Short: "Manage policies",
		PersistentPreRunE: func(cmd *cobra.Command, _ []string) error {
			if err := logging.Init("", getLogLevel()); err != nil {
				return err
			}
			logging.SetOutputWriter(cmd.OutOrStdout())
			logging.SetReportWriter(cmd.OutOrStdout())
			return nil
		},
	}

	cmd.AddCommand(newPoliciesListCmd())
	cmd.AddCommand(newPoliciesDownloadCmd())
	cmd.AddCommand(newPoliciesRemoveCmd())
	cmd.AddCommand(newPoliciesInstallCmd())
	cmd.AddCommand(newPoliciesUninstallCmd())
	cmd.AddCommand(newPoliciesShowCmd())
	return cmd
}

func newPoliciesListCmd() *cobra.Command {
	var local bool
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List available policy versions",
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runPoliciesList(cmd, local)
		},
	}
	cmd.Flags().BoolVar(&local, "local", false, "List only locally downloaded policy versions")
	return cmd
}

func newPoliciesDownloadCmd() *cobra.Command {
	var version string
	cmd := &cobra.Command{
		Use:   "download",
		Short: "Download policies into local storage",
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runPoliciesDownload(cmd, version)
		},
	}
	cmd.Flags().StringVar(&version, "version", "", "Policy version to download (defaults to latest)")
	return cmd
}

func newPoliciesRemoveCmd() *cobra.Command {
	var version string
	cmd := &cobra.Command{
		Use:   "remove",
		Short: "Remove policies from local storage",
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runPoliciesRemove(version)
		},
	}
	cmd.Flags().StringVar(&version, "version", "", "Policy version to remove (defaults to latest downloaded)")
	return cmd
}

func newPoliciesInstallCmd() *cobra.Command {
	var version string
	var overwrite bool
	var dryRun bool
	cmd := &cobra.Command{
		Use:   "install <policy-name>",
		Short: "Install a policy into the cluster",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runPolicyInstall(cmd, args[0], version, overwrite, dryRun)
		},
	}
	cmd.Flags().StringVar(&version, "version", "", "Policy version to use (defaults to latest)")
	cmd.Flags().BoolVar(&overwrite, "overwrite", false, "Overwrite an existing policy")
	cmd.Flags().BoolVar(&dryRun, "dry-run", false, "Preview changes without applying them")
	return cmd
}

func newPoliciesUninstallCmd() *cobra.Command {
	var version string
	var dryRun bool
	cmd := &cobra.Command{
		Use:   "uninstall <policy-name>",
		Short: "Uninstall a policy from the cluster",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runPolicyUninstall(cmd, args[0], version, dryRun)
		},
	}
	cmd.Flags().StringVar(&version, "version", "", "Policy version to use (defaults to latest)")
	cmd.Flags().BoolVar(&dryRun, "dry-run", false, "Preview changes without applying them")
	return cmd
}

func newPoliciesShowCmd() *cobra.Command {
	var version string
	var format string
	cmd := &cobra.Command{
		Use:   "show [policy-name]",
		Short: "Show policy details",
		Args:  cobra.RangeArgs(0, 1),
		RunE: func(cmd *cobra.Command, args []string) error {
			policyName := ""
			if len(args) > 0 {
				policyName = args[0]
			}
			return runPolicyShow(cmd, policyName, version, format)
		},
	}
	cmd.Flags().StringVar(&version, "version", "", "Policy version to use (defaults to latest)")
	cmd.Flags().StringVarP(&format, "format", "f", "table", "Output format: table, yaml, or json")
	return cmd
}

func runPoliciesList(cmd *cobra.Command, local bool) error {
	var index policiesIndex
	var err error
	if local {
		index, err = localPoliciesIndex()
	} else {
		index, err = fetchPoliciesIndex(cmd.Context(), policiesIndexURL)
	}
	if err != nil {
		return err
	}
	if len(index.Versions) == 0 {
		logging.Infof("No policy versions found.")
		return nil
	}
	latest := index.LatestVersion
	if latest == "" {
		latest = "-"
	}
	downloadedVersions, err := config.PolicyVersions()
	if err != nil {
		return err
	}
	downloadedSet := make(map[string]struct{}, len(downloadedVersions))
	for _, version := range downloadedVersions {
		downloadedSet[version] = struct{}{}
	}
	t := table.NewWriter()
	t.SetOutputMirror(logging.Writer())
	t.SetStyle(table.StyleRounded)
	t.AppendHeader(table.Row{"Latest", "Versions", "Downloaded"})
	versionLines := make([]string, 0, len(index.Versions))
	downloadedLines := make([]string, 0, len(index.Versions))
	for _, version := range index.Versions {
		versionLines = append(versionLines, version)
		if _, ok := downloadedSet[version]; ok {
			downloadedLines = append(downloadedLines, "x")
		} else {
			downloadedLines = append(downloadedLines, "")
		}
	}
	t.AppendRow(table.Row{latest, strings.Join(versionLines, "\n"), strings.Join(downloadedLines, "\n")})
	t.Render()
	logging.Newline()
	logging.Infof("Legend: x = version is downloaded")
	return nil
}

func runPoliciesDownload(cmd *cobra.Command, version string) error {
	index, err := fetchPoliciesIndex(cmd.Context(), policiesIndexURL)
	if err != nil {
		return err
	}
	if version != "" {
		if !policyVersionInIndex(index, version) {
			return fmt.Errorf("policy version %s not found; run `kubeapt policies list` to see available versions", version)
		}
	}
	resolved, err := resolvePolicyVersion(index, version)
	if err != nil {
		return err
	}
	if err := validateBundleSegment("policy version", resolved); err != nil {
		return err
	}
	dest, err := config.PolicyVersionDir(resolved)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(dest, 0o755); err != nil {
		return err
	}

	archiveURL := policiesArchiveURL(resolved)
	archivePath := filepath.Join(dest, policiesArchive)
	if err := downloadFileWithContext(cmd.Context(), archiveURL, archivePath); err != nil {
		return err
	}

	shaURL := archiveURL + ".sha256"
	shaPath := archivePath + ".sha256"
	if err := downloadFileWithContext(cmd.Context(), shaURL, shaPath); err != nil {
		return err
	}
	if err := verifySHA256(archivePath, shaPath); err != nil {
		return err
	}
	if err := extractTarGzStripRoot(archivePath, dest); err != nil {
		return err
	}
	if err := os.Remove(archivePath); err != nil && !os.IsNotExist(err) {
		return err
	}
	if err := os.Remove(shaPath); err != nil && !os.IsNotExist(err) {
		return err
	}

	logging.Infof("Downloaded policies %s to %s", resolved, dest)
	return nil
}

func runPoliciesRemove(version string) error {
	if version != "" {
		if err := validateBundleSegment("policy version", version); err != nil {
			return err
		}
		target, err := config.PolicyVersionDir(version)
		if err != nil {
			return err
		}
		if _, err := os.Stat(target); err != nil {
			if os.IsNotExist(err) {
				return fmt.Errorf("policy version %s not found", version)
			}
			return err
		}
		return os.RemoveAll(target)
	}

	versions, err := config.PolicyVersions()
	if err != nil {
		return err
	}
	if len(versions) == 0 {
		return fmt.Errorf("policies not found")
	}
	latest := versions[len(versions)-1]
	target, err := config.PolicyVersionDir(latest)
	if err != nil {
		return err
	}
	if _, err := os.Stat(target); err != nil {
		if os.IsNotExist(err) {
			return fmt.Errorf("policy version %s not found", latest)
		}
		return err
	}
	return os.RemoveAll(target)
}

func runPolicyInstall(cmd *cobra.Command, policyName, version string, overwrite, dryRun bool) error {
	resolved, err := ensurePolicyVersionAvailable(cmd, version)
	if err != nil {
		return err
	}
	policyPath, err := resolvePolicyFile(cmd.Context(), policyName, resolved)
	if err != nil {
		return err
	}
	resources, err := loadUnstructuredResources([]string{policyPath})
	if err != nil {
		return err
	}
	if len(resources) == 0 {
		return fmt.Errorf("policy %s not found in %s", policyName, policyPath)
	}

	if !overwrite {
		existing, err := kubernetes.ListValidatingAdmissionPolicies()
		if err != nil {
			return err
		}
		for _, policy := range existing {
			if policy.Name == policyName {
				return fmt.Errorf("policy %s already exists; use --overwrite to replace", policyName)
			}
		}
	}

	if err := applyKustomizeResources(resources, nil, dryRun); err != nil {
		return err
	}
	if dryRun {
		logging.Infof("Dry run: install policy %s %s", policyName, resolved)
	} else {
		logging.Infof("Installed policy %s %s", policyName, resolved)
	}
	return nil
}

func runPolicyUninstall(cmd *cobra.Command, policyName, version string, dryRun bool) error {
	resolved, err := ensurePolicyVersionAvailable(cmd, version)
	if err != nil {
		return err
	}
	policyPath, err := resolvePolicyFile(cmd.Context(), policyName, resolved)
	if err != nil {
		return err
	}
	resources, err := loadUnstructuredResources([]string{policyPath})
	if err != nil {
		return err
	}
	if len(resources) == 0 {
		return fmt.Errorf("policy %s not found in %s", policyName, policyPath)
	}
	if err := deleteKustomizeResources(resources, nil, dryRun); err != nil {
		return err
	}
	if dryRun {
		logging.Infof("Dry run: uninstall policy %s %s", policyName, resolved)
	} else {
		logging.Infof("Uninstalled policy %s %s", policyName, resolved)
	}
	return nil
}

func runPolicyShow(cmd *cobra.Command, policyName, version, format string) error {
	resolved, err := resolveLocalPolicyVersion(version)
	if err != nil {
		return err
	}
	format = strings.ToLower(strings.TrimSpace(format))
	if format == "" {
		format = "table"
	}
	if format != "table" && format != "yaml" && format != "json" {
		return fmt.Errorf("invalid format %s, expected table, yaml, or json", format)
	}

	index, err := loadPoliciesIndex(cmd.Context())
	if err != nil {
		return err
	}

	if policyName == "" {
		return renderPolicySummary(cmd, index, resolved, format)
	}

	policyPath, err := resolvePolicyFileWithIndex(index, policyName, resolved)
	if err != nil {
		return err
	}
	resources, err := loadUnstructuredResources([]string{policyPath})
	if err != nil {
		return err
	}
	if len(resources) == 0 {
		return fmt.Errorf("policy %s not found in %s", policyName, policyPath)
	}

	out := logging.Writer()
	switch format {
	case "json":
		data, err := json.MarshalIndent(resources[0].Object, "", "  ")
		if err != nil {
			return err
		}
		_, err = fmt.Fprintln(out, string(data))
		return err
	case "yaml":
		data, err := yaml.Marshal(resources[0].Object)
		if err != nil {
			return err
		}
		data = bytes.TrimSpace(data)
		if _, err := out.Write(data); err != nil {
			return err
		}
		_, err = fmt.Fprintln(out)
		return err
	default:
		policy, err := toValidatingAdmissionPolicy(resources[0].Object)
		if err != nil {
			return err
		}
		annotations := policyAnnotationsFrom(policy)
		t := table.NewWriter()
		t.SetOutputMirror(out)
		t.SetStyle(table.StyleRounded)
		t.AppendHeader(table.Row{"Field", "Value"})
		t.AppendRow(table.Row{"displayName", annotations.DisplayName})
		t.AppendRow(table.Row{"description", annotations.Description})
		t.AppendRow(table.Row{"resource", annotations.Resource})
		t.AppendRow(table.Row{"severity", annotations.Severity})
		t.AppendRow(table.Row{"remediation", annotations.Remediation})
		t.AppendRow(table.Row{"product", annotations.Product})
		if annotations.URL != "" {
			t.AppendRow(table.Row{"link", annotations.URL})
		}
		t.Render()
	}
	return nil
}

func renderPolicySummary(cmd *cobra.Command, index policiesIndex, version, format string) error {
	out := logging.Writer()
	root, err := config.PolicyVersionDir(version)
	if err != nil {
		return err
	}
	policies := make([]policySummary, 0, len(index.Policies))
	for _, entry := range index.Policies {
		path := filepath.Join(root, filepath.FromSlash(entry.File))
		policy, err := loadPolicyAnnotations(path)
		if err != nil {
			return err
		}
		policies = append(policies, policySummary{
			Name:        entry.Name,
			DisplayName: policy.DisplayName,
			Description: policy.Description,
			Product:     policy.Product,
		})
	}

	switch format {
	case "json":
		data, err := json.MarshalIndent(policies, "", "  ")
		if err != nil {
			return err
		}
		_, err = fmt.Fprintln(out, string(data))
		return err
	case "yaml":
		data, err := yaml.Marshal(policies)
		if err != nil {
			return err
		}
		data = bytes.TrimSpace(data)
		if _, err := out.Write(data); err != nil {
			return err
		}
		_, err = fmt.Fprintln(out)
		return err
	default:
		t := table.NewWriter()
		t.SetOutputMirror(out)
		t.SetStyle(table.StyleRounded)
		t.AppendHeader(table.Row{"Name", "Display Name", "Description", "Product"})
		for _, policy := range policies {
			t.AppendRow(table.Row{policy.Name, policy.DisplayName, policy.Description, policy.Product})
		}
		t.Render()
	}
	return nil
}

func resolvePolicyFile(ctx context.Context, policyName, version string) (string, error) {
	index, err := loadPoliciesIndex(ctx)
	if err != nil {
		return "", err
	}
	return resolvePolicyFileWithIndex(index, policyName, version)
}

func resolvePolicyFileWithIndex(index policiesIndex, policyName, version string) (string, error) {
	entry, ok := findPolicyIndexEntry(index, policyName)
	if !ok {
		return "", fmt.Errorf("policy %s not found in index", policyName)
	}
	return policyFilePath(version, entry.File)
}

func policyFilePath(version, file string) (string, error) {
	root, err := config.PolicyVersionDir(version)
	if err != nil {
		return "", err
	}
	path := filepath.Join(root, filepath.FromSlash(file))
	if _, err := os.Stat(path); err != nil {
		if os.IsNotExist(err) {
			return "", fmt.Errorf("policy file %s not found; download version %s first", path, version)
		}
		return "", err
	}
	return path, nil
}

func findPolicyIndexEntry(index policiesIndex, name string) (policiesIndexItem, bool) {
	for _, entry := range index.Policies {
		if entry.Name == name {
			return entry, true
		}
	}
	return policiesIndexItem{}, false
}

func loadPoliciesIndex(ctx context.Context) (policiesIndex, error) {
	path, err := config.PoliciesIndexPath()
	if err != nil {
		return policiesIndex{}, err
	}
	if data, err := os.ReadFile(path); err == nil {
		var index policiesIndex
		if err := json.Unmarshal(data, &index); err == nil {
			return index, nil
		}
	}
	return fetchPoliciesIndex(ctx, policiesIndexURL)
}

func fetchPoliciesIndex(ctx context.Context, url string) (policiesIndex, error) {
	client := &http.Client{Timeout: 30 * time.Second}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return policiesIndex{}, err
	}
	req.Header.Set("User-Agent", "kubeapt")

	resp, err := client.Do(req)
	if err != nil {
		return policiesIndex{}, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return policiesIndex{}, fmt.Errorf("policies index request failed: %s", resp.Status)
	}

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return policiesIndex{}, err
	}
	if err := syncPoliciesIndexCache(data); err != nil {
		return policiesIndex{}, err
	}

	var index policiesIndex
	if err := json.Unmarshal(data, &index); err != nil {
		return policiesIndex{}, err
	}
	return index, nil
}

func localPoliciesIndex() (policiesIndex, error) {
	versions, err := config.PolicyVersions()
	if err != nil {
		return policiesIndex{}, err
	}
	return policiesIndex{
		Versions: versions,
	}, nil
}

func syncPoliciesIndexCache(data []byte) error {
	path, err := config.PoliciesIndexPath()
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

func resolvePolicyVersion(index policiesIndex, version string) (string, error) {
	if version != "" {
		return version, nil
	}
	if index.LatestVersion == "" {
		return "", fmt.Errorf("latest policies version not found")
	}
	return index.LatestVersion, nil
}

func policyVersionInIndex(index policiesIndex, version string) bool {
	for _, v := range index.Versions {
		if v == version {
			return true
		}
	}
	return false
}

func policiesArchiveURL(version string) string {
	return fmt.Sprintf("https://github.com/cenroq/kubernetes-security-policies/releases/download/vap_policies%%40%s/%s", version, policiesArchive)
}

func policyVersionExists(version string) (bool, error) {
	path, err := config.PolicyVersionDir(version)
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

func resolveLocalPolicyVersion(version string) (string, error) {
	if version != "" {
		if err := validateBundleSegment("policy version", version); err != nil {
			return "", err
		}
		ok, err := policyVersionExists(version)
		if err != nil {
			return "", err
		}
		if ok {
			return version, nil
		}
		return "", fmt.Errorf("policy version %s not found; download it first", version)
	}
	versions, err := config.PolicyVersions()
	if err != nil {
		return "", err
	}
	if len(versions) == 0 {
		return "", fmt.Errorf("policies not found; run `kubeapt policies download`")
	}
	return versions[len(versions)-1], nil
}

func ensurePolicyVersionAvailable(cmd *cobra.Command, version string) (string, error) {
	index, err := fetchPoliciesIndex(cmd.Context(), policiesIndexURL)
	if err != nil {
		return "", err
	}
	resolved, err := resolvePolicyVersion(index, version)
	if err != nil {
		return "", err
	}
	if err := validateBundleSegment("policy version", resolved); err != nil {
		return "", err
	}
	ok, err := policyVersionExists(resolved)
	if err != nil {
		return "", err
	}
	if ok {
		return resolved, nil
	}
	if version != "" {
		if err := runPoliciesDownload(cmd, resolved); err != nil {
			return "", err
		}
		return resolved, nil
	}

	installed, err := config.PolicyVersions()
	if err != nil {
		return "", err
	}
	if len(installed) == 0 {
		if err := runPoliciesDownload(cmd, resolved); err != nil {
			return "", err
		}
		return resolved, nil
	}

	return "", fmt.Errorf("latest policy version %s is not downloaded; run `kubeapt policies download` or use --version", resolved)
}

func policyAnnotationsFrom(policy admissionregistrationv1.ValidatingAdmissionPolicy) policyAnnotations {
	annotations := policyAnnotations{}
	meta := policy.Annotations
	if meta == nil {
		return annotations
	}
	annotations.DisplayName = strings.TrimSpace(meta[policyAnnotationDisplayName])
	annotations.Description = strings.TrimSpace(meta[policyAnnotationDescription])
	annotations.Resource = strings.TrimSpace(meta[policyAnnotationResource])
	annotations.Severity = strings.TrimSpace(meta[policyAnnotationSeverity])
	annotations.Remediation = strings.TrimSpace(meta[policyAnnotationRemediation])
	annotations.Product = strings.TrimSpace(meta[policyAnnotationProduct])
	annotations.URL = policyURLFromAnnotations(meta)
	return annotations
}

func loadPolicyAnnotations(path string) (policyAnnotations, error) {
	resources, err := loadUnstructuredResources([]string{path})
	if err != nil {
		return policyAnnotations{}, err
	}
	if len(resources) == 0 {
		return policyAnnotations{}, fmt.Errorf("policy not found in %s", path)
	}
	policy, err := toValidatingAdmissionPolicy(resources[0].Object)
	if err != nil {
		return policyAnnotations{}, err
	}
	return policyAnnotationsFrom(policy), nil
}

func toValidatingAdmissionPolicy(obj map[string]interface{}) (admissionregistrationv1.ValidatingAdmissionPolicy, error) {
	var policy admissionregistrationv1.ValidatingAdmissionPolicy
	raw, err := json.Marshal(obj)
	if err != nil {
		return policy, err
	}
	if err := json.Unmarshal(raw, &policy); err != nil {
		return policy, err
	}
	return policy, nil
}
