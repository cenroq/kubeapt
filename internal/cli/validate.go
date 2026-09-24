// Copyright by cenroq AG
// Contact: info@cenroq.com

package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/fatih/color"
	"github.com/jedib0t/go-pretty/v6/progress"
	"github.com/jedib0t/go-pretty/v6/table"
	"github.com/jedib0t/go-pretty/v6/text"
	"github.com/spf13/cobra"
	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	utilyaml "k8s.io/apimachinery/pkg/util/yaml"

	"github.com/cenroq/kubeapt/v2/internal/config"
	"github.com/cenroq/kubeapt/v2/internal/format"
	"github.com/cenroq/kubeapt/v2/internal/kubernetes"
	"github.com/cenroq/kubeapt/v2/internal/logging"
	"github.com/cenroq/kubeapt/v2/internal/worker"
	policypkg "github.com/cenroq/kubeapt/v2/pkg/policies"
	"github.com/cenroq/kubeapt/v2/pkg/types"
)

var logLevelProvider func() string

type violationDetail struct {
	Policy   string   `json:"policy"`
	Binding  string   `json:"binding"`
	Severity string   `json:"severity"`
	Resource string   `json:"resource"`
	Message  string   `json:"message"`
	Path     string   `json:"path"`
	Actions  []string `json:"actions"`
	URL      string   `json:"url,omitempty"`
}

type bindingReport struct {
	Policy       string            `json:"policy"`
	Binding      string            `json:"binding"`
	Severity     string            `json:"severity"`
	Mode         string            `json:"mode"`
	URL          string            `json:"url,omitempty"`
	Total        int               `json:"total"`
	Compliant    int               `json:"compliant"`
	NonCompliant int               `json:"nonCompliant"`
	Violations   []violationDetail `json:"violations,omitempty"`
}

type namespaceReport struct {
	Namespace      string            `json:"namespace"`
	Total          int               `json:"total"`
	Compliant      int               `json:"compliant"`
	NonCompliant   int               `json:"nonCompliant"`
	SeverityCounts map[string]int    `json:"severityCounts,omitempty"`
	Violations     []violationDetail `json:"violations,omitempty"`
}

type resourceReport struct {
	Kind            string            `json:"kind"`
	Resource        string            `json:"resource"`
	TotalViolations int               `json:"totalViolations"`
	Violations      []violationDetail `json:"violations,omitempty"`
}

func ValidateCmd(getLogLevel func() string) *cobra.Command {
	logLevelProvider = getLogLevel
	cmd := &cobra.Command{
		Use:   "validate",
		Short: "Validate admission policies against resources",
		RunE:  runValidate,
	}
	cmd.PersistentFlags().Bool("pipeline", false, "Indicate the command runs inside CI/CD")
	cmd.PersistentFlags().BoolP("all-namespaces", "A", false, "Use all namespaces instead of the active one")
	cmd.PersistentFlags().StringP("namespaces", "n", "", "Comma separated list of namespaces to evaluate")
	cmd.PersistentFlags().String("namespace-selector", "", "Label selector to choose namespaces (e.g. env=prod)")
	cmd.PersistentFlags().StringP("format", "f", "table", "Specify the report output format: table or json")
	cmd.PersistentFlags().String("report", "summary", "Specify the final report type: summary or all")
	cmd.PersistentFlags().String("output", "", "Write the report to a file path instead of stdout")
	cmd.Flags().String("bundle", "", "Policy bundle name to use for policies/bindings")
	cmd.Flags().String("bundle-version", "", "Bundle version to use with --bundle (defaults to latest)")
	cmd.Flags().StringP("policies", "p", "", "Specify the file or folder to the ValidatingAdmissionPolicy YAML file")
	cmd.Flags().StringP("policy-name", "P", "", "Policy name to use from downloaded policies")
	cmd.Flags().String("policyresource", "", "Comma separated resource plurals (e.g. pods,deployments) to only evaluate policies whose matchConstraints target them")
	cmd.Flags().String("policy-resources", "", "Comma separated group/version/resource selectors (e.g. networking.k8s.io/v1/networkpolicies,/v1/services) to only evaluate policies whose matchConstraints target them; group-aware, unlike --policyresource")
	cmd.Flags().StringP("bindings", "b", "", "Specify the file or folder to the ValidatingAdmissionPolicyBinding YAML file")
	cmd.Flags().StringP("resource", "r", "", "Specify the file or folder to the resource YAML file to validate")
	cmd.Flags().String("psa-level", "", "PSA level to evaluate when using the pod-security-admission bundle: baseline or restricted")
	cmd.Flags().String("log-file", "", "Optional file to capture WARN/AUDIT output")
	cmd.Flags().Bool("ignore-bindings", false, "Ignore binding match rules and match policies on all selected resources")
	cmd.Flags().String("view", "", "Report view: policy, namespace, or resource")
	return cmd
}

func runValidate(cmd *cobra.Command, _ []string) error {
	flags := cmd.Flags()
	bundleName, err := flags.GetString("bundle")
	if err != nil {
		return err
	}
	bundleVersion, err := flags.GetString("bundle-version")
	if err != nil {
		return err
	}
	policyFile, err := flags.GetString("policies")
	if err != nil {
		return err
	}
	policyName, err := flags.GetString("policy-name")
	if err != nil {
		return err
	}
	policyResourceInput, err := flags.GetString("policyresource")
	if err != nil {
		return err
	}
	policyGVRInput, err := flags.GetString("policy-resources")
	if err != nil {
		return err
	}
	ignoreBindings, err := flags.GetBool("ignore-bindings")
	if err != nil {
		return err
	}
	bindingFile, err := flags.GetString("bindings")
	if err != nil {
		return err
	}
	resourceFile, err := flags.GetString("resource")
	if err != nil {
		return err
	}
	psaLevelInput, err := flags.GetString("psa-level")
	if err != nil {
		return err
	}
	viewInput, err := flags.GetString("view")
	if err != nil {
		return err
	}
	allNamespaces, err := flags.GetBool("all-namespaces")
	if err != nil {
		return err
	}
	namespaceList, err := flags.GetString("namespaces")
	if err != nil {
		return err
	}
	namespaceSelector, err := flags.GetString("namespace-selector")
	if err != nil {
		return err
	}
	namespaces := parseNamespaces(namespaceList)
	logFile, err := flags.GetString("log-file")
	if err != nil {
		return err
	}
	reportMode := strings.ToLower(cmd.Flag("report").Value.String())
	outputFormat := strings.ToLower(cmd.Flag("format").Value.String())
	outputPath := strings.TrimSpace(cmd.Flag("output").Value.String())

	if reportMode != "summary" && reportMode != "all" {
		return fmt.Errorf("invalid report type %s, expected summary or all", reportMode)
	}
	if outputFormat != "table" && outputFormat != "json" {
		return fmt.Errorf("invalid output format %s, expected table or json", outputFormat)
	}

	if err := logging.Init(logFile, logLevelProvider()); err != nil {
		return err
	}
	defer logging.Close()
	logging.SetOutputWriter(cmd.ErrOrStderr())
	logging.SetReportWriter(cmd.OutOrStdout())

	if bundleName != "" && (policyFile != "" || bindingFile != "" || policyName != "") {
		return fmt.Errorf("--bundle cannot be combined with --policies, --policy-name, or --bindings")
	}
	if bundleVersion != "" && bundleName == "" {
		return fmt.Errorf("--bundle-version requires --bundle")
	}
	if policyName != "" && policyFile != "" {
		return fmt.Errorf("--policy-name cannot be combined with --policies")
	}
	if policyName != "" && bindingFile != "" {
		return fmt.Errorf("--policy-name cannot be combined with --bindings")
	}
	if strings.TrimSpace(policyResourceInput) != "" && strings.TrimSpace(policyGVRInput) != "" {
		return fmt.Errorf("--policyresource and --policy-resources cannot be combined; use one")
	}

	if !ignoreBindings && bindingFile == "" && (policyFile != "" || policyName != "") {
		ignoreBindings = true
		logging.Warnf("No bindings provided, enabling --ignore-bindings")
	}

	psaLevel := strings.ToLower(strings.TrimSpace(psaLevelInput))
	if psaLevel != "" && psaLevel != "baseline" && psaLevel != "restricted" {
		return fmt.Errorf("invalid psa level %s, expected baseline or restricted", psaLevel)
	}
	if bundleName == "pod-security-admission" {
		if psaLevel == "" {
			return fmt.Errorf("--psa-level is required when using bundle pod-security-admission")
		}
	} else if psaLevel != "" {
		return fmt.Errorf("--psa-level is only supported with --bundle pod-security-admission")
	}

	view := strings.ToLower(strings.TrimSpace(viewInput))
	if view == "" {
		if bundleName != "" {
			view = "namespace"
		} else {
			view = "policy"
		}
	}
	if view != "policy" && view != "namespace" && view != "resource" {
		return fmt.Errorf("invalid view %s, expected policy, namespace, or resource", view)
	}
	viewHasPolicy := view == "policy"
	viewHasNamespace := view == "namespace"
	viewHasResource := view == "resource"

	if allNamespaces && len(namespaces) > 0 {
		return fmt.Errorf("--all-namespaces cannot be used together with --namespaces")
	}
	if namespaceSelector != "" {
		if allNamespaces || len(namespaces) > 0 {
			return fmt.Errorf("--namespace-selector cannot be used together with --all-namespaces or --namespaces")
		}
		selected, err := namespacesFromSelector(namespaceSelector)
		if err != nil {
			return err
		}
		if len(selected) == 0 {
			return fmt.Errorf("no namespaces matched selector %s", namespaceSelector)
		}
		namespaces = selected
	}
	if len(namespaces) == 0 && !allNamespaces {
		namespaces = []string{kubernetes.ActiveNamespace()}
	}

	progressEnabled := true
	writer := logging.Writer()
	tableStyle := table.StyleRounded
	useColor := true
	if outputPath != "" {
		f, err := os.Create(outputPath)
		if err != nil {
			return fmt.Errorf("failed to open output file: %w", err)
		}
		defer f.Close()
		logging.SetReportWriter(f)
		writer = logging.Writer()
		tableStyle = table.StyleDefault
		useColor = false
		progressEnabled = false
	}
	if outputFormat == "json" {
		progressEnabled = false
	}

	startTime := time.Now()

	var policies []admissionregistrationv1.ValidatingAdmissionPolicy
	var bindings []admissionregistrationv1.ValidatingAdmissionPolicyBinding

	switch {
	case bundleName != "":
		policiesPath, bindingsPath, err := locateInstalledBundle(bundleName, bundleVersion)
		if err != nil {
			return err
		}
		policyFiles, err := config.CollectManifestFilesRecursive(policiesPath)
		if err != nil {
			return err
		}
		bindingFiles, err := config.CollectManifestFilesRecursive(bindingsPath)
		if err != nil {
			return err
		}
		total := maxInt64(int64(len(policyFiles)+len(bindingFiles)), 1)
		err = withProgress("Reading policies", total, progressEnabled, func(tracker *progress.Tracker) error {
			policies, err = config.LoadPoliciesFromFilesWithProgress(policyFiles, func() {
				tracker.Increment(1)
			})
			if err != nil {
				return err
			}
			bindings, err = config.LoadBindingsFromFilesWithProgress(bindingFiles, func() {
				tracker.Increment(1)
			})
			return err
		})
		if err != nil {
			return err
		}
	case policyName != "":
		resolved, err := ensurePolicyVersionAvailable(cmd, "")
		if err != nil {
			return err
		}
		index, err := loadPoliciesIndex(cmd.Context())
		if err != nil {
			return err
		}
		policyPath, err := resolvePolicyFileWithIndex(index, policyName, resolved)
		if err != nil {
			return err
		}
		policyFiles, err := kubernetes.CountManifestFiles(policyPath)
		if err != nil {
			return err
		}
		total := maxInt64(int64(policyFiles), 1)
		err = withProgress("Reading policies", total, progressEnabled, func(tracker *progress.Tracker) error {
			policies, err = kubernetes.LoadValidatingAdmissionPoliciesWithProgress(policyPath, func(string) {
				tracker.Increment(1)
			})
			return err
		})
		if err != nil {
			return err
		}
	case policyFile != "" || bindingFile != "":
		if policyFile == "" && bindingFile != "" {
			policyFile = bindingFile
			logging.Debugf("No policies path provided, reusing %s", bindingFile)
		}
		if bindingFile == "" {
			bindingFile = policyFile
			logging.Debugf("No bindings path provided, reusing %s", policyFile)
		}
		policyFiles, err := kubernetes.CountManifestFiles(policyFile)
		if err != nil {
			return err
		}
		bindingFiles, err := kubernetes.CountManifestFiles(bindingFile)
		if err != nil {
			return err
		}
		total := maxInt64(int64(policyFiles+bindingFiles), 1)
		err = withProgress("Reading policies", total, progressEnabled, func(tracker *progress.Tracker) error {
			policies, err = kubernetes.LoadValidatingAdmissionPoliciesWithProgress(policyFile, func(string) {
				tracker.Increment(1)
			})
			if err != nil {
				return err
			}
			bindings, err = kubernetes.LoadValidatingAdmissionPolicyBindingsWithProgress(bindingFile, func(string) {
				tracker.Increment(1)
			})
			return err
		})
		if err != nil {
			return err
		}
	default:
		err = withProgress("Fetching remote policies", 2, progressEnabled, func(tracker *progress.Tracker) error {
			policies, err = kubernetes.ListValidatingAdmissionPolicies()
			if err != nil {
				return err
			}
			tracker.Increment(1)

			bindings, err = kubernetes.ListValidatingAdmissionPolicyBindings()
			if err != nil {
				return err
			}
			tracker.Increment(1)
			return nil
		})
		if err != nil {
			return err
		}
	}

	resourceFilter := parseResourceFilter(policyResourceInput)
	gvrFilter := parseGVRFilter(policyGVRInput)
	if len(resourceFilter) > 0 {
		originalCount := len(policies)
		policies, bindings = filterPoliciesByResource(policies, bindings, resourceFilter)
		if len(policies) == 0 {
			return fmt.Errorf("no policies target resource %s", strings.Join(resourceFilter, ", "))
		}
		logging.Debugf("Filtered policies by resource %s: %d of %d retained", strings.Join(resourceFilter, ", "), len(policies), originalCount)
	}
	if len(gvrFilter) > 0 {
		originalCount := len(policies)
		policies, bindings = filterPoliciesByGVR(policies, bindings, gvrFilter)
		if len(policies) == 0 {
			return fmt.Errorf("no policies target resource %s", policyGVRInput)
		}
		logging.Debugf("Filtered policies by GVR %s: %d of %d retained", policyGVRInput, len(policies), originalCount)
	}

	if ignoreBindings {
		bindings = implicitBindingsForPolicies(policies)
	}

	severityByPolicy := policySeverityMap(policies)

	var resources []map[string]interface{}
	namespaceLabels := make(map[string]map[string]string)

	if resourceFile != "" {
		localRes, localNS, err := loadLocalResources(resourceFile)
		if err != nil {
			return err
		}
		localRes = filterResourcesByNamespaces(localRes, namespaces, allNamespaces)
		logging.Debugf("Loaded %d resources from %s", len(localRes), resourceFile)
		resources = append(resources, localRes...)
		namespaceLabels = mergeFilteredNamespaceLabels(namespaceLabels, localNS, namespaces, allNamespaces)
	} else {
		scope := kubernetes.ResourceScopeSelected
		if allNamespaces {
			scope = kubernetes.ResourceScopeAllNamespaces
		}
		total := maxInt64(int64(len(policies)), 1)
		err = withProgress("Fetching remote resources", total, progressEnabled, func(tracker *progress.Tracker) error {
			remoteRes, remoteNS, err := kubernetes.ListResourcesForPoliciesWithProgress(policies, scope, namespaces, func() {
				tracker.Increment(1)
			})
			if err != nil {
				return err
			}
			logging.Debugf("Loaded %d resources from cluster", len(remoteRes))
			resources = append(resources, remoteRes...)
			namespaceLabels = mergeFilteredNamespaceLabels(namespaceLabels, remoteNS, namespaces, allNamespaces)
			return nil
		})
		if err != nil {
			return err
		}
	}

	if len(resources) == 0 {
		return fmt.Errorf("no resources available for validation")
	}

	kubernetes.NormalizeResourcesForCEL(resources)

	collectNamespace := viewHasNamespace
	collectResource := viewHasResource
	needPolicyEval := viewHasPolicy || collectNamespace || collectResource

	var (
		policyReports   []*bindingReport
		namespaceReport []namespaceReport
		resourceReport  []resourceReport
		policyFailures  bool
		resourceTotals  map[string]int
		resourceDetails []resourceDetail
	)

	if needPolicyEval {
		resourceTotals = countResourcesByKind(resources)
		resourceDetails = collectResourceDetails(resources)
		psaLevelForEval := ""
		if bundleName == "pod-security-admission" {
			psaLevelForEval = psaLevel
		}
		reports, nsReports, resReports, failures, err := evaluatePolicyReports(policies, bindings, resources, namespaceLabels, severityByPolicy, ignoreBindings, collectNamespace, collectResource, psaLevelForEval, progressEnabled)
		if err != nil {
			return err
		}
		policyReports = reports
		namespaceReport = nsReports
		resourceReport = resReports
		policyFailures = failures
	}

	if viewHasPolicy {
		if outputFormat == "json" {
			stopTime := time.Now()
			metadata := format.BuildJSONMetadata(cmd, view, namespacesFromResources(resources), resourceTotals, startTime, stopTime)
			payload := buildPolicyJSONReport(reportMode, policyReports, resourceTotals, resourceDetails)
			if err := format.WriteJSONEnvelope(writer, metadata, payload); err != nil {
				return err
			}
		} else {
			if err := renderReport(reportMode, outputFormat, policyReports, resourceTotals, resourceDetails, ignoreBindings, writer, tableStyle, useColor); err != nil {
				return err
			}
		}
	}
	if viewHasNamespace {
		if outputFormat == "json" {
			stopTime := time.Now()
			metadata := format.BuildJSONMetadata(cmd, view, namespacesFromResources(resources), resourceTotals, startTime, stopTime)
			payload := buildNamespaceJSONReport(reportMode, namespaceReport, resourceTotals)
			if err := format.WriteJSONEnvelope(writer, metadata, payload); err != nil {
				return err
			}
		} else {
			if err := renderNamespaceReport(reportMode, outputFormat, namespaceReport, resourceTotals, writer, tableStyle, useColor); err != nil {
				return err
			}
		}
	}
	if viewHasResource {
		if outputFormat == "json" {
			stopTime := time.Now()
			metadata := format.BuildJSONMetadata(cmd, view, namespacesFromResources(resources), resourceTotals, startTime, stopTime)
			payload := buildResourceJSONReport(reportMode, resourceReport)
			if err := format.WriteJSONEnvelope(writer, metadata, payload); err != nil {
				return err
			}
		} else {
			if err := renderResourceReport(reportMode, outputFormat, resourceReport, ignoreBindings, writer, tableStyle, useColor); err != nil {
				return err
			}
		}
	}

	if isPipeline(cmd) {
		if (viewHasPolicy || viewHasResource) && policyFailures {
			return fmt.Errorf("validation failures detected")
		}
		if viewHasNamespace {
			for _, namespaceEntry := range namespaceReport {
				if namespaceEntry.NonCompliant > 0 {
					return fmt.Errorf("validation failures detected")
				}
			}
		}
	}

	return nil
}

func evaluatePolicyReports(policies []admissionregistrationv1.ValidatingAdmissionPolicy, bindings []admissionregistrationv1.ValidatingAdmissionPolicyBinding, resources []map[string]interface{}, namespaceLabels map[string]map[string]string, severityByPolicy map[string]string, ignoreBindings bool, collectNamespace bool, collectResource bool, psaLevel string, progressEnabled bool) ([]*bindingReport, []namespaceReport, []resourceReport, bool, error) {
	if len(bindings) == 0 {
		logging.Debugf("No ValidatingAdmissionPolicyBindings available to evaluate")
		return nil, nil, nil, false, nil
	}

	policyIndex := make(map[string]*admissionregistrationv1.ValidatingAdmissionPolicy)
	for i := range policies {
		policy := &policies[i]
		policyIndex[policy.Name] = policy
	}

	var reports []*bindingReport
	storeResourceDetails := collectNamespace || collectResource
	var (
		resourceStatus     map[string]bool
		resourceNamespace  map[string]string
		resourceViolations map[string][]violationDetail
		resourceDisplay    map[string]string
		resourceKind       map[string]string
		resMu              sync.Mutex
	)
	if storeResourceDetails {
		resourceStatus = make(map[string]bool)
		resourceNamespace = make(map[string]string)
		resourceViolations = make(map[string][]violationDetail)
		resourceDisplay = make(map[string]string)
		resourceKind = make(map[string]string)
	}

	totalWork := len(resources) * len(bindings)
	tracker, stop := startProgress("Validating resources", int64(totalWork), progressEnabled)
	defer stop()
	progressCh := make(chan struct{}, 256)
	progressDone := make(chan struct{})
	go func() {
		for range progressCh {
			tracker.Increment(1)
		}
		close(progressDone)
	}()
	defer func() {
		close(progressCh)
		<-progressDone
	}()

	for i := range bindings {
		binding := &bindings[i]
		policy, ok := policyIndex[binding.Spec.PolicyName]
		if !ok {
			return nil, nil, nil, false, fmt.Errorf("binding %s references missing policy %s", binding.Name, binding.Spec.PolicyName)
		}

		severity := severityByPolicy[policy.Name]
		if severity == "" {
			severity = severityNotRated
		}
		policyURL := policyURLFromAnnotations(policy.Annotations)
		bReport := &bindingReport{
			Policy:   policy.Name,
			Binding:  binding.Name,
			Severity: severity,
			Mode:     bindingMode(binding),
			URL:      policyURL,
		}

		logging.Debugf("Evaluating binding %s targeting policy %s", binding.Name, policy.Name)
		matched := false
		var mu sync.Mutex
		ctx, cancel := context.WithCancel(context.Background())
		workers := worker.WorkerLimit(len(resources))
		tasks := make(chan map[string]interface{}, workers*2)
		errCh := make(chan error, 1)
		var wg sync.WaitGroup
		for w := 0; w < workers; w++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for {
					select {
					case <-ctx.Done():
						return
					case resource, ok := <-tasks:
						if !ok {
							return
						}
						progressCh <- struct{}{}
						namespaceName := kubernetes.MetadataString(resource, "namespace")
						namespaceLabelValues, namespaceKnown := namespaceLabels[namespaceName]
						if psaLevel != "" {
							namespaceLabelValues = kubernetes.ApplyPSALevelLabels(namespaceLabelValues, psaLevel)
							namespaceKnown = true
						}
						if !kubernetes.MatchesPolicy(policy, resource, namespaceLabelValues, namespaceKnown, false) {
							continue
						}
						if !ignoreBindings {
							if !kubernetes.MatchesBinding(binding, resource, namespaceLabelValues, namespaceKnown, false, false) {
								continue
							}
						}
						resourceName := describeResource(resource)
						resourceKindName, resourceDisplayName := resourceDisplayName(resource)
						logging.Debugf("  Matched %s", resourceName)
						result, err := kubernetes.EvaluateValidations(policy, binding, resource, namespaceName, namespaceLabelValues)
						if err != nil {
							select {
							case errCh <- err:
							default:
							}
							cancel()
							return
						}
						resourceKeyValue := resourceKey(resource)
						if result.Compliant {
							mu.Lock()
							matched = true
							bReport.Total++
							bReport.Compliant++
							mu.Unlock()
							if storeResourceDetails {
								updateResourceStatus(resourceStatus, resourceNamespace, resourceViolations, resourceDisplay, resourceKind, resourceKeyValue, resourceDisplayName, resourceKindName, namespaceName, true, nil, &resMu)
							}
							continue
						}
						violations := make([]violationDetail, len(result.Violations))
						for i, violation := range result.Violations {
							violations[i] = violationDetail{
								Policy:   policy.Name,
								Binding:  binding.Name,
								Severity: severity,
								Resource: resourceName,
								Message:  violation.Message,
								Path:     violation.Path,
								Actions:  violation.Actions,
								URL:      policyURL,
							}
						}
						mu.Lock()
						matched = true
						bReport.Total++
						bReport.NonCompliant++
						bReport.Violations = append(bReport.Violations, violations...)
						mu.Unlock()
						if storeResourceDetails {
							updateResourceStatus(resourceStatus, resourceNamespace, resourceViolations, resourceDisplay, resourceKind, resourceKeyValue, resourceDisplayName, resourceKindName, namespaceName, false, violations, &resMu)
						}
					}
				}
			}()
		}

	resourceLoop:
		for _, resource := range resources {
			select {
			case <-ctx.Done():
				break resourceLoop
			case tasks <- resource:
			}
		}
		close(tasks)
		wg.Wait()
		cancel()
		select {
		case err := <-errCh:
			return nil, nil, nil, false, err
		default:
		}

		mu.Lock()
		matchedNow := matched
		mu.Unlock()
		if !matchedNow {
			logging.Debugf("  No resources matched binding %s", binding.Name)
			continue
		}
		reports = append(reports, bReport)
	}

	var (
		namespaceReports []namespaceReport
		resourceReports  []resourceReport
	)
	if collectNamespace {
		namespaceMap := make(map[string]*namespaceReport)
		for id, status := range resourceStatus {
			namespaceName := resourceNamespace[id]
			if namespaceName == "" {
				namespaceName = "<cluster>"
			}
			report, ok := namespaceMap[namespaceName]
			if !ok {
				report = &namespaceReport{Namespace: namespaceName}
				namespaceMap[namespaceName] = report
			}
			report.Total++
			if status {
				report.Compliant++
			} else {
				report.NonCompliant++
				violations := resourceViolations[id]
				if len(violations) > 0 {
					report.Violations = append(report.Violations, violations...)
				}
				if report.SeverityCounts == nil {
					report.SeverityCounts = make(map[string]int)
				}
				report.SeverityCounts[highestResourceSeverity(violations)]++
			}
		}
		for _, resource := range resources {
			namespaceName := kubernetes.MetadataString(resource, "namespace")
			if namespaceName == "" {
				continue
			}
			if _, ok := namespaceMap[namespaceName]; !ok {
				namespaceMap[namespaceName] = &namespaceReport{Namespace: namespaceName}
			}
		}
		for namespaceName := range namespaceLabels {
			if namespaceName == "" {
				continue
			}
			if _, ok := namespaceMap[namespaceName]; !ok {
				namespaceMap[namespaceName] = &namespaceReport{Namespace: namespaceName}
			}
		}
		for _, report := range namespaceMap {
			namespaceReports = append(namespaceReports, *report)
		}
		sort.Slice(namespaceReports, func(i, j int) bool {
			return namespaceReports[i].Namespace < namespaceReports[j].Namespace
		})
	}
	if collectResource {
		for resourceKey := range resourceViolations {
			violations := resourceViolations[resourceKey]
			if len(violations) == 0 {
				continue
			}
			resourceName := resourceDisplay[resourceKey]
			if resourceName == "" {
				resourceName = resourceKey
			}
			resourceKindName := resourceKind[resourceKey]
			resourceReports = append(resourceReports, resourceReport{
				Kind:            resourceKindName,
				Resource:        resourceName,
				TotalViolations: len(violations),
				Violations:      violations,
			})
		}
		sort.Slice(resourceReports, func(i, j int) bool {
			if resourceReports[i].Kind == resourceReports[j].Kind {
				return resourceReports[i].Resource < resourceReports[j].Resource
			}
			return resourceReports[i].Kind < resourceReports[j].Kind
		})
	}

	hasFailures := false
	for _, report := range reports {
		if report.NonCompliant > 0 {
			hasFailures = true
			break
		}
	}

	return reports, namespaceReports, resourceReports, hasFailures, nil
}

func updateResourceStatus(status map[string]bool, namespaces map[string]string, violations map[string][]violationDetail, display map[string]string, kinds map[string]string, id, resourceName, kind, namespace string, compliant bool, newViolations []violationDetail, mu *sync.Mutex) {
	if status == nil {
		return
	}
	mu.Lock()
	defer mu.Unlock()
	if id == "" {
		return
	}
	if resourceName != "" {
		display[id] = resourceName
	}
	if kind != "" {
		kinds[id] = kind
	}
	namespaces[id] = namespace
	if compliant {
		if _, ok := status[id]; !ok {
			status[id] = true
		}
		return
	}
	status[id] = false
	if len(newViolations) > 0 {
		violations[id] = append(violations[id], newViolations...)
	}
}

// highestResourceSeverity returns the most severe violation severity for a resource.
func highestResourceSeverity(violations []violationDetail) string {
	best := severityNotRated
	bestRank := severityRank(best)
	for _, v := range violations {
		normalized := normalizeSeverity(v.Severity)
		r := severityRank(normalized)
		if r < bestRank {
			best = normalized
			bestRank = r
		}
	}
	return best
}

func implicitBindingsForPolicies(policies []admissionregistrationv1.ValidatingAdmissionPolicy) []admissionregistrationv1.ValidatingAdmissionPolicyBinding {
	if len(policies) == 0 {
		return nil
	}
	bindings := make([]admissionregistrationv1.ValidatingAdmissionPolicyBinding, 0, len(policies))
	for _, policy := range policies {
		name := strings.TrimSpace(policy.Name)
		if name == "" {
			continue
		}
		bindings = append(bindings, admissionregistrationv1.ValidatingAdmissionPolicyBinding{
			ObjectMeta: metav1.ObjectMeta{
				Name: name + "--implicit",
			},
			Spec: admissionregistrationv1.ValidatingAdmissionPolicyBindingSpec{
				PolicyName: name,
			},
		})
	}
	return bindings
}

func loadLocalResources(path string) ([]map[string]interface{}, map[string]map[string]string, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, nil, err
	}

	if info.IsDir() {
		files, err := collectFiles(path)
		if err != nil {
			return nil, nil, err
		}
		var objs []map[string]interface{}
		for _, file := range files {
			items, err := readResourceFile(file)
			if err != nil {
				logging.Debugf("Skipping resource file %s: %v", file, err)
				continue
			}
			objs = append(objs, items...)
		}
		return objs, buildNamespaceLabelIndex(objs), nil
	}

	objects, err := readResourceFile(path)
	if err != nil {
		return nil, nil, err
	}
	return objects, buildNamespaceLabelIndex(objects), nil
}

func readResourceFile(path string) ([]map[string]interface{}, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	return decodeResources(f)
}

func decodeResources(r io.Reader) ([]map[string]interface{}, error) {
	decoder := utilyaml.NewYAMLOrJSONDecoder(r, 4096)
	var resources []map[string]interface{}

	for {
		var raw runtime.RawExtension
		if err := decoder.Decode(&raw); err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			return nil, err
		}

		if len(bytes.TrimSpace(raw.Raw)) == 0 {
			continue
		}

		var obj map[string]interface{}
		if err := json.Unmarshal(raw.Raw, &obj); err != nil {
			return nil, err
		}

		if len(obj) == 0 {
			continue
		}

		if apiVersion, _ := obj["apiVersion"].(string); apiVersion == "" {
			continue
		}
		if kind, _ := obj["kind"].(string); kind == "" {
			continue
		}

		resources = append(resources, obj)
	}

	return resources, nil
}

func buildNamespaceLabelIndex(resources []map[string]interface{}) map[string]map[string]string {
	index := make(map[string]map[string]string)
	for _, obj := range resources {
		kind, _ := obj["kind"].(string)
		if strings.EqualFold(kind, "Namespace") {
			name := kubernetes.MetadataString(obj, "name")
			if name == "" {
				continue
			}
			index[name] = kubernetes.MetadataLabels(obj)
		}
	}
	return index
}

func describeResource(obj map[string]interface{}) string {
	kind, _ := obj["kind"].(string)
	name := kubernetes.MetadataString(obj, "name")
	namespace := kubernetes.MetadataString(obj, "namespace")
	if namespace == "" {
		namespace = "<cluster>"
	}
	return fmt.Sprintf("%s %s/%s", kind, namespace, name)
}

func resourceDisplayName(obj map[string]interface{}) (string, string) {
	kind, _ := obj["kind"].(string)
	name := kubernetes.MetadataString(obj, "name")
	namespace := kubernetes.MetadataString(obj, "namespace")
	if namespace == "" {
		return kind, name
	}
	return kind, fmt.Sprintf("%s/%s", namespace, name)
}

func actionsToStrings(actions []admissionregistrationv1.ValidationAction) []string {
	result := make([]string, len(actions))
	for i, action := range actions {
		result[i] = string(action)
	}
	return result
}

func startProgress(message string, total int64, enabled bool) (*progress.Tracker, func()) {
	if !enabled {
		tracker := &progress.Tracker{
			Message: message,
			Total:   maxInt64(total, 1),
		}
		return tracker, func() {}
	}
	pw := progress.NewWriter()
	pw.SetOutputWriter(logging.Writer())
	pw.SetAutoStop(false)
	pw.SetTrackerLength(40)
	pw.SetSortBy(progress.SortByNone)
	pw.SetMessageWidth(28)

	tracker := &progress.Tracker{
		Message: message,
		Total:   maxInt64(total, 1),
	}
	pw.AppendTracker(tracker)
	go pw.Render()

	stop := func() {
		tracker.MarkAsDone()
		pw.Stop()
		logging.Newline()
	}
	return tracker, stop
}

func withProgress(message string, total int64, enabled bool, fn func(*progress.Tracker) error) error {
	tracker, stop := startProgress(message, total, enabled)
	defer stop()
	return fn(tracker)
}

func resourceKey(obj map[string]interface{}) string {
	kind, _ := obj["kind"].(string)
	namespace := kubernetes.MetadataString(obj, "namespace")
	name := kubernetes.MetadataString(obj, "name")
	uid := kubernetes.MetadataString(obj, "uid")
	return fmt.Sprintf("%s/%s/%s/%s", kind, namespace, name, uid)
}

func bindingMode(binding *admissionregistrationv1.ValidatingAdmissionPolicyBinding) string {
	actions := binding.Spec.ValidationActions
	if len(actions) == 0 {
		return string(admissionregistrationv1.Deny)
	}
	return strings.Join(actionsToStrings(actions), ",")
}

func violationSeverityLabel(severity string) (string, *color.Color) {
	normalized := normalizeSeverity(severity)
	return strings.ToUpper(normalized), severityColor(normalized)
}

func maxInt64(a, b int64) int64 {
	if a > b {
		return a
	}
	return b
}

func mergeFilteredNamespaceLabels(dest, src map[string]map[string]string, namespaces []string, includeAll bool) map[string]map[string]string {
	if dest == nil {
		dest = make(map[string]map[string]string)
	}
	useFilter := !includeAll && len(namespaces) > 0
	allowed := make(map[string]struct{})
	if useFilter {
		for _, namespaceName := range namespaces {
			allowed[namespaceName] = struct{}{}
		}
	}
	for namespaceName, labels := range src {
		if useFilter {
			if _, ok := allowed[namespaceName]; !ok {
				continue
			}
		}
		dest[namespaceName] = convertPSANamespaceLabels(labels)
	}
	if useFilter {
		for namespaceName := range dest {
			if _, ok := allowed[namespaceName]; !ok {
				delete(dest, namespaceName)
			}
		}
	}
	return dest
}

func filterResourcesByNamespaces(resources []map[string]interface{}, namespaces []string, includeAll bool) []map[string]interface{} {
	if includeAll || len(namespaces) == 0 {
		return resources
	}
	allowed := make(map[string]struct{})
	for _, namespaceName := range namespaces {
		if namespaceName != "" {
			allowed[namespaceName] = struct{}{}
		}
	}
	var filtered []map[string]interface{}
	for _, resource := range resources {
		namespaceName := kubernetes.MetadataString(resource, "namespace")
		if namespaceName == "" {
			filtered = append(filtered, resource)
			continue
		}
		if _, ok := allowed[namespaceName]; ok {
			filtered = append(filtered, resource)
		}
	}
	return filtered
}

func parseNamespaces(arg string) []string {
	if arg == "" {
		return nil
	}
	parts := strings.Split(arg, ",")
	var result []string
	for _, part := range parts {
		trimmed := strings.TrimSpace(part)
		if trimmed != "" {
			result = append(result, trimmed)
		}
	}
	return result
}

// parseResourceFilter parses --policyresource into deduplicated lowercase resource plurals.
func parseResourceFilter(arg string) []string {
	if strings.TrimSpace(arg) == "" {
		return nil
	}
	seen := make(map[string]struct{})
	var result []string
	for _, part := range strings.Split(arg, ",") {
		trimmed := strings.ToLower(strings.TrimSpace(part))
		if trimmed == "" {
			continue
		}
		if _, ok := seen[trimmed]; ok {
			continue
		}
		seen[trimmed] = struct{}{}
		result = append(result, trimmed)
	}
	return result
}

// parseGVRFilter parses a comma-separated --policy-resources value into GVRs.
func parseGVRFilter(arg string) []types.GVR {
	if strings.TrimSpace(arg) == "" {
		return nil
	}
	seen := make(map[string]struct{})
	var result []types.GVR
	for _, part := range strings.Split(arg, ",") {
		if strings.TrimSpace(part) == "" {
			continue
		}
		gvr := parseGVRToken(part)
		if gvr.Resource == "" {
			continue
		}
		key := gvr.Group + "/" + gvr.Version + "/" + gvr.Resource
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		result = append(result, gvr)
	}
	return result
}

// parseGVRToken parses one "group/version/resource" selector into a GVR.
func parseGVRToken(token string) types.GVR {
	segments := strings.Split(token, "/")
	for i := range segments {
		segments[i] = strings.TrimSpace(segments[i])
	}
	switch len(segments) {
	case 1:
		return types.GVR{Group: "*", Version: "*", Resource: segments[0]}
	case 2:
		return types.GVR{Group: segments[0], Version: "*", Resource: segments[1]}
	default:
		return types.GVR{Group: segments[0], Version: segments[1], Resource: segments[len(segments)-1]}
	}
}

// filterPoliciesByGVR keeps policies targeting the GVRs and their bindings.
func filterPoliciesByGVR(policies []admissionregistrationv1.ValidatingAdmissionPolicy, bindings []admissionregistrationv1.ValidatingAdmissionPolicyBinding, gvrs []types.GVR) ([]admissionregistrationv1.ValidatingAdmissionPolicy, []admissionregistrationv1.ValidatingAdmissionPolicyBinding) {
	if len(gvrs) == 0 {
		return policies, bindings
	}

	keptPolicies := make([]admissionregistrationv1.ValidatingAdmissionPolicy, 0, len(policies))
	keptNames := make(map[string]struct{}, len(policies))
	for i := range policies {
		if policypkg.PolicyTargetsGVRs(&policies[i], gvrs) {
			keptPolicies = append(keptPolicies, policies[i])
			keptNames[policies[i].Name] = struct{}{}
		}
	}

	if len(bindings) == 0 {
		return keptPolicies, bindings
	}

	keptBindings := make([]admissionregistrationv1.ValidatingAdmissionPolicyBinding, 0, len(bindings))
	for i := range bindings {
		if _, ok := keptNames[bindings[i].Spec.PolicyName]; ok {
			keptBindings = append(keptBindings, bindings[i])
		}
	}
	return keptPolicies, keptBindings
}

// filterPoliciesByResource keeps policies targeting the resource plurals and their bindings.
func filterPoliciesByResource(policies []admissionregistrationv1.ValidatingAdmissionPolicy, bindings []admissionregistrationv1.ValidatingAdmissionPolicyBinding, resources []string) ([]admissionregistrationv1.ValidatingAdmissionPolicy, []admissionregistrationv1.ValidatingAdmissionPolicyBinding) {
	if len(resources) == 0 {
		return policies, bindings
	}

	keptPolicies := make([]admissionregistrationv1.ValidatingAdmissionPolicy, 0, len(policies))
	keptNames := make(map[string]struct{}, len(policies))
	for i := range policies {
		if policypkg.PolicyTargetsResources(&policies[i], resources) {
			keptPolicies = append(keptPolicies, policies[i])
			keptNames[policies[i].Name] = struct{}{}
		}
	}

	if len(bindings) == 0 {
		return keptPolicies, bindings
	}

	keptBindings := make([]admissionregistrationv1.ValidatingAdmissionPolicyBinding, 0, len(bindings))
	for i := range bindings {
		if _, ok := keptNames[bindings[i].Spec.PolicyName]; ok {
			keptBindings = append(keptBindings, bindings[i])
		}
	}
	return keptPolicies, keptBindings
}

func namespacesFromSelector(selector string) ([]string, error) {
	selector = strings.TrimSpace(selector)
	if selector == "" {
		return nil, nil
	}
	clientset, err := kubernetes.NewClientset()
	if err != nil {
		return nil, err
	}
	namespaceList, err := clientset.CoreV1().Namespaces().List(context.TODO(), metav1.ListOptions{
		LabelSelector: selector,
	})
	if err != nil {
		return nil, err
	}
	namespaceNames := make([]string, 0, len(namespaceList.Items))
	for _, namespace := range namespaceList.Items {
		if namespace.Name != "" {
			namespaceNames = append(namespaceNames, namespace.Name)
		}
	}
	sort.Strings(namespaceNames)
	return namespaceNames, nil
}

func extractPodsFromResources(resources []map[string]interface{}) ([]corev1.Pod, error) {
	var pods []corev1.Pod
	for _, obj := range resources {
		kind, _ := obj["kind"].(string)
		if !strings.EqualFold(kind, "Pod") {
			continue
		}
		raw, err := json.Marshal(obj)
		if err != nil {
			return nil, err
		}
		var pod corev1.Pod
		if err := json.Unmarshal(raw, &pod); err != nil {
			return nil, err
		}
		if pod.Namespace == "" {
			pod.Namespace = kubernetes.ActiveNamespace()
		}
		pods = append(pods, pod)
	}
	return pods, nil
}

func countResourcesByKind(resources []map[string]interface{}) map[string]int {
	totals := make(map[string]int)
	seen := make(map[string]struct{})
	for _, res := range resources {
		id := resourceKey(res)
		if _, ok := seen[id]; ok {
			continue
		}
		seen[id] = struct{}{}
		if kind, _ := res["kind"].(string); kind != "" {
			totals[kind]++
		}
	}
	return totals
}

func namespacesFromResources(resources []map[string]interface{}) []string {
	if len(resources) == 0 {
		return nil
	}
	namespaces := make([]string, 0, len(resources))
	for _, resource := range resources {
		namespaceName := kubernetes.MetadataString(resource, "namespace")
		if namespaceName == "" {
			continue
		}
		namespaces = append(namespaces, namespaceName)
	}
	return format.UniqueSortedStrings(namespaces)
}

func renderReport(reportMode, outputFormat string, reports []*bindingReport, resourceTotals map[string]int, resourceDetails []resourceDetail, hideBindingInfo bool, w io.Writer, style table.Style, useColor bool) error {
	switch outputFormat {
	case "json":
		return renderJSONReport(reportMode, reports, resourceTotals, resourceDetails, w)
	case "table":
		printSummaryTables(reports, hideBindingInfo, w, style, useColor)
		printResourceTotals(resourceTotals, w, style)
		if reportMode == "all" {
			printViolationLogs(reports, w, useColor)
		}
	default:
		return fmt.Errorf("unsupported format %s", outputFormat)
	}
	return nil
}

type policyJSONReport struct {
	Report     string            `json:"report"`
	Format     string            `json:"format"`
	Data       []*bindingReport  `json:"bindings"`
	Violations []violationDetail `json:"violations,omitempty"`
	Totals     map[string]int    `json:"resourceTotals,omitempty"`
	Resources  []resourceDetail  `json:"resources,omitempty"`
}

func buildPolicyJSONReport(reportMode string, reports []*bindingReport, resourceTotals map[string]int, details []resourceDetail) policyJSONReport {
	payload := policyJSONReport{
		Report: reportMode,
		Format: "json",
		Totals: resourceTotals,
	}
	if len(details) > 0 {
		payload.Resources = details
	}
	for _, br := range reports {
		copyReport := *br
		copyReport.Violations = nil
		payload.Data = append(payload.Data, &copyReport)
	}
	if reportMode == "all" {
		payload.Violations = flattenViolationsSortedBySeverity(reports)
	}
	return payload
}

func renderJSONReport(reportMode string, reports []*bindingReport, resourceTotals map[string]int, details []resourceDetail, w io.Writer) error {
	payload := buildPolicyJSONReport(reportMode, reports, resourceTotals, details)
	encoded, err := json.MarshalIndent(payload, "", "  ")
	if err != nil {
		return err
	}
	fmt.Fprintln(w, string(encoded))
	return nil
}

type namespaceJSONReport struct {
	Report         string            `json:"report"`
	Format         string            `json:"format"`
	Namespaces     []namespaceReport `json:"namespaces"`
	SeverityTotals map[string]int    `json:"severityTotals,omitempty"`
	Totals         map[string]int    `json:"resourceTotals,omitempty"`
}

func buildNamespaceJSONReport(reportMode string, reports []namespaceReport, resourceTotals map[string]int) namespaceJSONReport {
	payload := namespaceJSONReport{
		Report: reportMode,
		Format: "json",
		Totals: resourceTotals,
	}
	severityTotals := make(map[string]int)
	for _, res := range reports {
		copyRes := res
		if reportMode != "all" {
			copyRes.Violations = nil
		} else if len(copyRes.Violations) > 0 {
			sorted := append([]violationDetail(nil), copyRes.Violations...)
			sortViolationsBySeverity(sorted)
			copyRes.Violations = sorted
		}
		for sev, count := range copyRes.SeverityCounts {
			severityTotals[sev] += count
		}
		payload.Namespaces = append(payload.Namespaces, copyRes)
	}
	if len(severityTotals) > 0 {
		payload.SeverityTotals = severityTotals
	}
	return payload
}

func renderNamespaceReport(reportMode, outputFormat string, reports []namespaceReport, resourceTotals map[string]int, w io.Writer, style table.Style, useColor bool) error {
	switch outputFormat {
	case "json":
		payload := buildNamespaceJSONReport(reportMode, reports, resourceTotals)
		encoded, err := json.MarshalIndent(payload, "", "  ")
		if err != nil {
			return err
		}
		fmt.Fprintln(w, string(encoded))
	case "table":
		printNamespaceTable(reports, w, style)
		printResourceTotals(resourceTotals, w, style)
		if reportMode == "all" {
			printNamespaceViolationLogs(reports, w, useColor)
		}
	default:
		return fmt.Errorf("unsupported format %s", outputFormat)
	}
	return nil
}

func renderResourceReport(reportMode, outputFormat string, reports []resourceReport, ignoreBindings bool, w io.Writer, style table.Style, useColor bool) error {
	switch outputFormat {
	case "json":
		payload := buildResourceJSONReport(reportMode, reports)
		encoded, err := json.MarshalIndent(payload, "", "  ")
		if err != nil {
			return err
		}
		fmt.Fprintln(w, string(encoded))
	case "table":
		printResourceViolationTable(reportMode, reports, ignoreBindings, w, style, useColor)
	default:
		return fmt.Errorf("unsupported format %s", outputFormat)
	}
	return nil
}

type resourceJSONReport struct {
	Report    string           `json:"report"`
	Format    string           `json:"format"`
	Resources []resourceReport `json:"resources"`
}

func buildResourceJSONReport(reportMode string, reports []resourceReport) resourceJSONReport {
	payload := resourceJSONReport{
		Report: reportMode,
		Format: "json",
	}
	for _, res := range reports {
		copyRes := res
		if reportMode != "all" {
			copyRes.Violations = nil
		} else if len(copyRes.Violations) > 0 {
			sorted := append([]violationDetail(nil), copyRes.Violations...)
			sortViolationsBySeverity(sorted)
			copyRes.Violations = sorted
		}
		payload.Resources = append(payload.Resources, copyRes)
	}
	return payload
}

func printResourceViolationTable(reportMode string, reports []resourceReport, ignoreBindings bool, w io.Writer, style table.Style, useColor bool) {
	header := table.Row{"Resource", "Violations (Bindings)", "Violations", "Policies"}
	if ignoreBindings {
		header = table.Row{"Resource", "Violations", "Policies"}
	}
	if len(reports) == 0 {
		t := table.NewWriter()
		t.SetOutputMirror(w)
		t.SetStyle(style)
		t.AppendHeader(header)
		t.AppendSeparator()
		if ignoreBindings {
			t.AppendRow(table.Row{"Totals", 0, ""})
		} else {
			t.AppendRow(table.Row{"Totals", 0, 0, ""})
		}
		fmt.Fprintln(w)
		t.Render()
		return
	}
	t := table.NewWriter()
	t.SetOutputMirror(w)
	t.SetStyle(style)
	t.AppendHeader(header)
	totalViolations := 0
	totalPolicyViolations := 0
	currentKind := ""
	for _, report := range reports {
		if report.Kind != "" && report.Kind != currentKind {
			if currentKind != "" {
				t.AppendSeparator()
				if ignoreBindings {
					t.AppendRow(table.Row{"", "", ""})
				} else {
					t.AppendRow(table.Row{"", "", "", ""})
				}
			}
			currentKind = report.Kind
			if ignoreBindings {
				t.AppendRow(table.Row{fmt.Sprintf("Kind: %s", report.Kind), "", ""})
			} else {
				t.AppendRow(table.Row{fmt.Sprintf("Kind: %s", report.Kind), "", "", ""})
			}
		}
		uniquePolicies := uniqueViolationFields(report.Violations, func(v violationDetail) string { return v.Policy })
		policyCount := len(uniquePolicies)
		if ignoreBindings {
			t.AppendRow(table.Row{
				report.Resource,
				policyCount,
				strings.Join(uniquePolicies, "\n"),
			})
		} else {
			t.AppendRow(table.Row{
				report.Resource,
				report.TotalViolations,
				policyCount,
				strings.Join(uniquePolicies, "\n"),
			})
		}
		totalViolations += report.TotalViolations
		totalPolicyViolations += policyCount
	}
	t.AppendSeparator()
	if ignoreBindings {
		t.AppendRow(table.Row{"Totals", totalPolicyViolations, ""})
	} else {
		t.AppendRow(table.Row{"Totals", totalViolations, totalPolicyViolations, ""})
	}
	fmt.Fprintln(w)
	t.Render()
	if reportMode == "all" {
		printResourceViolationLogs(reports, w, useColor)
	}
}

func uniqueViolationFields(violations []violationDetail, fn func(violationDetail) string) []string {
	seen := make(map[string]struct{})
	var values []string
	for _, violation := range violations {
		value := strings.TrimSpace(fn(violation))
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		values = append(values, value)
	}
	sort.Strings(values)
	return values
}

func printResourceViolationLogs(reports []resourceReport, w io.Writer, useColor bool) {
	fmt.Fprintln(w, "\nViolations")
	found := false
	for _, res := range reports {
		if len(res.Violations) == 0 {
			continue
		}
		found = true
		if res.Kind != "" {
			fmt.Fprintf(w, "Resource: %s %s\n", res.Kind, res.Resource)
		} else {
			fmt.Fprintf(w, "Resource: %s\n", res.Resource)
		}
		sortedViolations := append([]violationDetail(nil), res.Violations...)
		sortViolationsBySeverity(sortedViolations)
		for _, violation := range sortedViolations {
			label, formatter := violationSeverityLabel(violation.Severity)
			if useColor {
				formatter.Fprintf(w, "[%s] Policy %s / Binding %s\n", label, violation.Policy, violation.Binding)
			} else {
				fmt.Fprintf(w, "[%s] Policy %s / Binding %s\n", label, violation.Policy, violation.Binding)
			}
			if violation.URL != "" {
				fmt.Fprintf(w, "Link    : %s\n", violation.URL)
			}
			fmt.Fprintf(w, "Message : %s\n", violation.Message)
		}
	}
	if !found {
		fmt.Fprintln(w, "No violations detected.")
	}
}

func printNamespaceTable(reports []namespaceReport, w io.Writer, style table.Style) {
	if len(reports) == 0 {
		t := table.NewWriter()
		t.SetOutputMirror(w)
		t.SetStyle(style)
		t.AppendHeader(table.Row{"Namespace", "Total", "Compliant", "NonCompliant"})
		t.AppendSeparator()
		t.AppendRow(table.Row{"Totals", 0, 0, 0})
		fmt.Fprintln(w)
		t.Render()
		return
	}

	visibleSeverities, severityTotals := visibleSeverityColumns(reports)

	header := table.Row{"Namespace", "Total Evaluated", "Compliant"}
	for _, sev := range visibleSeverities {
		header = append(header, sev)
	}
	header = append(header, "NonCompliant")

	t := table.NewWriter()
	t.SetOutputMirror(w)
	t.SetStyle(style)
	t.AppendHeader(header)

	var total, compliant, non int
	for _, res := range reports {
		row := table.Row{res.Namespace, res.Total, res.Compliant}
		for _, sev := range visibleSeverities {
			row = append(row, res.SeverityCounts[sev])
		}
		row = append(row, res.NonCompliant)
		t.AppendRow(row)
		total += res.Total
		compliant += res.Compliant
		non += res.NonCompliant
	}
	t.AppendSeparator()
	totalsRow := table.Row{"Totals", total, compliant}
	for _, sev := range visibleSeverities {
		totalsRow = append(totalsRow, severityTotals[sev])
	}
	totalsRow = append(totalsRow, non)
	t.AppendRow(totalsRow)
	fmt.Fprintln(w)
	t.Render()
}

// visibleSeverityColumns returns nonzero severity columns and their totals.
func visibleSeverityColumns(reports []namespaceReport) ([]string, map[string]int) {
	order := []string{severityCritical, severityHigh, severityModerate, severityLow, severityInfo, severityNotRated}
	totals := make(map[string]int, len(order))
	for _, res := range reports {
		for sev, count := range res.SeverityCounts {
			totals[sev] += count
		}
	}
	visible := make([]string, 0, len(order))
	for _, sev := range order {
		if totals[sev] > 0 {
			visible = append(visible, sev)
		}
	}
	return visible, totals
}

func printNamespaceViolationLogs(reports []namespaceReport, w io.Writer, useColor bool) {
	fmt.Fprintln(w, "\nViolations")
	found := false
	for _, res := range reports {
		if len(res.Violations) == 0 {
			continue
		}
		found = true
		fmt.Fprintf(w, "Namespace: %s\n", res.Namespace)
		sortedViolations := append([]violationDetail(nil), res.Violations...)
		sortViolationsBySeverity(sortedViolations)
		for _, violation := range sortedViolations {
			label, formatter := violationSeverityLabel(violation.Severity)
			if useColor {
				formatter.Fprintf(w, "[%s] Policy %s / Binding %s\n", label, violation.Policy, violation.Binding)
			} else {
				fmt.Fprintf(w, "[%s] Policy %s / Binding %s\n", label, violation.Policy, violation.Binding)
			}
			fmt.Fprintf(w, "Resource : %s\n", violation.Resource)
			if violation.URL != "" {
				fmt.Fprintf(w, "Link     : %s\n", violation.URL)
			}
			fmt.Fprintf(w, "Message  : %s\n", violation.Message)
		}
	}
	if !found {
		fmt.Fprintln(w, "No violations detected.")
	}
}

// linkedPolicyName renders a policy name as an OSC 8 hyperlink to its cenroq
// page. text.Hyperlink, unlike fatih/color, does not disable itself on a
// non-TTY, so plain output is gated on the same useColor flag as the rest of
// the report.
func linkedPolicyName(name, url string, useColor bool) string {
	if !useColor || url == "" {
		return name
	}
	return text.Hyperlink(url, name)
}

func printSummaryTables(reports []*bindingReport, hideBindingInfo bool, w io.Writer, style table.Style, useColor bool) {
	if len(reports) == 0 {
		fmt.Fprintln(w, "No policies evaluated.")
		return
	}

	t := table.NewWriter()
	t.SetOutputMirror(w)
	t.SetStyle(style)
	t.Style().Title.Align = text.AlignLeft

	if hideBindingInfo {
		t.AppendHeader(table.Row{"Policy", "Severity", "Total", "Compliant", "NonCompliant"})
	} else {
		t.AppendHeader(table.Row{"Policy", "Binding", "Severity", "Mode", "Total", "Compliant", "NonCompliant"})
	}
	var totalTotal, totalCompliant, totalNon int
	for _, br := range reports {
		policyCell := linkedPolicyName(br.Policy, br.URL, useColor)
		if hideBindingInfo {
			t.AppendRow(table.Row{policyCell, br.Severity, br.Total, br.Compliant, br.NonCompliant})
		} else {
			t.AppendRow(table.Row{policyCell, br.Binding, br.Severity, br.Mode, br.Total, br.Compliant, br.NonCompliant})
		}
		totalTotal += br.Total
		totalCompliant += br.Compliant
		totalNon += br.NonCompliant
	}
	t.AppendSeparator()
	if hideBindingInfo {
		t.AppendRow(table.Row{"Totals", "", totalTotal, totalCompliant, totalNon})
	} else {
		t.AppendRow(table.Row{"Totals", "", "", "", totalTotal, totalCompliant, totalNon})
	}
	t.SetTitle("Policy Compliance Overview")
	fmt.Fprintln(w)
	t.Render()
}

func printResourceTotals(counts map[string]int, w io.Writer, style table.Style) {
	if len(counts) == 0 {
		return
	}

	t := table.NewWriter()
	t.SetOutputMirror(w)
	t.SetStyle(style)
	t.SetTitle("Resources by Kind")
	t.SetColumnConfigs([]table.ColumnConfig{
		{Name: "Kind", WidthMin: 12},
		{Name: "Total", WidthMin: 5},
	})
	t.AppendHeader(table.Row{"Kind", "Total"})
	kinds := make([]string, 0, len(counts))
	for kind := range counts {
		kinds = append(kinds, kind)
	}
	sort.Strings(kinds)
	for _, kind := range kinds {
		t.AppendRow(table.Row{kind, counts[kind]})
	}
	fmt.Fprintln(w)
	t.Render()
}

type resourceDetail struct {
	Kind      string `json:"kind"`
	Namespace string `json:"namespace,omitempty"`
	Name      string `json:"name"`
}

func collectResourceDetails(resources []map[string]interface{}) []resourceDetail {
	seen := make(map[string]struct{})
	var details []resourceDetail
	for _, res := range resources {
		id := resourceKey(res)
		if _, ok := seen[id]; ok {
			continue
		}
		seen[id] = struct{}{}
		kind, _ := res["kind"].(string)
		details = append(details, resourceDetail{
			Kind:      kind,
			Namespace: kubernetes.MetadataString(res, "namespace"),
			Name:      kubernetes.MetadataString(res, "name"),
		})
	}
	sort.Slice(details, func(i, j int) bool {
		if details[i].Kind == details[j].Kind {
			if details[i].Namespace == details[j].Namespace {
				return details[i].Name < details[j].Name
			}
			return details[i].Namespace < details[j].Namespace
		}
		return details[i].Kind < details[j].Kind
	})
	return details
}

func printViolationLogs(reports []*bindingReport, w io.Writer, useColor bool) {
	fmt.Fprintln(w, "\nViolations")
	violations := flattenViolationsSortedBySeverity(reports)
	if len(violations) == 0 {
		fmt.Fprintln(w, "No violations detected.")
		return
	}
	for _, violation := range violations {
		label, formatter := violationSeverityLabel(violation.Severity)
		if useColor {
			formatter.Fprintf(w, "[%s] Policy %s\n", label, violation.Policy)
		} else {
			fmt.Fprintf(w, "[%s] Policy %s\n", label, violation.Policy)
		}
		fmt.Fprintf(w, "Resource : %s\n", violation.Resource)
		if violation.URL != "" {
			fmt.Fprintf(w, "Link     : %s\n", violation.URL)
		}
		fmt.Fprintf(w, "Message  : %s\n", violation.Message)
	}
}

func flattenViolationsSortedBySeverity(reports []*bindingReport) []violationDetail {
	var violations []violationDetail
	for _, br := range reports {
		violations = append(violations, br.Violations...)
	}
	sortViolationsBySeverity(violations)
	return violations
}

func sortViolationsBySeverity(violations []violationDetail) {
	sort.SliceStable(violations, func(i, j int) bool {
		ri := severityRank(violations[i].Severity)
		rj := severityRank(violations[j].Severity)
		if ri != rj {
			return ri < rj
		}
		if violations[i].Policy != violations[j].Policy {
			return violations[i].Policy < violations[j].Policy
		}
		if violations[i].Resource != violations[j].Resource {
			return violations[i].Resource < violations[j].Resource
		}
		return violations[i].Message < violations[j].Message
	})
}
func collectFiles(dir string) ([]string, error) {
	dirEntries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	var files []string
	for _, entry := range dirEntries {
		if entry.IsDir() {
			continue
		}
		name := entry.Name()
		if !isManifestFile(name) {
			continue
		}
		files = append(files, filepath.Join(dir, name))
	}
	return files, nil
}

func isManifestFile(name string) bool {
	lower := strings.ToLower(name)
	return strings.HasSuffix(lower, ".yaml") || strings.HasSuffix(lower, ".yml") || strings.HasSuffix(lower, ".json")
}

func isPipeline(cmd *cobra.Command) bool {
	return lookupBoolFlag(cmd, "pipeline")
}

func lookupBoolFlag(cmd *cobra.Command, name string) bool {
	if cmd == nil {
		return false
	}
	if flag := cmd.Flags().Lookup(name); flag != nil {
		val, err := strconv.ParseBool(flag.Value.String())
		if err == nil {
			return val
		}
	}
	return lookupBoolFlag(cmd.Parent(), name)
}

type psaNamespaceResult struct {
	Namespace    string            `json:"namespace"`
	Modes        map[string]string `json:"modes"`
	Pods         int               `json:"podsChecked"`
	Compliant    int               `json:"compliant"`
	NonCompliant int               `json:"nonCompliant"`
	Cenroq       map[string]bool   `json:"-"`
	Violations   []violationDetail `json:"violations,omitempty"`
}

func summarizePSALevels(pods []corev1.Pod, namespaceLabels map[string]map[string]string, namespaces []string, all bool, compliance map[string]kubernetes.PSAComplianceCounts) ([]psaNamespaceResult, bool) {
	results := make(map[string]*psaNamespaceResult)
	usesCenroqLabels := namespaceLabelsContainCenroq(namespaceLabels)
	targetNamespaces := make(map[string]struct{})
	for _, namespaceName := range namespaces {
		if namespaceName != "" {
			targetNamespaces[namespaceName] = struct{}{}
		}
	}
	includeNamespace := func(namespaceName string) bool {
		if all || len(targetNamespaces) == 0 {
			return true
		}
		_, ok := targetNamespaces[namespaceName]
		return ok
	}

	addNamespace := func(namespaceName string, labels map[string]string) *psaNamespaceResult {
		if res, ok := results[namespaceName]; ok {
			return res
		}
		labels = convertPSANamespaceLabels(labels)
		cenroqModes := make(map[string]bool)
		for _, mode := range []string{"enforce", "audit", "warn"} {
			if _, ok := labels[kubernetes.PSALabelPrefix+"/"+mode]; ok {
				cenroqModes[mode] = true
				usesCenroqLabels = true
				continue
			}
		}
		res := &psaNamespaceResult{
			Namespace: namespaceName,
			Modes:     convertPSALabels(labels),
			Cenroq:    cenroqModes,
		}
		results[namespaceName] = res
		return res
	}

	for _, pod := range pods {
		namespaceName := pod.Namespace
		if namespaceName == "" {
			namespaceName = kubernetes.ActiveNamespace()
		}
		if namespaceName == "" {
			namespaceName = "default"
		}
		if !includeNamespace(namespaceName) {
			continue
		}
		namespaceLabelValues := namespaceLabels[namespaceName]
		namespaceResult := addNamespace(namespaceName, namespaceLabelValues)
		namespaceResult.Pods++
	}

	for namespaceName, labels := range namespaceLabels {
		if !includeNamespace(namespaceName) {
			continue
		}
		addNamespace(namespaceName, labels)
	}

	for _, namespaceName := range namespaces {
		if namespaceName == "" {
			continue
		}
		if _, ok := results[namespaceName]; !ok && includeNamespace(namespaceName) {
			addNamespace(namespaceName, nil)
		}
	}

	for namespaceName, counts := range compliance {
		if !includeNamespace(namespaceName) {
			continue
		}
		res := addNamespace(namespaceName, namespaceLabels[namespaceName])
		res.Compliant = counts.Compliant
		res.NonCompliant = counts.NonCompliant
		res.Violations = convertPSAViolations(counts.Violations)
	}

	var sorted []psaNamespaceResult
	for _, res := range results {
		sorted = append(sorted, *res)
	}
	sort.Slice(sorted, func(i, j int) bool {
		return sorted[i].Namespace < sorted[j].Namespace
	})

	return sorted, usesCenroqLabels
}

func convertPSAViolations(violations []kubernetes.PSAViolation) []violationDetail {
	if len(violations) == 0 {
		return nil
	}
	out := make([]violationDetail, len(violations))
	for i, violation := range violations {
		out[i] = violationDetail{
			Policy:   violation.Policy,
			Binding:  violation.Binding,
			Resource: violation.Resource,
			Message:  violation.Message,
			Path:     violation.Path,
			Actions:  violation.Actions,
		}
	}
	return out
}

func printPSATable(results []psaNamespaceResult, useCenroqLabels bool, w io.Writer, style table.Style) {
	t := table.NewWriter()
	t.SetOutputMirror(w)
	t.SetStyle(style)
	t.SetTitle("PSA Namespace Levels")
	t.AppendHeader(table.Row{"Namespace", "Enforce", "Audit", "Warn", "Compliant", "Non-compliant"})
	var totalCompliant, totalNonCompliant int
	for _, res := range results {
		t.AppendRow(table.Row{
			res.Namespace,
			formatPSAMode(res.Modes, res.Cenroq, "enforce", useCenroqLabels),
			formatPSAMode(res.Modes, res.Cenroq, "audit", useCenroqLabels),
			formatPSAMode(res.Modes, res.Cenroq, "warn", useCenroqLabels),
			res.Compliant,
			res.NonCompliant,
		})
		totalCompliant += res.Compliant
		totalNonCompliant += res.NonCompliant
	}
	if len(results) > 0 {
		t.AppendSeparator()
		t.AppendRow(table.Row{"Totals", "", "", "", totalCompliant, totalNonCompliant})
	}
	fmt.Fprintln(w)
	t.Render()
}

func formatPSAMode(modes map[string]string, cenroqModes map[string]bool, mode string, useCenroqLabels bool) string {
	if modes == nil {
		return "-"
	}
	label := modes[mode]
	if label == "" {
		return "-"
	}
	if useCenroqLabels && cenroqModes != nil && cenroqModes[mode] {
		return label + " (cenroq)"
	}
	return label
}

func convertPSALabels(labels map[string]string) map[string]string {
	result := make(map[string]string)
	if labels == nil {
		return result
	}
	for k, v := range labels {
		canonical := ""
		switch {
		case strings.HasPrefix(k, "pod-security.kubernetes.io/"):
			canonical = strings.TrimPrefix(k, "pod-security.kubernetes.io/")
		case strings.HasPrefix(k, kubernetes.PSALabelPrefix+"/"):
			canonical = strings.TrimPrefix(k, kubernetes.PSALabelPrefix+"/")
		default:
			continue
		}
		if canonical != "enforce" && canonical != "audit" && canonical != "warn" {
			continue
		}
		if v == "" {
			continue
		}
		result[canonical] = v
	}
	return result
}

func namespaceLabelsContainCenroq(labels map[string]map[string]string) bool {
	for _, nsLabels := range labels {
		for k := range nsLabels {
			if strings.Contains(k, kubernetes.PSALabelPrefix+"/") {
				return true
			}
		}
	}
	return false
}

func convertPSANamespaceLabels(labels map[string]string) map[string]string {
	if len(labels) == 0 {
		return make(map[string]string)
	}

	result := make(map[string]string, len(labels))
	for k, v := range labels {
		result[k] = v
	}

	return result
}
