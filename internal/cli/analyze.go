// Copyright by cenroq AG
// Contact: info@cenroq.com

package cli

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/fatih/color"
	"github.com/jedib0t/go-pretty/v6/table"
	"github.com/jedib0t/go-pretty/v6/text"
	"github.com/spf13/cobra"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/cenroq/kubeapt/v2/internal/config"
	"github.com/cenroq/kubeapt/v2/internal/format"
	"github.com/cenroq/kubeapt/v2/internal/kubernetes"
	"github.com/cenroq/kubeapt/v2/internal/logging"
	"github.com/cenroq/kubeapt/v2/internal/worker"
	"github.com/cenroq/kubeapt/v2/pkg/analyze"
)

const (
	// defaultProbeBundle is a placeholder, not a published bundle. No bundle of
	// this name exists in the index, so the default only resolves once a probe
	// corpus ships and the published name is confirmed. Until then --probes is
	// the only working source, which is why the command is not registered in
	// root.go.
	defaultProbeBundle = "admission-probes"
	// maxProbeNameLength is 253 (the API server's name limit) minus the 17
	// characters collisionFreeName appends: "-kubeapt-" plus eight hex digits.
	maxProbeNameLength = 236
)

type analyzeRequest struct {
	bundleName        string
	bundleVersion     string
	probesPath        string
	probeIDs          []string
	allNamespaces     bool
	namespaces        []string
	namespaceSelector string
	outputFormat      string
	reportMode        string
	outputPath        string
	pipeline          bool
	timeout           time.Duration
}

// AnalyzeCmd measures what a cluster's admission chain actually enforces by
// submitting known-dangerous objects with dryRun=All.
func AnalyzeCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "analyze",
		Short: "Test what the cluster's admission control actually blocks",
		Long: `Submit deliberately dangerous objects to the connected cluster with dryRun=All
and report what admission control did with each one.

Nothing is ever created. A dry-run request runs the full admission chain --
built-in plugins, Pod Security Admission, ValidatingAdmissionPolicies and every
registered webhook -- and is discarded before persistence, so the verdict is
real while the object is not.

This answers a question scan and validate cannot. scan reports which controls
exist and validate reports what your policies would do; only analyze reports
what the cluster in front of you actually enforces.`,
		Example: `  # Probe the active namespace with the installed probe bundle
  kubeapt analyze

  # Probe every namespace and show why each verdict was reached
  kubeapt analyze --all-namespaces --report all

  # Fail a pipeline when a dangerous object is admitted
  kubeapt analyze --namespaces prod --pipeline

  # Run a local probe set instead of the bundle
  kubeapt analyze --probes ./probes --probe privileged-pod,hostpath-mount`,
		PreRunE: func(cmd *cobra.Command, _ []string) error {
			if err := logging.Init("", getLogLevel()); err != nil {
				return err
			}
			logging.SetOutputWriter(cmd.OutOrStdout())
			logging.SetReportWriter(cmd.OutOrStdout())
			return nil
		},
		RunE: runAnalyze,
	}
	cmd.Flags().String("bundle", defaultProbeBundle, "Probe bundle name to run")
	cmd.Flags().String("bundle-version", "", "Bundle version to use with --bundle (defaults to latest)")
	cmd.Flags().StringP("probes", "p", "", "File or folder holding probe manifests, instead of a bundle")
	cmd.Flags().String("probe", "", "Comma separated probe ids to run instead of the whole catalogue")
	cmd.Flags().BoolP("all-namespaces", "A", false, "Probe every namespace instead of the active one")
	cmd.Flags().StringP("namespaces", "n", "", "Comma separated list of namespaces to probe")
	cmd.Flags().String("namespace-selector", "", "Label selector to choose namespaces (e.g. env=prod)")
	cmd.Flags().StringP("format", "f", "table", "Specify the report output format: table or json")
	cmd.Flags().String("report", "summary", "Specify the final report type: summary or all")
	cmd.Flags().String("output", "", "Write the report to a file path instead of stdout")
	cmd.Flags().Bool("pipeline", false, "Indicate the command runs inside CI/CD and exit non-zero on any admitted probe")
	cmd.Flags().Duration("timeout", 30*time.Second, "Per-probe request timeout")
	return cmd
}

func runAnalyze(cmd *cobra.Command, _ []string) error {
	request, err := parseAnalyzeFlags(cmd)
	if err != nil {
		return err
	}

	probes, err := loadProbes(request)
	if err != nil {
		return err
	}
	probes, err = filterProbes(probes, request.probeIDs)
	if err != nil {
		return err
	}

	namespaces, err := resolveAnalyzeNamespaces(request)
	if err != nil {
		return err
	}

	client, err := kubernetes.NewResourceClient()
	if err != nil {
		return err
	}

	writer := logging.Writer()
	tableStyle := table.StyleRounded
	useColor := true
	progressEnabled := request.outputFormat != "json"
	if request.outputPath != "" {
		file, err := os.Create(request.outputPath)
		if err != nil {
			return fmt.Errorf("failed to open output file: %w", err)
		}
		defer file.Close()
		logging.SetReportWriter(file)
		writer = logging.Writer()
		tableStyle = table.StyleDefault
		useColor = false
		progressEnabled = false
	}

	startTime := time.Now()
	units, results := planProbeUnits(client, probes, namespaces)

	tracker, stop := startProgress("Submitting probes", maxInt64(int64(len(units)), 1), progressEnabled)
	executed := executeProbeUnits(cmd.Context(), client, units, request.timeout, func() {
		tracker.Increment(1)
	})
	stop()
	results = append(results, executed...)
	sortAnalyzeResults(results)
	stopTime := time.Now()

	summary := analyze.Summarize(results)

	if request.outputFormat == "json" {
		metadata := format.BuildJSONMetadata(cmd, "probe", namespaces, probeKindCounts(results), startTime, stopTime)
		if err := format.WriteJSONEnvelope(writer, metadata, buildAnalyzeJSON(results, summary)); err != nil {
			return err
		}
	} else {
		renderAnalyzeTable(results, summary, request.reportMode, writer, tableStyle, useColor)
	}

	if request.pipeline && summary.HasFailures() {
		return fmt.Errorf("%d dangerous object(s) were admitted by the cluster; review the report above", summary.Fail)
	}
	return nil
}

func parseAnalyzeFlags(cmd *cobra.Command) (analyzeRequest, error) {
	flags := cmd.Flags()
	request := analyzeRequest{}
	var err error

	if request.bundleName, err = flags.GetString("bundle"); err != nil {
		return request, err
	}
	if request.bundleVersion, err = flags.GetString("bundle-version"); err != nil {
		return request, err
	}
	if request.probesPath, err = flags.GetString("probes"); err != nil {
		return request, err
	}
	probeList, err := flags.GetString("probe")
	if err != nil {
		return request, err
	}
	request.probeIDs = splitCommaList(probeList)
	if request.allNamespaces, err = flags.GetBool("all-namespaces"); err != nil {
		return request, err
	}
	namespaceList, err := flags.GetString("namespaces")
	if err != nil {
		return request, err
	}
	request.namespaces = splitCommaList(namespaceList)
	if request.namespaceSelector, err = flags.GetString("namespace-selector"); err != nil {
		return request, err
	}
	if request.outputFormat, err = flags.GetString("format"); err != nil {
		return request, err
	}
	if request.reportMode, err = flags.GetString("report"); err != nil {
		return request, err
	}
	if request.outputPath, err = flags.GetString("output"); err != nil {
		return request, err
	}
	if request.pipeline, err = flags.GetBool("pipeline"); err != nil {
		return request, err
	}
	if request.timeout, err = flags.GetDuration("timeout"); err != nil {
		return request, err
	}

	request.outputFormat = strings.ToLower(strings.TrimSpace(request.outputFormat))
	if request.outputFormat != "table" && request.outputFormat != "json" {
		return request, fmt.Errorf("invalid format %s, expected table or json", request.outputFormat)
	}
	request.reportMode = strings.ToLower(strings.TrimSpace(request.reportMode))
	if request.reportMode != "summary" && request.reportMode != "all" {
		return request, fmt.Errorf("invalid report %s, expected summary or all", request.reportMode)
	}
	if request.timeout <= 0 {
		return request, fmt.Errorf("--timeout must be greater than zero")
	}
	if request.probesPath != "" && flags.Changed("bundle") {
		return request, fmt.Errorf("--probes cannot be combined with --bundle")
	}
	if request.probesPath != "" && flags.Changed("bundle-version") {
		return request, fmt.Errorf("--bundle-version cannot be combined with --probes")
	}
	if flags.Changed("bundle-version") && !flags.Changed("bundle") {
		return request, fmt.Errorf("--bundle-version requires --bundle")
	}
	if request.allNamespaces && len(request.namespaces) > 0 {
		return request, fmt.Errorf("--all-namespaces cannot be used together with --namespaces")
	}
	if request.namespaceSelector != "" && (request.allNamespaces || len(request.namespaces) > 0) {
		return request, fmt.Errorf("--namespace-selector cannot be used together with --all-namespaces or --namespaces")
	}

	return request, nil
}

func splitCommaList(raw string) []string {
	var out []string
	for _, part := range strings.Split(raw, ",") {
		if trimmed := strings.TrimSpace(part); trimmed != "" {
			out = append(out, trimmed)
		}
	}
	return out
}

// loadProbes reads the probe catalogue from a local path or an installed bundle.
func loadProbes(request analyzeRequest) ([]analyze.Probe, error) {
	source, err := resolveProbeSource(request)
	if err != nil {
		return nil, err
	}
	files, err := config.CollectManifestFilesRecursive(source)
	if err != nil {
		return nil, err
	}

	var probes []analyze.Probe
	seen := map[string]string{}
	for _, file := range files {
		objects, err := loadUnstructuredResources([]string{file})
		if err != nil {
			return nil, fmt.Errorf("failed to read probe %s: %w", file, err)
		}
		// The filename names the probe only when it holds exactly one, so a
		// multi-document file cannot mint duplicate ids.
		sourceFile := file
		if len(objects) != 1 {
			sourceFile = ""
		}
		for _, object := range objects {
			probe, err := analyze.NewProbe(object, sourceFile)
			if err != nil {
				return nil, fmt.Errorf("%s: %w", file, err)
			}
			if previous, clash := seen[probe.ID]; clash {
				return nil, fmt.Errorf("duplicate probe id %q in %s and %s", probe.ID, previous, file)
			}
			seen[probe.ID] = file
			probes = append(probes, probe)
		}
	}
	if len(probes) == 0 {
		return nil, fmt.Errorf("no probe manifests found in %s", source)
	}

	sort.Slice(probes, func(i, j int) bool { return probes[i].ID < probes[j].ID })
	return probes, nil
}

func resolveProbeSource(request analyzeRequest) (string, error) {
	if request.probesPath != "" {
		return request.probesPath, nil
	}

	version, err := resolveInstalledBundleVersion(request.bundleName, request.bundleVersion)
	if err != nil {
		return "", err
	}
	probesPath, err := config.BundleProbesPath(request.bundleName, version)
	if err != nil {
		return "", err
	}
	info, err := os.Stat(probesPath)
	if err != nil || !info.IsDir() {
		return "", fmt.Errorf("bundle %s %s has no probes/ directory; it is a policy bundle, not a probe bundle", request.bundleName, version)
	}
	return probesPath, nil
}

func filterProbes(probes []analyze.Probe, ids []string) ([]analyze.Probe, error) {
	if len(ids) == 0 {
		return probes, nil
	}
	wanted := make(map[string]bool, len(ids))
	for _, id := range ids {
		wanted[id] = false
	}
	var selected []analyze.Probe
	for _, probe := range probes {
		if _, ok := wanted[probe.ID]; ok {
			wanted[probe.ID] = true
			selected = append(selected, probe)
		}
	}
	var missing []string
	for id, found := range wanted {
		if !found {
			missing = append(missing, id)
		}
	}
	if len(missing) > 0 {
		sort.Strings(missing)
		return nil, fmt.Errorf("unknown probe id %s", strings.Join(missing, ", "))
	}
	return selected, nil
}

func resolveAnalyzeNamespaces(request analyzeRequest) ([]string, error) {
	if request.namespaceSelector != "" {
		selected, err := namespacesFromSelector(request.namespaceSelector)
		if err != nil {
			return nil, err
		}
		if len(selected) == 0 {
			return nil, fmt.Errorf("no namespaces matched selector %s", request.namespaceSelector)
		}
		return selected, nil
	}
	if request.allNamespaces {
		return allNamespaceNames()
	}
	if len(request.namespaces) > 0 {
		return request.namespaces, nil
	}
	active := kubernetes.ActiveNamespace()
	if active == "" {
		active = "default"
	}
	return []string{active}, nil
}

func allNamespaceNames() ([]string, error) {
	clientset, err := kubernetes.NewClientset()
	if err != nil {
		return nil, err
	}
	list, err := clientset.CoreV1().Namespaces().List(context.TODO(), metav1.ListOptions{})
	if err != nil {
		return nil, err
	}
	names := make([]string, 0, len(list.Items))
	for _, namespace := range list.Items {
		if namespace.Name != "" {
			names = append(names, namespace.Name)
		}
	}
	sort.Strings(names)
	return names, nil
}

// probeUnit is one probe submitted into one namespace.
type probeUnit struct {
	probe     analyze.Probe
	namespace string
}

// planProbeUnits expands the catalogue into work, fanning namespaced probes out
// across the selected namespaces while leaving cluster-scoped probes as a
// single unit. Probes whose kind the cluster does not serve resolve straight to
// a Skipped result and are never submitted.
func planProbeUnits(client *kubernetes.ResourceClient, probes []analyze.Probe, namespaces []string) ([]probeUnit, []analyze.Result) {
	var units []probeUnit
	var results []analyze.Result

	for _, probe := range probes {
		scout := probe.Object.DeepCopy()
		target, err := client.Resolve(scout, "")
		if err != nil {
			if errors.Is(err, kubernetes.ErrKindNotServed) {
				results = append(results, analyze.SkippedResult(probe, "", err.Error()))
			} else {
				results = append(results, analyze.ErrorResult(probe, "", err.Error()))
			}
			continue
		}
		if !target.Namespaced {
			units = append(units, probeUnit{probe: probe})
			continue
		}
		for _, namespace := range namespaces {
			units = append(units, probeUnit{probe: probe, namespace: namespace})
		}
	}
	return units, results
}

func executeProbeUnits(ctx context.Context, client *kubernetes.ResourceClient, units []probeUnit, timeout time.Duration, onUnit func()) []analyze.Result {
	if ctx == nil {
		ctx = context.Background()
	}
	if len(units) == 0 {
		return nil
	}

	results := make([]analyze.Result, len(units))
	queue := make(chan int)
	var wg sync.WaitGroup

	for w := 0; w < worker.WorkerLimit(len(units)); w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for index := range queue {
				results[index] = runProbeUnit(ctx, client, units[index], timeout)
				if onUnit != nil {
					onUnit()
				}
			}
		}()
	}
	for index := range units {
		queue <- index
	}
	close(queue)
	wg.Wait()

	return results
}

func runProbeUnit(ctx context.Context, client *kubernetes.ResourceClient, unit probeUnit, timeout time.Duration) analyze.Result {
	object := unit.probe.Object.DeepCopy()
	target, err := client.Resolve(object, unit.namespace)
	if err != nil {
		if errors.Is(err, kubernetes.ErrKindNotServed) {
			return analyze.SkippedResult(unit.probe, unit.namespace, err.Error())
		}
		return analyze.ErrorResult(unit.probe, unit.namespace, err.Error())
	}

	// Ask before submitting. An RBAC refusal and an admission refusal are both
	// 403, and treating the former as a block would report an inaccessible
	// cluster as a defended one.
	allowed, err := client.CanCreate(ctx, target)
	if err != nil {
		return analyze.ErrorResult(unit.probe, target.Namespace, fmt.Sprintf("access review failed: %v", err))
	}
	if !allowed {
		return analyze.InconclusiveResult(unit.probe, target.Namespace, analyze.ReasonRBAC,
			fmt.Sprintf("not permitted to create %s", target.Mapping.Resource.Resource))
	}

	requestCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	returned, err := target.DryRunCreate(requestCtx, object)
	if apierrors.IsAlreadyExists(err) {
		// A live object of the same name would make this an update rather than
		// a create, which fires a different set of admission rules. Retry once
		// under a name that cannot collide.
		object = unit.probe.Object.DeepCopy()
		object.SetName(collisionFreeName(unit.probe.Object.GetName()))
		retryTarget, retryErr := client.Resolve(object, unit.namespace)
		if retryErr != nil {
			return analyze.ErrorResult(unit.probe, target.Namespace, retryErr.Error())
		}
		returned, err = retryTarget.DryRunCreate(requestCtx, object)
	}

	return analyze.Classify(unit.probe, target.Namespace, object, returned, err)
}

// collisionFreeName appends random hex to a probe's name so a retry cannot hit
// an existing object.
func collisionFreeName(base string) string {
	suffix := make([]byte, 4)
	if _, err := rand.Read(suffix); err != nil {
		// crypto/rand does not fail in practice; a fixed suffix still beats
		// retrying under the colliding name.
		return trimName(base) + "-kubeapt"
	}
	return trimName(base) + "-kubeapt-" + hex.EncodeToString(suffix)
}

func trimName(base string) string {
	if base == "" {
		return "probe"
	}
	if len(base) > maxProbeNameLength {
		base = base[:maxProbeNameLength]
	}
	return strings.TrimRight(base, "-.")
}

func sortAnalyzeResults(results []analyze.Result) {
	sort.SliceStable(results, func(i, j int) bool {
		left, right := results[i], results[j]
		if lr, rr := verdictRank(left.Verdict), verdictRank(right.Verdict); lr != rr {
			return lr < rr
		}
		if ls, rs := severityRank(string(left.Probe.Severity)), severityRank(string(right.Probe.Severity)); ls != rs {
			return ls < rs
		}
		if left.Probe.ID != right.Probe.ID {
			return left.Probe.ID < right.Probe.ID
		}
		return left.Namespace < right.Namespace
	})
}

func verdictRank(v analyze.Verdict) int {
	switch v {
	case analyze.VerdictFail:
		return 0
	case analyze.VerdictWarn:
		return 1
	case analyze.VerdictInconclusive:
		return 2
	default:
		return 3
	}
}

func probeKindCounts(results []analyze.Result) map[string]int {
	counts := map[string]int{}
	for _, result := range results {
		if result.Probe.Object == nil {
			continue
		}
		if kind := result.Probe.Object.GetKind(); kind != "" {
			counts[kind]++
		}
	}
	return counts
}

func renderAnalyzeTable(results []analyze.Result, summary analyze.Summary, reportMode string, writer io.Writer, style table.Style, useColor bool) {
	t := table.NewWriter()
	t.SetOutputMirror(writer)
	t.SetStyle(style)
	t.Style().Title.Align = text.AlignLeft
	t.SetTitle("Admission probe results")

	header := table.Row{"Verdict", "Probe", "Kind", "Namespace", "Severity", "Outcome", "Enforced by"}
	if reportMode == "all" {
		header = append(header, "Detail")
		// A PSA denial runs to several hundred characters and go-pretty does
		// not wrap by default, which stretches the table far past any
		// terminal. Wrap the two columns that carry server text.
		t.SetColumnConfigs([]table.ColumnConfig{
			{Name: "Enforced by", WidthMax: 32},
			{Name: "Detail", WidthMax: 72},
		})
	}
	t.AppendHeader(header)

	for _, result := range results {
		row := table.Row{
			renderVerdict(result.Verdict, useColor),
			result.Probe.ID,
			probeKind(result.Probe),
			namespaceCell(result.Namespace),
			renderSeverity(string(result.Probe.Severity), useColor),
			string(result.Outcome),
			enforcerCell(result),
		}
		if reportMode == "all" {
			row = append(row, detailCell(result))
		}
		t.AppendRow(row)
	}

	logging.Newline()
	t.Render()

	logging.Infof("%d probe(s): %d passed, %d failed, %d warning(s), %d inconclusive",
		summary.Total, summary.Pass, summary.Fail, summary.Warn, summary.Inconclusive)
	if summary.Inconclusive > 0 {
		logging.Warnf("%d probe(s) produced no verdict; those techniques were not tested", summary.Inconclusive)
	}
	if summary.Fail > 0 {
		logging.Errorf("%d dangerous object(s) were admitted by this cluster", summary.Fail)
	}
	if reportMode != "all" && (summary.Fail > 0 || summary.Warn > 0 || summary.Inconclusive > 0) {
		logging.Infof("Run with --report all to see why each verdict was reached")
	}
}

func renderVerdict(verdict analyze.Verdict, useColor bool) string {
	if !useColor {
		return string(verdict)
	}
	return verdictColor(verdict).Sprint(string(verdict))
}

func renderSeverity(severity string, useColor bool) string {
	if !useColor {
		return severity
	}
	return severityColor(severity).Sprint(severity)
}

func probeKind(probe analyze.Probe) string {
	if probe.Object == nil {
		return ""
	}
	return probe.Object.GetKind()
}

func namespaceCell(namespace string) string {
	if namespace == "" {
		return "-"
	}
	return namespace
}

func enforcerCell(result analyze.Result) string {
	if result.Outcome != analyze.OutcomeBlocked {
		return "-"
	}
	return result.Enforcer.String()
}

func detailCell(result analyze.Result) string {
	switch {
	case len(result.Mutations) > 0:
		return "changed " + strings.Join(result.Mutations, ", ")
	case result.Outcome == analyze.OutcomeBlocked:
		return firstLine(result.Enforcer.Message)
	case result.Reason != analyze.ReasonNone && result.Detail != "":
		return string(result.Reason) + ": " + firstLine(result.Detail)
	case result.Reason != analyze.ReasonNone:
		return string(result.Reason)
	default:
		return firstLine(result.Detail)
	}
}

func firstLine(message string) string {
	message = strings.TrimSpace(message)
	if index := strings.IndexByte(message, '\n'); index != -1 {
		return strings.TrimSpace(message[:index])
	}
	return message
}

func verdictColor(verdict analyze.Verdict) *color.Color {
	switch verdict {
	case analyze.VerdictFail:
		return color.New(color.FgHiRed, color.Bold)
	case analyze.VerdictWarn:
		return color.New(color.FgYellow)
	case analyze.VerdictPass:
		return color.New(color.FgGreen)
	default:
		return color.New(color.FgHiBlack)
	}
}

type analyzeJSONEnforcer struct {
	Type    string `json:"type"`
	Name    string `json:"name,omitempty"`
	Detail  string `json:"detail,omitempty"`
	Message string `json:"message,omitempty"`
}

type analyzeJSONResult struct {
	Probe       string               `json:"probe"`
	DisplayName string               `json:"displayName,omitempty"`
	Description string               `json:"description,omitempty"`
	Category    string               `json:"category,omitempty"`
	Severity    string               `json:"severity"`
	Expect      string               `json:"expect"`
	APIVersion  string               `json:"apiVersion,omitempty"`
	Kind        string               `json:"kind,omitempty"`
	Namespace   string               `json:"namespace,omitempty"`
	Outcome     string               `json:"outcome"`
	Verdict     string               `json:"verdict"`
	EnforcedBy  *analyzeJSONEnforcer `json:"enforcedBy,omitempty"`
	Reason      string               `json:"reason,omitempty"`
	Detail      string               `json:"detail,omitempty"`
	Mutations   []string             `json:"mutations,omitempty"`
	SubmittedAs string               `json:"submittedAs,omitempty"`
}

type analyzeJSONSummary struct {
	Total        int            `json:"total"`
	Pass         int            `json:"pass"`
	Fail         int            `json:"fail"`
	Warn         int            `json:"warn"`
	Inconclusive int            `json:"inconclusive"`
	ByOutcome    map[string]int `json:"byOutcome"`
}

type analyzeJSONPayload struct {
	Summary analyzeJSONSummary `json:"summary"`
	// Named probes rather than results because WriteJSONEnvelope already
	// nests this payload under a "results" key.
	Results []analyzeJSONResult `json:"probes"`
}

func buildAnalyzeJSON(results []analyze.Result, summary analyze.Summary) analyzeJSONPayload {
	payload := analyzeJSONPayload{
		Summary: analyzeJSONSummary{
			Total:        summary.Total,
			Pass:         summary.Pass,
			Fail:         summary.Fail,
			Warn:         summary.Warn,
			Inconclusive: summary.Inconclusive,
			ByOutcome:    map[string]int{},
		},
		Results: make([]analyzeJSONResult, 0, len(results)),
	}
	for outcome, count := range summary.ByOutcome {
		payload.Summary.ByOutcome[string(outcome)] = count
	}

	for _, result := range results {
		entry := analyzeJSONResult{
			Probe:       result.Probe.ID,
			DisplayName: result.Probe.DisplayName,
			Description: result.Probe.Description,
			Category:    result.Probe.Category,
			Severity:    string(result.Probe.Severity),
			Expect:      string(result.Probe.Expect),
			Namespace:   result.Namespace,
			Outcome:     string(result.Outcome),
			Verdict:     string(result.Verdict),
			Reason:      string(result.Reason),
			Detail:      result.Detail,
			Mutations:   result.Mutations,
			SubmittedAs: result.SubmittedName,
		}
		if result.Probe.Object != nil {
			entry.APIVersion = result.Probe.Object.GetAPIVersion()
			entry.Kind = result.Probe.Object.GetKind()
		}
		if result.Outcome == analyze.OutcomeBlocked {
			// The raw message is always carried through, even when the
			// attribution patterns did not recognise it.
			entry.EnforcedBy = &analyzeJSONEnforcer{
				Type:    string(result.Enforcer.Type),
				Name:    result.Enforcer.Name,
				Detail:  result.Enforcer.Detail,
				Message: result.Enforcer.Message,
			}
		}
		payload.Results = append(payload.Results, entry)
	}
	return payload
}
