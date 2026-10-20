// Copyright by cenroq AG
// Contact: info@cenroq.com

package cli

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/fatih/color"
	"github.com/jedib0t/go-pretty/v6/table"
	"github.com/jedib0t/go-pretty/v6/text"
	"github.com/spf13/cobra"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/cenroq/kubeapt/v2/internal/config"
	"github.com/cenroq/kubeapt/v2/internal/format"
	"github.com/cenroq/kubeapt/v2/internal/kubernetes"
	"github.com/cenroq/kubeapt/v2/internal/logging"
	"github.com/cenroq/kubeapt/v2/pkg/analyze"
)

// defaultProbeBundle is the bundle analyze probes when none is named. Probes
// ship inside a policy bundle's probes/ directory, one deny manifest per
// policy, so the flagship bundle is also the broadest probe corpus.
const defaultProbeBundle = "cenroq-best-practices"

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

	// The client comes first: building it loads the kubeconfig, which is what
	// sets the active namespace resolveAnalyzeNamespaces falls back to.
	client, err := kubernetes.NewResourceClient()
	if err != nil {
		return err
	}

	namespaces, err := resolveAnalyzeNamespaces(request)
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

	// One unit per namespaced probe per namespace, plus one per cluster-scoped
	// probe. The exact count is not known until the runner resolves each kind,
	// so the tracker is sized on the upper bound.
	tracker, stop := startProgress("Submitting probes",
		maxInt64(int64(len(probes)*maxInt(len(namespaces), 1)), 1), progressEnabled)
	runner := analyze.NewRunner(kubernetes.NewProbeSubmitter(client))
	runner.Timeout = request.timeout
	runner.OnResult = func() { tracker.Increment(1) }
	results := runner.Run(cmd.Context(), probes, namespaces)
	stop()
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

// loadProbes reads the probe corpus from a local path or an installed bundle.
//
// A bundle is loaded whole so each probe's uuid resolves against the bundle's
// own policies.yaml: a deny manifest carries only kubeapt.io/uuid, so the
// policy name, severity and catalogue link all come from that join.
func loadProbes(request analyzeRequest) ([]analyze.Probe, error) {
	if request.probesPath != "" {
		info, err := os.Stat(request.probesPath)
		if err != nil {
			return nil, err
		}
		if !info.IsDir() {
			return analyze.LoadProbeFile(os.DirFS(filepath.Dir(request.probesPath)), filepath.Base(request.probesPath))
		}
		// A local set may be a whole bundle or a bare probes/ directory.
		if _, err := os.Stat(filepath.Join(request.probesPath, analyze.ProbesDirName)); err == nil {
			return analyze.LoadBundle(os.DirFS(request.probesPath), ".")
		}
		return analyze.LoadProbes(os.DirFS(request.probesPath), ".")
	}

	version, err := resolveInstalledBundleVersion(request.bundleName, request.bundleVersion)
	if err != nil {
		return nil, err
	}
	root, err := config.BundleVersionDir(request.bundleName, version)
	if err != nil {
		return nil, err
	}
	probesPath := filepath.Join(root, analyze.ProbesDirName)
	if info, err := os.Stat(probesPath); err != nil || !info.IsDir() {
		return nil, fmt.Errorf("bundle %s %s ships no probes/ directory; re-download it to get one", request.bundleName, version)
	}
	return analyze.LoadBundle(os.DirFS(root), ".")
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

// maxInt returns the larger of two ints, for sizing the progress tracker.
func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
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

	header := table.Row{"Verdict", "Probe", "Policy", "Kind", "Namespace", "Severity", "Outcome", "Enforced by"}
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
			linkedProbeName(result.Probe, useColor),
			policyCell(result.Probe),
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

	printProbeLinks(results, writer)

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

// linkedProbeName hyperlinks a probe id to the policy page behind it. The
// escape is gated on useColor because text.Hyperlink, unlike fatih/color, does
// not disable itself on a non-TTY.
func linkedProbeName(probe analyze.Probe, useColor bool) string {
	url := probe.DocsURL()
	if !useColor || url == "" {
		return probe.ID
	}
	return text.Hyperlink(url, probe.ID)
}

// policyCell names the policy a probe tests, which a deny manifest carries only
// as a uuid. An empty cell means the uuid did not resolve against the bundle.
func policyCell(probe analyze.Probe) string {
	if probe.Policy == nil {
		return "-"
	}
	if probe.Policy.DisplayName != "" {
		return probe.Policy.DisplayName
	}
	return probe.Policy.Name
}

// maxProbeLinks caps the link footer. A cluster enforcing nothing fails every
// probe, and listing 150 URLs would bury the summary that says so.
const maxProbeLinks = 20

// printProbeLinks lists the catalogue page for every probe that did not pass.
//
// The table hyperlinks the probe id, but a terminal that cannot render OSC 8 --
// or a report written to a file -- would otherwise lose the URL entirely, and
// the link is the point: it is where the reader learns what the finding means.
func printProbeLinks(results []analyze.Result, writer io.Writer) {
	seen := map[string]bool{}
	var lines []string
	for _, result := range results {
		if result.Verdict == analyze.VerdictPass {
			continue
		}
		url := result.Probe.DocsURL()
		if url == "" || seen[url] {
			continue
		}
		seen[url] = true
		lines = append(lines, fmt.Sprintf("  %-44s %s", result.Probe.ID, url))
	}
	if len(lines) == 0 {
		return
	}
	logging.Newline()
	fmt.Fprintln(writer, "Policy details")
	shown := lines
	if len(shown) > maxProbeLinks {
		shown = shown[:maxProbeLinks]
	}
	for _, line := range shown {
		fmt.Fprintln(writer, line)
	}
	if remaining := len(lines) - len(shown); remaining > 0 {
		fmt.Fprintf(writer, "  ... and %d more; run with -f json for every link\n", remaining)
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
	Policy      string               `json:"policy,omitempty"`
	UUID        string               `json:"uuid,omitempty"`
	URL         string               `json:"url,omitempty"`
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
			DisplayName: result.Probe.Title(),
			Description: result.Probe.Summary(),
			Category:    result.Probe.Category,
			UUID:        result.Probe.UUID,
			URL:         result.Probe.DocsURL(),
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
		if result.Probe.Policy != nil {
			entry.Policy = result.Probe.Policy.Name
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
