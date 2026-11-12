// Copyright by cenroq AG
// Contact: info@cenroq.com

package cli

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spf13/cobra"

	"github.com/cenroq/kubeapt/v2/internal/config"
	"github.com/cenroq/kubeapt/v2/internal/logging"
	"github.com/cenroq/kubeapt/v2/pkg/policies"
)

const showPolicyYAML = `apiVersion: admissionregistration.k8s.io/v1
kind: ValidatingAdmissionPolicy
metadata:
  name: container-windows-hostprocess
  annotations:
    cenroq.io/finding: "oq-0327"
    security.kubeapt.io/displayName: "Runs as a Windows HostProcess"
    security.kubeapt.io/severity: "High"
spec:
  validations:
  - expression: "true"
`

const showPolicyWithoutIDYAML = `apiVersion: admissionregistration.k8s.io/v1
kind: ValidatingAdmissionPolicy
metadata:
  name: no-id
  annotations:
    security.cenroq.io/displayName: "Has no finding id"
spec:
  validations:
  - expression: "true"
`

// seedDownloadedPolicies installs a policies index cache and a downloaded
// policy version, the state `kubeapt policies download` leaves behind, so
// policies show runs without the network.
func seedDownloadedPolicies(t *testing.T) {
	t.Helper()
	t.Setenv("HOME", t.TempDir())
	const version = "v0.4.0"
	index := policiesIndex{
		LatestVersion: version,
		Versions:      []string{version},
		Policies: []policiesIndexItem{
			{Name: "container-windows-hostprocess", File: "windows-hostprocess/containers/policy.yaml"},
			{Name: "no-id", File: "no-id/policy.yaml"},
		},
	}
	indexPath, err := config.PoliciesIndexPath()
	if err != nil {
		t.Fatal(err)
	}
	data, err := json.Marshal(index)
	if err != nil {
		t.Fatal(err)
	}
	versionDir, err := config.PolicyVersionDir(version)
	if err != nil {
		t.Fatal(err)
	}
	files := map[string]string{
		indexPath: string(data),
		filepath.Join(versionDir, "windows-hostprocess", "containers", "policy.yaml"): showPolicyYAML,
		filepath.Join(versionDir, "no-id", "policy.yaml"):                             showPolicyWithoutIDYAML,
	}
	for path, content := range files {
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

// captureReport routes the report writer, which policies show prints to,
// into a buffer for one test.
func captureReport(t *testing.T) *bytes.Buffer {
	t.Helper()
	var buf bytes.Buffer
	logging.SetOutputWriter(&buf)
	logging.SetReportWriter(&buf)
	t.Cleanup(func() {
		logging.SetOutputWriter(os.Stdout)
		logging.SetReportWriter(os.Stdout)
	})
	return &buf
}

// showRow returns the value cell of the table row whose field cell is field.
func showRow(t *testing.T, out, field string) string {
	t.Helper()
	for _, line := range strings.Split(out, "\n") {
		cells := strings.Split(line, "│")
		if len(cells) == 4 && strings.TrimSpace(cells[1]) == field {
			return strings.TrimSpace(cells[2])
		}
	}
	t.Fatalf("no %q row in:\n%s", field, out)
	return ""
}

func TestPolicyShowListsFindingAndDocsLink(t *testing.T) {
	seedDownloadedPolicies(t)
	out := captureReport(t)

	if err := runPolicyShow(&cobra.Command{}, "container-windows-hostprocess", "", "table"); err != nil {
		t.Fatalf("runPolicyShow: %v", err)
	}
	if got := showRow(t, out.String(), "finding"); got != "oq-0327" {
		t.Errorf("finding = %q, want oq-0327", got)
	}
	if got, want := showRow(t, out.String(), "docs"), policies.DocsBaseURL+"/oq-0327"; got != want {
		t.Errorf("docs = %q, want %q", got, want)
	}
	if got := showRow(t, out.String(), "displayName"); got != "Runs as a Windows HostProcess" {
		t.Errorf("displayName = %q", got)
	}
}

// A policy without an id has no page, so both rows stay empty rather than
// pointing at a guessed URL.
func TestPolicyShowWithoutFindingID(t *testing.T) {
	seedDownloadedPolicies(t)
	out := captureReport(t)

	if err := runPolicyShow(&cobra.Command{}, "no-id", "", "table"); err != nil {
		t.Fatalf("runPolicyShow: %v", err)
	}
	if got := showRow(t, out.String(), "finding"); got != "" {
		t.Errorf("finding = %q, want empty", got)
	}
	if got := showRow(t, out.String(), "docs"); got != "" {
		t.Errorf("docs = %q, want empty", got)
	}
}

// The overview (no policy name) carries the id and link in json, and leaves
// them out for a policy that has none.
func TestPolicyShowSummaryJSONIncludesDocsLink(t *testing.T) {
	seedDownloadedPolicies(t)
	out := captureReport(t)

	if err := runPolicyShow(&cobra.Command{}, "", "", "json"); err != nil {
		t.Fatalf("runPolicyShow: %v", err)
	}
	var got []map[string]any
	if err := json.Unmarshal(out.Bytes(), &got); err != nil {
		t.Fatalf("summary is not json: %v\n%s", err, out.String())
	}
	if len(got) != 2 {
		t.Fatalf("summary has %d entries, want 2: %s", len(got), out.String())
	}
	if got[0]["finding"] != "oq-0327" || got[0]["docs"] != policies.DocsBaseURL+"/oq-0327" {
		t.Errorf("entry 0 = %v, want finding oq-0327 and its docs link", got[0])
	}
	if _, ok := got[1]["docs"]; ok {
		t.Errorf("entry 1 = %v, want no docs field for a policy without an id", got[1])
	}
}
