// Copyright by cenroq AG
// Contact: info@cenroq.com

package analyze

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"path"
	"sort"
	"strings"

	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	utilyaml "k8s.io/apimachinery/pkg/util/yaml"
	sigsyaml "sigs.k8s.io/yaml"

	"github.com/cenroq/kubeapt/v2/pkg/policies"
	"github.com/cenroq/kubeapt/v2/pkg/types"
)

// Layout of the probes/ directory inside a published bundle.
const (
	// ProbesDirName is the bundle subdirectory holding the probe corpus. It is
	// a subdirectory on purpose: `bundles install` reads a fixed
	// (policies.yaml, bindings.yaml) allowlist and a non-recursive
	// `kubectl apply -f <dir>` skips subdirectories, so neither can apply a
	// deny manifest by accident.
	ProbesDirName = "probes"
	// DenyFileName holds every self-contained violation in one multi-document
	// file, one document per policy.
	DenyFileName = "deny.yaml"
	// AllowFileName holds manifests that must be admitted. The published
	// bundles carry none; a local probe set may.
	AllowFileName = "allow.yaml"
	// DebugFileSuffix marks an EphemeralContainer fragment. A fragment is not
	// a standalone manifest, and its companion Pod is compliant on its own, so
	// neither can be exercised by a dry-run create.
	DebugFileSuffix = ".debug.yaml"
	// PoliciesFileName is the bundle's policy set, used to resolve a probe's
	// uuid to the policy it tests.
	PoliciesFileName = "policies.yaml"
)

// PolicyRef is the policy a probe's uuid resolves to. Probe manifests carry
// only kubeapt.io/uuid, so every human-readable field comes from here.
type PolicyRef struct {
	UUID        string
	Name        string
	DisplayName string
	Description string
	Severity    types.Severity
	URL         string
}

// LoadPolicyIndex reads a bundle's policies.yaml and indexes it by uuid.
//
// Policies without a uuid are skipped rather than rejected: a bundle built
// before the catalogue existed is still usable, it just cannot name the policy
// behind a verdict.
func LoadPolicyIndex(fsys fs.FS, name string) (map[string]PolicyRef, error) {
	docs, err := readDocuments(fsys, name)
	if err != nil {
		return nil, err
	}
	index := make(map[string]PolicyRef, len(docs))
	for _, doc := range docs {
		var policy admissionregistrationv1.ValidatingAdmissionPolicy
		if err := runtime.DefaultUnstructuredConverter.FromUnstructured(doc.object, &policy); err != nil {
			return nil, fmt.Errorf("analyze: %s doc %d: %w", name, doc.index, err)
		}
		uuid := strings.TrimSpace(policy.Annotations[policies.AnnotationUUID])
		if uuid == "" {
			continue
		}
		index[uuid] = PolicyRef{
			UUID:        uuid,
			Name:        policy.Name,
			DisplayName: policies.LookupAnnotation(policy.Annotations, policies.AnnotationDisplayName, policies.KyvernoAnnotationTitle),
			Description: policies.LookupAnnotation(policy.Annotations, policies.AnnotationDescription, policies.KyvernoAnnotationDescription),
			Severity:    policies.NormalizeSeverity(policy.Annotations[policies.AnnotationSeverity]),
			URL:         policies.DocsURL(uuid),
		}
	}
	return index, nil
}

// AttachPolicies resolves each probe's uuid against index, filling in Policy
// and back-filling the severity the probe manifest does not carry.
func AttachPolicies(probes []Probe, index map[string]PolicyRef) {
	for i := range probes {
		ref, ok := index[probes[i].UUID]
		if !ok {
			continue
		}
		policy := ref
		probes[i].Policy = &policy
		if probes[i].Severity == types.SeverityNotRated && ref.Severity != "" {
			probes[i].Severity = ref.Severity
		}
	}
}

// nonProbeFiles are bundle files that sit beside a probe corpus but are not
// probes. Submitting a policy or a binding would measure nothing.
var nonProbeFiles = map[string]bool{
	"policies.yaml": true,
	"bindings.yaml": true,
	"policy.yaml":   true,
	"bindings.yml":  true,
	"policies.yml":  true,
	"policy.yml":    true,
	"bundle.json":   true,
}

// LoadProbes reads every probe manifest under dir, recursively.
//
// Every manifest is a probe expected to be blocked unless its filename starts
// with "allow" or it annotates analyze.kubeapt.io/expect. Policy and binding
// files are skipped, so pointing this at a whole bundle works.
//
// An EphemeralContainer case ships as a compliant Pod beside a <name>.debug.yaml
// fragment; neither is submittable, so the pair becomes a single Unsupported
// probe rather than being dropped. Reporting it keeps the count honest: those
// techniques were not tested, which is not the same as passing.
func LoadProbes(fsys fs.FS, dir string) ([]Probe, error) {
	if dir == "" {
		dir = "."
	}

	// A fragment's companion is recognised by name, so every directory's file
	// list has to be known before any of its files are read.
	debugCompanions := map[string]bool{}
	var files []string
	err := fs.WalkDir(fsys, dir, func(name string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() || !isManifestName(entry.Name()) {
			return nil
		}
		if nonProbeFiles[strings.ToLower(entry.Name())] {
			return nil
		}
		if strings.HasSuffix(entry.Name(), DebugFileSuffix) {
			debugCompanions[strings.TrimSuffix(name, DebugFileSuffix)+".yaml"] = true
			return nil
		}
		files = append(files, name)
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("analyze: read %s: %w", dir, err)
	}
	sort.Strings(files)

	var probes []Probe
	seen := map[string]string{}
	for _, name := range files {
		loaded, err := probesFromFile(fsys, name, expectationForFile(path.Base(name)))
		if err != nil {
			return nil, err
		}
		if debugCompanions[name] {
			// The Pod on its own is compliant; the violation only exists once
			// kubectl debug attaches the fragment, which a create cannot do.
			if len(loaded) == 0 {
				continue
			}
			loaded = loaded[:1]
			loaded[0].Unsupported = "needs an ephemeral container; reproduce with the kubectl debug command in " + path.Base(name)
		}
		for _, probe := range loaded {
			if err := claimID(seen, probe.ID, name); err != nil {
				return nil, err
			}
			probes = append(probes, probe)
		}
	}

	if len(probes) == 0 {
		return nil, fmt.Errorf("analyze: no probe manifests found in %s", dir)
	}
	sort.Slice(probes, func(i, j int) bool { return probes[i].ID < probes[j].ID })
	return probes, nil
}

// LoadProbeFile reads a single manifest file as a probe set.
func LoadProbeFile(fsys fs.FS, name string) ([]Probe, error) {
	probes, err := probesFromFile(fsys, name, expectationForFile(path.Base(name)))
	if err != nil {
		return nil, err
	}
	if len(probes) == 0 {
		return nil, fmt.Errorf("analyze: no probe manifests found in %s", name)
	}
	seen := map[string]string{}
	for _, probe := range probes {
		if err := claimID(seen, probe.ID, name); err != nil {
			return nil, err
		}
	}
	sort.Slice(probes, func(i, j int) bool { return probes[i].ID < probes[j].ID })
	return probes, nil
}

// LoadBundle reads an extracted bundle directory: the probes under probes/,
// resolved against the policies in policies.yaml. It is the one call an
// embedding tool needs to turn a downloaded bundle into a runnable corpus.
func LoadBundle(fsys fs.FS, root string) ([]Probe, error) {
	if root == "" {
		root = "."
	}
	probes, err := LoadProbes(fsys, path.Join(root, ProbesDirName))
	if err != nil {
		return nil, err
	}
	index, err := LoadPolicyIndex(fsys, path.Join(root, PoliciesFileName))
	if errors.Is(err, fs.ErrNotExist) {
		// A probe set without its policies is still runnable; it just cannot
		// name the policy behind each verdict.
		return probes, nil
	}
	if err != nil {
		// A policies.yaml that is present but unreadable is not the same
		// thing: swallowing it would strip every name, severity and link
		// from the report without saying why.
		return nil, err
	}
	AttachPolicies(probes, index)
	return probes, nil
}

// expectationForFile reads a probe's expectation from its filename. The corpus
// names the deliberately non-compliant file deny.yaml and the control, where
// one exists, allow.yaml. Anything else is assumed dangerous, which is the safe
// default: a probe wrongly expected to be blocked reports a Fail that a human
// checks, while the reverse would hide an admitted object.
func expectationForFile(name string) Expectation {
	if strings.HasPrefix(strings.ToLower(name), "allow") {
		return ExpectAllowed
	}
	return ExpectBlocked
}

func probesFromFile(fsys fs.FS, name string, expect Expectation) ([]Probe, error) {
	docs, err := readDocuments(fsys, name)
	if err != nil {
		return nil, err
	}
	// The filename names the probe only when the file holds exactly one, so a
	// merged deny.yaml cannot mint 150 probes all called "deny".
	sourceFile := name
	if len(docs) != 1 {
		sourceFile = ""
	}
	var probes []Probe
	for _, doc := range docs {
		object := &unstructured.Unstructured{Object: doc.object}
		probe, err := NewProbe(object, sourceFile)
		if err != nil {
			return nil, fmt.Errorf("%s doc %d: %w", name, doc.index, err)
		}
		// The filename is the corpus-wide signal; an explicit annotation
		// still wins. NewProbe deep-copies, so object still carries it.
		if strings.TrimSpace(object.GetAnnotations()[AnnotationProbeExpect]) == "" {
			probe.Expect = expect
		}
		probes = append(probes, probe)
	}
	return probes, nil
}

func claimID(seen map[string]string, id, file string) error {
	if previous, clash := seen[id]; clash {
		return fmt.Errorf("analyze: duplicate probe id %q in %s and %s", id, previous, file)
	}
	seen[id] = file
	return nil
}

func isManifestName(name string) bool {
	lower := strings.ToLower(name)
	return strings.HasSuffix(lower, ".yaml") || strings.HasSuffix(lower, ".yml") || strings.HasSuffix(lower, ".json")
}

// document is one decoded YAML document and its position in the file, counted
// from zero across every "---"-separated chunk, so errors can point at it.
type document struct {
	index  int
	object map[string]any
}

// readDocuments splits a manifest file into its non-empty YAML documents.
//
// A document that does not parse is an error, never a skip. In a merged
// deny.yaml a single typo would otherwise drop one probe silently, and the
// report would claim coverage of a technique it never tested.
func readDocuments(fsys fs.FS, name string) ([]document, error) {
	data, err := fs.ReadFile(fsys, name)
	if err != nil {
		return nil, fmt.Errorf("analyze: read %s: %w", name, err)
	}
	reader := utilyaml.NewYAMLReader(bufio.NewReader(bytes.NewReader(data)))
	var docs []document
	for index := 0; ; index++ {
		raw, err := reader.Read()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			// An invalid separator such as "--- garbage" lands here, and
			// it would otherwise discard the document buffered before it.
			return nil, fmt.Errorf("analyze: %s doc %d: %w", name, index, err)
		}
		var object map[string]any
		if err := sigsyaml.Unmarshal(raw, &object); err != nil {
			return nil, fmt.Errorf("analyze: %s doc %d: %w", name, index, err)
		}
		// A document that is only comments or whitespace parses to null; the
		// banner at the top of a merged deny.yaml is exactly that.
		if len(object) == 0 {
			continue
		}
		docs = append(docs, document{index: index, object: object})
	}
	return docs, nil
}
