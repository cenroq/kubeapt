// Copyright by cenroq AG
// Contact: info@cenroq.com

// Package policies loads kubeapt policy bundles from an fs.FS or directory,
// preserving each policy's raw YAML bytes for downstream "remediation as code"
// artifact bundling.
package policies

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"iter"
	"os"
	"path"
	"sort"
	"strings"

	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	utilyaml "k8s.io/apimachinery/pkg/util/yaml"
	sigsyaml "sigs.k8s.io/yaml"

	"github.com/cenroq/kubeapt/v2/internal/scanaccess"
	"github.com/cenroq/kubeapt/v2/pkg/types"
)

// ErrDuplicatePolicy reports two policies sharing a metadata.name.
var ErrDuplicatePolicy = errors.New("policies: duplicate policy id")

// Annotation keys read from a parsed policy's metadata.
//
// The security.cenroq.io keys are authoritative. Policy sets published before
// the switch carry the same metadata under security.kubeapt.io, which is read
// only as a fallback (see the LegacyAnnotation constants). Read metadata
// through the *FromAnnotations accessors rather than indexing the map, so the
// precedence lives in one place.
const (
	AnnotationSeverity    = "security.cenroq.io/severity"
	AnnotationDisplayName = "security.cenroq.io/displayName"
	AnnotationDescription = "security.cenroq.io/description"
	AnnotationCategory    = "security.cenroq.io/category"
	AnnotationResource    = "security.cenroq.io/resource"
	AnnotationRemediation = "security.cenroq.io/remediation"
	AnnotationProduct     = "security.cenroq.io/product"

	// AnnotationFinding carries the policy's cenroq finding id, such as
	// "oq-0276". It is read verbatim; nothing is derived or hashed from it. The
	// same id is stamped on the policy and on the deny manifest that probes it,
	// which is what lets an analyze result name the policy that should have
	// blocked it.
	AnnotationFinding = "cenroq.io/finding"

	// AnnotationUUID is the catalogue identifier policy sets stamped before
	// finding ids existed.
	//
	// Deprecated: read only as a fallback for AnnotationFinding. Future policy
	// sets carry AnnotationFinding alone.
	AnnotationUUID = "kubeapt.io/uuid"
)

// Legacy spellings of the metadata annotations, used by policy sets published
// before the switch to security.cenroq.io.
//
// Deprecated: read only as fallbacks for the matching Annotation constant.
// Future policy sets carry the security.cenroq.io keys alone.
const (
	LegacyAnnotationSeverity    = "security.kubeapt.io/severity"
	LegacyAnnotationDisplayName = "security.kubeapt.io/displayName"
	LegacyAnnotationDescription = "security.kubeapt.io/description"
	LegacyAnnotationCategory    = "security.kubeapt.io/category"
	LegacyAnnotationResource    = "security.kubeapt.io/resource"
	LegacyAnnotationRemediation = "security.kubeapt.io/remediation"
	LegacyAnnotationProduct     = "security.kubeapt.io/product"
)

// legacyAnnotations pairs each metadata key with its deprecated spelling, in
// a fixed order so UsesLegacyAnnotations is deterministic.
var legacyAnnotations = [...][2]string{
	{AnnotationSeverity, LegacyAnnotationSeverity},
	{AnnotationDisplayName, LegacyAnnotationDisplayName},
	{AnnotationDescription, LegacyAnnotationDescription},
	{AnnotationCategory, LegacyAnnotationCategory},
	{AnnotationResource, LegacyAnnotationResource},
	{AnnotationRemediation, LegacyAnnotationRemediation},
	{AnnotationProduct, LegacyAnnotationProduct},
}

// DisplayNameFromAnnotations returns the policy's display name from a
// metadata.annotations map: security.cenroq.io first, then the legacy
// security.kubeapt.io key, then Kyverno's title. "" when none is set.
func DisplayNameFromAnnotations(in map[string]string) string {
	return LookupAnnotation(in, AnnotationDisplayName, LegacyAnnotationDisplayName, KyvernoAnnotationTitle)
}

// DescriptionFromAnnotations returns the description with the same
// precedence as DisplayNameFromAnnotations.
func DescriptionFromAnnotations(in map[string]string) string {
	return LookupAnnotation(in, AnnotationDescription, LegacyAnnotationDescription, KyvernoAnnotationDescription)
}

// CategoryFromAnnotations returns the category with the same precedence as
// DisplayNameFromAnnotations.
func CategoryFromAnnotations(in map[string]string) string {
	return LookupAnnotation(in, AnnotationCategory, LegacyAnnotationCategory, KyvernoAnnotationCategory)
}

// SeverityFromAnnotations returns the normalized severity: security.cenroq.io
// first, then the legacy security.kubeapt.io key.
//
// It deliberately never reads Kyverno's severity. Kyverno spells the middle
// rung "medium", which NormalizeSeverity does not know, so accepting it would
// quietly report a medium-severity policy as Not Rated.
func SeverityFromAnnotations(in map[string]string) types.Severity {
	return NormalizeSeverity(LookupAnnotation(in, AnnotationSeverity, LegacyAnnotationSeverity))
}

// UsesLegacyAnnotations reports whether any metadata value would be read from
// a deprecated security.kubeapt.io key because its security.cenroq.io key is
// absent or blank. Callers use it to warn that a policy set needs replacing.
func UsesLegacyAnnotations(in map[string]string) bool {
	for _, pair := range legacyAnnotations {
		if LookupAnnotation(in, pair[0]) == "" && LookupAnnotation(in, pair[1]) != "" {
			return true
		}
	}
	return false
}

// FindingID returns the trimmed finding id from a metadata.annotations map:
// AnnotationFinding when set, else the deprecated AnnotationUUID. deprecated
// reports that the fallback supplied the id, so a caller can warn that the
// policy set needs re-publishing. A nil map yields "".
func FindingID(annotations map[string]string) (id string, deprecated bool) {
	if id := strings.TrimSpace(annotations[AnnotationFinding]); id != "" {
		return id, false
	}
	if id := strings.TrimSpace(annotations[AnnotationUUID]); id != "" {
		return id, true
	}
	return "", false
}

// DocsBaseURL is the root of the published policy catalogue.
const DocsBaseURL = "https://cenroq.com/open-source/policies"

// DocsURL returns the catalogue page for a finding id, or "" when unset.
// There is deliberately no fallback: a policy with no id has no page, and
// linking to a guessed one would be worse than linking to nothing.
func DocsURL(findingID string) string {
	findingID = strings.TrimSpace(findingID)
	if findingID == "" {
		return ""
	}
	return DocsBaseURL + "/" + findingID
}

// DocsURLFromAnnotations resolves a metadata.annotations map to its catalogue
// page via FindingID, or "" when the map carries no id.
func DocsURLFromAnnotations(meta map[string]string) string {
	id, _ := FindingID(meta)
	return DocsURL(id)
}

// Kyverno annotation keys, read as the last fallback by the accessors above and
// written alongside their security.cenroq.io equivalents by policy conversion.
const (
	KyvernoAnnotationTitle       = "policies.kyverno.io/title"
	KyvernoAnnotationDescription = "policies.kyverno.io/description"
	KyvernoAnnotationCategory    = "policies.kyverno.io/category"
	KyvernoAnnotationSeverity    = "policies.kyverno.io/severity"
)

// Policy is a sealed handle to one ValidatingAdmissionPolicy in a Bundle.
type Policy struct {
	ID          string
	RawYAML     []byte
	BindingYAML []byte

	parsed *scanaccess.Parsed
}

// Parsed returns the sealed typed view, gated by a token.
func (p *Policy) Parsed(_ scanaccess.Token) *scanaccess.Parsed {
	return p.parsed
}

// Title returns the policy's display name, falling back to ID.
func (p *Policy) Title() string {
	if v := DisplayNameFromAnnotations(p.annotations()); v != "" {
		return v
	}
	return p.ID
}

// Description returns the policy's description, or "" if unset.
func (p *Policy) Description() string {
	return DescriptionFromAnnotations(p.annotations())
}

// Category returns the policy's category, or "" if unset.
func (p *Policy) Category() string {
	return CategoryFromAnnotations(p.annotations())
}

// FindingID returns the policy's finding id, falling back to the deprecated
// AnnotationUUID, or "" if neither is set.
func (p *Policy) FindingID() string {
	return LookupAnnotation(p.annotations(), AnnotationFinding, AnnotationUUID)
}

// DocsURL returns the policy's catalogue page, or "" if it carries no id.
func (p *Policy) DocsURL() string {
	return DocsURL(p.FindingID())
}

// annotations returns the policy's metadata.annotations, or nil.
func (p *Policy) annotations() map[string]string {
	if p == nil || p.parsed == nil || p.parsed.VAP == nil {
		return nil
	}
	return p.parsed.VAP.Annotations
}

// LookupAnnotation returns the first non-empty, trimmed value among keys, or "".
func LookupAnnotation(in map[string]string, keys ...string) string {
	for _, k := range keys {
		if v := strings.TrimSpace(in[k]); v != "" {
			return v
		}
	}
	return ""
}

// Resources returns the sorted resource plurals the policy targets.
func (p *Policy) Resources() []string {
	if p == nil || p.parsed == nil {
		return nil
	}
	return PolicyResources(p.parsed.VAP)
}

// TargetsResources reports whether the policy targets any given resource plural.
func (p *Policy) TargetsResources(resources ...string) bool {
	if p == nil || p.parsed == nil {
		return false
	}
	return PolicyTargetsResources(p.parsed.VAP, resources)
}

// TargetsGVR reports whether the policy's matchConstraints select any GVR.
func (p *Policy) TargetsGVR(gvrs ...types.GVR) bool {
	if p == nil || p.parsed == nil {
		return false
	}
	return PolicyTargetsGVRs(p.parsed.VAP, gvrs)
}

// Bundle is an iterable collection of *Policy keyed by ID.
type Bundle struct {
	items []*Policy
	byID  map[string]*Policy

	name        string
	description string
	version     string
	labels      map[string]string
	sources     []string
}

// Iterate yields every Policy in load order.
func (b *Bundle) Iterate() iter.Seq[*Policy] {
	return func(yield func(*Policy) bool) {
		for _, p := range b.items {
			if !yield(p) {
				return
			}
		}
	}
}

// Get returns the Policy with the given ID, or (nil, false) if none exists.
func (b *Bundle) Get(id string) (*Policy, bool) {
	p, ok := b.byID[id]
	return p, ok
}

// Len returns the number of policies in the bundle.
func (b *Bundle) Len() int {
	return len(b.items)
}

// Name returns the bundle's declared name, or "".
func (b *Bundle) Name() string { return b.name }

// Description returns the bundle's declared description, or "".
func (b *Bundle) Description() string { return b.description }

// Version returns the bundle's declared version, or "".
func (b *Bundle) Version() string { return b.version }

// Labels returns a defensive copy of the bundle's labels, or nil.
func (b *Bundle) Labels() map[string]string {
	if len(b.labels) == 0 {
		return nil
	}
	out := make(map[string]string, len(b.labels))
	for k, v := range b.labels {
		out[k] = v
	}
	return out
}

// Sources returns a defensive copy of the bundle's source URLs, or nil.
func (b *Bundle) Sources() []string {
	if len(b.sources) == 0 {
		return nil
	}
	return append([]string(nil), b.sources...)
}

// FilterByResources returns a new Bundle keeping only policies targeting the resources.
func (b *Bundle) FilterByResources(resources ...string) *Bundle {
	out := &Bundle{
		byID:        make(map[string]*Policy, len(b.items)),
		name:        b.name,
		description: b.description,
		version:     b.version,
	}
	if len(b.labels) > 0 {
		out.labels = make(map[string]string, len(b.labels))
		for k, v := range b.labels {
			out.labels[k] = v
		}
	}
	if len(b.sources) > 0 {
		out.sources = append([]string(nil), b.sources...)
	}
	for _, p := range b.items {
		if len(resources) == 0 || p.TargetsResources(resources...) {
			out.items = append(out.items, p)
			out.byID[p.ID] = p
		}
	}
	return out
}

// LoadDir loads a bundle from a host filesystem path.
func LoadDir(p string) (*Bundle, error) {
	if p == "" {
		return nil, errors.New("policies: empty path")
	}
	return Load(os.DirFS(p), ".")
}

// Load walks fsys from root, building a Bundle from policy documents.
func Load(fsys fs.FS, root string) (*Bundle, error) {
	if fsys == nil {
		return nil, errors.New("policies: nil fs.FS")
	}
	if root == "" {
		root = "."
	}

	files, err := collectYAMLFiles(fsys, root)
	if err != nil {
		return nil, err
	}
	sort.Strings(files)

	type pendingPolicy struct {
		id   string
		yaml []byte
		vap  *admissionregistrationv1.ValidatingAdmissionPolicy
	}
	type pendingBinding struct {
		yaml    []byte
		binding *admissionregistrationv1.ValidatingAdmissionPolicyBinding
	}

	var policies []pendingPolicy
	bindingsByPolicy := map[string][]pendingBinding{}

	for _, file := range files {
		docs, err := readYAMLDocuments(fsys, file)
		if err != nil {
			return nil, fmt.Errorf("policies: read %s: %w", file, err)
		}
		for i, doc := range docs {
			kind, err := documentKind(doc)
			if err != nil {
				return nil, fmt.Errorf("policies: %s doc %d: %w", file, i, err)
			}
			switch kind {
			case "ValidatingAdmissionPolicy":
				var vap admissionregistrationv1.ValidatingAdmissionPolicy
				if err := sigsyaml.Unmarshal(doc, &vap); err != nil {
					return nil, fmt.Errorf("policies: %s doc %d: %w", file, i, err)
				}
				if vap.Name == "" {
					return nil, fmt.Errorf("policies: %s doc %d: ValidatingAdmissionPolicy missing metadata.name", file, i)
				}
				policies = append(policies, pendingPolicy{
					id:   vap.Name,
					yaml: doc,
					vap:  &vap,
				})
			case "ValidatingAdmissionPolicyBinding":
				var binding admissionregistrationv1.ValidatingAdmissionPolicyBinding
				if err := sigsyaml.Unmarshal(doc, &binding); err != nil {
					return nil, fmt.Errorf("policies: %s doc %d: %w", file, i, err)
				}
				key := binding.Spec.PolicyName
				if key == "" {
					return nil, fmt.Errorf("policies: %s doc %d: ValidatingAdmissionPolicyBinding missing spec.policyName", file, i)
				}
				bindingsByPolicy[key] = append(bindingsByPolicy[key], pendingBinding{
					yaml:    doc,
					binding: &binding,
				})
			default:
				continue
			}
		}
	}

	bundle := &Bundle{
		byID: make(map[string]*Policy, len(policies)),
	}
	for _, pp := range policies {
		if _, dup := bundle.byID[pp.id]; dup {
			return nil, fmt.Errorf("policies: %s: %w", pp.id, ErrDuplicatePolicy)
		}
		pending := bindingsByPolicy[pp.id]
		var bindingYAML []byte
		bindings := make([]*admissionregistrationv1.ValidatingAdmissionPolicyBinding, 0, len(pending))
		if len(pending) > 0 {
			docs := make([][]byte, 0, len(pending))
			for _, pb := range pending {
				docs = append(docs, pb.yaml)
				bindings = append(bindings, pb.binding)
			}
			bindingYAML = joinYAMLDocuments(docs)
		}
		severity := SeverityFromAnnotations(pp.vap.Annotations)
		policy := &Policy{
			ID:          pp.id,
			RawYAML:     pp.yaml,
			BindingYAML: bindingYAML,
			parsed: &scanaccess.Parsed{
				VAP:      pp.vap,
				Bindings: bindings,
				Severity: severity,
			},
		}
		bundle.items = append(bundle.items, policy)
		bundle.byID[pp.id] = policy
	}

	if err := loadBundleMetadata(fsys, root, bundle); err != nil {
		return nil, err
	}

	return bundle, nil
}

// loadBundleMetadata populates bundle fields from an optional bundle.json.
func loadBundleMetadata(fsys fs.FS, root string, bundle *Bundle) error {
	manifestPath := path.Join(root, "bundle.json")
	data, err := fs.ReadFile(fsys, manifestPath)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil
		}
		return fmt.Errorf("policies: read %s: %w", manifestPath, err)
	}
	var meta struct {
		Name        string            `json:"name"`
		Description string            `json:"description"`
		Version     string            `json:"version"`
		Labels      map[string]string `json:"labels"`
		Sources     []string          `json:"sources"`
	}
	if err := json.Unmarshal(data, &meta); err != nil {
		return fmt.Errorf("policies: parse %s: %w", manifestPath, err)
	}
	bundle.name = strings.TrimSpace(meta.Name)
	bundle.description = strings.TrimSpace(meta.Description)
	bundle.version = strings.TrimSpace(meta.Version)
	if len(meta.Labels) > 0 {
		bundle.labels = make(map[string]string, len(meta.Labels))
		for k, v := range meta.Labels {
			bundle.labels[k] = v
		}
	}
	if len(meta.Sources) > 0 {
		bundle.sources = append([]string(nil), meta.Sources...)
	}
	return nil
}

func collectYAMLFiles(fsys fs.FS, root string) ([]string, error) {
	var files []string
	err := fs.WalkDir(fsys, root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		switch strings.ToLower(path.Ext(p)) {
		case ".yaml", ".yml", ".json":
			files = append(files, p)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return files, nil
}

func readYAMLDocuments(fsys fs.FS, name string) ([][]byte, error) {
	f, err := fsys.Open(name)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	reader := utilyaml.NewYAMLReader(bufio.NewReader(f))
	var docs [][]byte
	for {
		raw, err := reader.Read()
		if err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			return nil, err
		}
		if len(bytes.TrimSpace(raw)) == 0 {
			continue
		}
		docs = append(docs, append([]byte(nil), raw...))
	}
	return docs, nil
}

// documentKind extracts the Kind from a single-document YAML or JSON blob.
func documentKind(doc []byte) (string, error) {
	var meta struct {
		APIVersion string `json:"apiVersion"`
		Kind       string `json:"kind"`
	}
	if err := sigsyaml.Unmarshal(doc, &meta); err != nil {
		return "", err
	}
	return meta.Kind, nil
}

// joinYAMLDocuments concatenates YAML blobs into one multi-document stream.
func joinYAMLDocuments(docs [][]byte) []byte {
	if len(docs) == 0 {
		return nil
	}
	if len(docs) == 1 {
		return append([]byte(nil), docs[0]...)
	}
	var buf bytes.Buffer
	for i, d := range docs {
		if i > 0 {
			if !bytes.HasSuffix(buf.Bytes(), []byte("\n")) {
				buf.WriteByte('\n')
			}
			buf.WriteString("---\n")
		}
		buf.Write(d)
	}
	return buf.Bytes()
}

// NormalizeSeverity maps a raw annotation value onto kubeapt's severity scale,
// returning types.SeverityNotRated for anything unrecognized.
func NormalizeSeverity(raw string) types.Severity {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "critical":
		return types.SeverityCritical
	case "high":
		return types.SeverityHigh
	case "moderate":
		return types.SeverityModerate
	case "low":
		return types.SeverityLow
	case "info":
		return types.SeverityInfo
	default:
		return types.SeverityNotRated
	}
}

// PolicyTargetsResources reports whether vap targets any given resource plural.
func PolicyTargetsResources(vap *admissionregistrationv1.ValidatingAdmissionPolicy, resources []string) bool {
	if vap == nil || vap.Spec.MatchConstraints == nil || len(resources) == 0 {
		return false
	}
	for _, rule := range vap.Spec.MatchConstraints.ResourceRules {
		for _, ruleResource := range rule.Resources {
			for _, want := range resources {
				if resourceRuleSelects(ruleResource, want) {
					return true
				}
			}
		}
	}
	return false
}

// PolicyResources returns the sorted resource plurals vap targets.
func PolicyResources(vap *admissionregistrationv1.ValidatingAdmissionPolicy) []string {
	if vap == nil || vap.Spec.MatchConstraints == nil {
		return nil
	}
	seen := make(map[string]struct{})
	var out []string
	for _, rule := range vap.Spec.MatchConstraints.ResourceRules {
		for _, ruleResource := range rule.Resources {
			base := baseResource(ruleResource)
			if base == "" {
				continue
			}
			if _, ok := seen[base]; ok {
				continue
			}
			seen[base] = struct{}{}
			out = append(out, base)
		}
	}
	sort.Strings(out)
	return out
}

// PolicyTargetsGVRs reports whether the policy's matchConstraints select any GVR.
func PolicyTargetsGVRs(vap *admissionregistrationv1.ValidatingAdmissionPolicy, gvrs []types.GVR) bool {
	if vap == nil || vap.Spec.MatchConstraints == nil || len(gvrs) == 0 {
		return false
	}
	for _, rule := range vap.Spec.MatchConstraints.ResourceRules {
		for _, gvr := range gvrs {
			if ruleSelectsGVR(rule, gvr) {
				return true
			}
		}
	}
	return false
}

// ruleSelectsGVR reports whether one rule selects the requested GVR.
func ruleSelectsGVR(rule admissionregistrationv1.NamedRuleWithOperations, gvr types.GVR) bool {
	resource := strings.ToLower(strings.TrimSpace(gvr.Resource))
	if resource == "" {
		return false
	}
	if !apiGroupRequestMatches(gvr.Group, rule.APIGroups) {
		return false
	}
	// Version is ignored for selection: group+resource only.
	if len(rule.Resources) > 0 && !resourceRulesSelect(rule.Resources, resource) {
		return false
	}
	return true
}

// apiGroupRequestMatches reports whether the group satisfies the rule's apiGroups.
func apiGroupRequestMatches(reqGroup string, ruleGroups []string) bool {
	reqGroup = strings.TrimSpace(reqGroup)
	if reqGroup == "*" {
		return true
	}
	if len(ruleGroups) == 0 {
		return true
	}
	for _, g := range ruleGroups {
		g = strings.TrimSpace(g)
		if g == "*" || g == reqGroup {
			return true
		}
	}
	return false
}

// resourceRulesSelect reports whether any rule resource covers the request.
func resourceRulesSelect(ruleResources []string, want string) bool {
	for _, r := range ruleResources {
		if resourceRuleSelects(r, want) {
			return true
		}
	}
	return false
}

// resourceRuleSelects reports whether a rule resource entry covers want.
func resourceRuleSelects(ruleResource, want string) bool {
	ruleResource = strings.ToLower(strings.TrimSpace(ruleResource))
	want = strings.ToLower(strings.TrimSpace(want))
	if ruleResource == "" || want == "" {
		return false
	}
	if ruleResource == "*" || ruleResource == "*/*" {
		return true
	}
	if ruleResource == want {
		return true
	}
	return baseResource(ruleResource) == want
}

// baseResource normalizes a resource entry, dropping any subresource suffix.
func baseResource(resource string) string {
	resource = strings.ToLower(strings.TrimSpace(resource))
	if idx := strings.IndexByte(resource, '/'); idx != -1 {
		return resource[:idx]
	}
	return resource
}
