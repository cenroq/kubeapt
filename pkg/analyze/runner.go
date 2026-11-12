// Copyright by cenroq AG
// Contact: info@cenroq.com

package analyze

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"runtime"
	"strings"
	"sync"
	"time"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

// ErrKindNotServed reports that the connected cluster does not serve a probe's
// kind, which is the normal answer for a probe targeting a CRD that is not
// installed. A Submitter must wrap its own not-served error with this so the
// runner can skip the probe instead of aborting the run.
var ErrKindNotServed = errors.New("analyze: cluster does not serve this kind")

// maxProbeNameLength is 253 (the API server's name limit) minus the 17
// characters collisionFreeName appends: "-kubeapt-" plus eight hex digits.
const maxProbeNameLength = 236

// DefaultTimeout bounds a single probe request.
const DefaultTimeout = 30 * time.Second

// Target is a resolved destination for one probe object. A Submitter returns
// its own implementation; the runner only reads the scope and submits.
type Target interface {
	// Namespace is the namespace the object will be sent to, or "" when the
	// resource is cluster scoped.
	Namespace() string
	// Namespaced reports whether the resource is namespace scoped, which is
	// what decides whether a probe fans out across the selected namespaces.
	Namespaced() bool
	// Resource is the plural resource name, used only in messages.
	Resource() string
	// DryRunCreate submits obj with dryRun=All and returns the object as it
	// would have been persisted. A rejection is returned as an error, which
	// for a caller measuring admission posture is the interesting result.
	DryRunCreate(ctx context.Context, obj *unstructured.Unstructured) (*unstructured.Unstructured, error)
}

// Submitter is the cluster seam. It is the only thing an embedding tool has to
// provide to run the corpus against a cluster of its own; kubeapt supplies one
// backed by a dynamic client and a discovery RESTMapper.
type Submitter interface {
	// Resolve maps obj to a Target, writing the chosen namespace back onto obj
	// so the object that goes over the wire carries the namespace it was sent
	// to. It must return an error wrapping ErrKindNotServed when the cluster
	// does not serve obj's kind.
	Resolve(obj *unstructured.Unstructured, namespaceOverride string) (Target, error)
	// CanCreate reports whether the caller may create the target's resource.
	//
	// This is asked before every submission and is not optional: an RBAC
	// refusal and an admission refusal are both 403 and are not reliably
	// distinguishable from the error text. Answering it wrong reports an
	// inaccessible cluster as a defended one.
	CanCreate(ctx context.Context, target Target) (bool, error)
}

// Runner submits a probe corpus to a cluster and collects the verdicts.
//
// The zero value is not usable; build one with NewRunner. A Runner is safe for
// a single Run at a time and may be reused across runs.
type Runner struct {
	// Submitter talks to the cluster.
	Submitter Submitter
	// Timeout bounds each individual probe request. Zero means DefaultTimeout.
	Timeout time.Duration
	// Workers caps concurrent submissions. Zero means one per CPU.
	Workers int
	// OnResult, when set, is called once per completed unit. It is called
	// from multiple goroutines, so it must be safe for concurrent use. It
	// exists for progress reporting; the results are returned by Run.
	OnResult func()
}

// NewRunner returns a Runner submitting through s.
func NewRunner(s Submitter) *Runner {
	return &Runner{Submitter: s}
}

// Run submits every probe and returns one Result per probe per namespace.
//
// A namespaced probe is submitted once per entry in namespaces, or once into
// the Submitter's default namespace when namespaces is empty; a cluster scoped
// probe is submitted once regardless. Nothing is ever created: every
// submission carries dryRun=All.
//
// Run does not return an error. A probe that could not be submitted becomes an
// Inconclusive or Error result, because a run that gives up halfway would
// report a cluster as defended on the strength of the probes that happened to
// run first.
func (r *Runner) Run(ctx context.Context, probes []Probe, namespaces []string) []Result {
	if ctx == nil {
		ctx = context.Background()
	}
	units, results := r.plan(probes, namespaces)
	// plan() resolves a result for every probe it does not turn into a unit,
	// so the OnResult count matches len(units)+len(results) either way.
	for range results {
		r.notify()
	}
	return append(results, r.execute(ctx, units)...)
}

type probeUnit struct {
	probe     Probe
	namespace string
}

// plan expands the corpus into work, fanning namespaced probes across the
// selected namespaces and leaving cluster-scoped ones as a single unit. A probe
// the cluster cannot serve, or that a dry-run create cannot express, resolves
// straight to a result and is never submitted.
func (r *Runner) plan(probes []Probe, namespaces []string) ([]probeUnit, []Result) {
	var units []probeUnit
	var results []Result

	// An empty selection still submits each namespaced probe once, with no
	// override, so the Submitter picks the namespace. Fanning out over nothing
	// would drop the probe from the report without a trace.
	if len(namespaces) == 0 {
		namespaces = []string{""}
	}

	for _, probe := range probes {
		if probe.Unsupported != "" {
			results = append(results, UnsupportedResult(probe, ""))
			continue
		}
		scout := probe.Object.DeepCopy()
		target, err := r.Submitter.Resolve(scout, "")
		if err != nil {
			if errors.Is(err, ErrKindNotServed) {
				results = append(results, SkippedResult(probe, "", err.Error()))
			} else {
				results = append(results, ErrorResult(probe, "", err.Error()))
			}
			continue
		}
		if !target.Namespaced() {
			units = append(units, probeUnit{probe: probe})
			continue
		}
		for _, namespace := range namespaces {
			units = append(units, probeUnit{probe: probe, namespace: namespace})
		}
	}
	return units, results
}

func (r *Runner) execute(ctx context.Context, units []probeUnit) []Result {
	if len(units) == 0 {
		return nil
	}
	results := make([]Result, len(units))
	queue := make(chan int)
	var wg sync.WaitGroup

	for w := 0; w < r.workerCount(len(units)); w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for index := range queue {
				results[index] = r.runUnit(ctx, units[index])
				r.notify()
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

func (r *Runner) runUnit(ctx context.Context, unit probeUnit) Result {
	object := unit.probe.Object.DeepCopy()
	target, err := r.Submitter.Resolve(object, unit.namespace)
	if err != nil {
		if errors.Is(err, ErrKindNotServed) {
			return SkippedResult(unit.probe, unit.namespace, err.Error())
		}
		return ErrorResult(unit.probe, unit.namespace, err.Error())
	}

	// The timeout bounds the access review as well as the create: a hung
	// review would otherwise stall the unit past --timeout.
	requestCtx, cancel := context.WithTimeout(ctx, r.timeout())
	defer cancel()

	// Ask before submitting. An RBAC refusal and an admission refusal are both
	// 403, and treating the former as a block would report an inaccessible
	// cluster as a defended one.
	allowed, err := r.Submitter.CanCreate(requestCtx, target)
	if err != nil {
		return ErrorResult(unit.probe, target.Namespace(), fmt.Sprintf("access review failed: %v", err))
	}
	if !allowed {
		return InconclusiveResult(unit.probe, target.Namespace(), ReasonRBAC,
			fmt.Sprintf("not permitted to create %s", target.Resource()))
	}

	returned, err := target.DryRunCreate(requestCtx, object)
	if apierrors.IsAlreadyExists(err) {
		// A live object of the same name would make this an update rather than
		// a create, which fires a different set of admission rules. Retry once
		// under a name that cannot collide.
		object = unit.probe.Object.DeepCopy()
		object.SetName(collisionFreeName(unit.probe.Object.GetName()))
		retryTarget, retryErr := r.Submitter.Resolve(object, unit.namespace)
		if retryErr != nil {
			return ErrorResult(unit.probe, target.Namespace(), retryErr.Error())
		}
		returned, err = retryTarget.DryRunCreate(requestCtx, object)
	}

	return Classify(unit.probe, target.Namespace(), object, returned, err)
}

func (r *Runner) notify() {
	if r.OnResult != nil {
		r.OnResult()
	}
}

func (r *Runner) timeout() time.Duration {
	if r.Timeout > 0 {
		return r.Timeout
	}
	return DefaultTimeout
}

// workerCount caps concurrency to the work available and, by default, to CPU
// count. It mirrors internal/worker, which pkg cannot import. execute never
// calls it with zero units.
func (r *Runner) workerCount(total int) int {
	limit := r.Workers
	if limit < 1 {
		limit = runtime.GOMAXPROCS(0)
	}
	return min(total, limit)
}

// collisionFreeName appends random hex to a probe's name so a retry cannot hit
// an existing object.
func collisionFreeName(base string) string {
	suffix := make([]byte, 4)
	// crypto/rand.Read never returns an error since Go 1.24; it crashes the
	// program rather than hand back a predictable suffix.
	_, _ = rand.Read(suffix)
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
