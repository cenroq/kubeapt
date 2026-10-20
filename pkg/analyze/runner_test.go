// Copyright by cenroq AG
// Contact: info@cenroq.com

package analyze

import (
	"context"
	"errors"
	"fmt"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

// fakeSubmitter is the whole cluster seam an embedding tool has to provide,
// which is what this file doubles as a worked example of.
type fakeSubmitter struct {
	namespaced bool
	notServed  bool
	canCreate  bool
	// respond decides what admission did with each submitted object.
	respond func(obj *unstructured.Unstructured) (*unstructured.Unstructured, error)
	// resolveErr, when set, can fail an individual Resolve call.
	resolveErr func(obj *unstructured.Unstructured, namespaceOverride string) error
	// review, when set, replaces the canCreate answer.
	review func(ctx context.Context) (bool, error)
	// hold keeps each submission in flight for a while, so concurrency can be
	// observed.
	hold time.Duration

	mu          sync.Mutex
	submitted   []string
	reviews     int
	inFlight    int
	maxInFlight int
	deadlines   []time.Time
}

type fakeTarget struct {
	sub       *fakeSubmitter
	namespace string
}

func (t fakeTarget) Namespace() string { return t.namespace }
func (t fakeTarget) Namespaced() bool  { return t.sub.namespaced }
func (t fakeTarget) Resource() string  { return "pods" }

func (t fakeTarget) DryRunCreate(ctx context.Context, obj *unstructured.Unstructured) (*unstructured.Unstructured, error) {
	t.sub.mu.Lock()
	t.sub.submitted = append(t.sub.submitted, t.namespace+"/"+obj.GetName())
	if deadline, ok := ctx.Deadline(); ok {
		t.sub.deadlines = append(t.sub.deadlines, deadline)
	}
	t.sub.inFlight++
	t.sub.maxInFlight = max(t.sub.maxInFlight, t.sub.inFlight)
	t.sub.mu.Unlock()
	defer func() {
		t.sub.mu.Lock()
		t.sub.inFlight--
		t.sub.mu.Unlock()
	}()
	if t.sub.hold > 0 {
		time.Sleep(t.sub.hold)
	}
	if t.sub.respond != nil {
		return t.sub.respond(obj)
	}
	return obj, nil
}

func (s *fakeSubmitter) Resolve(obj *unstructured.Unstructured, namespaceOverride string) (Target, error) {
	if s.notServed {
		return nil, fmt.Errorf("%w: no matches for Pod", ErrKindNotServed)
	}
	if s.resolveErr != nil {
		if err := s.resolveErr(obj, namespaceOverride); err != nil {
			return nil, err
		}
	}
	if s.namespaced && namespaceOverride != "" {
		obj.SetNamespace(namespaceOverride)
	}
	return fakeTarget{sub: s, namespace: namespaceOverride}, nil
}

func (s *fakeSubmitter) CanCreate(ctx context.Context, _ Target) (bool, error) {
	s.mu.Lock()
	s.reviews++
	s.mu.Unlock()
	if s.review != nil {
		return s.review(ctx)
	}
	return s.canCreate, nil
}

func (s *fakeSubmitter) names() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.submitted...)
}

func testProbe(id string) Probe {
	obj := &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": "v1",
		"kind":       "Pod",
		"metadata":   map[string]any{"name": id},
		"spec":       map[string]any{"hostPID": true},
	}}
	return Probe{ID: id, Expect: ExpectBlocked, Object: obj, UUID: testUUID}
}

func forbidden() error {
	return apierrors.NewForbidden(schema.GroupResource{Resource: "pods"}, "p",
		fmt.Errorf(`ValidatingAdmissionPolicy 'pod-hostpid' with binding 'b' denied request: hostPID is disallowed`))
}

// A namespaced probe is submitted once per namespace; the verdict is per
// namespace because enforcement usually is.
func TestRunnerFansOutNamespacedProbes(t *testing.T) {
	sub := &fakeSubmitter{namespaced: true, canCreate: true, respond: func(*unstructured.Unstructured) (*unstructured.Unstructured, error) {
		return nil, forbidden()
	}}
	results := NewRunner(sub).Run(context.Background(), []Probe{testProbe("hostpid")}, []string{"a", "b"})

	if len(results) != 2 {
		t.Fatalf("got %d results, want 2", len(results))
	}
	if got := sub.names(); len(got) != 2 || got[0] == got[1] {
		t.Fatalf("submissions = %v, want one per namespace", got)
	}
	for _, r := range results {
		if r.Outcome != OutcomeBlocked || r.Verdict != VerdictPass {
			t.Errorf("%s: outcome %q verdict %q", r.Namespace, r.Outcome, r.Verdict)
		}
		if r.Enforcer.Name != "pod-hostpid" {
			t.Errorf("enforcer not attributed: %+v", r.Enforcer)
		}
	}
}

// A cluster-scoped probe is one unit no matter how many namespaces are selected.
func TestRunnerSubmitsClusterScopedProbeOnce(t *testing.T) {
	sub := &fakeSubmitter{canCreate: true}
	results := NewRunner(sub).Run(context.Background(), []Probe{testProbe("clusterrole")}, []string{"a", "b", "c"})

	if len(results) != 1 {
		t.Fatalf("got %d results, want 1", len(results))
	}
	// Admitted with expect=blocked is the headline finding.
	if results[0].Verdict != VerdictFail {
		t.Fatalf("verdict = %q, want Fail", results[0].Verdict)
	}
}

// An RBAC refusal and an admission refusal are both 403. Reporting the former
// as a block would call an inaccessible cluster a defended one.
func TestRunnerRBACDenialIsInconclusiveNotPass(t *testing.T) {
	sub := &fakeSubmitter{namespaced: true, canCreate: false}
	results := NewRunner(sub).Run(context.Background(), []Probe{testProbe("hostpid")}, []string{"a"})

	if len(results) != 1 {
		t.Fatalf("got %d results", len(results))
	}
	if results[0].Verdict != VerdictInconclusive || results[0].Reason != ReasonRBAC {
		t.Fatalf("verdict %q reason %q, want Inconclusive/rbac", results[0].Verdict, results[0].Reason)
	}
	if len(sub.names()) != 0 {
		t.Error("probe was submitted despite the access review saying no")
	}
}

func TestRunnerSkipsKindsTheClusterDoesNotServe(t *testing.T) {
	sub := &fakeSubmitter{notServed: true, canCreate: true}
	results := NewRunner(sub).Run(context.Background(), []Probe{testProbe("ciliumpolicy")}, []string{"a"})

	if len(results) != 1 || results[0].Outcome != OutcomeSkipped {
		t.Fatalf("results = %+v, want one Skipped", results)
	}
	if results[0].Reason != ReasonKindNotServed {
		t.Errorf("reason = %q", results[0].Reason)
	}
	if results[0].Verdict == VerdictPass {
		t.Error("an unserved kind must never read as a pass")
	}
}

// An unsupported probe is reported without ever reaching the cluster.
func TestRunnerReportsUnsupportedWithoutSubmitting(t *testing.T) {
	probe := testProbe("ephemeral")
	probe.Unsupported = "needs an ephemeral container"
	sub := &fakeSubmitter{namespaced: true, canCreate: true}
	results := NewRunner(sub).Run(context.Background(), []Probe{probe}, []string{"a", "b"})

	if len(results) != 1 {
		t.Fatalf("got %d results, want 1", len(results))
	}
	if results[0].Verdict != VerdictInconclusive || results[0].Reason != ReasonUnsupported {
		t.Fatalf("verdict %q reason %q", results[0].Verdict, results[0].Reason)
	}
	if len(sub.names()) != 0 {
		t.Error("an unsupported probe must not be submitted")
	}
	if sub.reviews != 0 {
		t.Error("an unsupported probe must not cost an access review")
	}
}

// A live object of the same name would make the request an update, which fires
// a different set of admission rules, so the runner retries under a fresh name.
func TestRunnerRetriesUnderFreshNameOnCollision(t *testing.T) {
	var calls int
	var mu sync.Mutex
	sub := &fakeSubmitter{namespaced: true, canCreate: true, respond: func(obj *unstructured.Unstructured) (*unstructured.Unstructured, error) {
		mu.Lock()
		defer mu.Unlock()
		calls++
		if calls == 1 {
			return nil, apierrors.NewAlreadyExists(schema.GroupResource{Resource: "pods"}, obj.GetName())
		}
		return nil, forbidden()
	}}
	results := NewRunner(sub).Run(context.Background(), []Probe{testProbe("hostpid")}, []string{"a"})

	if results[0].Outcome != OutcomeBlocked {
		t.Fatalf("outcome = %q, want Blocked after the retry", results[0].Outcome)
	}
	names := sub.names()
	if len(names) != 2 {
		t.Fatalf("submissions = %v, want an original and a retry", names)
	}
	if !strings.Contains(names[1], "hostpid-kubeapt-") {
		t.Errorf("retry did not use a collision-free name: %q", names[1])
	}
}

// Every probe produces exactly one progress callback, whether or not it was
// ever submitted, so a caller's tracker cannot stall.
func TestRunnerReportsProgressForEveryUnit(t *testing.T) {
	sub := &fakeSubmitter{namespaced: true, canCreate: true}
	unsupported := testProbe("ephemeral")
	unsupported.Unsupported = "needs an ephemeral container"

	var mu sync.Mutex
	var ticks int
	runner := NewRunner(sub)
	runner.OnResult = func() {
		mu.Lock()
		ticks++
		mu.Unlock()
	}
	results := runner.Run(context.Background(), []Probe{testProbe("a"), unsupported}, []string{"x", "y"})

	if ticks != len(results) {
		t.Fatalf("ticks = %d, results = %d", ticks, len(results))
	}
}

func TestCollisionFreeName(t *testing.T) {
	got := collisionFreeName("privileged-probe")
	if !strings.HasPrefix(got, "privileged-probe-kubeapt-") {
		t.Fatalf("name = %q", got)
	}
	if got == collisionFreeName("privileged-probe") {
		t.Fatal("collision suffix is not random")
	}
	if trimmed := collisionFreeName(strings.Repeat("a", 300)); len(trimmed) > 253 {
		t.Fatalf("name exceeds the API server limit: %d", len(trimmed))
	}
	if got := collisionFreeName(""); !strings.HasPrefix(got, "probe-kubeapt-") {
		t.Fatalf("empty base = %q", got)
	}
	if got := collisionFreeName("trailing-"); !strings.HasPrefix(got, "trailing-kubeapt-") {
		t.Fatalf("trailing separator not trimmed: %q", got)
	}
}

// A nil context must not panic; Run substitutes Background.
func TestRunnerAcceptsNilContext(t *testing.T) {
	var ctx context.Context
	results := NewRunner(&fakeSubmitter{canCreate: true}).Run(ctx, []Probe{testProbe("hostpid")}, []string{"a"})
	if len(results) != 1 || results[0].Outcome != OutcomeAdmitted {
		t.Fatalf("results = %+v", results)
	}
}

// A failure to resolve that is not "kind not served" is an error, never a skip.
func TestRunnerPlanResolveErrorIsAnError(t *testing.T) {
	sub := &fakeSubmitter{canCreate: true, resolveErr: func(*unstructured.Unstructured, string) error {
		return errors.New("discovery timed out")
	}}
	results := NewRunner(sub).Run(context.Background(), []Probe{testProbe("hostpid")}, []string{"a"})

	if len(results) != 1 {
		t.Fatalf("got %d results", len(results))
	}
	if r := results[0]; r.Outcome != OutcomeError || r.Reason != ReasonRequestFailed || r.Verdict != VerdictInconclusive {
		t.Fatalf("outcome %q reason %q verdict %q", r.Outcome, r.Reason, r.Verdict)
	}
	if !strings.Contains(results[0].Detail, "discovery timed out") {
		t.Errorf("detail = %q", results[0].Detail)
	}
	if len(sub.names()) != 0 {
		t.Error("a probe that failed to resolve was submitted")
	}
}

// Plan resolves without a namespace; each unit then resolves into its own. A
// failure at that second step keeps the namespace it happened in.
func TestRunnerUnitResolveFailureKeepsNamespace(t *testing.T) {
	tests := []struct {
		name    string
		err     error
		outcome Outcome
		reason  Reason
	}{
		{"not served", fmt.Errorf("%w: gone", ErrKindNotServed), OutcomeSkipped, ReasonKindNotServed},
		{"other", errors.New("connection reset"), OutcomeError, ReasonRequestFailed},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			sub := &fakeSubmitter{namespaced: true, canCreate: true,
				resolveErr: func(_ *unstructured.Unstructured, override string) error {
					if override == "b" {
						return tc.err
					}
					return nil
				}}
			results := NewRunner(sub).Run(context.Background(), []Probe{testProbe("hostpid")}, []string{"a", "b"})

			var failed *Result
			for i := range results {
				if results[i].Namespace == "b" {
					failed = &results[i]
				}
			}
			if failed == nil {
				t.Fatalf("no result for namespace b: %+v", results)
			}
			if failed.Outcome != tc.outcome || failed.Reason != tc.reason {
				t.Fatalf("outcome %q reason %q", failed.Outcome, failed.Reason)
			}
			if failed.Verdict == VerdictPass {
				t.Error("a probe that never ran must not pass")
			}
		})
	}
}

func TestRunnerAccessReviewErrorIsAnError(t *testing.T) {
	sub := &fakeSubmitter{namespaced: true, review: func(context.Context) (bool, error) {
		return false, errors.New("authorization webhook unavailable")
	}}
	results := NewRunner(sub).Run(context.Background(), []Probe{testProbe("hostpid")}, []string{"a"})

	if r := results[0]; r.Outcome != OutcomeError || !strings.Contains(r.Detail, "access review failed") {
		t.Fatalf("outcome %q detail %q", r.Outcome, r.Detail)
	}
	if len(sub.names()) != 0 {
		t.Error("probe was submitted without a successful access review")
	}
}

func TestRunnerRetryResolveErrorIsAnError(t *testing.T) {
	sub := &fakeSubmitter{namespaced: true, canCreate: true,
		respond: func(obj *unstructured.Unstructured) (*unstructured.Unstructured, error) {
			return nil, apierrors.NewAlreadyExists(schema.GroupResource{Resource: "pods"}, obj.GetName())
		},
		resolveErr: func(obj *unstructured.Unstructured, _ string) error {
			if strings.Contains(obj.GetName(), "-kubeapt-") {
				return errors.New("mapper reset")
			}
			return nil
		}}
	results := NewRunner(sub).Run(context.Background(), []Probe{testProbe("hostpid")}, []string{"a"})

	if r := results[0]; r.Outcome != OutcomeError || r.Detail != "mapper reset" || r.Namespace != "a" {
		t.Fatalf("result = %+v", r)
	}
}

// --timeout bounds every request, including the access review that precedes
// the create.
func TestRunnerTimeoutBoundsReviewAndCreate(t *testing.T) {
	sub := &fakeSubmitter{namespaced: true, canCreate: true}
	runner := NewRunner(sub)
	runner.Timeout = 5 * time.Second
	before := time.Now()
	runner.Run(context.Background(), []Probe{testProbe("hostpid")}, []string{"a"})

	if len(sub.deadlines) != 1 {
		t.Fatalf("create carried %d deadlines, want 1", len(sub.deadlines))
	}
	if d := sub.deadlines[0]; d.Before(before) || d.After(before.Add(5*time.Second+time.Second)) {
		t.Errorf("deadline %v not within the 5s timeout", d)
	}

	// A review that hangs until its context is done must give up at the
	// timeout instead of stalling the run.
	hung := &fakeSubmitter{namespaced: true, review: func(ctx context.Context) (bool, error) {
		<-ctx.Done()
		return false, ctx.Err()
	}}
	hungRunner := NewRunner(hung)
	hungRunner.Timeout = 20 * time.Millisecond
	done := make(chan []Result, 1)
	go func() { done <- hungRunner.Run(context.Background(), []Probe{testProbe("hostpid")}, []string{"a"}) }()
	select {
	case results := <-done:
		if results[0].Outcome != OutcomeError || !strings.Contains(results[0].Detail, "deadline exceeded") {
			t.Fatalf("result = %+v", results[0])
		}
	case <-time.After(5 * time.Second):
		t.Fatal("a hung access review was not bounded by Timeout")
	}
}

func TestRunnerDefaultTimeout(t *testing.T) {
	sub := &fakeSubmitter{canCreate: true}
	before := time.Now()
	NewRunner(sub).Run(context.Background(), []Probe{testProbe("clusterrole")}, nil)

	if len(sub.deadlines) != 1 {
		t.Fatalf("create carried %d deadlines, want 1", len(sub.deadlines))
	}
	if d := sub.deadlines[0]; d.Before(before.Add(DefaultTimeout-time.Second)) || d.After(before.Add(DefaultTimeout+time.Second)) {
		t.Errorf("deadline %v is not DefaultTimeout from the start", d)
	}
}

func TestRunnerCapsConcurrencyAtWorkers(t *testing.T) {
	sub := &fakeSubmitter{namespaced: true, canCreate: true, hold: 5 * time.Millisecond}
	runner := NewRunner(sub)
	runner.Workers = 2
	namespaces := []string{"a", "b", "c", "d", "e", "f", "g", "h"}
	results := runner.Run(context.Background(), []Probe{testProbe("hostpid")}, namespaces)

	if len(results) != len(namespaces) {
		t.Fatalf("got %d results, want %d", len(results), len(namespaces))
	}
	if sub.maxInFlight > 2 {
		t.Fatalf("%d submissions in flight, Workers is 2", sub.maxInFlight)
	}
}

func TestRunnerWorkerCount(t *testing.T) {
	procs := runtime.GOMAXPROCS(0)
	tests := []struct {
		workers, total, want int
	}{
		{workers: 3, total: 10, want: 3},
		{workers: 10, total: 4, want: 4},
		{workers: 0, total: 1, want: 1},
		{workers: 0, total: procs + 5, want: procs},
		{workers: -1, total: procs + 5, want: procs},
	}
	for _, tc := range tests {
		r := &Runner{Workers: tc.workers}
		if got := r.workerCount(tc.total); got != tc.want {
			t.Errorf("workerCount(workers=%d, total=%d) = %d, want %d", tc.workers, tc.total, got, tc.want)
		}
	}
}

// With no namespaces selected a namespaced probe still runs once, in whatever
// namespace the Submitter defaults to, rather than silently disappearing.
func TestRunnerNoNamespacesSubmitsNamespacedProbeOnce(t *testing.T) {
	sub := &fakeSubmitter{namespaced: true, canCreate: true}
	results := NewRunner(sub).Run(context.Background(), []Probe{testProbe("hostpid")}, nil)

	if len(results) != 1 {
		t.Fatalf("got %d results, want 1", len(results))
	}
	if got := sub.names(); len(got) != 1 {
		t.Fatalf("submissions = %v, want exactly one", got)
	}
}

func TestRunnerEmptyCorpus(t *testing.T) {
	ticks := 0
	runner := NewRunner(&fakeSubmitter{canCreate: true})
	runner.OnResult = func() { ticks++ }
	if results := runner.Run(context.Background(), nil, []string{"a"}); len(results) != 0 {
		t.Fatalf("results = %+v", results)
	}
	if ticks != 0 {
		t.Fatalf("ticks = %d for an empty corpus", ticks)
	}
}

// A Runner may be reused; a second run starts from a clean slate.
func TestRunnerIsReusable(t *testing.T) {
	runner := NewRunner(&fakeSubmitter{namespaced: true, canCreate: true})
	probes := []Probe{testProbe("a"), testProbe("b")}
	first := runner.Run(context.Background(), probes, []string{"x"})
	second := runner.Run(context.Background(), probes, []string{"x"})

	if len(first) != 2 || len(second) != 2 {
		t.Fatalf("runs returned %d and %d results", len(first), len(second))
	}
	for i := range first {
		if first[i].Probe.ID != second[i].Probe.ID || first[i].Verdict != second[i].Verdict {
			t.Errorf("run %d differs: %+v vs %+v", i, first[i], second[i])
		}
	}
}
