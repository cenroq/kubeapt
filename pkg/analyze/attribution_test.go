// Copyright by cenroq AG
// Contact: info@cenroq.com

package analyze_test

import (
	"strings"
	"testing"

	"github.com/cenroq/kubeapt/v2/pkg/analyze"
)

// The messages below are the shapes real API servers emit. The parser is only
// as good as this corpus, so prefer pasting a captured denial over inventing
// one when adding a case.
func TestAttribute(t *testing.T) {
	tests := []struct {
		name       string
		message    string
		wantType   analyze.EnforcerType
		wantName   string
		wantDetail string
	}{
		{
			name:     "pod security admission",
			message:  `pods "privileged-probe" is forbidden: violates PodSecurity "restricted:latest": privileged (container "app" must not set securityContext.privileged=true), allowPrivilegeEscalation != false (container "app" must set securityContext.allowPrivilegeEscalation=false)`,
			wantType: analyze.EnforcerPSA,
			wantName: "restricted:latest",
		},
		{
			name:     "pod security baseline",
			message:  `pods "hostpath-probe" is forbidden: violates PodSecurity "baseline:v1.31": hostPath volumes (volume "data")`,
			wantType: analyze.EnforcerPSA,
			wantName: "baseline:v1.31",
		},
		{
			name:       "validating admission policy with binding",
			message:    `pods "probe" is forbidden: ValidatingAdmissionPolicy 'disallow-privileged.kubeapt.io' with binding 'disallow-privileged-binding.kubeapt.io' denied request: privileged containers are not allowed`,
			wantType:   analyze.EnforcerVAP,
			wantName:   "disallow-privileged.kubeapt.io",
			wantDetail: "binding disallow-privileged-binding.kubeapt.io",
		},
		{
			name:     "validating admission policy without binding",
			message:  `pods "probe" is forbidden: ValidatingAdmissionPolicy 'require-labels' denied request: missing owner label`,
			wantType: analyze.EnforcerVAP,
			wantName: "require-labels",
		},
		{
			name:     "kyverno webhook",
			message:  "admission webhook \"validate.kyverno.svc-fail\" denied the request: \n\nresource Pod/default/privileged-probe was blocked due to the following policies \n\ndisallow-privileged-containers:\n  privileged-containers: 'validation error: Privileged mode is disallowed.'",
			wantType: analyze.EnforcerWebhook,
			wantName: "validate.kyverno.svc-fail",
		},
		{
			name:     "gatekeeper webhook",
			message:  `admission webhook "validation.gatekeeper.sh" denied the request: [psp-privileged-container] Privileged container is not allowed: app, securityContext: {"privileged": true}`,
			wantType: analyze.EnforcerWebhook,
			wantName: "validation.gatekeeper.sh",
		},
		{
			name:     "resource quota",
			message:  `pods "probe" is forbidden: exceeded quota: compute-quota, requested: requests.cpu=1, used: requests.cpu=1, limited: requests.cpu=1`,
			wantType: analyze.EnforcerResourceQuota,
			wantName: "compute-quota",
		},
		{
			name:     "limit ranger",
			message:  `pods "probe" is forbidden: minimum memory usage per Container is 100Mi, but request is 50Mi`,
			wantType: analyze.EnforcerLimitRanger,
		},
		{
			name:     "rbac denial is not attributed to an admission control",
			message:  `pods is forbidden: User "system:serviceaccount:default:nobody" cannot create resource "pods" in API group "" in the namespace "default"`,
			wantType: analyze.EnforcerUnattributed,
		},
		{
			name:     "unrecognised message",
			message:  `something entirely new rejected this`,
			wantType: analyze.EnforcerUnattributed,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := analyze.Attribute(tc.message)
			if got.Type != tc.wantType {
				t.Errorf("type = %q, want %q", got.Type, tc.wantType)
			}
			if got.Name != tc.wantName {
				t.Errorf("name = %q, want %q", got.Name, tc.wantName)
			}
			if got.Detail != tc.wantDetail {
				t.Errorf("detail = %q, want %q", got.Detail, tc.wantDetail)
			}
			if got.Message != tc.message {
				t.Errorf("raw message not retained:\ngot  %q\nwant %q", got.Message, tc.message)
			}
		})
	}
}

// A webhook that embeds PSA wording in its own denial must still be attributed
// to the webhook: it is the component that actually rejected the request.
func TestAttributeWebhookOutranksEmbeddedPSAWording(t *testing.T) {
	message := `admission webhook "validate.kyverno.svc-fail" denied the request: pod violates PodSecurity "restricted:latest" equivalent rules`
	got := analyze.Attribute(message)
	if got.Type != analyze.EnforcerWebhook {
		t.Fatalf("type = %q, want %q", got.Type, analyze.EnforcerWebhook)
	}
	if got.Name != "validate.kyverno.svc-fail" {
		t.Fatalf("name = %q", got.Name)
	}
}

func TestEnforcerResource(t *testing.T) {
	tests := []struct {
		enforcerType analyze.EnforcerType
		want         bool
	}{
		{analyze.EnforcerResourceQuota, true},
		{analyze.EnforcerLimitRanger, true},
		{analyze.EnforcerPSA, false},
		{analyze.EnforcerVAP, false},
		{analyze.EnforcerWebhook, false},
		{analyze.EnforcerUnattributed, false},
	}
	for _, tc := range tests {
		if got := (analyze.Enforcer{Type: tc.enforcerType}).Resource(); got != tc.want {
			t.Errorf("%s.Resource() = %v, want %v", tc.enforcerType, got, tc.want)
		}
	}
}

func TestEnforcerString(t *testing.T) {
	tests := []struct {
		enforcer analyze.Enforcer
		want     string
	}{
		{analyze.Enforcer{Type: analyze.EnforcerPSA, Name: "restricted:latest"}, "PodSecurity restricted:latest"},
		{analyze.Enforcer{Type: analyze.EnforcerVAP, Name: "p", Detail: "binding b"}, "ValidatingAdmissionPolicy p (binding b)"},
		{analyze.Enforcer{Type: analyze.EnforcerLimitRanger}, "LimitRanger"},
		{analyze.Enforcer{Type: analyze.EnforcerUnattributed, Message: "raw"}, "unattributed"},
	}
	for _, tc := range tests {
		if got := tc.enforcer.String(); got != tc.want {
			t.Errorf("String() = %q, want %q", got, tc.want)
		}
	}
}

// Guards against a pattern that matches so loosely it swallows unrelated text.
func TestAttributeDoesNotMatchPartialWords(t *testing.T) {
	for _, message := range []string{
		"the myadmission webhookish thing rejected it",
		"ValidatingAdmissionPolicyBindingList denied nothing",
	} {
		if got := analyze.Attribute(message); got.Type != analyze.EnforcerUnattributed {
			t.Errorf("Attribute(%q).Type = %q, want Unattributed", message, got.Type)
		}
	}
}

func TestAttributeRetainsMultilineMessage(t *testing.T) {
	message := "admission webhook \"x.svc\" denied the request:\nline two\nline three"
	got := analyze.Attribute(message)
	if !strings.Contains(got.Message, "line three") {
		t.Fatalf("multiline message truncated: %q", got.Message)
	}
}
