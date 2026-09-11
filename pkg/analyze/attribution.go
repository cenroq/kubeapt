// Copyright by cenroq AG
// Contact: info@cenroq.com

package analyze

import "regexp"

// EnforcerType names the admission component that rejected a probe.
type EnforcerType string

const (
	// EnforcerWebhook covers every registered validating webhook, including
	// Kyverno and Gatekeeper, which are identified by their webhook name.
	EnforcerWebhook EnforcerType = "Webhook"
	// EnforcerVAP is a ValidatingAdmissionPolicy.
	EnforcerVAP EnforcerType = "ValidatingAdmissionPolicy"
	// EnforcerPSA is built-in Pod Security Admission.
	EnforcerPSA EnforcerType = "PodSecurity"
	// EnforcerResourceQuota is quota accounting, not a security control.
	EnforcerResourceQuota EnforcerType = "ResourceQuota"
	// EnforcerLimitRanger is LimitRanger defaulting, not a security control.
	EnforcerLimitRanger EnforcerType = "LimitRanger"
	// EnforcerUnattributed means the denial did not match any known message
	// shape. It is a valid result, not a bug: the raw message is retained.
	EnforcerUnattributed EnforcerType = "Unattributed"
)

// Enforcer identifies what rejected a probe. Message always holds the API
// server's text verbatim, whether or not a pattern matched.
type Enforcer struct {
	Type    EnforcerType `json:"type"`
	Name    string       `json:"name,omitempty"`
	Detail  string       `json:"detail,omitempty"`
	Message string       `json:"message,omitempty"`
}

// Resource reports whether the enforcer is resource accounting rather than a
// security control. A quota or LimitRanger rejection says nothing about whether
// the cluster would have blocked the dangerous technique, so it must not be
// recorded as a successful block.
func (e Enforcer) Resource() bool {
	return e.Type == EnforcerResourceQuota || e.Type == EnforcerLimitRanger
}

// Attribution patterns, ordered most authoritative first.
//
// Webhooks come before everything else deliberately. Kyverno and Gatekeeper
// embed their own policy text inside the webhook denial, and that text can
// quote PSA wording; the component that actually rejected the request is still
// the webhook, so the outer frame wins.
var (
	webhookPattern      = regexp.MustCompile(`admission webhook "([^"]+)" denied the request`)
	vapPattern          = regexp.MustCompile(`ValidatingAdmissionPolicy '([^']+)'(?: with binding '([^']+)')? denied request`)
	psaPattern          = regexp.MustCompile(`violates PodSecurity "([^"]+)"`)
	quotaPattern        = regexp.MustCompile(`exceeded quota: ([^,]+)`)
	limitRangerPattern  = regexp.MustCompile(`(?:minimum|maximum) [a-zA-Z ]+ per (?:Container|Pod)`)
	limitRangerFallback = regexp.MustCompile(`\bLimitRanger\b`)
)

// Attribute parses an admission denial message and names the component that
// produced it.
//
// This is string matching against text Kubernetes does not treat as API, so it
// is built to degrade rather than guess: an unrecognised message yields
// EnforcerUnattributed with the original text intact, which is strictly more
// useful than a confident wrong attribution.
func Attribute(message string) Enforcer {
	enforcer := Enforcer{Type: EnforcerUnattributed, Message: message}

	if m := webhookPattern.FindStringSubmatch(message); m != nil {
		enforcer.Type = EnforcerWebhook
		enforcer.Name = m[1]
		return enforcer
	}
	if m := vapPattern.FindStringSubmatch(message); m != nil {
		enforcer.Type = EnforcerVAP
		enforcer.Name = m[1]
		if len(m) > 2 && m[2] != "" {
			enforcer.Detail = "binding " + m[2]
		}
		return enforcer
	}
	if m := psaPattern.FindStringSubmatch(message); m != nil {
		enforcer.Type = EnforcerPSA
		enforcer.Name = m[1]
		return enforcer
	}
	if m := quotaPattern.FindStringSubmatch(message); m != nil {
		enforcer.Type = EnforcerResourceQuota
		enforcer.Name = m[1]
		return enforcer
	}
	if limitRangerPattern.MatchString(message) || limitRangerFallback.MatchString(message) {
		enforcer.Type = EnforcerLimitRanger
		return enforcer
	}

	return enforcer
}

// String renders the enforcer for a report column.
func (e Enforcer) String() string {
	switch {
	case e.Type == EnforcerUnattributed:
		return "unattributed"
	case e.Name == "" && e.Detail == "":
		return string(e.Type)
	case e.Detail == "":
		return string(e.Type) + " " + e.Name
	case e.Name == "":
		return string(e.Type) + " (" + e.Detail + ")"
	default:
		return string(e.Type) + " " + e.Name + " (" + e.Detail + ")"
	}
}
