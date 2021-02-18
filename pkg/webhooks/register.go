package webhooks

import (
	admissionregv1 "k8s.io/api/admissionregistration/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	admissionctl "sigs.k8s.io/controller-runtime/pkg/webhook/admission"
)

type RegisteredWebhooks map[string]WebhookFactory

// Webhooks are all registered webhooks mapping name to hook
var Webhooks = RegisteredWebhooks{}

// Webhook interface
type Webhook interface {
	// Authorized will determine if the request is allowed
	Authorized(request admissionctl.Request) admissionctl.Response
	// GetURI returns the URI for the webhook
	GetURI() string
	// Validate will validate the incoming request
	Validate(admissionctl.Request) bool
	// Name is the name of the webhook
	Name() string
	// FailurePolicy is how the hook config should react if k8s can't access it
	FailurePolicy() admissionregv1.FailurePolicyType
	// MatchPolicy mirrors validatingwebhookconfiguration.webhooks[].matchPolicy.
	// If it is important to the webhook, be sure to check subResource vs
	// requestSubResource.
	MatchPolicy() admissionregv1.MatchPolicyType
	// Rules is a slice of rules on which this hook should trigger
	Rules() []admissionregv1.RuleWithOperations
	// ObjectSelector uses a *metav1.LabelSelector to augment the webhook's
	// Rules() to match only on incoming requests which match the specific
	// LabelSelector.
	ObjectSelector() *metav1.LabelSelector
	// SideEffects are what side effects, if any, this hook has. Refer to
	// https://kubernetes.io/docs/reference/access-authn-authz/extensible-admission-controllers/#side-effects
	SideEffects() admissionregv1.SideEffectClass
	// TimeoutSeconds returns an int32 representing how long to wait for this hook to complete
	TimeoutSeconds() int32
	// Doc returns a string for end-customer documentation purposes.
	Doc() string
	// SyncSetLabelSelector returns the label selector to use in the SyncSet.
	// Return utils.DefaultLabelSelector() to stick with the default
	SyncSetLabelSelector() metav1.LabelSelector
}

// WebhookFactory return a kind of Webhook
type WebhookFactory func() Webhook

// Register webhooks
func Register(name string, input WebhookFactory) {
	Webhooks[name] = input
}
