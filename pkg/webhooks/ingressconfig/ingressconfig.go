package ingressconfig

import (
	"os"
	"regexp"
	"sync"

	admissionv1 "k8s.io/api/admission/v1"
	admissionregv1 "k8s.io/api/admissionregistration/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	admissionctl "sigs.k8s.io/controller-runtime/pkg/webhook/admission"

	"github.com/openshift/managed-cluster-validating-webhooks/pkg/webhooks/utils"
)

const (
	WebhookName               string = "ingress-config-validation"
	privilegedServiceAccounts string = `^system:serviceaccounts:(kube.*|openshift.*|default|redhat.*|osde2e-[a-z0-9]{5})`
	privilegedUsers           string = `system:admin`
	docString                 string = `Managed OpenShift customers may not modify ingress config resources because it can can degrade cluster operators and can interfere with OpenShift SRE monitoring.`
)

var (
	log                         = logf.Log.WithName(WebhookName)
	privilegedServiceAccountsRe = regexp.MustCompile(privilegedServiceAccounts)
	privilegedUsersRe           = regexp.MustCompile(privilegedUsers)

	scope = admissionregv1.ClusterScope
	rules = []admissionregv1.RuleWithOperations{
		{
			Operations: []admissionregv1.OperationType{"CREATE", "UPDATE", "DELETE"},
			Rule: admissionregv1.Rule{
				APIGroups:   []string{"config.openshift.io"},
				APIVersions: []string{"*"},
				Resources:   []string{"ingresses"},
				Scope:       &scope,
			},
		},
	}
)

type IngressConfigWebhook struct {
	mu sync.Mutex
	s  runtime.Scheme
}

// Authorized will determine if the request is allowed
func (w *IngressConfigWebhook) Authorized(request admissionctl.Request) (ret admissionctl.Response) {
	ret = admissionctl.Denied("Only privileged service accounts may access")
	ret.UID = request.AdmissionRequest.UID

	// allow if modified by an allowlist-ed service account
	for _, group := range request.UserInfo.Groups {
		if privilegedServiceAccountsRe.Match([]byte(group)) {
			ret = admissionctl.Allowed("Privileged service accounts may access")
			ret.UID = request.AdmissionRequest.UID
		}
	}

	// allow if modified by an allowliste-ed user
	if privilegedUsersRe.Match([]byte(request.UserInfo.Username)) {
		ret = admissionctl.Allowed("Privileged service accounts may access")
		ret.UID = request.AdmissionRequest.UID
	}

	return
}

// GetURI returns the URI for the webhook
func (w *IngressConfigWebhook) GetURI() string { return "/ingressconfig-validation" }

// Validate will validate the incoming request
func (w *IngressConfigWebhook) Validate(req admissionctl.Request) bool {
	valid := true
	valid = valid && (req.UserInfo.Username != "")
	valid = valid && (req.Kind.Kind == "Ingress")

	return valid
}

// Name is the name of the webhook
func (w *IngressConfigWebhook) Name() string { return WebhookName }

// FailurePolicy is how the hook config should react if k8s can't access it
func (w *IngressConfigWebhook) FailurePolicy() admissionregv1.FailurePolicyType {
	return admissionregv1.Ignore
}

// MatchPolicy mirrors validatingwebhookconfiguration.webhooks[].matchPolicy
// If it is important to the webhook, be sure to check subResource vs
// requestSubResource.
func (w *IngressConfigWebhook) MatchPolicy() admissionregv1.MatchPolicyType {
	return admissionregv1.Equivalent
}

// Rules is a slice of rules on which this hook should trigger
func (w *IngressConfigWebhook) Rules() []admissionregv1.RuleWithOperations { return rules }

// ObjectSelector uses a *metav1.LabelSelector to augment the webhook's
// Rules() to match only on incoming requests which match the specific
// LabelSelector.
func (w *IngressConfigWebhook) ObjectSelector() *metav1.LabelSelector { return nil }

// SideEffects are what side effects, if any, this hook has. Refer to
// https://kubernetes.io/docs/reference/access-authn-authz/extensible-admission-controllers/#side-effects
func (w *IngressConfigWebhook) SideEffects() admissionregv1.SideEffectClass {
	return admissionregv1.SideEffectClassNone
}

// TimeoutSeconds returns an int32 representing how long to wait for this hook to complete
func (w *IngressConfigWebhook) TimeoutSeconds() int32 { return 2 }

// Doc returns a string for end-customer documentation purposes.
func (w *IngressConfigWebhook) Doc() string { return docString }

// SyncSetLabelSelector returns the label selector to use in the SyncSet.
// Return utils.DefaultLabelSelector() to stick with the default
func (w *IngressConfigWebhook) SyncSetLabelSelector() metav1.LabelSelector {
	return utils.DefaultLabelSelector()
}

func (w *IngressConfigWebhook) ClassicEnabled() bool { return true }

// HypershiftEnabled will return boolean value for hypershift enabled configurations
func (w *IngressConfigWebhook) HypershiftEnabled() bool { return true }

// NewWebhook creates a new webhook
func NewWebhook() *IngressConfigWebhook {
	scheme := runtime.NewScheme()
	err := admissionv1.AddToScheme(scheme)
	if err != nil {
		log.Error(err, "Fail adding admissionsv1 scheme to IngressConfigWebhook")
		os.Exit(1)
	}

	err = corev1.AddToScheme(scheme)
	if err != nil {
		log.Error(err, "Fail adding corev1 scheme to IngressConfigWebhook")
		os.Exit(1)
	}

	return &IngressConfigWebhook{
		s: *scheme,
	}
}
