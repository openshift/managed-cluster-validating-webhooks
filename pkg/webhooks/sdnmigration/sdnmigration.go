package sdnmigration

import (
	"net/http"
	"regexp"

	configv1 "github.com/openshift/api/config/v1"
	admissionv1 "k8s.io/api/admission/v1"
	admissionregv1 "k8s.io/api/admissionregistration/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	admissionctl "sigs.k8s.io/controller-runtime/pkg/webhook/admission"

	"github.com/openshift/managed-cluster-validating-webhooks/pkg/webhooks/utils"
)

const (
	WebhookName               string = "sdn-migration-validation"
	privilegedServiceAccounts string = `^system:serviceaccounts:(kube.*|openshift.*|default|redhat.*|osde2e-[a-z0-9]{5})`
	docString                 string = `Managed OpenShift customers may not modify the network config type because it can can degrade cluster operators and can interfere with OpenShift SRE monitoring.`
	overrideAnnotation        string = "unsupported-red-hat-internal-testing"
)

var (
	log                         = logf.Log.WithName(WebhookName)
	privilegedServiceAccountsRe = regexp.MustCompile(privilegedServiceAccounts)

	scope = admissionregv1.ClusterScope
	rules = []admissionregv1.RuleWithOperations{
		{
			Operations: []admissionregv1.OperationType{"UPDATE"},
			Rule: admissionregv1.Rule{
				APIGroups:   []string{"config.openshift.io"},
				APIVersions: []string{"*"},
				Resources:   []string{"networks"},
				Scope:       &scope,
			},
		},
	}
)

type NetworkConfigWebhook struct {
	s runtime.Scheme
}

// Authorized will determine if the request is allowed
func (w *NetworkConfigWebhook) Authorized(request admissionctl.Request) admissionctl.Response {
	// allow if modified by an allow listed service account
	for _, group := range request.UserInfo.Groups {
		if privilegedServiceAccountsRe.Match([]byte(group)) {
			return utils.WebhookResponse(request, true, "Privileged service accounts may access")
		}
	}

	if request.Operation == admissionv1.Update {
		decoder, err := admissionctl.NewDecoder(&w.s)
		if err != nil {
			log.Error(err, "failed to initialize decoder")
			ret := admissionctl.Errored(http.StatusBadRequest, err)
			ret.UID = request.AdmissionRequest.UID
			return ret
		}

		object := &configv1.Network{}
		oldObject := &configv1.Network{}

		if err := decoder.Decode(request, object); err != nil {
			log.Error(err, "failed to render a Network from request.Object")
			ret := admissionctl.Errored(http.StatusBadRequest, err)
			ret.UID = request.AdmissionRequest.UID
			return ret
		}
		if err := decoder.DecodeRaw(request.OldObject, oldObject); err != nil {
			log.Error(err, "failed to render a Network from request.OldObject")
			ret := admissionctl.Errored(http.StatusBadRequest, err)
			ret.UID = request.AdmissionRequest.UID
			return ret
		}

		if v, ok := oldObject.Annotations[overrideAnnotation]; ok && v == "true" {
			return utils.WebhookResponse(request, true, "`red-hat-internal-testing: true` annotation present")
		}

		if object.Spec.NetworkType != oldObject.Status.NetworkType {
			return utils.WebhookResponse(request, false, "Changing the network type is not allowed")
		}

		return utils.WebhookResponse(request, true, "allowed action")
	}

	return utils.WebhookResponse(request, false, "Changing the network type is not allowed")
}

// GetURI returns the URI for the webhook
func (w *NetworkConfigWebhook) GetURI() string { return "/sdnmigration-validation" }

// Validate will validate the incoming request
func (w *NetworkConfigWebhook) Validate(req admissionctl.Request) bool {
	valid := true
	valid = valid && (req.UserInfo.Username != "")
	valid = valid && (req.Kind.Kind == "Network")

	return valid
}

// Name is the name of the webhook
func (w *NetworkConfigWebhook) Name() string { return WebhookName }

// FailurePolicy is how the hook config should react if k8s can't access it
func (w *NetworkConfigWebhook) FailurePolicy() admissionregv1.FailurePolicyType {
	return admissionregv1.Ignore
}

// MatchPolicy mirrors validatingwebhookconfiguration.webhooks[].matchPolicy
// If it is important to the webhook, be sure to check subResource vs
// requestSubResource.
func (w *NetworkConfigWebhook) MatchPolicy() admissionregv1.MatchPolicyType {
	return admissionregv1.Equivalent
}

// Rules is a slice of rules on which this hook should trigger
func (w *NetworkConfigWebhook) Rules() []admissionregv1.RuleWithOperations { return rules }

// ObjectSelector uses a *metav1.LabelSelector to augment the webhook's
// Rules() to match only on incoming requests which match the specific
// LabelSelector.
func (w *NetworkConfigWebhook) ObjectSelector() *metav1.LabelSelector { return nil }

// SideEffects are what side effects, if any, this hook has. Refer to
// https://kubernetes.io/docs/reference/access-authn-authz/extensible-admission-controllers/#side-effects
func (w *NetworkConfigWebhook) SideEffects() admissionregv1.SideEffectClass {
	return admissionregv1.SideEffectClassNone
}

// TimeoutSeconds returns an int32 representing how long to wait for this hook to complete
func (w *NetworkConfigWebhook) TimeoutSeconds() int32 { return 2 }

// Doc returns a string for end-customer documentation purposes.
func (w *NetworkConfigWebhook) Doc() string { return docString }

// SyncSetLabelSelector returns the label selector to use in the SyncSet.
// Return utils.DefaultLabelSelector() to stick with the default
func (w *NetworkConfigWebhook) SyncSetLabelSelector() metav1.LabelSelector {
	return utils.DefaultLabelSelector()
}

func (w *NetworkConfigWebhook) ClassicEnabled() bool { return true }

// HypershiftEnabled will return boolean value for hypershift enabled configurations
func (w *NetworkConfigWebhook) HypershiftEnabled() bool { return false }

// NewWebhook creates a new webhook
func NewWebhook() *NetworkConfigWebhook {
	scheme := runtime.NewScheme()

	return &NetworkConfigWebhook{
		s: *scheme,
	}
}
