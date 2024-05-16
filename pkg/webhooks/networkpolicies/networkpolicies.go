package networkpolicies

import (
	"fmt"
	"net/http"
	"regexp"
	"slices"
	"strings"

	hookconfig "github.com/openshift/managed-cluster-validating-webhooks/pkg/config"
	"github.com/openshift/managed-cluster-validating-webhooks/pkg/webhooks/utils"

	admissionregv1 "k8s.io/api/admissionregistration/v1"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	admissionctl "sigs.k8s.io/controller-runtime/pkg/webhook/admission"
)

const (
	WebhookName string = "networkpolicies-validation"
	docString   string = `Managed OpenShift Customers may not create NetworkPolicies in namespaces managed by Red Hat.`
)

var (
	timeout                          int32 = 2
	allowedUsers                           = []string{"system:admin", "backplane-cluster-admin"}
	sreAdminGroups                         = []string{"system:serviceaccounts:openshift-backplane-srep"}
	privilegedServiceAccountGroupsRe       = regexp.MustCompile(utils.PrivilegedServiceAccountGroups)
	scope                                  = admissionregv1.NamespacedScope
	rules                                  = []admissionregv1.RuleWithOperations{
		{
			Operations: []admissionregv1.OperationType{
				admissionregv1.Create,
				admissionregv1.Update,
				admissionregv1.Delete,
			},
			Rule: admissionregv1.Rule{
				APIGroups:   []string{"networking.k8s.io"},
				APIVersions: []string{"*"},
				Resources:   []string{"networkpolicies"},
				Scope:       &scope,
			},
		},
	}
	log = logf.Log.WithName(WebhookName)
)

// networkpoliciesruleWebhook validates a networkpolicy change
type networkpoliciesruleWebhook struct {
	s runtime.Scheme
}

// NewWebhook creates the new webhook
func NewWebhook() *networkpoliciesruleWebhook {
	scheme := runtime.NewScheme()
	return &networkpoliciesruleWebhook{
		s: *scheme,
	}
}

// Authorized implements Webhook interface
func (s *networkpoliciesruleWebhook) Authorized(request admissionctl.Request) admissionctl.Response {
	//Implement authorized next
	return s.authorized(request)
}

func (s *networkpoliciesruleWebhook) authorized(request admissionctl.Request) admissionctl.Response {
	var ret admissionctl.Response

	np, err := s.renderNetworkPolicy(request)
	if err != nil {
		log.Error(err, "Could not render a NetworkPolicy from the incoming request")
		return admissionctl.Errored(http.StatusBadRequest, err)
	}

	if !isAllowedNamespace(np.GetNamespace()) {
		log.Info(fmt.Sprintf("%s operation detected on managed namespace: %s", request.Operation, np.GetNamespace()))
		if isAllowedUser(request) {
			ret = admissionctl.Allowed(fmt.Sprintf("User '%s' in group(s) '%s' can operate on NetworkPolicies", request.UserInfo.Username, strings.Join(request.UserInfo.Groups, ", ")))
			ret.UID = request.AdmissionRequest.UID
			return ret
		}
		for _, group := range request.UserInfo.Groups {
			if privilegedServiceAccountGroupsRe.Match([]byte(group)) {
				ret = admissionctl.Allowed(fmt.Sprintf("Privileged service accounts in group(s) '%s' can operate on NetworkPolicies", strings.Join(request.UserInfo.Groups, ", ")))
				ret.UID = request.AdmissionRequest.UID
				return ret
			}
		}

		ret = admissionctl.Denied(fmt.Sprintf("User '%s' prevented from accessing Red Mat managed resources. This is in an effort to prevent harmful actions that may cause unintended consequences or affect the stability of the cluster. If you have any questions about this, please reach out to Red Hat support at https://access.redhat.com/support", request.UserInfo.Username))
		ret.UID = request.AdmissionRequest.UID
		return ret
	}

	if np.GetNamespace() == "openshift-ingress" {
		ingressName, labelFound := np.Spec.PodSelector.MatchLabels["ingresscontroller.operator.openshift.io/deployment-ingresscontroller"]
		if !labelFound || ingressName == "default" {
			ret = admissionctl.Denied(fmt.Sprintf("User '%s' prevented from creating network policy that may impact default ingress, which is managed by Red Hat. This is in an effort to prevent harmful actions that may cause unintended consequences or affect the stability of the cluster. If you have any questions about this, please reach out to Red Hat support at https://access.redhat.com/support", request.UserInfo.Username))
			ret.UID = request.AdmissionRequest.UID
			return ret
		}
	}

	log.Info("Allowing access", "request", request.AdmissionRequest)
	ret = admissionctl.Allowed("Non managed namespace")
	ret.UID = request.AdmissionRequest.UID
	return ret
}

// isAllowedNamespace checks if the namespace is excluded from this webhook
func isAllowedNamespace(namespace string) bool {
	return !hookconfig.IsPrivilegedNamespace(namespace) || namespace == "openshift-ingress"
}

// isAllowedUser checks if the user or group is allowed to perform the action
func isAllowedUser(request admissionctl.Request) bool {
	if slices.Contains(allowedUsers, request.UserInfo.Username) {
		return true
	}

	for _, group := range sreAdminGroups {
		if slices.Contains(request.UserInfo.Groups, group) {
			return true
		}
	}

	return false
}

func (s *networkpoliciesruleWebhook) renderNetworkPolicy(req admissionctl.Request) (*networkingv1.NetworkPolicy, error) {
	decoder, err := admissionctl.NewDecoder(&s.s)
	if err != nil {
		return nil, err
	}
	networkPolicy := &networkingv1.NetworkPolicy{}

	if len(req.Object.Raw) > 0 {
		err = decoder.DecodeRaw(req.Object, networkPolicy)
		return networkPolicy, err
	}
	err = decoder.DecodeRaw(req.OldObject, networkPolicy)
	return networkPolicy, err
}

// GetURI implements Webhook interface
func (s *networkpoliciesruleWebhook) GetURI() string {
	return "/" + WebhookName
}

// Validate implements Webhook interface
func (s *networkpoliciesruleWebhook) Validate(request admissionctl.Request) bool {
	valid := true
	valid = valid && (request.UserInfo.Username != "")
	valid = valid && (request.Kind.Kind == "NetworkPolicy")

	return valid
}

// Name implements Webhook interface
func (s *networkpoliciesruleWebhook) Name() string {
	return WebhookName
}

// FailurePolicy implements Webhook interface
func (s *networkpoliciesruleWebhook) FailurePolicy() admissionregv1.FailurePolicyType {
	return admissionregv1.Ignore
}

// MatchPolicy implements Webhook interface
func (s *networkpoliciesruleWebhook) MatchPolicy() admissionregv1.MatchPolicyType {
	return admissionregv1.Equivalent
}

// Rules implements Webhook interface
func (s *networkpoliciesruleWebhook) Rules() []admissionregv1.RuleWithOperations {
	return rules
}

// ObjectSelector implements Webhook interface
func (s *networkpoliciesruleWebhook) ObjectSelector() *metav1.LabelSelector {
	return nil
}

// SideEffects implements Webhook interface
func (s *networkpoliciesruleWebhook) SideEffects() admissionregv1.SideEffectClass {
	return admissionregv1.SideEffectClassNone
}

// TimeoutSeconds implements Webhook interface
func (s *networkpoliciesruleWebhook) TimeoutSeconds() int32 {
	return timeout
}

// Doc implements Webhook interface
func (s *networkpoliciesruleWebhook) Doc() string {
	return (docString)
}

// SyncSetLabelSelector returns the label selector to use in the SyncSet.
// Return utils.DefaultLabelSelector() to stick with the default
func (s *networkpoliciesruleWebhook) SyncSetLabelSelector() metav1.LabelSelector {
	return utils.DefaultLabelSelector()
}

func (s *networkpoliciesruleWebhook) ClassicEnabled() bool { return true }

func (s *networkpoliciesruleWebhook) HypershiftEnabled() bool { return false }
