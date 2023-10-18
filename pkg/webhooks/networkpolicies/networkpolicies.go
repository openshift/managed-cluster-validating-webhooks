package networkpolicies

import (
	"fmt"
	"net/http"
	"regexp"

	hookconfig "github.com/openshift/managed-cluster-validating-webhooks/pkg/config"
	"github.com/openshift/managed-cluster-validating-webhooks/pkg/webhooks/utils"

	admissionregv1 "k8s.io/api/admissionregistration/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	admissionctl "sigs.k8s.io/controller-runtime/pkg/webhook/admission"

	logf "sigs.k8s.io/controller-runtime/pkg/log"
)

const (
	WebhookName                    string = "networkpolicies-validation"
	docString                      string = `Managed OpenShift Customers may not create NetworkPolicies in namespaces managed by Red Hat.`
	privilegedServiceAccountGroups string = `^system:serviceaccounts:(kube.*|openshift.*|default|redhat.*|osde2e-[a-z0-9]{5})`
	managedNamespaces              string = `(^openshift-.*|kube-system)`
)

var (
	timeout                          int32 = 2
	allowedUsers                           = []string{"system:admin", "backplane-cluster-admin"}
	sreAdminGroups                         = []string{"system:serviceaccounts:openshift-backplane-srep"}
	privilegedServiceAccountGroupsRe       = regexp.MustCompile(privilegedServiceAccountGroups)
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
				Resources:   []string{"networkpolicy"},
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

// We just need a runtime object to get the namespace
type networkPolicy struct {
	runtime.Object
	metav1.ObjectMeta `json:"metadata,omitempty" protobuf:"bytes,1,opt,name=metadata"`
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

	if hookconfig.IsPrivilegedNamespace(np.GetNamespace()) {
		log.Info(fmt.Sprintf("%s operation detected on managed namespace: %s", request.Operation, np.GetNamespace()))
		if isAllowedUser(request) {
			ret = admissionctl.Allowed(fmt.Sprintf("User can do operations on NetworkPolicies"))
			ret.UID = request.AdmissionRequest.UID
			return ret
		}
		for _, group := range request.UserInfo.Groups {
			if privilegedServiceAccountGroupsRe.Match([]byte(group)) {
				ret = admissionctl.Allowed("Privileged service accounts do operations on NetworkPolicies")
				ret.UID = request.AdmissionRequest.UID
				return ret
			}
		}

		ret = admissionctl.Denied(fmt.Sprintf("Prevented from accessing Red Mat managed resources. This is in an effort to prevent harmful actions that may cause unintended consequences or affect the stability of the cluster. If you have any questions about this, please reach out to Red Hat support at https://access.redhat.com/support"))
		ret.UID = request.AdmissionRequest.UID
		return ret
	}

	log.Info("Allowing access", "request", request.AdmissionRequest)
	ret = admissionctl.Allowed("Non managed namespace")
	ret.UID = request.AdmissionRequest.UID
	return ret
}

// isclusterAdminUsers checks if the user or group is allowed to perform the action
func isAllowedUser(request admissionctl.Request) bool {
	if utils.SliceContains(request.UserInfo.Username, allowedUsers) {
		return true
	}

	for _, group := range sreAdminGroups {
		if utils.SliceContains(group, request.UserInfo.Groups) {
			return true
		}
	}

	return false
}

func (s *networkpoliciesruleWebhook) renderNetworkPolicy(req admissionctl.Request) (*networkPolicy, error) {
	decoder, err := admissionctl.NewDecoder(&s.s)
	if err != nil {
		return nil, err
	}
	networkPolicy := &networkPolicy{}

	if len(req.OldObject.Raw) > 0 {
		err = decoder.DecodeRaw(req.OldObject, networkPolicy)
	} else {
		err = decoder.Decode(req, networkPolicy)
	}
	if err != nil {
		return nil, err
	}
	return networkPolicy, nil
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

func (s *networkpoliciesruleWebhook) HypershiftEnabled() bool { return false }
