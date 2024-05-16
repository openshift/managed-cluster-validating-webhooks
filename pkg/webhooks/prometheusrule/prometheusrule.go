package prometheusrule

import (
	"fmt"
	"net/http"
	"regexp"
	"slices"

	hookconfig "github.com/openshift/managed-cluster-validating-webhooks/pkg/config"
	"github.com/openshift/managed-cluster-validating-webhooks/pkg/webhooks/utils"

	admissionregv1 "k8s.io/api/admissionregistration/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	admissionctl "sigs.k8s.io/controller-runtime/pkg/webhook/admission"

	logf "sigs.k8s.io/controller-runtime/pkg/log"
)

const (
	WebhookName                    string = "prometheusrule-validation"
	docString                      string = `Managed OpenShift Customers may not create PrometheusRule in namespaces managed by Red Hat.`
	privilegedServiceAccountGroups string = `^system:serviceaccounts:(kube.*|openshift.*|default|redhat.*|osde2e-[a-z0-9]{5})`
)

var (
	timeout                          int32 = 2
	allowedUsers                           = []string{"kube:admin", "system:admin", "backplane-cluster-admin"}
	sreAdminGroups                         = []string{"system:serviceaccounts:openshift-backplane-srep"}
	privilegedServiceAccountGroupsRe       = regexp.MustCompile(privilegedServiceAccountGroups)
	privilegedLabels                       = map[string]string{"app.kubernetes.io/name": "stackrox"}
	scope                                  = admissionregv1.NamespacedScope
	rules                                  = []admissionregv1.RuleWithOperations{
		{
			Operations: []admissionregv1.OperationType{
				admissionregv1.Create,
				admissionregv1.Update,
				admissionregv1.Delete,
			},
			Rule: admissionregv1.Rule{
				APIGroups:   []string{"monitoring.coreos.com"},
				APIVersions: []string{"*"},
				Resources:   []string{"prometheusrules"},
				Scope:       &scope,
			},
		},
	}
	log = logf.Log.WithName(WebhookName)
)

// prometheusruleWebhook validates a prometheusRule change
type prometheusruleWebhook struct {
	s runtime.Scheme
}

// We just need a runtime object to get the namespace
type prometheusRule struct {
	runtime.Object
	metav1.ObjectMeta `json:"metadata,omitempty" protobuf:"bytes,1,opt,name=metadata"`
}

// NewWebhook creates the new webhook
func NewWebhook() *prometheusruleWebhook {
	scheme := runtime.NewScheme()
	return &prometheusruleWebhook{
		s: *scheme,
	}
}

// Authorized implements Webhook interface
func (s *prometheusruleWebhook) Authorized(request admissionctl.Request) admissionctl.Response {
	return s.authorized(request)
}

func (s *prometheusruleWebhook) authorized(request admissionctl.Request) admissionctl.Response {
	var ret admissionctl.Response

	pr, err := s.renderPrometheusRule(request)
	if err != nil {
		log.Error(err, "Couldn't render a PrometheusRule from the incoming request")
		return admissionctl.Errored(http.StatusBadRequest, err)
	}

	if hookconfig.IsPrivilegedNamespace(pr.GetNamespace()) &&
		// TODO: [OSD-13680] Remove this exception for openshift-customer-monitoring
		pr.GetNamespace() != "openshift-customer-monitoring" &&
		pr.GetNamespace() != "openshift-user-workload-monitoring" &&
		// TODO: [OSD-13909] Remove this exception for openshift-monitoring
		pr.GetNamespace() != "openshift-monitoring" {
		log.Info(fmt.Sprintf("%s operation detected on managed namespace: %s", request.Operation, pr.GetNamespace()))
		if isAllowedUser(request) {
			ret = admissionctl.Allowed(fmt.Sprintf("User can do operations on PrometheusRules"))
			ret.UID = request.AdmissionRequest.UID
			return ret
		}
		for _, group := range request.UserInfo.Groups {
			if privilegedServiceAccountGroupsRe.Match([]byte(group)) {
				ret = admissionctl.Allowed("Privileged service accounts do operations on PrometheusRules")
				ret.UID = request.AdmissionRequest.UID
				return ret
			}
		}

		// TODO: [OSD-20025] Remove this exception after MON-3518 is completed
		if hasPrivilegedLabel(pr) {
			ret = admissionctl.Allowed("PrometheusRules with privileged labels can be modified")
			ret.UID = request.AdmissionRequest.UID
			return ret
		}

		ret = admissionctl.Denied(fmt.Sprintf("Prevented from accessing Red Hat managed resources. This is in an effort to prevent harmful actions that may cause unintended consequences or affect the stability of the cluster. If you have any questions about this, please reach out to Red Hat support at https://access.redhat.com/support"))
		ret.UID = request.AdmissionRequest.UID
		return ret
	}

	log.Info("Allowing access")
	ret = admissionctl.Allowed("Non managed namespace")
	ret.UID = request.AdmissionRequest.UID
	return ret
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

// hasPrivilegedLabel checks if the rendered rule's labels match one of the privilegedLabels
func hasPrivilegedLabel(rule *prometheusRule) bool {
	for key, val := range privilegedLabels {
		if rule.Labels[key] == val {
			return true
		}
	}
	return false
}

// GetURI implements Webhook interface
func (s *prometheusruleWebhook) GetURI() string {
	return "/" + WebhookName
}

// Validate implements Webhook interface
func (s *prometheusruleWebhook) Validate(request admissionctl.Request) bool {
	valid := true
	valid = valid && (request.UserInfo.Username != "")
	valid = valid && (request.Kind.Kind == "PrometheusRule")

	return valid
}
func (s *prometheusruleWebhook) renderPrometheusRule(req admissionctl.Request) (*prometheusRule, error) {
	decoder, err := admissionctl.NewDecoder(&s.s)
	if err != nil {
		return nil, err
	}
	prometheusRule := &prometheusRule{}

	if len(req.OldObject.Raw) > 0 {
		err = decoder.DecodeRaw(req.OldObject, prometheusRule)
	} else {
		err = decoder.Decode(req, prometheusRule)
	}
	if err != nil {
		return nil, err
	}
	return prometheusRule, nil
}

// Name implements Webhook interface
func (s *prometheusruleWebhook) Name() string {
	return WebhookName
}

// FailurePolicy implements Webhook interface
func (s *prometheusruleWebhook) FailurePolicy() admissionregv1.FailurePolicyType {
	return admissionregv1.Ignore
}

// MatchPolicy implements Webhook interface
func (s *prometheusruleWebhook) MatchPolicy() admissionregv1.MatchPolicyType {
	return admissionregv1.Equivalent
}

// Rules implements Webhook interface
func (s *prometheusruleWebhook) Rules() []admissionregv1.RuleWithOperations {
	return rules
}

// ObjectSelector implements Webhook interface
func (s *prometheusruleWebhook) ObjectSelector() *metav1.LabelSelector {
	return nil
}

// SideEffects implements Webhook interface
func (s *prometheusruleWebhook) SideEffects() admissionregv1.SideEffectClass {
	return admissionregv1.SideEffectClassNone
}

// TimeoutSeconds implements Webhook interface
func (s *prometheusruleWebhook) TimeoutSeconds() int32 {
	return timeout
}

// Doc implements Webhook interface
func (s *prometheusruleWebhook) Doc() string {
	return (docString)
}

// SyncSetLabelSelector returns the label selector to use in the SyncSet.
// Return utils.DefaultLabelSelector() to stick with the default
func (s *prometheusruleWebhook) SyncSetLabelSelector() metav1.LabelSelector {
	return utils.DefaultLabelSelector()
}

func (s *prometheusruleWebhook) ClassicEnabled() bool { return true }

func (s *prometheusruleWebhook) HypershiftEnabled() bool { return false }
