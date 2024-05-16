package customresourcedefinitions

import (
	"fmt"
	"net/http"
	"regexp"
	"slices"
	"strings"

	"github.com/openshift/managed-cluster-validating-webhooks/pkg/webhooks/utils"

	admissionregv1 "k8s.io/api/admissionregistration/v1"
	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	admissionctl "sigs.k8s.io/controller-runtime/pkg/webhook/admission"
)

const (
	WebhookName string = "customresourcedefinitions-validation"
	docString   string = `Managed OpenShift Customers may not change CustomResourceDefinitions managed by Red Hat.`
)

var (
	timeout                          int32 = 2
	allowedUsers                           = []string{"system:admin", "backplane-cluster-admin"}
	sreAdminGroups                         = []string{"system:serviceaccounts:openshift-backplane-srep"}
	privilegedServiceAccountGroupsRe       = regexp.MustCompile(utils.PrivilegedServiceAccountGroups)
	scope                                  = admissionregv1.ClusterScope
	rules                                  = []admissionregv1.RuleWithOperations{
		{
			Operations: []admissionregv1.OperationType{
				admissionregv1.Create,
				admissionregv1.Update,
				admissionregv1.Delete,
			},
			Rule: admissionregv1.Rule{
				APIGroups:   []string{"apiextensions.k8s.io"},
				APIVersions: []string{"*"},
				Resources:   []string{"customresourcedefinitions"},
				Scope:       &scope,
			},
		},
	}
	log = logf.Log.WithName(WebhookName)
)

// customresourcedefinitionsruleWebhook validates a customresourcedefinition change
type customresourcedefinitionsruleWebhook struct {
	s runtime.Scheme
}

// NewWebhook creates the new webhook
func NewWebhook() *customresourcedefinitionsruleWebhook {
	scheme := runtime.NewScheme()
	return &customresourcedefinitionsruleWebhook{
		s: *scheme,
	}
}

// Authorized implements Webhook interface
func (s *customresourcedefinitionsruleWebhook) Authorized(request admissionctl.Request) admissionctl.Response {
	//Implement authorized next
	return s.authorized(request)
}

func (s *customresourcedefinitionsruleWebhook) authorized(request admissionctl.Request) admissionctl.Response {
	var ret admissionctl.Response

	crd, err := s.renderCustomResourceDefinition(request)
	if err != nil {
		log.Error(err, "Could not render a CustomResourceDefinition from the incoming request")
		return admissionctl.Errored(http.StatusBadRequest, err)
	}

	if utils.IsProtectedByResourceName(crd.GetName()) {
		log.Info(fmt.Sprintf("%s operation detected on protected CustomResourceDefinition: %s", request.Operation, crd.Name))
		if isAllowedUser(request) {
			ret = admissionctl.Allowed(fmt.Sprintf("User '%s' in group(s) '%s' can operate on CustomResourceDefinitions", request.UserInfo.Username, strings.Join(request.UserInfo.Groups, ", ")))
			ret.UID = request.AdmissionRequest.UID
			return ret
		}
		for _, group := range request.UserInfo.Groups {
			if privilegedServiceAccountGroupsRe.Match([]byte(group)) {
				ret = admissionctl.Allowed(fmt.Sprintf("Privileged service accounts in group(s) '%s' can operate on CustomResourceDefinitions", strings.Join(request.UserInfo.Groups, ", ")))
				ret.UID = request.AdmissionRequest.UID
				return ret
			}
		}

		ret = admissionctl.Denied(fmt.Sprintf("User '%s' prevented from accessing Red Mat managed resources. This is in an effort to prevent harmful actions that may cause unintended consequences or affect the stability of the cluster. If you have any questions about this, please reach out to Red Hat support at https://access.redhat.com/support", request.UserInfo.Username))
		ret.UID = request.AdmissionRequest.UID
		return ret
	}

	log.Info("Allowing access", "request", request.AdmissionRequest)
	ret = admissionctl.Allowed("Non managed CustomResourceDefinition")
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

func (s *customresourcedefinitionsruleWebhook) renderCustomResourceDefinition(req admissionctl.Request) (*apiextensionsv1.CustomResourceDefinition, error) {
	decoder, err := admissionctl.NewDecoder(&s.s)
	if err != nil {
		return nil, err
	}
	customResourceDefinition := &apiextensionsv1.CustomResourceDefinition{}

	if len(req.OldObject.Raw) > 0 {
		err = decoder.DecodeRaw(req.OldObject, customResourceDefinition)
	} else {
		err = decoder.Decode(req, customResourceDefinition)
	}
	if err != nil {
		return nil, err
	}
	return customResourceDefinition, nil
}

// GetURI implements Webhook interface
func (s *customresourcedefinitionsruleWebhook) GetURI() string {
	return "/" + WebhookName
}

// Validate implements Webhook interface
func (s *customresourcedefinitionsruleWebhook) Validate(request admissionctl.Request) bool {
	valid := true
	valid = valid && (request.UserInfo.Username != "")
	valid = valid && (request.Kind.Kind == "CustomResourceDefinition")

	return valid
}

// Name implements Webhook interface
func (s *customresourcedefinitionsruleWebhook) Name() string {
	return WebhookName
}

// FailurePolicy implements Webhook interface
func (s *customresourcedefinitionsruleWebhook) FailurePolicy() admissionregv1.FailurePolicyType {
	return admissionregv1.Ignore
}

// MatchPolicy implements Webhook interface
func (s *customresourcedefinitionsruleWebhook) MatchPolicy() admissionregv1.MatchPolicyType {
	return admissionregv1.Equivalent
}

// Rules implements Webhook interface
func (s *customresourcedefinitionsruleWebhook) Rules() []admissionregv1.RuleWithOperations {
	return rules
}

// ObjectSelector implements Webhook interface
func (s *customresourcedefinitionsruleWebhook) ObjectSelector() *metav1.LabelSelector {
	return nil
}

// SideEffects implements Webhook interface
func (s *customresourcedefinitionsruleWebhook) SideEffects() admissionregv1.SideEffectClass {
	return admissionregv1.SideEffectClassNone
}

// TimeoutSeconds implements Webhook interface
func (s *customresourcedefinitionsruleWebhook) TimeoutSeconds() int32 {
	return timeout
}

// Doc implements Webhook interface
func (s *customresourcedefinitionsruleWebhook) Doc() string {
	return (docString)
}

// SyncSetLabelSelector returns the label selector to use in the SyncSet.
// Return utils.DefaultLabelSelector() to stick with the default
func (s *customresourcedefinitionsruleWebhook) SyncSetLabelSelector() metav1.LabelSelector {
	return utils.DefaultLabelSelector()
}

func (s *customresourcedefinitionsruleWebhook) ClassicEnabled() bool { return true }

func (s *customresourcedefinitionsruleWebhook) HypershiftEnabled() bool { return false }
