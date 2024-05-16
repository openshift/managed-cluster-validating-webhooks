package serviceaccount

import (
	"fmt"
	"net/http"
	"os"
	"slices"
	"strings"

	admissionv1 "k8s.io/api/admission/v1"
	admissionregv1 "k8s.io/api/admissionregistration/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	admissionctl "sigs.k8s.io/controller-runtime/pkg/webhook/admission"

	"github.com/openshift/managed-cluster-validating-webhooks/pkg/config"
	"github.com/openshift/managed-cluster-validating-webhooks/pkg/webhooks/utils"
)

const (
	WebhookName string = "serviceaccount-validation"
	docString   string = `Managed OpenShift Customers may not delete the service accounts under the managed namespaces。`
)

var (
	timeout int32 = 2
	log           = logf.Log.WithName(WebhookName)
	scope         = admissionregv1.NamespacedScope
	rules         = []admissionregv1.RuleWithOperations{
		{
			Operations: []admissionregv1.OperationType{"DELETE"},
			Rule: admissionregv1.Rule{
				APIGroups:   []string{""},
				APIVersions: []string{"v1"},
				Resources:   []string{"serviceaccounts"},
				Scope:       &scope,
			},
		},
	}
	allowedUsers = []string{
		"backplane-cluster-admin",
	}
	allowedGroups = []string{
		"system:serviceaccounts:openshift-backplane-srep",
	}
	allowedServiceAccounts = []string{
		"builder",
		"default",
		"deployer",
	}
	exceptionNamespaces = []string{
		"openshift-logging",
		"openshift-user-workload-monitoring",
		"openshift-operators",
	}
)

type serviceAccountWebhook struct {
	s runtime.Scheme
}

// NewWebhook creates the new webhook
func NewWebhook() *serviceAccountWebhook {
	scheme := runtime.NewScheme()
	err := admissionv1.AddToScheme(scheme)
	if err != nil {
		log.Error(err, "Fail adding admissionsv1 scheme to serviceAccountWebhook")
		os.Exit(1)
	}
	err = corev1.AddToScheme(scheme)
	if err != nil {
		log.Error(err, "Fail adding corev1 scheme to serviceAccountWebhook")
		os.Exit(1)
	}

	return &serviceAccountWebhook{
		s: *scheme,
	}
}

// Authorized implements Webhook interface
func (s *serviceAccountWebhook) Authorized(request admissionctl.Request) admissionctl.Response {
	return s.authorized(request)
}

func (s *serviceAccountWebhook) authorized(request admissionctl.Request) admissionctl.Response {
	var ret admissionctl.Response

	if request.AdmissionRequest.UserInfo.Username == "system:unauthenticated" {
		// This could highlight a significant problem with RBAC since an
		// unauthenticated user should have no permissions.
		log.Info("system:unauthenticated made a webhook request. Check RBAC rules", "request", request.AdmissionRequest)
		ret = admissionctl.Denied("Unauthenticated")
		ret.UID = request.AdmissionRequest.UID
		return ret
	}
	if strings.HasPrefix(request.AdmissionRequest.UserInfo.Username, "system:") {
		ret = admissionctl.Allowed("authenticated system: users are allowed")
		ret.UID = request.AdmissionRequest.UID
		return ret
	}
	if strings.HasPrefix(request.AdmissionRequest.UserInfo.Username, "kube:") {
		ret = admissionctl.Allowed("kube: users are allowed")
		ret.UID = request.AdmissionRequest.UID
		return ret
	}

	sa, err := s.renderServiceAccount(request)
	if err != nil {
		log.Error(err, "Couldn't render a service account from the incoming request")
		return admissionctl.Errored(http.StatusBadRequest, err)
	}

	if isProtectedNamespace(request) && !isAllowedUserGroup(request) {
		if request.Operation == admissionv1.Delete && !isAllowedServiceAccount(sa) {
			log.Info(fmt.Sprintf("Deleting operation detected on proteced serviceaccount: %v", sa.Name))
			ret = admissionctl.Denied(fmt.Sprintf("Deleting protected service account under namespace %v is not allowed", request.Namespace))
			ret.UID = request.AdmissionRequest.UID
			return ret
		}
	}

	ret = admissionctl.Allowed("Request is allowed")
	ret.UID = request.AdmissionRequest.UID
	return ret
}

// renderServiceAccount render the serviceaccount object from the requests
func (s *serviceAccountWebhook) renderServiceAccount(request admissionctl.Request) (*corev1.ServiceAccount, error) {
	decoder, err := admissionctl.NewDecoder(&s.s)
	if err != nil {
		return nil, err
	}
	sa := &corev1.ServiceAccount{}

	if len(request.OldObject.Raw) > 0 {
		err = decoder.DecodeRaw(request.OldObject, sa)
	}
	if err != nil {
		return nil, err
	}

	return sa, nil
}

// isAllowedUserGroup checks if the user or group is allowed to perform the action
func isAllowedUserGroup(request admissionctl.Request) bool {
	if slices.Contains(allowedUsers, request.UserInfo.Username) {
		return true
	}

	for _, group := range allowedGroups {
		if slices.Contains(request.UserInfo.Groups, group) {
			return true
		}
	}

	return false
}

// isProtectedNamespace checks if the request is going to operate on the serviceaccount in the
// protected namespace list
func isProtectedNamespace(request admissionctl.Request) bool {
	ns := request.Namespace

	if config.IsPrivilegedNamespace(ns) && !slices.Contains(exceptionNamespaces, ns) {
		return true
	}
	return false
}

func isAllowedServiceAccount(sa *corev1.ServiceAccount) bool {
	for _, s := range allowedServiceAccounts {
		if sa.Name == s {
			return true
		}
	}

	return false
}

// GetURI implements Webhook interface
func (s *serviceAccountWebhook) GetURI() string {
	return "/" + WebhookName
}

// Validate implements Webhook interface
func (s *serviceAccountWebhook) Validate(request admissionctl.Request) bool {
	valid := true
	valid = valid && (request.UserInfo.Username != "")
	valid = valid && (request.Kind.Kind == "ServiceAccount")

	return valid
}

// Name implements Webhook interface
func (s *serviceAccountWebhook) Name() string {
	return WebhookName
}

// FailurePolicy implements Webhook interface
func (s *serviceAccountWebhook) FailurePolicy() admissionregv1.FailurePolicyType {
	return admissionregv1.Ignore
}

// MatchPolicy implements Webhook interface
func (s *serviceAccountWebhook) MatchPolicy() admissionregv1.MatchPolicyType {
	return admissionregv1.Equivalent
}

// Rules implements Webhook interface
func (s *serviceAccountWebhook) Rules() []admissionregv1.RuleWithOperations {
	return rules
}

// ObjectSelector implements Webhook interface
func (s *serviceAccountWebhook) ObjectSelector() *metav1.LabelSelector {
	return nil
}

// SideEffects implements Webhook interface
func (s *serviceAccountWebhook) SideEffects() admissionregv1.SideEffectClass {
	return admissionregv1.SideEffectClassNone
}

// TimeoutSeconds implements Webhook interface
func (s *serviceAccountWebhook) TimeoutSeconds() int32 {
	return timeout
}

// Doc implements Webhook interface
func (s *serviceAccountWebhook) Doc() string {
	return fmt.Sprintf(docString)
}

// SyncSetLabelSelector returns the label selector to use in the SyncSet.
// Return utils.DefaultLabelSelector() to stick with the default
func (s *serviceAccountWebhook) SyncSetLabelSelector() metav1.LabelSelector {
	return utils.DefaultLabelSelector()
}

func (s *serviceAccountWebhook) ClassicEnabled() bool { return true }

func (s *serviceAccountWebhook) HypershiftEnabled() bool { return true }
