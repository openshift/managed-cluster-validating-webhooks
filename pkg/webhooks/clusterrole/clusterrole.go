package clusterrole

import (
	"fmt"
	"net/http"
	"os"
	"slices"
	"strings"

	"github.com/openshift/managed-cluster-validating-webhooks/pkg/webhooks/utils"
	admissionv1 "k8s.io/api/admission/v1"
	admissionregv1 "k8s.io/api/admissionregistration/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	admissionctl "sigs.k8s.io/controller-runtime/pkg/webhook/admission"
)

const (
	WebhookName  string = "clusterroles-validation"
	docString    string = `Managed OpenShift Customers may not delete the cluster-admin ClusterRole`
)

var (
	timeout int32 = 2
	log           = logf.Log.WithName(WebhookName)
	scope         = admissionregv1.ClusterScope
	rules         = []admissionregv1.RuleWithOperations{
		{
			Operations: []admissionregv1.OperationType{"DELETE"},
			Rule: admissionregv1.Rule{
				APIGroups:   []string{"rbac.authorization.k8s.io"},
				APIVersions: []string{"v1"},
				Resources:   []string{"clusterroles"},
				Scope:       &scope,
			},
		},
	}

	// Protected ClusterRoles that should not be deleted
	protectedClusterRoles = []string{
		"cluster-admin",
		"view",
		"edit",
	}

	// Users allowed to delete protected ClusterRoles
	allowedUsers = []string{
		"backplane-cluster-admin",
	}

	// Groups allowed to delete protected ClusterRoles
	allowedGroups = []string{
		"system:serviceaccounts:openshift-backplane-srep",
	}
)

type ClusterRoleWebHook struct {
	s runtime.Scheme
}

// NewWebhook creates the new webhook
func NewWebhook() *ClusterRoleWebHook {
	scheme := runtime.NewScheme()
	err := admissionv1.AddToScheme(scheme)
	if err != nil {
		log.Error(err, "Fail adding admissionsv1 scheme to ClusterRoleWebHook")
		os.Exit(1)
	}
	err = corev1.AddToScheme(scheme)
	if err != nil {
		log.Error(err, "Fail adding corev1 scheme to ClusterRoleWebHook")
		os.Exit(1)
	}

	return &ClusterRoleWebHook{
		s: *scheme,
	}
}

// Authorized implements Webhook interface
func (s *ClusterRoleWebHook) Authorized(request admissionctl.Request) admissionctl.Response {
	return s.authorized(request)
}

func (s *ClusterRoleWebHook) authorized(request admissionctl.Request) admissionctl.Response {
	var ret admissionctl.Response

	if request.AdmissionRequest.UserInfo.Username == "system:unauthenticated" {
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

	clusterRole, err := s.renderClusterRole(request)
	if err != nil {
		log.Error(err, "Couldn't render a ClusterRole from the incoming request")
		return admissionctl.Errored(http.StatusBadRequest, err)
	}

	log.Info(fmt.Sprintf("Found clusterrole: %v", clusterRole.Name))

	if isProtectedClusterRole(clusterRole) && !isAllowedUserGroup(request) {
		switch request.Operation {
		case admissionv1.Delete:
			log.Info(fmt.Sprintf("Deleting operation detected on ClusterRole: %v", clusterRole.Name))

			ret = admissionctl.Denied(fmt.Sprintf("Deleting ClusterRole %v is not allowed", clusterRole.Name))
			ret.UID = request.AdmissionRequest.UID
			return ret
		}
	}

	ret = admissionctl.Allowed("Request is allowed")
	ret.UID = request.AdmissionRequest.UID
	return ret
}

// renderClusterRole renders the ClusterRole object from the request
func (s *ClusterRoleWebHook) renderClusterRole(request admissionctl.Request) (*rbacv1.ClusterRole, error) {
	decoder := admissionctl.NewDecoder(&s.s)
	clusterRole := &rbacv1.ClusterRole{}

	var err error
	if len(request.OldObject.Raw) > 0 {
		err = decoder.DecodeRaw(request.OldObject, clusterRole)
	}
	if err != nil {
		return nil, err
	}

	return clusterRole, nil
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

// isProtectedClusterRole returns true if the ClusterRole is in the protected list
func isProtectedClusterRole(clusterRole *rbacv1.ClusterRole) bool {
	return slices.Contains(protectedClusterRoles, clusterRole.Name)
}

// GetURI implements Webhook interface
func (s *ClusterRoleWebHook) GetURI() string {
	return "/" + WebhookName
}

// Validate implements Webhook interface
func (s *ClusterRoleWebHook) Validate(request admissionctl.Request) bool {
	valid := true
	valid = valid && (request.UserInfo.Username != "")
	valid = valid && (request.Kind.Kind == "ClusterRole")

	return valid
}

// Name implements Webhook interface
func (s *ClusterRoleWebHook) Name() string {
	return WebhookName
}

// FailurePolicy implements Webhook interface
func (s *ClusterRoleWebHook) FailurePolicy() admissionregv1.FailurePolicyType {
	return admissionregv1.Ignore
}

// MatchPolicy implements Webhook interface
func (s *ClusterRoleWebHook) MatchPolicy() admissionregv1.MatchPolicyType {
	return admissionregv1.Equivalent
}

// Rules implements Webhook interface
func (s *ClusterRoleWebHook) Rules() []admissionregv1.RuleWithOperations {
	return rules
}

// ObjectSelector implements Webhook interface
func (s *ClusterRoleWebHook) ObjectSelector() *metav1.LabelSelector {
	return nil
}

// SideEffects implements Webhook interface
func (s *ClusterRoleWebHook) SideEffects() admissionregv1.SideEffectClass {
	return admissionregv1.SideEffectClassNone
}

// TimeoutSeconds implements Webhook interface
func (s *ClusterRoleWebHook) TimeoutSeconds() int32 {
	return timeout
}

// Doc implements Webhook interface
func (s *ClusterRoleWebHook) Doc() string {
	return docString
}

// SyncSetLabelSelector returns the label selector to use in the SyncSet.
// Return utils.DefaultLabelSelector() to stick with the default
func (s *ClusterRoleWebHook) SyncSetLabelSelector() metav1.LabelSelector {
	return utils.DefaultLabelSelector()
}

func (s *ClusterRoleWebHook) ClassicEnabled() bool { return true }

func (s *ClusterRoleWebHook) HypershiftEnabled() bool { return true }
