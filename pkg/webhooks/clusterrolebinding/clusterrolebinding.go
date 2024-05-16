package clusterrolebinding

import (
	"fmt"
	"net/http"
	"os"
	"regexp"
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
	WebhookName       string = "clusterrolebindings-validation"
	docString         string = `Managed OpenShift Customers may not delete the cluster role bindings under the managed namespaces: %s`
	managedNamespaces string = `(^openshift-.*|kube-system)`
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
				Resources:   []string{"clusterrolebindings"},
				Scope:       &scope,
			},
		},
	}

	protectedNamespaces = regexp.MustCompile(managedNamespaces)

	exceptionNamespaces = []string{
		"openshift-logging",
		"openshift-user-workload-monitoring",
		"openshift-operators",
		"openshift-backplane-managed-scripts",
		"openshift-gitops",
	}

	allowedUsers = []string{
		"backplane-cluster-admin",
	}
	allowedGroups = []string{
		"system:serviceaccounts:openshift-backplane-srep",
	}
)

type ClusterRoleBindingWebHook struct {
	s runtime.Scheme
}

// NewWebhook creates the new webhook
func NewWebhook() *ClusterRoleBindingWebHook {
	scheme := runtime.NewScheme()
	err := admissionv1.AddToScheme(scheme)
	if err != nil {
		log.Error(err, "Fail adding admissionsv1 scheme to ClusterRoleBindingWebHook")
		os.Exit(1)
	}
	err = corev1.AddToScheme(scheme)
	if err != nil {
		log.Error(err, "Fail adding corev1 scheme to ClusterRoleBindingWebHook")
		os.Exit(1)
	}

	return &ClusterRoleBindingWebHook{
		s: *scheme,
	}
}

// Authorized implements Webhook interface
func (s *ClusterRoleBindingWebHook) Authorized(request admissionctl.Request) admissionctl.Response {
	return s.authorized(request)
}

func (s *ClusterRoleBindingWebHook) authorized(request admissionctl.Request) admissionctl.Response {
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

	clusterRoleBinding, err := s.renderClusterRoleBinding(request)
	if err != nil {
		log.Error(err, "Couldn't render a ClusterRoleBinding from the incoming request")
		return admissionctl.Errored(http.StatusBadRequest, err)
	}

	log.Info(fmt.Sprintf("Found clusterrolebinding: %v", clusterRoleBinding.Name))

	if isProtectedNamespace(clusterRoleBinding) && !isAllowedUserGroup(request) {
		switch request.Operation {
		case admissionv1.Delete:
			log.Info(fmt.Sprintf("Deleting operation detected on ClusterRoleBinding: %v", clusterRoleBinding.Name))

			annotations := clusterRoleBinding.GetObjectMeta().GetAnnotations()
			if annotations["oc.openshift.io/command"] == "oc adm must-gather" && request.AdmissionRequest.UserInfo.Username == "cluster-admin" {
				ret = admissionctl.Allowed("cluster-admin: cluster-admin may manage must-gather resources")
				ret.UID = request.AdmissionRequest.UID
				return ret
			}

			ret = admissionctl.Denied(fmt.Sprintf("Deleting ClusterRoleBinding %v is not allowed", clusterRoleBinding.Name))
			ret.UID = request.AdmissionRequest.UID
			return ret
		}
	}

	ret = admissionctl.Allowed("Request is allowed")
	ret.UID = request.AdmissionRequest.UID
	return ret
}

// renderSCC render the SCC object from the requests
func (s *ClusterRoleBindingWebHook) renderClusterRoleBinding(request admissionctl.Request) (*rbacv1.ClusterRoleBinding, error) {
	decoder, err := admissionctl.NewDecoder(&s.s)
	if err != nil {
		return nil, err
	}
	clusterRoleBinding := &rbacv1.ClusterRoleBinding{}

	if len(request.OldObject.Raw) > 0 {
		err = decoder.DecodeRaw(request.OldObject, clusterRoleBinding)
	}
	if err != nil {
		return nil, err
	}

	return clusterRoleBinding, nil
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

// isProtectedNamespace returns true if clusterRoleBinding subject link
// to ServiceAccount and openshift-*|kube-system ns
func isProtectedNamespace(clusterRoleBinding *rbacv1.ClusterRoleBinding) bool {
	for _, subject := range clusterRoleBinding.Subjects {
		if subject.Kind == "ServiceAccount" {
			if protectedNamespaces.Match([]byte(subject.Namespace)) && !slices.Contains(exceptionNamespaces, subject.Namespace) {
				return true
			}
		}
	}

	return false
}

// GetURI implements Webhook interface
func (s *ClusterRoleBindingWebHook) GetURI() string {
	return "/" + WebhookName
}

// Validate implements Webhook interface
func (s *ClusterRoleBindingWebHook) Validate(request admissionctl.Request) bool {
	valid := true
	valid = valid && (request.UserInfo.Username != "")
	valid = valid && (request.Kind.Kind == "ClusterRoleBinding")

	return valid
}

// Name implements Webhook interface
func (s *ClusterRoleBindingWebHook) Name() string {
	return WebhookName
}

// FailurePolicy implements Webhook interface
func (s *ClusterRoleBindingWebHook) FailurePolicy() admissionregv1.FailurePolicyType {
	return admissionregv1.Ignore
}

// MatchPolicy implements Webhook interface
func (s *ClusterRoleBindingWebHook) MatchPolicy() admissionregv1.MatchPolicyType {
	return admissionregv1.Equivalent
}

// Rules implements Webhook interface
func (s *ClusterRoleBindingWebHook) Rules() []admissionregv1.RuleWithOperations {
	return rules
}

// ObjectSelector implements Webhook interface
func (s *ClusterRoleBindingWebHook) ObjectSelector() *metav1.LabelSelector {
	return nil
}

// SideEffects implements Webhook interface
func (s *ClusterRoleBindingWebHook) SideEffects() admissionregv1.SideEffectClass {
	return admissionregv1.SideEffectClassNone
}

// TimeoutSeconds implements Webhook interface
func (s *ClusterRoleBindingWebHook) TimeoutSeconds() int32 {
	return timeout
}

// Doc implements Webhook interface
func (s *ClusterRoleBindingWebHook) Doc() string {
	return fmt.Sprintf(docString, managedNamespaces)
}

// SyncSetLabelSelector returns the label selector to use in the SyncSet.
// Return utils.DefaultLabelSelector() to stick with the default
func (s *ClusterRoleBindingWebHook) SyncSetLabelSelector() metav1.LabelSelector {
	return utils.DefaultLabelSelector()
}

func (s *ClusterRoleBindingWebHook) ClassicEnabled() bool { return true }

func (s *ClusterRoleBindingWebHook) HypershiftEnabled() bool { return true }
