package hcpnamespace

import (
	"fmt"
	"os"
	"regexp"
	"slices"

	"github.com/openshift/managed-cluster-validating-webhooks/pkg/webhooks/utils"
	admissionv1 "k8s.io/api/admission/v1"
	admissionregv1 "k8s.io/api/admissionregistration/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	admissionctl "sigs.k8s.io/controller-runtime/pkg/webhook/admission"
)

const (
	WebhookName string = "hcpnamespace-validation"
	docString   string = "Validates HCP namespace deletion operations are only performed by authorized service accounts"
)

var (
	allowedUsers = []string{
		"system:admin",
		"system:serviceaccount:open-cluster-management-agent:klusterlet-work-sa",
		"system:serviceaccount:open-cluster-management-agent:klusterlet",
		"system:serviceaccount:hypershift:operator",
	}

	// Protected namespace patterns
	protectedNamespacePatterns = []string{
		"^ocm-staging-.*",
		"^ocm-production-.*",
		"^ocm-integration-.*",
		"^klusterlet-.*",
		"^hs-mc-.*",
	}

	protectedNamespaceRegexps = compileRegexps(protectedNamespacePatterns)

	scope = admissionregv1.ClusterScope
	rules = []admissionregv1.RuleWithOperations{
		{
			Operations: []admissionregv1.OperationType{"DELETE"},
			Rule: admissionregv1.Rule{
				APIGroups:   []string{""},
				APIVersions: []string{"*"},
				Resources:   []string{"namespaces"},
				Scope:       &scope,
			},
		},
	}
	log = logf.Log.WithName(WebhookName)
)

func compileRegexps(patterns []string) []*regexp.Regexp {
	regexps := make([]*regexp.Regexp, len(patterns))
	for i, pattern := range patterns {
		regexps[i] = regexp.MustCompile(pattern)
	}
	return regexps
}

// HCPNamespaceWebhook validates HCP namespace deletion operations
type HCPNamespaceWebhook struct {
	s runtime.Scheme
}

// ObjectSelector implements Webhook interface
func (s *HCPNamespaceWebhook) ObjectSelector() *metav1.LabelSelector { return nil }

func (s *HCPNamespaceWebhook) Doc() string {
	return docString
}

// TimeoutSeconds implements Webhook interface
func (s *HCPNamespaceWebhook) TimeoutSeconds() int32 { return 2 }

// MatchPolicy implements Webhook interface
func (s *HCPNamespaceWebhook) MatchPolicy() admissionregv1.MatchPolicyType {
	return admissionregv1.Equivalent
}

// Name implements Webhook interface
func (s *HCPNamespaceWebhook) Name() string { return WebhookName }

// FailurePolicy implements Webhook interface
func (s *HCPNamespaceWebhook) FailurePolicy() admissionregv1.FailurePolicyType {
	return admissionregv1.Ignore
}

// Rules implements Webhook interface
func (s *HCPNamespaceWebhook) Rules() []admissionregv1.RuleWithOperations { return rules }

// GetURI implements Webhook interface
func (s *HCPNamespaceWebhook) GetURI() string { return "/hcpnamespace-validation" }

// SideEffects implements Webhook interface
func (s *HCPNamespaceWebhook) SideEffects() admissionregv1.SideEffectClass {
	return admissionregv1.SideEffectClassNone
}

// Validate - Make sure we're working with a well-formed Admission Request object
func (s *HCPNamespaceWebhook) Validate(req admissionctl.Request) bool {
	valid := true
	valid = valid && (req.UserInfo.Username != "")
	valid = valid && (req.Kind.Kind == "Namespace")

	return valid
}

// isProtectedNamespace checks if the namespace matches any of the protected patterns
func isProtectedNamespace(namespaceName string) bool {
	for _, re := range protectedNamespaceRegexps {
		if re.MatchString(namespaceName) {
			return true
		}
	}
	return false
}

// Authorized implements Webhook interface
func (s *HCPNamespaceWebhook) Authorized(request admissionctl.Request) admissionctl.Response {
	return s.authorized(request)
}

// Is the request authorized
func (s *HCPNamespaceWebhook) authorized(request admissionctl.Request) admissionctl.Response {
	var ret admissionctl.Response

	// Allow authorized users/service accounts
	if slices.Contains(allowedUsers, request.UserInfo.Username) {
		ret = admissionctl.Allowed("User/ServiceAccount is authorized to delete HCP namespaces")
		ret.UID = request.AdmissionRequest.UID
		return ret
	}

	// Check if the namespace is protected
	namespace := request.Name
	if !isProtectedNamespace(namespace) {
		// If the namespace doesn't match protected patterns, allow the operation
		ret = admissionctl.Allowed("Namespace is not protected")
		ret.UID = request.AdmissionRequest.UID
		return ret
	}

	// If not a delete operation, allow it
	if request.Operation != admissionv1.Delete {
		ret = admissionctl.Allowed("Only DELETE operations are restricted")
		ret.UID = request.AdmissionRequest.UID
		return ret
	}

	// If we get here, the namespace is protected and the user is not authorized
	log.Info("Unauthorized attempt to delete protected namespace",
		"user", request.UserInfo.Username,
		"namespace", namespace,
		"groups", request.UserInfo.Groups)

	ret = admissionctl.Denied(fmt.Sprintf("Only authorized users/service accounts can delete this namespace %s", namespace))
	ret.UID = request.AdmissionRequest.UID
	return ret
}

// SyncSetLabelSelector returns the label selector to use in the SyncSet.
func (s *HCPNamespaceWebhook) SyncSetLabelSelector() metav1.LabelSelector {
	customLabelSelector := utils.DefaultLabelSelector()
	customLabelSelector.MatchExpressions = append(customLabelSelector.MatchExpressions,
		metav1.LabelSelectorRequirement{
			Key:      "ext-hypershift.openshift.io/cluster-type",
			Operator: metav1.LabelSelectorOpIn,
			Values: []string{
				"management-cluster",
				"service-cluster",
			},
		})
	return customLabelSelector
}

func (s *HCPNamespaceWebhook) ClassicEnabled() bool { return true }

func (s *HCPNamespaceWebhook) HypershiftEnabled() bool { return false }

// NewWebhook creates a new webhook
func NewWebhook() *HCPNamespaceWebhook {
	scheme := runtime.NewScheme()
	err := admissionv1.AddToScheme(scheme)
	if err != nil {
		log.Error(err, "Fail adding admissionsv1 scheme to HCPNamespaceWebhook")
		os.Exit(1)
	}

	return &HCPNamespaceWebhook{
		s: *scheme,
	}
}
