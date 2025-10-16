package hostedcontrolplane

import (
	"fmt"
	"os"
	"strings"

	"github.com/openshift/managed-cluster-validating-webhooks/pkg/webhooks/utils"
	admissionv1 "k8s.io/api/admission/v1"
	admissionregv1 "k8s.io/api/admissionregistration/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	admissionctl "sigs.k8s.io/controller-runtime/pkg/webhook/admission"
)

const (
	WebhookName string = "hostedcontrolplane-validation"
	docString   string = "Validates HostedControlPlane deletion operations are only performed by authorized service accounts"
)

var (
	// Service accounts allowed to delete HostedControlPlanes
	allowedServiceAccounts = []string{
		"system:serviceaccount:open-cluster-management-agent:klusterlet-work-sa",
	}

	scope = admissionregv1.NamespacedScope
	rules = []admissionregv1.RuleWithOperations{
		{
			Operations: []admissionregv1.OperationType{"DELETE"},
			Rule: admissionregv1.Rule{
				APIGroups:   []string{"hypershift.openshift.io"},
				APIVersions: []string{"*"},
				Resources:   []string{"hostedcontrolplanes"},
				Scope:       &scope,
			},
		},
	}
	log = logf.Log.WithName(WebhookName)
)

// HostedControlPlaneWebhook validates HostedControlPlane deletion operations
type HostedControlPlaneWebhook struct {
	s runtime.Scheme
}

// ObjectSelector implements Webhook interface
func (s *HostedControlPlaneWebhook) ObjectSelector() *metav1.LabelSelector { return nil }

func (s *HostedControlPlaneWebhook) Doc() string {
	return fmt.Sprintf(docString)
}

// TimeoutSeconds implements Webhook interface
func (s *HostedControlPlaneWebhook) TimeoutSeconds() int32 { return 2 }

// MatchPolicy implements Webhook interface
func (s *HostedControlPlaneWebhook) MatchPolicy() admissionregv1.MatchPolicyType {
	return admissionregv1.Equivalent
}

// Name implements Webhook interface
func (s *HostedControlPlaneWebhook) Name() string { return WebhookName }

// FailurePolicy implements Webhook interface
func (s *HostedControlPlaneWebhook) FailurePolicy() admissionregv1.FailurePolicyType {
	return admissionregv1.Ignore
}

// Rules implements Webhook interface
func (s *HostedControlPlaneWebhook) Rules() []admissionregv1.RuleWithOperations { return rules }

// GetURI implements Webhook interface
func (s *HostedControlPlaneWebhook) GetURI() string { return "/hostedcontrolplane-validation" }

// SideEffects implements Webhook interface
func (s *HostedControlPlaneWebhook) SideEffects() admissionregv1.SideEffectClass {
	return admissionregv1.SideEffectClassNone
}

// Validate - Make sure we're working with a well-formed Admission Request object
func (s *HostedControlPlaneWebhook) Validate(req admissionctl.Request) bool {
	valid := true
	valid = valid && (req.UserInfo.Username != "")
	valid = valid && (req.Kind.Kind == "HostedControlPlane")
	valid = valid && (req.Kind.Group == "hypershift.openshift.io")

	return valid
}

// Authorized implements Webhook interface
func (s *HostedControlPlaneWebhook) Authorized(request admissionctl.Request) admissionctl.Response {
	return s.authorized(request)
}

// Is the request authorized?
func (s *HostedControlPlaneWebhook) authorized(request admissionctl.Request) admissionctl.Response {
	var ret admissionctl.Response

	// Allow authorized service accounts
	for _, sa := range allowedServiceAccounts {
		if request.UserInfo.Username == sa {
			ret = admissionctl.Allowed("Service account is authorized to delete HostedControlPlane resources")
			ret.UID = request.AdmissionRequest.UID
			return ret
		}
	}

	// If not a delete operation, allow it
	if request.Operation != admissionv1.Delete {
		ret = admissionctl.Allowed("Only DELETE operations are restricted")
		ret.UID = request.AdmissionRequest.UID
		return ret
	}

	// Deny all other delete attempts
	log.Info("Unauthorized attempt to delete HostedControlPlane",
		"user", request.UserInfo.Username,
		"groups", request.UserInfo.Groups)

	ret = admissionctl.Denied(fmt.Sprintf("Only authorized service accounts %s can delete HostedControlPlane resources", strings.Join(allowedServiceAccounts, ", ")))
	ret.UID = request.AdmissionRequest.UID
	return ret

}

// SyncSetLabelSelector returns the label selector to use in the SyncSet.
func (s *HostedControlPlaneWebhook) SyncSetLabelSelector() metav1.LabelSelector {
	customLabelSelector := utils.DefaultLabelSelector()
	customLabelSelector.MatchExpressions = append(customLabelSelector.MatchExpressions,
		metav1.LabelSelectorRequirement{
			Key:      "ext-hypershift.openshift.io/cluster-type",
			Operator: metav1.LabelSelectorOpIn,
			Values:   []string{"management-cluster"},
		})
	return customLabelSelector
}

func (s *HostedControlPlaneWebhook) ClassicEnabled() bool { return true }

func (s *HostedControlPlaneWebhook) HypershiftEnabled() bool { return false }

// NewWebhook creates a new webhook
func NewWebhook() *HostedControlPlaneWebhook {
	scheme := runtime.NewScheme()
	err := admissionv1.AddToScheme(scheme)
	if err != nil {
		log.Error(err, "Fail adding admissionsv1 scheme to HostedControlPlaneWebhook")
		os.Exit(1)
	}
	return &HostedControlPlaneWebhook{
		s: *scheme,
	}
}
