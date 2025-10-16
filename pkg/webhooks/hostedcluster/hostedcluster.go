package hostedcluster

import (
	"fmt"
	"os"
	"sync"

	"github.com/openshift/managed-cluster-validating-webhooks/pkg/webhooks/utils"
	admissionv1 "k8s.io/api/admission/v1"
	admissionregv1 "k8s.io/api/admissionregistration/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	admissionctl "sigs.k8s.io/controller-runtime/pkg/webhook/admission"
)

const (
	WebhookName string = "hostedcluster-validation"
	docString   string = "Validates HostedCluster deletion operations are only performed by authorized service accounts"
)

var (
	// Only this service account is allowed to delete HostedClusters
	allowedServiceAccount = "system:serviceaccount:open-cluster-management-agent:klusterlet-work-sa"

	scope = admissionregv1.NamespacedScope
	rules = []admissionregv1.RuleWithOperations{
		{
			Operations: []admissionregv1.OperationType{"DELETE"},
			Rule: admissionregv1.Rule{
				APIGroups:   []string{"hypershift.openshift.io"},
				APIVersions: []string{"*"},
				Resources:   []string{"hostedclusters"},
				Scope:       &scope,
			},
		},
	}
	log = logf.Log.WithName(WebhookName)
)

// HostedClusterWebhook validates HostedCluster deletion operations
type HostedClusterWebhook struct {
	mu sync.Mutex
	s  runtime.Scheme
}

// ObjectSelector implements Webhook interface
func (s *HostedClusterWebhook) ObjectSelector() *metav1.LabelSelector { return nil }

func (s *HostedClusterWebhook) Doc() string {
	return fmt.Sprintf(docString)
}

// TimeoutSeconds implements Webhook interface
func (s *HostedClusterWebhook) TimeoutSeconds() int32 { return 2 }

// MatchPolicy implements Webhook interface
func (s *HostedClusterWebhook) MatchPolicy() admissionregv1.MatchPolicyType {
	return admissionregv1.Equivalent
}

// Name implements Webhook interface
func (s *HostedClusterWebhook) Name() string { return WebhookName }

// FailurePolicy implements Webhook interface
func (s *HostedClusterWebhook) FailurePolicy() admissionregv1.FailurePolicyType {
	return admissionregv1.Ignore
}

// Rules implements Webhook interface
func (s *HostedClusterWebhook) Rules() []admissionregv1.RuleWithOperations { return rules }

// GetURI implements Webhook interface
func (s *HostedClusterWebhook) GetURI() string { return "/hostedcluster-validation" }

// SideEffects implements Webhook interface
func (s *HostedClusterWebhook) SideEffects() admissionregv1.SideEffectClass {
	return admissionregv1.SideEffectClassNone
}

// Validate - Make sure we're working with a well-formed Admission Request object
func (s *HostedClusterWebhook) Validate(req admissionctl.Request) bool {
	valid := true
	valid = valid && (req.UserInfo.Username != "")
	valid = valid && (req.Kind.Kind == "HostedCluster")
	valid = valid && (req.Kind.Group == "hypershift.openshift.io")

	return valid
}

// Authorized implements Webhook interface
func (s *HostedClusterWebhook) Authorized(request admissionctl.Request) admissionctl.Response {
	return s.authorized(request)
}

// Is the request authorized
func (s *HostedClusterWebhook) authorized(request admissionctl.Request) admissionctl.Response {
	var ret admissionctl.Response

	// Only allow DELETE operations from the specified service account
	if request.UserInfo.Username == allowedServiceAccount {
		ret = admissionctl.Allowed("Service account is authorized to delete HostedCluster resources")
		ret.UID = request.AdmissionRequest.UID
		return ret
	}

	// If not a delete operation, allow it
	if request.Operation != admissionv1.Delete {
		ret = admissionctl.Allowed("Only DELETE operations are restricted")
		ret.UID = request.AdmissionRequest.UID
		return ret
	}

	// Deny all other requests
	log.Info("Unauthorized attempt to delete HostedCluster",
		"user", request.UserInfo.Username,
		"groups", request.UserInfo.Groups)

	ret = admissionctl.Denied(fmt.Sprintf("Only %s is authorized to delete HostedCluster resources", allowedServiceAccount))
	ret.UID = request.AdmissionRequest.UID
	return ret
}

// SyncSetLabelSelector returns the label selector to use in the SyncSet.
func (s *HostedClusterWebhook) SyncSetLabelSelector() metav1.LabelSelector {
	customLabelSelector := utils.DefaultLabelSelector()
	customLabelSelector.MatchExpressions = append(customLabelSelector.MatchExpressions,
		metav1.LabelSelectorRequirement{
			Key:      "ext-hypershift.openshift.io/cluster-type",
			Operator: metav1.LabelSelectorOpIn,
			Values:   []string{"management-cluster"},
		})
	return customLabelSelector
}

func (s *HostedClusterWebhook) ClassicEnabled() bool { return true }

func (s *HostedClusterWebhook) HypershiftEnabled() bool { return false }

// NewWebhook creates a new webhook
func NewWebhook() *HostedClusterWebhook {
	scheme := runtime.NewScheme()
	err := admissionv1.AddToScheme(scheme)
	if err != nil {
		log.Error(err, "Fail adding admissionsv1 scheme to HostedClusterWebhook")
		os.Exit(1)
	}
	return &HostedClusterWebhook{
		s: *scheme,
	}
}
