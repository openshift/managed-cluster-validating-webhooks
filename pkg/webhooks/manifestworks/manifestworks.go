package manifestworks

import (
	"fmt"
	"os"
	"slices"
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
	WebhookName string = "manifestworks-validation"
	docString   string = "Validates ManifestWorks deletion operations are only performed by authorized service accounts"
)

var (
	// List of service accounts allowed to delete ManifestWorks
	allowedServiceAccounts = []string{
		"system:serviceaccount:ocm:ocm",
		"system:serviceaccount:kube-system:generic-garbage-collector",
		"system:serviceaccount:multicluster-engine:ocm-foundation-sa",
		"system:serviceaccount:multicluster-hub:grc-policy-addon-sa",
		"system:serviceaccount:multicluster-engine:managedcluster-import-controller-v2",
		"system:serviceaccount:kube-system:namespace-controller",
	}

	scope = admissionregv1.NamespacedScope
	rules = []admissionregv1.RuleWithOperations{
		{
			Operations: []admissionregv1.OperationType{"DELETE"},
			Rule: admissionregv1.Rule{
				APIGroups:   []string{"work.open-cluster-management.io"},
				APIVersions: []string{"*"},
				Resources:   []string{"manifestworks"},
				Scope:       &scope,
			},
		},
	}
	log = logf.Log.WithName(WebhookName)
)

// ManifestWorksWebhook validates ManifestWorks deletion operations
type ManifestWorksWebhook struct {
	mu sync.Mutex
	s  runtime.Scheme
}

// ObjectSelector implements Webhook interface
func (s *ManifestWorksWebhook) ObjectSelector() *metav1.LabelSelector { return nil }

func (s *ManifestWorksWebhook) Doc() string {
	return fmt.Sprintf(docString)
}

// TimeoutSeconds implements Webhook interface
func (s *ManifestWorksWebhook) TimeoutSeconds() int32 { return 2 }

// MatchPolicy implements Webhook interface
func (s *ManifestWorksWebhook) MatchPolicy() admissionregv1.MatchPolicyType {
	return admissionregv1.Equivalent
}

// Name implements Webhook interface
func (s *ManifestWorksWebhook) Name() string { return WebhookName }

// FailurePolicy implements Webhook interface
func (s *ManifestWorksWebhook) FailurePolicy() admissionregv1.FailurePolicyType {
	return admissionregv1.Ignore
}

// Rules implements Webhook interface
func (s *ManifestWorksWebhook) Rules() []admissionregv1.RuleWithOperations { return rules }

// GetURI implements Webhook interface
func (s *ManifestWorksWebhook) GetURI() string { return "/manifestworks-validation" }

// SideEffects implements Webhook interface
func (s *ManifestWorksWebhook) SideEffects() admissionregv1.SideEffectClass {
	return admissionregv1.SideEffectClassNone
}

// Validate - Make sure we're working with a well-formed Admission Request object
func (s *ManifestWorksWebhook) Validate(req admissionctl.Request) bool {
	valid := true
	valid = valid && (req.UserInfo.Username != "")
	valid = valid && (req.Kind.Kind == "ManifestWork")
	valid = valid && (req.Kind.Group == "work.open-cluster-management.io")

	return valid
}

// Authorized implements Webhook interface
func (s *ManifestWorksWebhook) Authorized(request admissionctl.Request) admissionctl.Response {
	return s.authorized(request)
}

// Is the request authorized?
func (s *ManifestWorksWebhook) authorized(request admissionctl.Request) admissionctl.Response {
	var ret admissionctl.Response

	// Check if the requesting user is in the list of allowed service accounts
	if slices.Contains(allowedServiceAccounts, request.UserInfo.Username) {
		ret = admissionctl.Allowed("Service account is authorized to delete ManifestWork resources")
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
	log.Info("Unauthorized attempt to delete ManifestWork",
		"user", request.UserInfo.Username,
		"groups", request.UserInfo.Groups)

	ret = admissionctl.Denied(fmt.Sprintf("Only authorized service accounts can delete ManifestWork resources. Allowed service accounts: %v", allowedServiceAccounts))
	ret.UID = request.AdmissionRequest.UID
	return ret
}

// SyncSetLabelSelector returns the label selector to use in the SyncSet.
func (s *ManifestWorksWebhook) SyncSetLabelSelector() metav1.LabelSelector {
	customLabelSelector := utils.DefaultLabelSelector()
	customLabelSelector.MatchExpressions = append(customLabelSelector.MatchExpressions, []metav1.LabelSelectorRequirement{
		metav1.LabelSelectorRequirement{
			Key:      "ext-hypershift.openshift.io/cluster-type",
			Operator: metav1.LabelSelectorOpIn,
			Values:   []string{"service-cluster"},
		},
		metav1.LabelSelectorRequirement{
			Key:      "api.openshift.com/environment",
			Operator: metav1.LabelSelectorOpNotIn,
			Values:   []string{"integration"},
		},
	}...)
	return customLabelSelector
}

func (s *ManifestWorksWebhook) ClassicEnabled() bool { return true }

func (s *ManifestWorksWebhook) HypershiftEnabled() bool { return false }

// NewWebhook creates a new webhook
func NewWebhook() *ManifestWorksWebhook {
	scheme := runtime.NewScheme()
	err := admissionv1.AddToScheme(scheme)
	if err != nil {
		log.Error(err, "Fail adding admissionsv1 scheme to ManifestWorksWebhook")
		os.Exit(1)
	}
	return &ManifestWorksWebhook{
		s: *scheme,
	}
}
