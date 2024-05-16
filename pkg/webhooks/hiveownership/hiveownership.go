package hiveownership

import (
	"os"
	"slices"
	"sync"

	"github.com/openshift/managed-cluster-validating-webhooks/pkg/webhooks/utils"
	admissionregv1 "k8s.io/api/admissionregistration/v1"
	admissionv1 "k8s.io/api/apps/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	admissionctl "sigs.k8s.io/controller-runtime/pkg/webhook/admission"
)

// const
const (
	WebhookName string = "hiveownership-validation"
	docString   string = `Managed OpenShift customers may not edit certain managed resources. A managed resource has a "hive.openshift.io/managed": "true" label.`
)

// HiveOwnershipWebhook denies requests
// if it made by a customer to manage hive-labeled resources
type HiveOwnershipWebhook struct {
	mu sync.Mutex
	s  runtime.Scheme
}

var (
	privilegedUsers = []string{"kube:admin", "system:admin", "system:serviceaccount:kube-system:generic-garbage-collector", "backplane-cluster-admin"}
	adminGroups     = []string{"system:serviceaccounts:openshift-backplane-srep"}

	log = logf.Log.WithName(WebhookName)

	scope = admissionregv1.ClusterScope
	rules = []admissionregv1.RuleWithOperations{
		{
			Operations: []admissionregv1.OperationType{"UPDATE", "DELETE"},
			Rule: admissionregv1.Rule{
				APIGroups:   []string{"quota.openshift.io"},
				APIVersions: []string{"*"},
				Resources:   []string{"clusterresourcequotas"},
				Scope:       &scope,
			},
		},
	}
)

// TimeoutSeconds implements Webhook interface
func (s *HiveOwnershipWebhook) TimeoutSeconds() int32 { return 2 }

// MatchPolicy implements Webhook interface
func (s *HiveOwnershipWebhook) MatchPolicy() admissionregv1.MatchPolicyType {
	return admissionregv1.Equivalent
}

// Name implements Webhook interface
func (s *HiveOwnershipWebhook) Name() string { return WebhookName }

// FailurePolicy implements Webhook interface
func (s *HiveOwnershipWebhook) FailurePolicy() admissionregv1.FailurePolicyType {
	return admissionregv1.Ignore
}

// Rules implements Webhook interface
func (s *HiveOwnershipWebhook) Rules() []admissionregv1.RuleWithOperations { return rules }

// GetURI implements Webhook interface
func (s *HiveOwnershipWebhook) GetURI() string { return "/" + WebhookName }

// SideEffects implements Webhook interface
func (s *HiveOwnershipWebhook) SideEffects() admissionregv1.SideEffectClass {
	return admissionregv1.SideEffectClassNone
}

// Validate is the incoming request even valid?
func (s *HiveOwnershipWebhook) Validate(req admissionctl.Request) bool {
	valid := true
	valid = valid && (req.UserInfo.Username != "")

	return valid
}

// Doc documents the hook
func (s *HiveOwnershipWebhook) Doc() string {
	return docString
}

// ObjectSelector intercepts based on having the label
// .metadata.labels["hive.openshift.io/managed"] == "true"
func (s *HiveOwnershipWebhook) ObjectSelector() *metav1.LabelSelector {
	return &metav1.LabelSelector{
		MatchLabels: map[string]string{
			"hive.openshift.io/managed": "true",
		},
	}
}

func (s *HiveOwnershipWebhook) authorized(request admissionctl.Request) admissionctl.Response {
	var ret admissionctl.Response

	// Admin users
	if slices.Contains(privilegedUsers, request.AdmissionRequest.UserInfo.Username) {
		ret = admissionctl.Allowed("Admin users may edit managed resources")
		ret.UID = request.AdmissionRequest.UID
		return ret
	}
	// Users in admin groups
	for _, group := range request.AdmissionRequest.UserInfo.Groups {
		if slices.Contains(adminGroups, group) {
			ret = admissionctl.Allowed("Members of admin group may edit managed resources")
			ret.UID = request.AdmissionRequest.UID
			return ret
		}
	}

	ret = admissionctl.Denied("Prevented from accessing Red Hat managed resources. This is in an effort to prevent harmful actions that may cause unintended consequences or affect the stability of the cluster. If you have any questions about this, please reach out to Red Hat support at https://access.redhat.com/support")
	ret.UID = request.AdmissionRequest.UID
	return ret
}

// Authorized implements Webhook interface
func (s *HiveOwnershipWebhook) Authorized(request admissionctl.Request) admissionctl.Response {
	return s.authorized(request)
}

// CustomSelector implements Webhook interface, returning the custom label selector for the syncset, if any
func (s *HiveOwnershipWebhook) SyncSetLabelSelector() metav1.LabelSelector {
	return utils.DefaultLabelSelector()
}

func (s *HiveOwnershipWebhook) ClassicEnabled() bool { return true }

func (s *HiveOwnershipWebhook) HypershiftEnabled() bool { return false }

// NewWebhook creates a new webhook
func NewWebhook() *HiveOwnershipWebhook {
	scheme := runtime.NewScheme()
	err := admissionv1.AddToScheme(scheme)
	if err != nil {
		log.Error(err, "Fail adding admissionsv1 scheme to HiveOwnershipWebhook")
		os.Exit(1)
	}

	return &HiveOwnershipWebhook{
		s: *scheme,
	}
}
