package subscription

import (
	"encoding/json"
	"fmt"
	"net/http"
	"sync"

	"github.com/openshift/managed-cluster-validating-webhooks/pkg/webhooks/utils"
	"k8s.io/api/admission/v1beta1"
	admissionregv1 "k8s.io/api/admissionregistration/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	logf "sigs.k8s.io/controller-runtime/pkg/runtime/log"
	admissionctl "sigs.k8s.io/controller-runtime/pkg/webhook/admission"
)

const (
	WebhookName    string = "subscription-validation"
	loggingSubName string = "cluster-logging"
	esSubName      string = "elasticsearch-operator"
	docString      string = `Managed OpenShift customers may not update change the %s subscription from the %s channel(s) because there are known issues with those channel(s) that are being worked on.`
)

var (
	privilegedUsers = []string{"kube:admin", "system:admin", "system:serviceaccount:kube-system:generic-garbage-collector"}
	adminGroups     = []string{"osd-sre-admins", "osd-sre-cluster-admins"}
	blockedChannels = []string{"4.5", "4.6"}

	log = logf.Log.WithName(WebhookName)

	scope = admissionregv1.NamespacedScope
	rules = []admissionregv1.RuleWithOperations{
		{
			Operations: []admissionregv1.OperationType{"UPDATE", "CREATE"},
			Rule: admissionregv1.Rule{
				APIGroups:   []string{"operators.coreos.com"},
				APIVersions: []string{"*"},
				Resources:   []string{"subscriptions"},
				Scope:       &scope,
			},
		},
	}
)

type subscriptionRequest struct {
	Metadata struct {
		Name      string `json:"name"`
		Namespace string `json:"namespace"`
	} `json:"metadata"`
	Spec struct {
		Channel string `json:"channel"`
		Name    string `json:"name"`
	} `json:"spec"`
}

// SubscriptionWebhook validates a Subscription change
type SubscriptionWebhook struct {
	mu sync.Mutex
	s  runtime.Scheme
}

// ObjectSelector implements Webhook interface
func (s *SubscriptionWebhook) ObjectSelector() *metav1.LabelSelector { return nil }

func (s *SubscriptionWebhook) Doc() string {
	return fmt.Sprintf(docString, esSubName, blockedChannels)
}

// TimeoutSeconds implements Webhook interface
func (s *SubscriptionWebhook) TimeoutSeconds() int32 { return 2 }

// MatchPolicy implements Webhook interface
func (s *SubscriptionWebhook) MatchPolicy() admissionregv1.MatchPolicyType {
	return admissionregv1.Equivalent
}

// Name implements Webhook interface
func (s *SubscriptionWebhook) Name() string { return WebhookName }

// FailurePolicy implements Webhook interface
func (s *SubscriptionWebhook) FailurePolicy() admissionregv1.FailurePolicyType {
	return admissionregv1.Ignore
}

// Rules implements Webhook interface
func (s *SubscriptionWebhook) Rules() []admissionregv1.RuleWithOperations { return rules }

// GetURI implements Webhook interface
func (s *SubscriptionWebhook) GetURI() string { return "/" + WebhookName }

// SideEffects implements Webhook interface
func (s *SubscriptionWebhook) SideEffects() admissionregv1.SideEffectClass {
	return admissionregv1.SideEffectClassNone
}

// Validate is the incoming request even valid?
func (s *SubscriptionWebhook) Validate(req admissionctl.Request) bool {
	valid := true
	valid = valid && (req.UserInfo.Username != "")
	valid = valid && (req.Kind.Kind == "Subscription")

	return valid
}

// isBlockedLoggingRequest is a helper to consolidate logic. Returns true
// if the request is for the cluster-logging or elasticsearch-operator
// subscription on 4.5 or 4.6 channels
func (s *SubscriptionWebhook) isBlockedLoggingRequest(subscriptionReq *subscriptionRequest) bool {
	if utils.SliceContains(subscriptionReq.Spec.Channel, blockedChannels) && (subscriptionReq.Spec.Name == loggingSubName || subscriptionReq.Spec.Name == esSubName) {
		return true
	}
	return false
}

func (s *SubscriptionWebhook) authorized(request admissionctl.Request) admissionctl.Response {
	var ret admissionctl.Response
	var err error
	subReq := &subscriptionRequest{}

	// if we delete, then look to OldObject in the request.
	if request.Operation == v1beta1.Delete {
		err = json.Unmarshal(request.OldObject.Raw, subReq)
	} else {
		err = json.Unmarshal(request.Object.Raw, subReq)
	}

	if err != nil {
		ret = admissionctl.Errored(http.StatusBadRequest, err)
		return ret
	}

	// can comment this out or remove after manual tests
	// log.Info("User is attempting to modify subscription", "username", request.AdmissionRequest.UserInfo.Username, "operation", request.Operation, "subscription name", subReq.Spec.Name, "channel", subReq.Spec.Channel)

	// If this isn't a request to install or upgrade logging 4.5 or 4.6, let RBAC handle this
	if !s.isBlockedLoggingRequest(subReq) {
		ret = admissionctl.Allowed("Base decisions for non-logging subscriptions on RBAC")
		ret.UID = request.AdmissionRequest.UID
		return ret
	}

	// Admin users
	if utils.SliceContains(request.AdmissionRequest.UserInfo.Username, privilegedUsers) {
		ret = admissionctl.Allowed("Admin users may install or upgrade to logging 4.5 or 4.6 operator")
		ret.UID = request.AdmissionRequest.UID
		return ret
	}
	// Users in admin groups
	for _, group := range request.AdmissionRequest.UserInfo.Groups {
		if utils.SliceContains(group, adminGroups) {
			ret = admissionctl.Allowed("Members of admin group may install or upgrade to logging 4.5 or 4.6 operator")
			ret.UID = request.AdmissionRequest.UID
			return ret
		}
	}

	// if we're here, non-privileged user is attempting to CREATE or UPDATE logging
	// operator at 4.5 or 4.6 - deny this
	ret = admissionctl.Denied("Only Red Hat SREs can install or upgrade to the v4.5 or v4.6 logging operator at this time, as there are known issues with logging v4.5/v4.6 which we are working to resolve.")
	ret.UID = request.AdmissionRequest.UID
	return ret
}

// Authorized implements Webhook interface
func (s *SubscriptionWebhook) Authorized(request admissionctl.Request) admissionctl.Response {
	return s.authorized(request)
}

// NewWebhook creates a new webhook
func NewWebhook() *SubscriptionWebhook {
	scheme := runtime.NewScheme()
	v1beta1.AddToScheme(scheme)

	return &SubscriptionWebhook{
		s: *scheme,
	}
}
