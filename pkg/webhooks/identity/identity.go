package identity

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
	admissionctl "sigs.k8s.io/controller-runtime/pkg/webhook/admission"

	logf "sigs.k8s.io/controller-runtime/pkg/runtime/log"
)

const (
	WebhookName             string = "identity-validation"
	DefaultIdentityProvider string = "OpenShift_SRE"
	docString               string = `Managed OpenShift customers may not modify Red Hat's managed Identities (prefixed and identified with %s).`
)

var (
	privilegedUsers = []string{"kube:admin", "system:admin", "system:serviceaccount:openshift-authentication:oauth-openshift", "backplane-cluster-admin"}
	adminGroups     = []string{"osd-sre-admins", "osd-sre-cluster-admins"}

	log = logf.Log.WithName(WebhookName)

	scope = admissionregv1.ClusterScope
	rules = []admissionregv1.RuleWithOperations{
		{
			Operations: []admissionregv1.OperationType{"UPDATE", "CREATE", "DELETE"},
			Rule: admissionregv1.Rule{
				APIGroups:   []string{"user.openshift.io"},
				APIVersions: []string{"*"},
				Resources:   []string{"identities"},
				Scope:       &scope,
			},
		},
	}
)

type identityRequest struct {
	Metadata struct {
		Name string `json:"name"`
	} `json:"metadata"`
	ProviderName string `json:"providerName"`
}

// IdentityWebhook validates an Identity change
type IdentityWebhook struct {
	mu sync.Mutex
	s  runtime.Scheme
}

// ObjectSelector implements Webhook interface
func (s *IdentityWebhook) ObjectSelector() *metav1.LabelSelector { return nil }

func (s *IdentityWebhook) Doc() string {
	return fmt.Sprintf(docString, DefaultIdentityProvider)
}

// TimeoutSeconds implements Webhook interface
func (s *IdentityWebhook) TimeoutSeconds() int32 { return 2 }

// MatchPolicy implements Webhook interface
func (s *IdentityWebhook) MatchPolicy() admissionregv1.MatchPolicyType {
	return admissionregv1.Equivalent
}

// Name implements Webhook interface
func (s *IdentityWebhook) Name() string { return WebhookName }

// FailurePolicy implements Webhook interface
func (s *IdentityWebhook) FailurePolicy() admissionregv1.FailurePolicyType {
	return admissionregv1.Ignore
}

// Rules implements Webhook interface
func (s *IdentityWebhook) Rules() []admissionregv1.RuleWithOperations { return rules }

// GetURI implements Webhook interface
func (s *IdentityWebhook) GetURI() string { return "/identity-validation" }

// SideEffects implements Webhook interface
func (s *IdentityWebhook) SideEffects() admissionregv1.SideEffectClass {
	return admissionregv1.SideEffectClassNone
}

// Validate - Make sure we're working with a well-formed Admission Request object
func (s *IdentityWebhook) Validate(req admissionctl.Request) bool {
	valid := true
	valid = valid && (req.UserInfo.Username != "")
	valid = valid && (req.Kind.Kind == "Identity")

	return valid
}

// Is the request authorized?
func (s *IdentityWebhook) authorized(request admissionctl.Request) admissionctl.Response {
	var ret admissionctl.Response
	var err error
	idReq := &identityRequest{}

	// if we delete, then look to OldObject in the request.
	if request.Operation == v1beta1.Delete {
		err = json.Unmarshal(request.OldObject.Raw, idReq)
	} else {
		err = json.Unmarshal(request.Object.Raw, idReq)
	}
	if err != nil {
		ret = admissionctl.Errored(http.StatusBadRequest, err)
		return ret
	}
	// Admin user
	if utils.SliceContains(request.AdmissionRequest.UserInfo.Username, privilegedUsers) {
		ret = admissionctl.Allowed("Admin users are allowed")
		ret.UID = request.AdmissionRequest.UID
		return ret
	}
	if idReq.ProviderName == DefaultIdentityProvider {
		for _, group := range request.AdmissionRequest.UserInfo.Groups {
			if utils.SliceContains(group, adminGroups) {
				ret = admissionctl.Allowed("members of admin group may interact with default idp")
				ret.UID = request.AdmissionRequest.UID
				return ret
			}
		}
		log.Info("Denying access", "request", request.AdmissionRequest)
		ret = admissionctl.Denied(fmt.Sprintf("Prevented from modifying Red Hat's managed Identity. You may create/modify any Identity objects, except for %s.", DefaultIdentityProvider))
		ret.UID = request.AdmissionRequest.UID
		return ret
	}

	ret = admissionctl.Allowed("Allowed by RBAC")
	ret.UID = request.AdmissionRequest.UID
	return ret

}

// Authorized implements Webhook interface
func (s *IdentityWebhook) Authorized(request admissionctl.Request) admissionctl.Response {
	return s.authorized(request)
}

// SyncSetLabelSelector returns the label selector to use in the SyncSet.
func (s *IdentityWebhook) SyncSetLabelSelector() metav1.LabelSelector {
	return utils.DefaultLabelSelector()
}

// NewWebhook creates a new webhook
func NewWebhook() *IdentityWebhook {
	scheme := runtime.NewScheme()
	v1beta1.AddToScheme(scheme)

	return &IdentityWebhook{
		s: *scheme,
	}
}
