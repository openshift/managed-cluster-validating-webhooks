package user

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"

	responsehelper "github.com/openshift/managed-cluster-validating-webhooks/pkg/helpers"
	"github.com/openshift/managed-cluster-validating-webhooks/pkg/webhooks/utils"
	"k8s.io/api/admission/v1beta1"
	admissionregv1 "k8s.io/api/admissionregistration/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	admissionctl "sigs.k8s.io/controller-runtime/pkg/webhook/admission"

	logf "sigs.k8s.io/controller-runtime/pkg/runtime/log"
)

const (
	WebhookName         string = "user-validation"
	protectedUserSuffix string = "@redhat.com"
)

var (
	adminGroups = []string{"osd-sre-admins", "osd-sre-cluster-admins"}
	// kubeAdminUsernames are core Kubernetes users, not generally created by people
	kubeAdminUsernames = []string{"kube:admin", "system:admin", "system:serviceaccount:openshift-authentication:oauth-openshift"}

	scope = admissionregv1.ClusterScope
	rules = []admissionregv1.RuleWithOperations{

		{
			Operations: []admissionregv1.OperationType{"UPDATE", "CREATE", "DELETE"},
			Rule: admissionregv1.Rule{
				APIGroups:   []string{"user.openshift.io"},
				APIVersions: []string{"*"},
				Resources:   []string{"users"},
				Scope:       &scope,
			},
		},
	}
	log = logf.Log.WithName(WebhookName)
)

// UserWebhook validates a User (user.openshift.io) change
type UserWebhook struct {
	mu sync.Mutex
	s  runtime.Scheme
}

type userRequest struct {
	Metadata struct {
		Name string `json:"name"`
	} `json:"metadata"`
}

// TimeoutSeconds implements Webhook interface
func (s *UserWebhook) TimeoutSeconds() int32 { return 2 }

// MatchPolicy implements Webhook interface
func (s *UserWebhook) MatchPolicy() admissionregv1.MatchPolicyType { return admissionregv1.Equivalent }

// Name implements Webhook interface
func (s *UserWebhook) Name() string { return WebhookName }

// FailurePolicy implements Webhook interface
func (s *UserWebhook) FailurePolicy() admissionregv1.FailurePolicyType { return admissionregv1.Ignore }

// Rules implements Webhook interface
func (s *UserWebhook) Rules() []admissionregv1.RuleWithOperations { return rules }

// GetURI implements Webhook interface
func (s *UserWebhook) GetURI() string { return "/user-validation" }

// SideEffects implements Webhook interface
func (s *UserWebhook) SideEffects() admissionregv1.SideEffectClass {
	return admissionregv1.SideEffectClassNone
}

// Validate is the incoming request even valid?
func (s *UserWebhook) Validate(req admissionctl.Request) bool {
	valid := true
	valid = valid && (req.UserInfo.Username != "")

	return valid
}

func (s *UserWebhook) authorized(request admissionctl.Request) admissionctl.Response {
	var ret admissionctl.Response
	var err error
	userReq := &userRequest{}

	// if we delete, then look to OldObject in the request.
	if request.Operation == v1beta1.Delete {
		err = json.Unmarshal(request.OldObject.Raw, userReq)
	} else {
		err = json.Unmarshal(request.Object.Raw, userReq)
	}
	if err != nil {
		ret = admissionctl.Errored(http.StatusBadRequest, err)
		return ret
	}

	// Admin kube admin users can do whatever they want
	if utils.SliceContains(request.AdmissionRequest.UserInfo.Username, kubeAdminUsernames) {
		ret = admissionctl.Allowed("Admin users are allowed")
		ret.UID = request.AdmissionRequest.UID
		return ret
	}

	// If it's a protected user kind, perform other checks to require requestors be a member of an admin group.
	if strings.HasSuffix(userReq.Metadata.Name, protectedUserSuffix) {
		for _, userGroup := range request.AdmissionRequest.UserInfo.Groups {
			if utils.SliceContains(userGroup, adminGroups) {
				ret = admissionctl.Allowed("Members of admin group are allowed")
				ret.UID = request.AdmissionRequest.UID
				return ret
			}
		}
		// not an admin group member, so denied
		log.Info("Denying access", "request", request.AdmissionRequest)
		ret = admissionctl.Denied("User not authorized")
		ret.UID = request.AdmissionRequest.UID
		return ret
	}

	ret = admissionctl.Allowed("Allowed by RBAC")
	ret.UID = request.AdmissionRequest.UID
	return ret
}

// HandleRequest hndles the incoming HTTP request
func (s *UserWebhook) HandleRequest(w http.ResponseWriter, r *http.Request) {

	s.mu.Lock()
	defer s.mu.Unlock()
	request, _, err := utils.ParseHTTPRequest(r)
	if err != nil {
		log.Error(err, "Error parsing HTTP Request Body")
		responsehelper.SendResponse(w, admissionctl.Errored(http.StatusBadRequest, err))
		return
	}
	// Is this a valid request?
	if !s.Validate(request) {
		resp := admissionctl.Errored(http.StatusBadRequest, fmt.Errorf("Could not parse Namespace from request"))
		resp.UID = request.AdmissionRequest.UID
		responsehelper.SendResponse(w, resp)
		return
	}
	// should the request be authorized?

	responsehelper.SendResponse(w, s.authorized(request))

}

// NewWebhook creates a new webhook
func NewWebhook() *UserWebhook {
	scheme := runtime.NewScheme()
	v1beta1.AddToScheme(scheme)
	corev1.AddToScheme(scheme)

	return &UserWebhook{
		s: *scheme,
	}
}
