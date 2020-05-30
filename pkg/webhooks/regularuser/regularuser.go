package regularuser

import (
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
	WebhookName string = "regular-user-validation"
)

var (
	adminGroups = []string{"osd-sre-admins", "osd-sre-cluster-admins"}

	scope = admissionregv1.AllScopes
	rules = []admissionregv1.RuleWithOperations{
		{
			Operations: []admissionregv1.OperationType{"*"},
			Rule: admissionregv1.Rule{
				APIGroups: []string{
					"autoscaling.openshift.io",
					"cloudcredential.openshift.io",
					"machine.openshift.io",
					"admissionregistration.k8s.io",
					"cloudingress.managed.openshift.io",
					"veleros.managed.openshift.io",
				},
				APIVersions: []string{"*"},
				Resources:   []string{"*/*"},
				Scope:       &scope,
			},
		},
		{
			Operations: []admissionregv1.OperationType{"*"},
			Rule: admissionregv1.Rule{
				APIGroups:   []string{"config.openshift.io"},
				APIVersions: []string{"*"},
				Resources:   []string{"clusterversions", "clusterversions/status"},
				Scope:       &scope,
			},
		},
		{
			Operations: []admissionregv1.OperationType{"*"},
			Rule: admissionregv1.Rule{
				APIGroups:   []string{""},
				APIVersions: []string{"*"},
				Resources:   []string{"nodes", "nodes/*"},
				Scope:       &scope,
			},
		},
		{
			Operations: []admissionregv1.OperationType{"*"},
			Rule: admissionregv1.Rule{
				APIGroups:   []string{"managed.openshift.io"},
				APIVersions: []string{"*"},
				Resources:   []string{"subjectpermissions", "subjectpermissions/*"},
				Scope:       &scope,
			},
		},
	}
	log = logf.Log.WithName(WebhookName)
)

// NamespaceWebhook validates a Namespace change
type RegularuserWebhook struct {
	mu sync.Mutex
	s  runtime.Scheme
}

// TimeoutSeconds implements Webhook interface
func (s *RegularuserWebhook) TimeoutSeconds() int32 { return 2 }

// MatchPolicy implements Webhook interface
func (s *RegularuserWebhook) MatchPolicy() admissionregv1.MatchPolicyType {
	return admissionregv1.Equivalent
}

// Name implements Webhook interface
func (s *RegularuserWebhook) Name() string { return WebhookName }

// FailurePolicy implements Webhook interface
func (s *RegularuserWebhook) FailurePolicy() admissionregv1.FailurePolicyType {
	return admissionregv1.Ignore
}

// Rules implements Webhook interface
func (s *RegularuserWebhook) Rules() []admissionregv1.RuleWithOperations { return rules }

// GetURI implements Webhook interface
func (s *RegularuserWebhook) GetURI() string { return "/regularuser-validation" }

// SideEffects implements Webhook interface
func (s *RegularuserWebhook) SideEffects() admissionregv1.SideEffectClass {
	return admissionregv1.SideEffectClassNone
}

// Validate is the incoming request even valid?
func (s *RegularuserWebhook) Validate(req admissionctl.Request) bool {
	valid := true
	valid = valid && (req.UserInfo.Username != "")

	return valid
}

func (s *RegularuserWebhook) authorized(request admissionctl.Request) admissionctl.Response {
	var ret admissionctl.Response

	if request.AdmissionRequest.UserInfo.Username == "system:unauthenticated" {
		// This could highlight a significant problem with RBAC since an
		// unauthenticated user should have no permissions.
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
	for _, userGroup := range request.UserInfo.Groups {
		if utils.SliceContains(userGroup, adminGroups) {
			ret = admissionctl.Allowed("Members of admin groups are allowed")
			ret.UID = request.AdmissionRequest.UID
			return ret
		}
	}

	log.Info("Denying access", "request", request.AdmissionRequest)
	ret = admissionctl.Denied("Denied")
	ret.UID = request.AdmissionRequest.UID
	return ret
}

// HandleRequest hndles the incoming HTTP request
func (s *RegularuserWebhook) HandleRequest(w http.ResponseWriter, r *http.Request) {

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
func NewWebhook() *RegularuserWebhook {
	scheme := runtime.NewScheme()
	v1beta1.AddToScheme(scheme)
	corev1.AddToScheme(scheme)

	return &RegularuserWebhook{
		s: *scheme,
	}
}
