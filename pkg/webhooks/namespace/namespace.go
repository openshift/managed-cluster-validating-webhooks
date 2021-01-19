package namespace

import (
	"fmt"
	"net/http"
	"regexp"
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
	WebhookName                  string = "namespace-validation"
	privilegedNamespace          string = `(^kube.*|^openshift.*|^default$|^redhat.*)`
	badNamespace                 string = `(^com$|^io$|^in$)`
	privilegedServiceAccounts    string = `^system:serviceaccounts:(kube.*|openshift.*|default|redhat.*)`
	layeredProductNamespace      string = `^redhat.*`
	layeredProductAdminGroupName string = "layered-sre-cluster-admins"
)

var (
	clusterAdminUsers = []string{"kube:admin", "system:admin"}
	sreAdminGroups    = []string{"osd-sre-admins", "osd-sre-cluster-admins"}

	privilegedNamespaceRe       = regexp.MustCompile(privilegedNamespace)
	badNamespaceRe              = regexp.MustCompile(badNamespace)
	privilegedServiceAccountsRe = regexp.MustCompile(privilegedServiceAccounts)
	layeredProductNamespaceRe   = regexp.MustCompile(layeredProductNamespace)

	log = logf.Log.WithName(WebhookName)

	scope = admissionregv1.ClusterScope
	rules = []admissionregv1.RuleWithOperations{
		{
			Operations: []admissionregv1.OperationType{"CREATE", "UPDATE", "DELETE"},
			Rule: admissionregv1.Rule{
				APIGroups:   []string{""},
				APIVersions: []string{"*"},
				Resources:   []string{"namespaces"},
				Scope:       &scope,
			},
		},
	}
)

// NamespaceWebhook validates a Namespace change
type NamespaceWebhook struct {
	mu sync.Mutex
	s  runtime.Scheme
}

// TimeoutSeconds implements Webhook interface
func (s *NamespaceWebhook) TimeoutSeconds() int32 { return 2 }

// MatchPolicy implements Webhook interface
func (s *NamespaceWebhook) MatchPolicy() admissionregv1.MatchPolicyType {
	return admissionregv1.Equivalent
}

// Name implements Webhook interface
func (s *NamespaceWebhook) Name() string { return WebhookName }

// FailurePolicy implements Webhook interface
func (s *NamespaceWebhook) FailurePolicy() admissionregv1.FailurePolicyType {
	return admissionregv1.Ignore
}

// Rules implements Webhook interface
func (s *NamespaceWebhook) Rules() []admissionregv1.RuleWithOperations { return rules }

// GetURI implements Webhook interface
func (s *NamespaceWebhook) GetURI() string { return "/namespace-validation" }

// SideEffects implements Webhook interface
func (s *NamespaceWebhook) SideEffects() admissionregv1.SideEffectClass {
	return admissionregv1.SideEffectClassNone
}

// Validate - Make sure we're working with a well-formed Admission Request object
func (s *NamespaceWebhook) Validate(req admissionctl.Request) bool {
	valid := true
	valid = valid && (req.UserInfo.Username != "")
	valid = valid && (req.Kind.Kind == "Namespace")

	return valid
}

// renderNamespace pluck out the Namespace from the Object or OldObject
func (s *NamespaceWebhook) renderNamespace(req admissionctl.Request) (*corev1.Namespace, error) {
	decoder, err := admissionctl.NewDecoder(&s.s)
	if err != nil {
		return nil, err
	}
	namespace := &corev1.Namespace{}
	if len(req.OldObject.Raw) > 0 {
		err = decoder.DecodeRaw(req.OldObject, namespace)
	} else {
		err = decoder.Decode(req, namespace)
	}
	if err != nil {
		return nil, err
	}
	return namespace, nil
}

// Is the request authorized?
func (s *NamespaceWebhook) authorized(request admissionctl.Request) admissionctl.Response {
	log.Info("Request log", "request", request)
	var ret admissionctl.Response
	ns, err := s.renderNamespace(request)
	if err != nil {
		log.Error(err, "Couldn't render a Namespace from the incoming request")
		return admissionctl.Errored(http.StatusBadRequest, err)
	}
	// L49-L56
	// service accounts making requests will include their name in the group
	for _, group := range request.UserInfo.Groups {
		if privilegedServiceAccountsRe.Match([]byte(group)) {
			ret = admissionctl.Allowed("Privileged service accounts may access")
			ret.UID = request.AdmissionRequest.UID
			return ret
		}
	}
	// L58-L62
	// This must be prior to privileged namespace check
	if utils.SliceContains(layeredProductAdminGroupName, request.UserInfo.Groups) &&
		layeredProductNamespaceRe.Match([]byte(ns.GetName())) {
		ret = admissionctl.Allowed("Layered product admins may access")
		ret.UID = request.AdmissionRequest.UID
		return ret
	}
	// L64-73
	if privilegedNamespaceRe.Match([]byte(ns.GetName())) {
		amISREAdmin := false
		amIClusterAdmin := utils.SliceContains(request.UserInfo.Username, clusterAdminUsers)

		for _, group := range sreAdminGroups {
			if utils.SliceContains(group, request.UserInfo.Groups) {
				amISREAdmin = true
				break
			}
		}
		if amIClusterAdmin || amISREAdmin {
			ret = admissionctl.Allowed("Cluster and SRE admins may access")
			ret.UID = request.AdmissionRequest.UID
			return ret
		}
		log.Info("Non-admin attempted to access a privileged namespace (eg matching this regex)", "regex", privilegedNamespace, "request", request.AdmissionRequest)
		ret = admissionctl.Denied(fmt.Sprintf("Prevented from accessing Red Hat managed namespaces. Customer workloads should be placed in customer namespaces, and should not match this regular expression: %s", privilegedNamespace))
		ret.UID = request.AdmissionRequest.UID
		return ret
	}

	if badNamespaceRe.Match([]byte(ns.GetName())) {
		amISREAdmin := false
		amIClusterAdmin := utils.SliceContains(request.UserInfo.Username, clusterAdminUsers)

		for _, group := range sreAdminGroups {
			if utils.SliceContains(group, request.UserInfo.Groups) {
				amISREAdmin = true
				break
			}
		}
		if amIClusterAdmin || amISREAdmin {
			ret = admissionctl.Allowed("Cluster and SRE admins may access")
			ret.UID = request.AdmissionRequest.UID
			return ret
		}
		log.Info("Non-admin attempted to access a potentially harmful namespace (eg matching this regex)", "regex", badNamespace, "request", request.AdmissionRequest)
		ret = admissionctl.Denied(fmt.Sprintf("Prevented from creating a potentially harmful namespace. Customer namespaces should not match this regular expression, as this would impact DNS resolution: %s", badNamespace))
		ret.UID = request.AdmissionRequest.UID
		return ret
	}
	// L75-L77
	ret = admissionctl.Allowed("RBAC allowed")
	ret.UID = request.AdmissionRequest.UID
	return ret
}

// HandleRequest Decide if the incoming request is allowed
// Based on https://github.com/openshift/managed-cluster-validating-webhooks/blob/ad1ecb38621c485b5832eea729244e3b5ef354cc/src/webhook/namespace_validation.py
func (s *NamespaceWebhook) HandleRequest(w http.ResponseWriter, r *http.Request) {

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
		responsehelper.SendResponse(w,
			admissionctl.Errored(http.StatusBadRequest,
				fmt.Errorf("Could not parse Namespace from request")))
		return
	}
	// should the request be authorized?

	responsehelper.SendResponse(w, s.authorized(request))

}

// NewWebhook creates a new webhook
func NewWebhook() *NamespaceWebhook {
	scheme := runtime.NewScheme()
	v1beta1.AddToScheme(scheme)
	corev1.AddToScheme(scheme)

	return &NamespaceWebhook{
		s: *scheme,
	}
}
