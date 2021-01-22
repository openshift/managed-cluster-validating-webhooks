package regularuser

import (
	"fmt"
	"strings"
	"sync"

	"github.com/openshift/managed-cluster-validating-webhooks/pkg/webhooks/utils"
	"k8s.io/api/admission/v1beta1"
	admissionregv1 "k8s.io/api/admissionregistration/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	admissionctl "sigs.k8s.io/controller-runtime/pkg/webhook/admission"

	logf "sigs.k8s.io/controller-runtime/pkg/runtime/log"
)

const (
	WebhookName string = "regular-user-validation"
	docString   string = `Managed OpenShift customers may not manage any objects in the following APIgroups %s, nor may Managed OpenShift customers alter the ClusterVersion, Node or SubjectPermission objects.`
)

var (
	adminGroups           = []string{"osd-sre-admins", "osd-sre-cluster-admins"}
	ceeGroup       string = "osd-devaccess"
	mustGatherKind string = "MustGather"

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
					// Deny ability to manage SRE resources
					// oc get --raw /apis | jq -r '.groups[] | select(.name | contains("managed")) | .name'
					"managed.openshift.io",
					"splunkforwarder.managed.openshift.io",
					"upgrade.managed.openshift.io",
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

// RegularuserWebhook protects various objects from unauthorized manipulation
type RegularuserWebhook struct {
	mu sync.Mutex
	s  runtime.Scheme
}

func (s *RegularuserWebhook) Doc() string {
	hist := make(map[string]bool)
	for _, rule := range rules {
		for _, group := range rule.APIGroups {
			if group != "" {
				// If there's an empty API group let's not include it because it would be confusing.
				hist[group] = true
			}
		}
	}
	//dedup
	allGroups := make([]string, 0)
	for k := range hist {
		allGroups = append(allGroups, k)
	}

	return fmt.Sprintf(docString, allGroups)
}

// ObjectSelector implements Webhook interface
func (s *RegularuserWebhook) ObjectSelector() *metav1.LabelSelector { return nil }

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

// Authorized implements Webhook interface
func (s *RegularuserWebhook) Authorized(request admissionctl.Request) admissionctl.Response {
	return s.authorized(request)
}

func (s *RegularuserWebhook) authorized(request admissionctl.Request) admissionctl.Response {
	var ret admissionctl.Response
	log.Info("Request Object", "request", request)

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

		if (userGroup == ceeGroup) && (request.Kind.Kind == mustGatherKind) {
			ret = admissionctl.Allowed("Members of CEE may manage MustGather CRs")
			ret.UID = request.AdmissionRequest.UID
			return ret
		}
	}

	log.Info("Denying access", "request", request.AdmissionRequest)
	ret = admissionctl.Denied("Prevented from accessing Red Hat managed resources. This is in an effort to prevent harmful actions that may cause unintended consequences or affect the stability of the cluster. If you have any questions about this, please reach out to Red Hat support at https://access.redhat.com/support")
	ret.UID = request.AdmissionRequest.UID
	return ret
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
