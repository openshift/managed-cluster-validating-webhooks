package scc

import (
	"fmt"
	"net/http"

	securityv1 "github.com/openshift/api/security/v1"
	"github.com/openshift/managed-cluster-validating-webhooks/pkg/webhooks/utils"
	admissionv1 "k8s.io/api/admission/v1"
	admissionregv1 "k8s.io/api/admissionregistration/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	admissionctl "sigs.k8s.io/controller-runtime/pkg/webhook/admission"
)

const (
	WebhookName string = "scc-validation"
	docString   string = `Managed OpenShift Customers may not modify the following default SCCs: %s`
)

var (
	timeout        int32 = 2
	log                  = logf.Log.WithName(WebhookName)
	anyuidPriority int32 = 10
	scope                = admissionregv1.ClusterScope
	rules                = []admissionregv1.RuleWithOperations{
		{
			Operations: []admissionregv1.OperationType{"CREATE", "UPDATE", "DELETE"},
			Rule: admissionregv1.Rule{
				APIGroups:   []string{"security.openshift.io"},
				APIVersions: []string{"*"},
				Resources:   []string{"securitycontextconstraints"},
				Scope:       &scope,
			},
		},
	}
	defaultSCCs = []string{
		"anyuid",
		"hostaccess",
		"hostmount-anyuid",
		"hostnetwork",
		"node-exporter",
		"nonroot",
		"privileged",
		"restricted",
		"pipelines-scc",
	}
)

type SCCWebHook struct {
	s runtime.Scheme
}

// NewWebhook creates the new webhook
func NewWebhook() *SCCWebHook {
	scheme := runtime.NewScheme()
	admissionv1.AddToScheme(scheme)
	corev1.AddToScheme(scheme)

	return &SCCWebHook{
		s: *scheme,
	}
}

// Authorized implements Webhook interface
func (s *SCCWebHook) Authorized(request admissionctl.Request) admissionctl.Response {
	return s.authorized(request)
}

func (s *SCCWebHook) authorized(request admissionctl.Request) admissionctl.Response {
	var ret admissionctl.Response

	scc, err := s.renderSCC(request)
	if err != nil {
		log.Error(err, "Couldn't render a SCC from the incoming request")
		return admissionctl.Errored(http.StatusBadRequest, err)
	}

	if request.Operation == admissionv1.Delete {
		if isDefaultSCC(scc) {
			ret = admissionctl.Denied("Deleting default SCCs is not allowed")
			ret.UID = request.AdmissionRequest.UID
			return ret
		}
	}

	if request.Operation == admissionv1.Update {
		if isDefaultSCC(scc) {
			ret = admissionctl.Denied("Modifying default SCCs is not allowed")
			ret.UID = request.AdmissionRequest.UID
			return ret
		}
	}

	if request.Operation == admissionv1.Create {
		if SCCwithHigherPriority(scc) {
			ret = admissionctl.Denied(fmt.Sprintf("Creating SCC with priority higher than %d is not allowed", anyuidPriority))
			ret.UID = request.AdmissionRequest.UID
			return ret
		}
	}

	ret = admissionctl.Allowed("Request is allowed")
	ret.UID = request.AdmissionRequest.UID
	return ret
}

// renderSCC render the SCC object from the requests
func (s *SCCWebHook) renderSCC(request admissionctl.Request) (*securityv1.SecurityContextConstraints, error) {
	decoder, err := admissionctl.NewDecoder(&s.s)
	if err != nil {
		return nil, err
	}
	scc := &securityv1.SecurityContextConstraints{}
	if len(request.OldObject.Raw) > 0 {
		err = decoder.DecodeRaw(request.OldObject, scc)
	} else {
		err = decoder.DecodeRaw(request.Object, scc)
	}
	if err != nil {
		return nil, err
	}
	return scc, nil
}

// isDefaultSCC checks if the request is going to operate on the SCC in the
// default list
func isDefaultSCC(scc *securityv1.SecurityContextConstraints) bool {
	for _, s := range defaultSCCs {
		if scc.Name == s {
			return true
		}
	}
	return false
}

// SCCwithHigherPriority checks if the created SCC has the higher priority
// than 10 (default to anyuid)
func SCCwithHigherPriority(scc *securityv1.SecurityContextConstraints) bool {
	if scc.Priority != nil {
		if *scc.Priority > anyuidPriority {
			return true
		}
	}
	return false
}

// GetURI implements Webhook interface
func (s *SCCWebHook) GetURI() string {
	return "/" + WebhookName
}

// Validate implements Webhook interface
func (s *SCCWebHook) Validate(request admissionctl.Request) bool {
	valid := true
	valid = valid && (request.UserInfo.Username != "")
	valid = valid && (request.Kind.Kind == "SecurityContextConstraint")

	return valid
}

// Name implements Webhook interface
func (s *SCCWebHook) Name() string {
	return WebhookName
}

// FailurePolicy implements Webhook interface
func (s *SCCWebHook) FailurePolicy() admissionregv1.FailurePolicyType {
	return admissionregv1.Ignore
}

// MatchPolicy implements Webhook interface
func (s *SCCWebHook) MatchPolicy() admissionregv1.MatchPolicyType {
	return admissionregv1.Equivalent
}

// Rules implements Webhook interface
func (s *SCCWebHook) Rules() []admissionregv1.RuleWithOperations {
	return rules
}

// ObjectSelector implements Webhook interface
func (s *SCCWebHook) ObjectSelector() *metav1.LabelSelector {
	return nil
}

// SideEffects implements Webhook interface
func (s *SCCWebHook) SideEffects() admissionregv1.SideEffectClass {
	return admissionregv1.SideEffectClassNone
}

// TimeoutSeconds implements Webhook interface
func (s *SCCWebHook) TimeoutSeconds() int32 {
	return timeout
}

// Doc implements Webhook interface
func (s *SCCWebHook) Doc() string {
	return fmt.Sprintf(docString, defaultSCCs)
}

// SyncSetLabelSelector returns the label selector to use in the SyncSet.
// Return utils.DefaultLabelSelector() to stick with the default
func (s *SCCWebHook) SyncSetLabelSelector() metav1.LabelSelector {
	return utils.DefaultLabelSelector()
}
