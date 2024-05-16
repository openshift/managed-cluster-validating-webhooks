package scc

import (
	"fmt"
	"net/http"
	"slices"

	securityv1 "github.com/openshift/api/security/v1"
	"github.com/openshift/managed-cluster-validating-webhooks/pkg/webhooks/utils"
	admissionv1 "k8s.io/api/admission/v1"
	admissionregv1 "k8s.io/api/admissionregistration/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	admissionctl "sigs.k8s.io/controller-runtime/pkg/webhook/admission"
)

const (
	WebhookName = "scc-validation"
	docString   = `Managed OpenShift Customers may not modify the following default SCCs: %s`
)

var (
	timeout int32 = 2
	log           = logf.Log.WithName(WebhookName)
	scope         = admissionregv1.ClusterScope
	rules         = []admissionregv1.RuleWithOperations{
		{
			Operations: []admissionregv1.OperationType{"UPDATE", "DELETE"},
			Rule: admissionregv1.Rule{
				APIGroups:   []string{"security.openshift.io"},
				APIVersions: []string{"*"},
				Resources:   []string{"securitycontextconstraints"},
				Scope:       &scope,
			},
		},
	}
	allowedUsers = []string{
		"system:serviceaccount:openshift-monitoring:cluster-monitoring-operator",
		"system:serviceaccount:openshift-cluster-version:default",
		"system:admin",
	}
	allowedGroups = []string{}
	defaultSCCs   = []string{
		"anyuid",
		"hostaccess",
		"hostmount-anyuid",
		"hostnetwork",
		"hostnetwork-v2",
		"node-exporter",
		"nonroot",
		"nonroot-v2",
		"privileged",
		"restricted",
		"restricted-v2",
	}
)

type SCCWebHook struct {
	scheme *runtime.Scheme
}

// NewWebhook creates the new webhook
func NewWebhook() *SCCWebHook {
	return &SCCWebHook{
		scheme: runtime.NewScheme(),
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

	if isDefaultSCC(scc) && !isAllowedUserGroup(request) {
		switch request.Operation {
		case admissionv1.Delete:
			log.Info(fmt.Sprintf("Deleting operation detected on default SCC: %v", scc.Name))
			ret = admissionctl.Denied(fmt.Sprintf("Deleting default SCCs %v is not allowed", defaultSCCs))
			ret.UID = request.AdmissionRequest.UID
			return ret
		case admissionv1.Update:
			log.Info(fmt.Sprintf("Updating operation detected on default SCC: %v", scc.Name))
			ret = admissionctl.Denied(fmt.Sprintf("Modifying default SCCs %v is not allowed", defaultSCCs))
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
	decoder, err := admissionctl.NewDecoder(s.scheme)
	if err != nil {
		return nil, err
	}
	scc := &securityv1.SecurityContextConstraints{}

	if len(request.OldObject.Raw) > 0 {
		err = decoder.DecodeRaw(request.OldObject, scc)
	}
	if err != nil {
		return nil, err
	}

	return scc, nil
}

// isAllowedUserGroup checks if the user or group is allowed to perform the action
func isAllowedUserGroup(request admissionctl.Request) bool {
	if slices.Contains(allowedUsers, request.UserInfo.Username) {
		return true
	}

	for _, group := range allowedGroups {
		if slices.Contains(request.UserInfo.Groups, group) {
			return true
		}
	}

	return false
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

// GetURI implements Webhook interface
func (s *SCCWebHook) GetURI() string {
	return "/" + WebhookName
}

// Validate implements Webhook interface
func (s *SCCWebHook) Validate(request admissionctl.Request) bool {
	valid := true
	valid = valid && (request.UserInfo.Username != "")
	valid = valid && (request.Kind.Kind == "SecurityContextConstraints")

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

func (s *SCCWebHook) ClassicEnabled() bool { return true }

func (s *SCCWebHook) HypershiftEnabled() bool { return true }
