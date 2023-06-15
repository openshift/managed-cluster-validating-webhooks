package ingresscontroller

import (
	"fmt"
	"net/http"
	"regexp"
	"strings"

	operatorv1 "github.com/openshift/api/operator/v1"
	"github.com/openshift/managed-cluster-validating-webhooks/pkg/webhooks/utils"
	admissionregv1 "k8s.io/api/admissionregistration/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	admissionctl "sigs.k8s.io/controller-runtime/pkg/webhook/admission"

	logf "sigs.k8s.io/controller-runtime/pkg/log"
)

const (
	WebhookName   string = "ingresscontroller-validation"
	docString     string = `Managed OpenShift Customer may create IngressControllers without necessary taints. This can cause those workloads to be provisioned on infra or master nodes.`
	allowedGroups string = `^system:serviceaccounts:(kube.*|openshift.*|default|redhat.*|osde2e-[a-z0-9]{5})`
)

var (
	log   = logf.Log.WithName(WebhookName)
	scope = admissionregv1.NamespacedScope
	rules = []admissionregv1.RuleWithOperations{
		{
			Operations: []admissionregv1.OperationType{admissionregv1.Create, admissionregv1.Update},
			Rule: admissionregv1.Rule{
				APIGroups:   []string{"operator.openshift.io"},
				APIVersions: []string{"*"},
				Resources:   []string{"ingresscontroller", "ingresscontrollers"},
				Scope:       &scope,
			},
		},
	}
	allowedUsers = []string{
		"backplane-cluster-admin",
	}
	allowedGroupsRe = regexp.MustCompile(allowedGroups)
)

type IngressControllerWebhook struct {
	s runtime.Scheme
}

// ObjectSelector implements Webhook interface
func (wh *IngressControllerWebhook) ObjectSelector() *metav1.LabelSelector { return nil }

func (wh *IngressControllerWebhook) Doc() string {
	return fmt.Sprintf(docString)
}

// TimeoutSeconds implements Webhook interface
func (wh *IngressControllerWebhook) TimeoutSeconds() int32 { return 1 }

// MatchPolicy implements Webhook interface
func (wh *IngressControllerWebhook) MatchPolicy() admissionregv1.MatchPolicyType {
	return admissionregv1.Equivalent
}

// Name implements Webhook interface
func (wh *IngressControllerWebhook) Name() string { return WebhookName }

// FailurePolicy implements Webhook interface and defines how unrecognized errors and timeout errors from the admission webhook are handled. Allowed values are Ignore or Fail.
// Ignore means that an error calling the webhook is ignored and the API request is allowed to continue.
// It's important to leave the FailurePolicy set to Ignore because otherwise the pod will fail to be created as the API request will be rejected.
func (wh *IngressControllerWebhook) FailurePolicy() admissionregv1.FailurePolicyType {
	return admissionregv1.Ignore
}

// Rules implements Webhook interface
func (wh *IngressControllerWebhook) Rules() []admissionregv1.RuleWithOperations { return rules }

// GetURI implements Webhook interface
func (wh *IngressControllerWebhook) GetURI() string { return "/" + WebhookName }

// SideEffects implements Webhook interface
func (wh *IngressControllerWebhook) SideEffects() admissionregv1.SideEffectClass {
	return admissionregv1.SideEffectClassNone
}

// Validate implements Webhook interface
func (wh *IngressControllerWebhook) Validate(req admissionctl.Request) bool {
	valid := true
	valid = valid && (req.UserInfo.Username != "")
	valid = valid && (req.Kind.Kind == "IngressController")

	return valid
}

func (wh *IngressControllerWebhook) renderIngressController(req admissionctl.Request) (*operatorv1.IngressController, error) {
	decoder, err := admissionctl.NewDecoder(&wh.s)
	if err != nil {
		return nil, err
	}
	ic := &operatorv1.IngressController{}
	err = decoder.DecodeRaw(req.Object, ic)

	if err != nil {
		return nil, err
	}

	return ic, nil
}

func (wh *IngressControllerWebhook) authorized(request admissionctl.Request) admissionctl.Response {
	var ret admissionctl.Response
	ic, err := wh.renderIngressController(request)
	if err != nil {
		log.Error(err, "Couldn't render an IngressController from the incoming request")
		return admissionctl.Errored(http.StatusBadRequest, err)
	}

	// Check if the group does not have exceptions
	if !isAllowedUserGroup(request) {
		for _, toleration := range ic.Spec.NodePlacement.Tolerations {
			if strings.Contains(toleration.Key, "node-role.kubernetes.io/master") || strings.Contains(toleration.Key, "node-role.kubernetes.io/infra") {
				ret = admissionctl.Denied("Not allowed to provision ingress controller pods with toleration for master and infra nodes.")
				ret.UID = request.AdmissionRequest.UID

				return ret
			}
		}
	}

	ret = admissionctl.Allowed("IngressController operation is allowed")
	ret.UID = request.AdmissionRequest.UID

	return ret
}

// isAllowedUserGroup checks if the user or group is allowed to perform the action
func isAllowedUserGroup(request admissionctl.Request) bool {

	if utils.SliceContains(request.UserInfo.Username, allowedUsers) {
		return true
	}

	for _, group := range request.UserInfo.Groups {
		if allowedGroupsRe.Match([]byte(group)) {
			return true
		}
	}

	return false
}

// Authorized implements Webhook interface
func (wh *IngressControllerWebhook) Authorized(request admissionctl.Request) admissionctl.Response {
	return wh.authorized(request)
}

// SyncSetLabelSelector returns the label selector to use in the SyncSet.
func (s *IngressControllerWebhook) SyncSetLabelSelector() metav1.LabelSelector {
	return utils.DefaultLabelSelector()
}

func (s *IngressControllerWebhook) HypershiftEnabled() bool { return false }

// NewWebhook creates a new webhook
func NewWebhook() *IngressControllerWebhook {
	scheme := runtime.NewScheme()
	return &IngressControllerWebhook{
		s: *scheme,
	}
}
