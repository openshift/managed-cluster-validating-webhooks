package node

import (
	"net/http"
	"slices"
	"strings"

	"github.com/openshift/managed-cluster-validating-webhooks/pkg/localmetrics"
	"github.com/openshift/managed-cluster-validating-webhooks/pkg/webhooks/utils"
	admissionv1 "k8s.io/api/admission/v1"
	admissionregv1 "k8s.io/api/admissionregistration/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"
	admissionctl "sigs.k8s.io/controller-runtime/pkg/webhook/admission"
)

// This webhook is intended to stop non-Hypershift Managed OpenShift (ie: OSD
// and traditional ROSA) clusters' users from modifying node resources

const (
	WebhookName string = "node-validation-osd"
	docString   string = `Managed OpenShift customers may not alter Node objects.`
)

var (
	adminGroups = []string{"system:serviceaccounts:openshift-backplane-srep"}
	adminUsers  = []string{"backplane-cluster-admin"}
	scope       = admissionregv1.AllScopes
	rules       = []admissionregv1.RuleWithOperations{
		{
			Operations: []admissionregv1.OperationType{
				admissionregv1.OperationType(admissionv1.Create),
				admissionregv1.OperationType(admissionv1.Update),
				admissionregv1.OperationType(admissionv1.Delete),
			},
			Rule: admissionregv1.Rule{
				APIGroups:   []string{""},
				APIVersions: []string{"*"},
				Resources:   []string{"nodes", "nodes/*"},
				Scope:       &scope,
			},
		},
	}
	log = logf.Log.WithName(WebhookName)
)

// NodeWebhook protects various objects from unauthorized manipulation
type NodeWebhook struct {
	scheme *runtime.Scheme
}

func (s *NodeWebhook) Doc() string {
	return docString
}

// ObjectSelector implements Webhook interface
func (s *NodeWebhook) ObjectSelector() *metav1.LabelSelector { return nil }

// TimeoutSeconds implements Webhook interface
func (s *NodeWebhook) TimeoutSeconds() int32 { return 2 }

// MatchPolicy implements Webhook interface
func (s *NodeWebhook) MatchPolicy() admissionregv1.MatchPolicyType {
	return admissionregv1.Equivalent
}

// Name implements Webhook interface
func (s *NodeWebhook) Name() string { return WebhookName }

// FailurePolicy implements Webhook interface
func (s *NodeWebhook) FailurePolicy() admissionregv1.FailurePolicyType {
	return admissionregv1.Ignore
}

// Rules implements Webhook interface
func (s *NodeWebhook) Rules() []admissionregv1.RuleWithOperations { return rules }

// GetURI implements Webhook interface
func (s *NodeWebhook) GetURI() string { return "/node-validation-osd" }

// SideEffects implements Webhook interface
func (s *NodeWebhook) SideEffects() admissionregv1.SideEffectClass {
	return admissionregv1.SideEffectClassNone
}

// Validate is the incoming request even valid?
func (s *NodeWebhook) Validate(req admissionctl.Request) bool {
	valid := true
	valid = valid && (req.UserInfo.Username != "")

	return valid
}

// Authorized implements Webhook interface
func (s *NodeWebhook) Authorized(request admissionctl.Request) admissionctl.Response {
	return s.authorized(request)
}

func (s *NodeWebhook) authorized(request admissionctl.Request) admissionctl.Response {
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
	if slices.Contains(adminUsers, request.AdmissionRequest.UserInfo.Username) {
		ret = admissionctl.Allowed("Specified admin users are allowed")
		ret.UID = request.AdmissionRequest.UID
		return ret
	}
	for _, userGroup := range request.UserInfo.Groups {
		if slices.Contains(adminGroups, userGroup) {
			ret = admissionctl.Allowed("Members of admin groups are allowed")
			ret.UID = request.AdmissionRequest.UID
			return ret
		}
	}

	//Checks for non-adminGroups non-ceeGroup non-adminGroups users
	if request.Kind.Kind == "Node" {
		node := corev1.Node{}
		decoder, err := admission.NewDecoder(s.scheme)
		if err != nil {
			return admission.Errored(http.StatusBadRequest, err)
		}

		switch request.Operation {
		case admissionv1.Delete:
			// request.Object is empty for the DELETE operation
			// https://kubernetes.io/docs/reference/access-authn-authz/extensible-admission-controllers/#request
			if err := decoder.DecodeRaw(request.OldObject, &node); err != nil {
				log.Error(err, "failed to render a Node from request.OldObject")
				return admission.Errored(http.StatusBadRequest, err)
			}
		default:
			if err := decoder.Decode(request, &node); err != nil {
				log.Error(err, "failed to render a Node from request.Object")
				return admission.Errored(http.StatusBadRequest, err)
			}
		}
		log.Info("Processing request for", "node", node.Name, "operation", request.Operation, "user", request.UserInfo.Username)

		if request.Operation == admissionv1.Delete {
			localmetrics.IncrementNodeWebhookBlockedRequest(request.UserInfo.Username)
			ret = admissionctl.Denied("Prevented from deleting nodes. This is in an effort to prevent harmful actions that may cause unintended consequences or affect the stability of the cluster. If you have any questions about this, please reach out to Red Hat support at https://access.redhat.com/support")
			ret.UID = request.AdmissionRequest.UID
			return ret
		}

		if _, ok := node.Labels["node-role.kubernetes.io/infra"]; ok {
			localmetrics.IncrementNodeWebhookBlockedRequest(request.UserInfo.Username)
			log.Info("Denying access to infra node")
			ret = admissionctl.Denied("Prevented from modifying Red Hat managed infra nodes. This is in an effort to prevent harmful actions that may cause unintended consequences or affect the stability of the cluster. If you have any questions about this, please reach out to Red Hat support at https://access.redhat.com/support")
			ret.UID = request.AdmissionRequest.UID
			return ret
		}

		if _, ok := node.Labels["node-role.kubernetes.io/control-plane"]; ok {
			localmetrics.IncrementNodeWebhookBlockedRequest(request.UserInfo.Username)
			log.Info("Denying access to control plane node")
			ret = admissionctl.Denied("Prevented from modifying Red Hat managed control plane nodes. This is in an effort to prevent harmful actions that may cause unintended consequences or affect the stability of the cluster. If you have any questions about this, please reach out to Red Hat support at https://access.redhat.com/support")
			ret.UID = request.AdmissionRequest.UID
			return ret
		}

		if _, ok := node.Labels["node-role.kubernetes.io/master"]; ok {
			localmetrics.IncrementNodeWebhookBlockedRequest(request.UserInfo.Username)
			log.Info("Denying access to control plane node")
			ret = admissionctl.Denied("Prevented from modifying Red Hat managed master nodes. This is in an effort to prevent harmful actions that may cause unintended consequences or affect the stability of the cluster. If you have any questions about this, please reach out to Red Hat support at https://access.redhat.com/support")
			ret.UID = request.AdmissionRequest.UID
			return ret
		}

		ret = admissionctl.Allowed("Allowed to modify worker nodes")
		ret.UID = request.AdmissionRequest.UID
		return ret
	}

	// Should never get here
	log.Info("Unexpectedly denying access", "request", request.AdmissionRequest)
	ret = admissionctl.Denied("Prevented from accessing Red Hat managed resources. This is in an effort to prevent harmful actions that may cause unintended consequences or affect the stability of the cluster. If you have any questions about this, please reach out to Red Hat support at https://access.redhat.com/support")
	ret.UID = request.AdmissionRequest.UID
	return ret
}

// SyncSetLabelSelector returns the label selector to use in the SyncSet.
func (s *NodeWebhook) SyncSetLabelSelector() metav1.LabelSelector {
	return utils.DefaultLabelSelector()
}

func (s *NodeWebhook) ClassicEnabled() bool { return true }

func (s *NodeWebhook) HypershiftEnabled() bool { return false }

// NewWebhook creates a new webhook
func NewWebhook() *NodeWebhook {
	return &NodeWebhook{
		scheme: runtime.NewScheme(),
	}
}
