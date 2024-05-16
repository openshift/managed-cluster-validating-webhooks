package pod

import (
	"fmt"
	"net/http"
	"os"
	"regexp"
	"sync"

	admissionv1 "k8s.io/api/admission/v1"
	admissionregv1 "k8s.io/api/admissionregistration/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	admissionctl "sigs.k8s.io/controller-runtime/pkg/webhook/admission"

	hookconfig "github.com/openshift/managed-cluster-validating-webhooks/pkg/config"
	"github.com/openshift/managed-cluster-validating-webhooks/pkg/webhooks/utils"
)

const (
	WebhookName           string = "pod-validation"
	unprivilegedNamespace string = `(openshift-logging|openshift-operators)`
	docString             string = `Managed OpenShift Customers may use tolerations on Pods that could cause those Pods to be scheduled on infra or master nodes.`
)

var (
	unprivilegedNamespaceRe = regexp.MustCompile(unprivilegedNamespace)
	log                     = logf.Log.WithName(WebhookName)

	scope = admissionregv1.NamespacedScope
	rules = []admissionregv1.RuleWithOperations{
		{
			Operations: []admissionregv1.OperationType{admissionregv1.OperationAll},
			Rule: admissionregv1.Rule{
				APIGroups:   []string{"v1"},
				APIVersions: []string{"*"},
				Resources:   []string{"pods"},
				Scope:       &scope,
			},
		},
	}
)

type PodWebhook struct {
	mu sync.Mutex
	s  runtime.Scheme
}

// ObjectSelector implements Webhook interface
func (s *PodWebhook) ObjectSelector() *metav1.LabelSelector { return nil }

func (s *PodWebhook) Doc() string {
	return fmt.Sprintf(docString)
}

// TimeoutSeconds implements Webhook interface
func (s *PodWebhook) TimeoutSeconds() int32 { return 1 }

// MatchPolicy implements Webhook interface
func (s *PodWebhook) MatchPolicy() admissionregv1.MatchPolicyType {
	return admissionregv1.Equivalent
}

// Name implements Webhook interface
func (s *PodWebhook) Name() string { return WebhookName }

// FailurePolicy implements Webhook interface and defines how unrecognized errors and timeout errors from the admission webhook are handled. Allowed values are Ignore or Fail.
// Ignore means that an error calling the webhook is ignored and the API request is allowed to continue.
// It's important to leave the FailurePolicy set to Ignore because otherwise the pod will fail to be created as the API request will be rejected.
func (s *PodWebhook) FailurePolicy() admissionregv1.FailurePolicyType {
	return admissionregv1.Ignore
}

// Rules implements Webhook interface
func (s *PodWebhook) Rules() []admissionregv1.RuleWithOperations { return rules }

// GetURI implements Webhook interface
func (s *PodWebhook) GetURI() string { return "/" + WebhookName }

// SideEffects implements Webhook interface
func (s *PodWebhook) SideEffects() admissionregv1.SideEffectClass {
	return admissionregv1.SideEffectClassNone
}

// Validate implements Webhook interface
func (s *PodWebhook) Validate(req admissionctl.Request) bool {
	valid := true
	valid = valid && (req.UserInfo.Username != "")
	valid = valid && (req.Kind.Kind == "Pod")

	return valid
}

func (s *PodWebhook) renderPod(req admissionctl.Request) (*corev1.Pod, error) {
	decoder, err := admissionctl.NewDecoder(&s.s)
	if err != nil {
		return nil, err
	}
	pod := &corev1.Pod{}
	if len(req.OldObject.Raw) > 0 {
		err = decoder.DecodeRaw(req.OldObject, pod)
	} else {
		err = decoder.DecodeRaw(req.Object, pod)
	}
	if err != nil {
		return nil, err
	}
	return pod, nil
}

func isRequestPrivileged(namespace string) bool {
	if hookconfig.IsPrivilegedNamespace(namespace) {
		if unprivilegedNamespaceRe.Match([]byte(namespace)) {
			return false
		}
		return true
	}
	return false
}

// Authorized implements Webhook interface
func (s *PodWebhook) Authorized(request admissionctl.Request) admissionctl.Response {
	return s.authorized(request)
}

func (s *PodWebhook) authorized(request admissionctl.Request) admissionctl.Response {
	var ret admissionctl.Response
	pod, err := s.renderPod(request)
	if err != nil {
		log.Error(err, "Couldn't render a Pod from the incoming request")
		return admissionctl.Errored(http.StatusBadRequest, err)
	}

	// If the incoming Pod is aimed at a privileged namespace except for unprivilegedNamespace, allow it to do whatever it wants.
	// However, if the pod is targeting a customer's namespace (aka non-privileged), then it may not tolerate certain master/infra node taints.
	if !isRequestPrivileged(pod.ObjectMeta.GetNamespace()) {
		for _, toleration := range pod.Spec.Tolerations {
			if toleration.Key == "node-role.kubernetes.io/infra" && toleration.Effect == corev1.TaintEffectNoSchedule {
				ret = admissionctl.Denied("Not allowed to schedule a pod with NoSchedule taint on infra node")
				ret.UID = request.AdmissionRequest.UID
				return ret
			}
			if toleration.Key == "node-role.kubernetes.io/infra" && toleration.Effect == corev1.TaintEffectPreferNoSchedule {
				ret = admissionctl.Denied("Not allowed to schedule a pod with PreferNoSchedule taint on infra node")
				ret.UID = request.AdmissionRequest.UID
				return ret
			}
			if toleration.Key == "node-role.kubernetes.io/master" && toleration.Effect == corev1.TaintEffectNoSchedule {
				ret = admissionctl.Denied("Not allowed to schedule a pod with NoSchedule taint on master node")
				ret.UID = request.AdmissionRequest.UID
				return ret
			}
			if toleration.Key == "node-role.kubernetes.io/master" && toleration.Effect == corev1.TaintEffectPreferNoSchedule {
				ret = admissionctl.Denied("Not allowed to schedule a pod with PreferNoSchedule taint on master node")
				ret.UID = request.AdmissionRequest.UID
				return ret
			}
		}
	}

	// Hereafter, all requests are controlled by RBAC
	ret = admissionctl.Allowed("Allowed to create Pod because of RBAC")
	ret.UID = request.AdmissionRequest.UID
	return ret
}

// SyncSetLabelSelector returns the label selector to use in the SyncSet.
func (s *PodWebhook) SyncSetLabelSelector() metav1.LabelSelector {
	return utils.DefaultLabelSelector()
}

func (s *PodWebhook) ClassicEnabled() bool { return true }

func (s *PodWebhook) HypershiftEnabled() bool { return false }

// NewWebhook creates a new webhook
func NewWebhook() *PodWebhook {
	scheme := runtime.NewScheme()
	err := admissionv1.AddToScheme(scheme)
	if err != nil {
		log.Error(err, "Fail adding admissionsv1 scheme to PodWebhook")
		os.Exit(1)
	}

	err = corev1.AddToScheme(scheme)
	if err != nil {
		log.Error(err, "Fail adding corev1 scheme to PodWebhook")
		os.Exit(1)
	}

	return &PodWebhook{
		s: *scheme,
	}
}
