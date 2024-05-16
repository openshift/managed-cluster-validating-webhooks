package podimagespec

import (
	"fmt"
	"net/http"
	"regexp"

	"github.com/openshift/managed-cluster-validating-webhooks/pkg/webhooks/utils"

	admissionregv1 "k8s.io/api/admissionregistration/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	admissionctl "sigs.k8s.io/controller-runtime/pkg/webhook/admission"
)

const (
	WebhookName string = "podimagespec-mutation"
	docString   string = `OpenShift debugging tools on Managed OpenShift clusters must be available even if internal image registry is removed.`
)

var (
	timeout int32 = 2
	scope         = admissionregv1.NamespacedScope
	rules         = []admissionregv1.RuleWithOperations{
		{
			Operations: []admissionregv1.OperationType{
				admissionregv1.Create,
			},
			Rule: admissionregv1.Rule{
				APIGroups:   []string{""},
				APIVersions: []string{"v1"},
				Resources:   []string{"pods"},
				Scope:       &scope,
			},
		},
	}
	log = logf.Log.WithName(WebhookName)
)

// PodImageSpecWebhook mutates an image spec in a pod
type PodImageSpecWebhook struct {
	s runtime.Scheme
}

// NewWebhook creates the new webhook
func NewWebhook() *PodImageSpecWebhook {
	scheme := runtime.NewScheme()
	return &PodImageSpecWebhook{
		s: *scheme,
	}
}

// Authorized implements Webhook interface
func (s *PodImageSpecWebhook) Authorized(request admissionctl.Request) admissionctl.Response {
	//Implement authorized next
	return s.authorizeOrMutate(request)
}

// authorizeOrMutate decides whether the Request requires mutation before it's allowed to proceed.
func (s *PodImageSpecWebhook) authorizeOrMutate(request admissionctl.Request) admissionctl.Response {
	var ret admissionctl.Response
	pod, err := s.renderPod(request)
	if err != nil {
		log.Error(err, "Couldn't render a Pod from the incoming request")
		return admissionctl.Errored(http.StatusBadRequest, err)
	}

	for _ ,container := range pod.Spec.Containers {
		err := mutateContainerImageSpec(container)
		if err != nil {
			return admissionctl.Errored(http.StatusBadRequest, err)
	}

	ret = admissionctl.Patched(
		fmt.Sprintf("images on pod %s mutated for reliablity", pod.GetName()),
	)
	

	log.Info(fmt.Sprintf("images on pod %s mutated for reliablity", pod.GetName()))
	// ret.Complete() sets the UID and finalizes the patch
	ret.Complete(request)
	return ret
}

func (s *PodImageSpecWebhook) renderPod(req admissionctl.Request) (*corev1.Pod, error) {
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

func checkContainerImageSpecByRegex(container corev1.Container) (bool, string, string, string, error) {
	regex, err := regexp.Compile(`(image-registry.openshift-image-registry.svc:5000\/\)\(?P<namespace>openshift)(/)(?P<image>\S*)(:)(?P<tag>\S*)`)
	if err != nil {
		return false, "", "", "", err
	}

	matches := regex.FindStringSubmatch(container.Image)
	namespaceIndex := regex.SubexpIndex("namespace")
	imageIndex := regex.SubexpIndex("image")
	tagIndex := regex.SubexpIndex("tag")
	
	if regex.MatchString(container.Image) {
		return true, matches[namespaceIndex], matches[imageIndex], matches[tagIndex], nil
	}

	return false, "", "", "", nil
}

func mutateContainerImageSpec(container corev1.Container) error {
	matched, namespace, image, tag, err := checkContainerImageSpecByRegex(container)
	if err != nil {
		return err
	}

	if matched {
		// TODO: We need to pull the raw image spec to replace the image spec
		// ImageStreams have the raw image spec by namespace and name ie: oc get is -A
		// Also this needs to be a jsonpatch path
		container.Image = "rawimagespec"
	}

	return nil
}

// GetURI implements Webhook interface
func (s *PodImageSpecWebhook) GetURI() string {
	return "/" + WebhookName
}

// Validate implements Webhook interface
func (s *PodImageSpecWebhook) Validate(request admissionctl.Request) bool {
	valid := true
	valid = valid && (request.UserInfo.Username != "")
	valid = valid && (request.Kind.Kind == "Pod")

	return valid
}

// Name implements Webhook interface
func (s *PodImageSpecWebhook) Name() string {
	return WebhookName
}

// FailurePolicy implements Webhook interface
func (s *PodImageSpecWebhook) FailurePolicy() admissionregv1.FailurePolicyType {
	return admissionregv1.Ignore
}

// MatchPolicy implements Webhook interface
func (s *PodImageSpecWebhook) MatchPolicy() admissionregv1.MatchPolicyType {
	return admissionregv1.Equivalent
}

// Rules implements Webhook interface
func (s *PodImageSpecWebhook) Rules() []admissionregv1.RuleWithOperations {
	return rules
}

// ObjectSelector implements Webhook interface
func (s *PodImageSpecWebhook) ObjectSelector() *metav1.LabelSelector {
	return nil
}

// SideEffects implements Webhook interface
func (s *PodImageSpecWebhook) SideEffects() admissionregv1.SideEffectClass {
	return admissionregv1.SideEffectClassNone
}

// TimeoutSeconds implements Webhook interface
func (s *PodImageSpecWebhook) TimeoutSeconds() int32 {
	return timeout
}

// Doc implements Webhook interface
func (s *PodImageSpecWebhook) Doc() string {
	return (docString)
}

// SyncSetLabelSelector returns the label selector to use in the SyncSet.
// Return utils.DefaultLabelSelector() to stick with the  default
func (s *PodImageSpecWebhook) SyncSetLabelSelector() metav1.LabelSelector {
	return utils.DefaultLabelSelector()
}

// HypershiftEnabled indicates that this webhook is compatible with hosted
// control plane clusters
func (s *PodImageSpecWebhook) HypershiftEnabled() bool { return true }

