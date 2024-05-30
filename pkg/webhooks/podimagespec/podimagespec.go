package podimagespec

import (
	"context"
	"fmt"
	"net/http"
	"regexp"

	"github.com/openshift/managed-cluster-validating-webhooks/pkg/k8sutil"
	"github.com/openshift/managed-cluster-validating-webhooks/pkg/webhooks/utils"

	imagestreamv1 "github.com/openshift/api/image/v1"
	registryv1 "github.com/openshift/api/imageregistry/v1"
	operatorv1 "github.com/openshift/api/operator/v1"
	admissionregv1 "k8s.io/api/admissionregistration/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
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
	log        = logf.Log.WithName(WebhookName)
	imageRegex = regexp.MustCompile(`^(image-registry\.openshift-image-registry\.svc:5000\/)(?P<namespace>\S*)(/)(?P<image>\w*)(:)(?P<tag>\S*)`)
)

// PodImageSpecWebhook mutates an image spec in a pod
type PodImageSpecWebhook struct {
	s          *runtime.Scheme
	kubeClient client.Client
}

// NewWebhook creates the new webhook
func NewWebhook() *PodImageSpecWebhook {
	scheme := runtime.NewScheme()
	return &PodImageSpecWebhook{
		s: scheme,
	}
}

// Authorized implements Webhook interface
func (s *PodImageSpecWebhook) Authorized(request admissionctl.Request) admissionctl.Response {
	var err error
	ctx := context.Background()

	if s.kubeClient == nil {
		s.kubeClient, err = k8sutil.KubeClient(s.s)
		if err != nil {
			return admissionctl.Errored(http.StatusBadRequest, err)
		}
	}

	pod, err := s.renderPod(request)
	if err != nil {
		log.Error(err, "couldn't render a Pod from the incoming request")
		return admissionctl.Errored(http.StatusBadRequest, err)
	}

	if !podContainsContainerRegexMatch(pod) {
		return admissionctl.Allowed("Pod image spec is valid")
	}

	registryAvailable, err := s.checkImageRegistryStatus(ctx)
	if err != nil {
		log.Error(err, "failed to check image registry status")
		return admissionctl.Errored(http.StatusInternalServerError, err)
	}

	if registryAvailable {
		return admissionctl.Allowed("Image registry is available, no mutation required")
	}

	mutatedPod, err := s.mutatePod(pod, ctx)
	if err != nil {
		log.Error(err, "Unable mutate pod")
		return admissionctl.Errored(http.StatusInternalServerError, err)
	}

	return admissionctl.PatchResponseFromRaw(request.Object.Raw, mutatedPod)
}

// renderPod renders the Pod in the admission Request
func (s *PodImageSpecWebhook) renderPod(request admissionctl.Request) (*corev1.Pod, error) {
	decoder, err := admissionctl.NewDecoder(s.s)
	if err != nil {
		return nil, err
	}
	pod := &corev1.Pod{}
	err = decoder.Decode(request, pod)
	if err != nil {
		return nil, err
	}
	return pod, nil
}

func podContainsContainerRegexMatch(pod *corev1.Pod) (podMatch bool) {
	podMatch = false

	for i := range pod.Spec.Containers {
		containerMatch, namespace, _, _ := checkContainerImageSpecByRegex(pod.Spec.Containers[i].Image)
		if containerMatch && namespace == "openshift" {
			podMatch = true
		}
	}

	for i := range pod.Spec.InitContainers {
		containerMatch, namespace, _, _ := checkContainerImageSpecByRegex(pod.Spec.InitContainers[i].Image)
		if containerMatch && namespace == "openshift" {
			podMatch = true
		}
	}

	return
}

func (s *PodImageSpecWebhook) mutatePod(pod *corev1.Pod, ctx context.Context) ([]byte, error) {
	mutatedPod := pod.DeepCopy()

	for i := range pod.Spec.Containers {
		imageURI, err := s.lookupImageStreamTagSpec(pod.Spec.Containers[i].Image, ctx)
		if err != nil {
			return []byte{}, err
		}
		mutatedPod.Spec.Containers[i].Image = imageURI
	}

	for i := range pod.Spec.InitContainers {
		imageURI, err := s.lookupImageStreamTagSpec(pod.Spec.InitContainers[i].Image, ctx)
		if err != nil {
			return []byte{}, err
		}
		mutatedPod.Spec.InitContainers[i].Image = imageURI
	}

	return mutatedPod.Marshal()
}

// checkImageRegistryStatus checks the status of the image registry service
func (s *PodImageSpecWebhook) checkImageRegistryStatus(ctx context.Context) (bool, error) {
	var err error
	registryV1 := &registryv1.Config{}

	err = s.kubeClient.Get(ctx, client.ObjectKey{Name: "cluster"}, registryV1)
	if err != nil {
		return false, fmt.Errorf("failed to get image registry config: %v", err)
	}

	// if image registry is set to managed then it is operational
	if registryV1.Spec.ManagementState == operatorv1.Managed {
		return true, nil
	}

	return false, nil
}

// checkContainerImageSpecByRegex checks to see if the image is in the openshift namespace in the internal registry
func checkContainerImageSpecByRegex(imagespec string) (bool, string, string, string) {
	matches := imageRegex.FindStringSubmatch(imagespec)
	if matches == nil {
		return false, "", "", ""
	}
	namespaceIndex := imageRegex.SubexpIndex("namespace")
	imageIndex := imageRegex.SubexpIndex("image")
	tagIndex := imageRegex.SubexpIndex("tag")
	return true, matches[namespaceIndex], matches[imageIndex], matches[tagIndex]
}

func (s *PodImageSpecWebhook) lookupImageStreamTagSpec(imagespec string, ctx context.Context) (string, error) {
	var err error

	matched, namespace, image, tag := checkContainerImageSpecByRegex(imagespec)
	if !matched {
		return imagespec, nil
	}

	// get the image refrence from the imagestream
	imageStreamTag := imagestreamv1.ImageStreamTag{}
	err = s.kubeClient.Get(ctx, client.ObjectKey{Name: fmt.Sprintf("%s:%s", image, tag), Namespace: namespace}, &imageStreamTag)
	if err != nil {
		return imagespec, fmt.Errorf("failed to get image spec: %v", err)
	}

	// TODO add error checking for imageStreamTag.Tag.From.Name is set
	// ie: validateImageStreamTagFromName()

	return imageStreamTag.Tag.From.Name, nil
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
	return docString
}

// SyncSetLabelSelector returns the label selector to use in the SyncSet.
// Return utils.DefaultLabelSelector() to stick with the  default
func (s *PodImageSpecWebhook) SyncSetLabelSelector() metav1.LabelSelector {
	return utils.DefaultLabelSelector()
}

// ClassicEnabled indicates that this webhook is compatible with classic clusters
func (s *PodImageSpecWebhook) ClassicEnabled() bool {
	return false
}

// HypershiftEnabled indicates that this webhook is compatible with hosted
// control plane clusters
func (s *PodImageSpecWebhook) HypershiftEnabled() bool {
	return true
}
