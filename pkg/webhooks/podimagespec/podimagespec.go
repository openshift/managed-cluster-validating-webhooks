package podimagespec

import (
	"context"
	"fmt"
	"net/http"
	"regexp"

	"github.com/openshift/managed-cluster-validating-webhooks/pkg/k8sutil"
	"github.com/openshift/managed-cluster-validating-webhooks/pkg/webhooks/utils"
	"gomodules.xyz/jsonpatch/v2"

	imagestreamv1 "github.com/openshift/api/image/v1"
	configv1 "github.com/openshift/api/imageregistry/v1"
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
	imageRegex = regexp.MustCompile(`(image-registry\.openshift-image-registry\.svc:5000\/)(?P<namespace>\S*)(/)(?P<image>\S*)(:)(?P<tag>\S*)`)
)

// PodImageSpecWebhook mutates an image spec in a pod
type PodImageSpecWebhook struct {
	s          *runtime.Scheme
	configV1   configv1.Config
	imageV1    imagestreamv1.Image
	kubeClient client.Client
}

// NewWebhook creates the new webhook
func NewWebhook() *PodImageSpecWebhook {
	scheme := runtime.NewScheme()
	err := configv1.Install(scheme)
	if err != nil {
		fmt.Println("Error:", err)
		return nil
	}
	return &PodImageSpecWebhook{
		s: scheme,
	}
}

// CheckImageRegistryStatus checks the status of the image registry service
func (s *PodImageSpecWebhook) CheckImageRegistryStatus(ctx context.Context) (bool, error) {
	var err error
	if s.kubeClient == nil {
		s.kubeClient, err = k8sutil.KubeClient(s.s)
		if err != nil {
			return false, err
		}
	}

	err = s.kubeClient.Get(ctx, client.ObjectKey{Name: "cluster"}, &s.configV1)
	if err != nil {
		return false, fmt.Errorf("failed to get image registry config: %v", err)
	}

	// if image registry is set to managed then it is operational
	if s.configV1.Spec.ManagementState == operatorv1.Managed {
		return true, nil
	} else {
		return false, nil
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

	for i := range pod.Spec.Containers {
		container := &pod.Spec.Containers[i]
		ret, err := s.authorizeOrMutateContainer(container)
		ret.UID = request.AdmissionRequest.UID
		if err != nil {
			return admissionctl.Errored(http.StatusInternalServerError, err)
		}
	}

	for i := range pod.Spec.InitContainers {
		container := &pod.Spec.InitContainers[i]
		ret, err := s.authorizeOrMutateContainer(container)
		ret.UID = request.AdmissionRequest.UID
		if err != nil {
			return admissionctl.Errored(http.StatusInternalServerError, err)
		}
	}

	ret.Complete(request)
	return ret
}

func (s *PodImageSpecWebhook) authorizeOrMutateContainer(container *corev1.Container) (admissionctl.Response, error) {
	var ret admissionctl.Response
	//1. Regex match
	matched, namespace, image, _, err := checkContainerImageSpecByRegex(container.Image)
	if err != nil {
		return admissionctl.Errored(http.StatusBadRequest, err), err
	}
	if namespace != "openshift" {
		return admissionctl.Allowed("Pod image spec is valid"), nil
	}
	//if the regex matches, check image-registry status
	if matched {
		ctx := context.Background()
		//check if image-registry is enabled
		registryAvailable, err := s.CheckImageRegistryStatus(ctx)
		if err != nil {
			log.Error(err, "Failed to check image registry status")
			return admissionctl.Errored(http.StatusBadRequest, err), err
		}
		// if image registry is not available mutate the container image spec
		if !registryAvailable {
			patch, err := s.buildPatchOperation(image, namespace, ctx)
			if err != nil {
				return admissionctl.Errored(http.StatusBadRequest, err), err
			}
			ret = admissionctl.Patched(fmt.Sprintf("image for container %s mutated for reliability", container.Name), *patch)
		} else {
			ret = admissionctl.Allowed("Image registry is available, no mutation required")
		}
	} else {
		ret = admissionctl.Allowed("Pod image spec is valid")
	}
	return ret, nil
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

// checkContainerImageSpecByRegex checks to see if the image is in the openshift namespace in the internal registry
func checkContainerImageSpecByRegex(imagespec string) (bool, string, string, string, error) {

	matches := imageRegex.FindStringSubmatch(imagespec)
	if matches == nil {
		return false, "", "", "", nil
	}
	namespaceIndex := imageRegex.SubexpIndex("namespace")
	imageIndex := imageRegex.SubexpIndex("image")
	tagIndex := imageRegex.SubexpIndex("tag")
	return true, matches[namespaceIndex], matches[imageIndex], matches[tagIndex], nil
}

func (s *PodImageSpecWebhook) buildPatchOperation(image string, namespace string, ctx context.Context) (*jsonpatch.JsonPatchOperation, error) {
	var err error
	if s.kubeClient == nil {
		s.kubeClient, err = k8sutil.KubeClient(s.s)
		if err != nil {
			return nil, err
		}
	}
	// get the image refrence from the imagestream
	err = s.kubeClient.Get(ctx, client.ObjectKey{Name: image, Namespace: namespace}, &s.imageV1)
	if err != nil {
		return nil, fmt.Errorf("failed to get image spec: %v", err)
	}

	patchPath := "spec/containers/image"
	patch := jsonpatch.NewOperation("replace", patchPath, s.imageV1.DockerImageReference)
	return &patch, nil
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
