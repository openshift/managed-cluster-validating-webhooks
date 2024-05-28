package podimagespec

import (
	"context"
	"fmt"
	"net/http"
	"regexp"

	"github.com/openshift/managed-cluster-validating-webhooks/pkg/k8sutil"
	"github.com/openshift/managed-cluster-validating-webhooks/pkg/webhooks/utils"

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

	if s.configV1.Spec.ManagementState == operatorv1.Managed || s.configV1.Spec.ManagementState == operatorv1.Unmanaged {
		return true, nil
	} else if s.configV1.Spec.ManagementState == operatorv1.Removed {
		return false, nil
	}

	return false, fmt.Errorf("unknown managementState: %s", s.configV1.Spec.ManagementState)
}

// Authorized implements Webhook interface
func (s *PodImageSpecWebhook) Authorized(request admissionctl.Request) admissionctl.Response {
	//Implement authorized next
	return s.authorizeOrMutate(request)
}

// order of operations
// check regex
// pull image-registry status
// pull image spec

// kube client?
// generate on boot
// permissions for webhook service account
// get kubeconfig from webhook service acount
// make sure service account token is in the pod
// ask micheal shen about where to put kubeclient

// run performance tests

// authorizeOrMutate decides whether the Request requires mutation before it's allowed to proceed.
func (s *PodImageSpecWebhook) authorizeOrMutate(request admissionctl.Request) admissionctl.Response {
	var ret admissionctl.Response
	pod, err := s.renderPod(request)
	if err != nil {
		log.Error(err, "Couldn't render a Pod from the incoming request")
		return admissionctl.Errored(http.StatusBadRequest, err)
	}
	//1. Regex match
	for i := range pod.Spec.Containers {
		container := &pod.Spec.Containers[i]
		matched, namespace, _, _, err := checkContainerImageSpecByRegex(container.Image)
		if err != nil {
			return admissionctl.Errored(http.StatusBadRequest, err)
		}
		if namespace != "openshift" {
			ret.UID = request.AdmissionRequest.UID
			ret = admissionctl.Allowed("Pod image spec is valid")
			return ret
		}
		//if the regex does not match, check image-registry status
		if matched {
			ctx := context.Background()
			//check if image-registry is enabled
			registryAvailable, err := s.CheckImageRegistryStatus(ctx)
			if err != nil {
				log.Error(err, "Failed to check image registry status")
				return admissionctl.Errored(http.StatusInternalServerError, err)
			}
			if !registryAvailable {
				imageMutated, err := s.mutateContainerImageSpec(&container.Image, namespace, ctx)
				if err != nil {
					return admissionctl.Errored(http.StatusBadRequest, err)
				}
				if imageMutated {
					ret = admissionctl.Patched(
						fmt.Sprintf("images on pod %s mutated for reliability", pod.GetName()),
					)

					log.Info(fmt.Sprintf("images on pod %s mutated for reliablity", pod.GetName()))
					// ret.Complete() sets the UID and finalizes the patch
					ret.Complete(request)
				} else {
					return admissionctl.Errored(http.StatusBadRequest, err)
				}
			} else {
				ret = admissionctl.Allowed("Image registry is available, no mutation required")
				ret.UID = request.AdmissionRequest.UID
			}
		} else {
			ret = admissionctl.Allowed("Pod image spec is valid")
			ret.UID = request.AdmissionRequest.UID
		}
	}

	return ret
}

// renderPod renders the Pod in the admission Request
func (s *PodImageSpecWebhook) renderPod(request admissionctl.Request) (*corev1.Pod, error) {
	decoder, err := admissionctl.NewDecoder(s.s)
	if err != nil {
		return nil, err
	}
	pod := &corev1.Pod{}
	if len(request.OldObject.Raw) > 0 {
		err = decoder.DecodeRaw(request.OldObject, pod)
	} else {
		err = decoder.DecodeRaw(request.Object, pod)
	}
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

// mutateContainerImageSpec mutates the container image specification if it matches the internal registry pattern and the namespace is openshift.
func (s *PodImageSpecWebhook) mutateContainerImageSpec(imagespec *string, namespace string, ctx context.Context) (bool, error) {
	// TODO: We need to pull the raw image spec to replace the image spec
	// ImageStreams have the raw image spec by namespace and name ie: oc get is -A
	// The current idea is to pull this from the cluster..
	// but seems heavy handed query Kube API on every pod admiission?
	var err error
	if s.kubeClient == nil {
		s.kubeClient, err = k8sutil.KubeClient(s.s)
		if err != nil {
			return false, err
		}
	}

	err = s.kubeClient.Get(ctx, client.ObjectKey{Name: *imagespec}, &s.imageV1)
	if err != nil {
		return false, fmt.Errorf("failed to get image registry config: %v", err)
	}
	*imagespec = s.imageV1.DockerImageReference

	return true, nil
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
