package service

import (
	"fmt"
	"net/http"
	"slices"
	"strings"

	"github.com/openshift/managed-cluster-validating-webhooks/pkg/webhooks/utils"
	"gomodules.xyz/jsonpatch/v2"

	admissionregv1 "k8s.io/api/admissionregistration/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	admissionctl "sigs.k8s.io/controller-runtime/pkg/webhook/admission"
)

const (
	WebhookName           string = "service-mutation"
	docString             string = `LoadBalancer-type services on Managed OpenShift clusters must contain an additional annotation for managed policy compliance.`
	annotationKey         string = "service.beta.kubernetes.io/aws-load-balancer-additional-resource-tags"
	annotationValuePrefix string = "red-hat-managed="
	annotationValueSuffix string = "true"
)

var (
	timeout int32 = 2
	scope         = admissionregv1.NamespacedScope
	rules         = []admissionregv1.RuleWithOperations{
		{
			Operations: []admissionregv1.OperationType{
				admissionregv1.Create,
				admissionregv1.Update,
			},
			Rule: admissionregv1.Rule{
				APIGroups:   []string{""},
				APIVersions: []string{"v1"},
				Resources:   []string{"services"},
				Scope:       &scope,
			},
		},
	}
	log = logf.Log.WithName(WebhookName)
)

// ServiceWebhook mutates a Service change
type ServiceWebhook struct {
	s runtime.Scheme
}

// NewWebhook creates the new webhook
func NewWebhook() *ServiceWebhook {
	scheme := runtime.NewScheme()
	return &ServiceWebhook{
		s: *scheme,
	}
}

// Authorized implements Webhook interface
func (s *ServiceWebhook) Authorized(request admissionctl.Request) admissionctl.Response {
	//Implement authorized next
	return s.authorizeOrMutate(request)
}

// authorizeOrMutate decides whether the Request requires mutation before it's allowed to proceed.
// For this webhook, this function ensures that any LoadBalancer-type Service touched by this
// Request is annotated with the proper compliance tags
func (s *ServiceWebhook) authorizeOrMutate(request admissionctl.Request) admissionctl.Response {
	var ret admissionctl.Response

	service, err := s.renderService(request)
	if err != nil {
		log.Error(err, "Could not render a Service from the incoming request")
		return admissionctl.Errored(http.StatusBadRequest, err)
	}

	if service.Spec.Type != corev1.ServiceTypeLoadBalancer {
		ret = admissionctl.Allowed("Non-LoadBalancer Services are exempt from compliance annotation requirements")
		ret.UID = request.AdmissionRequest.UID
		return ret
	}

	if hasRedHatManagedTag(service.GetAnnotations()) {
		ret = admissionctl.Allowed(fmt.Sprintf("Service '%s' contains the proper compliance annotation", service.GetName()))
		ret.UID = request.AdmissionRequest.UID
		return ret
	}

	// If we've gotten this far, then mutation is necessary
	ret = admissionctl.Patched(
		fmt.Sprintf("Added necessary compliance annotation to service '%s'", service.GetName()),
		buildPatch(service.GetAnnotations()),
	)
	log.Info(fmt.Sprintf("%s operation on service %s mutated for compliance", request.Operation, service.GetName()))
	// ret.Complete() sets the UID and finalizes the patch
	ret.Complete(request)
	return ret
}

// hasRedHatManagedTag checks if a Service's "aws-load-balancer-additional-resource-tags"
// annotation contains the necessary value for compliance with managed policies.
// Set serviceAnnotations param to output of service.GetAnnotations()
func hasRedHatManagedTag(serviceAnnotations map[string]string) bool {
	// User could theoretically specify multiple comma-separated tags in this annotation
	tags := strings.Split(serviceAnnotations[annotationKey], ",")
	return slices.Contains(tags, annotationValuePrefix+annotationValueSuffix)
}

// buildPatch constructs a JSONPatch that either adds the necessary annotation
// to the Service, or replaces the existing annotation with one that contains
// the necessary tag value (along with pre-existing tags that don't conflict).
// Set serviceAnnotations param to output of service.GetAnnotations()
func buildPatch(serviceAnnotations map[string]string) jsonpatch.JsonPatchOperation {
	patchPath := "/metadata/annotations"
	if serviceAnnotations != nil {
		rfc6901Encoder := strings.NewReplacer("~", "~0", "/", "~1")
		patchPath += "/" + rfc6901Encoder.Replace(annotationKey)
	}

	existingAnnotationValue, hasAnnotation := serviceAnnotations[annotationKey]

	if !hasAnnotation {
		if serviceAnnotations == nil {
			// No annotation key at all
			return jsonpatch.NewOperation("add", patchPath, map[string]string{annotationKey: annotationValuePrefix + annotationValueSuffix})
		}
		// Has annotation key but is empty
		return jsonpatch.NewOperation("add", patchPath, annotationValuePrefix+annotationValueSuffix)
	}

	// Break down existing annotation and rebuild starting with required tag
	existingTags := strings.Split(existingAnnotationValue, ",")
	newTags := []string{annotationValuePrefix + annotationValueSuffix}
	for _, exTag := range existingTags {
		if !strings.HasPrefix(exTag, annotationValuePrefix) {
			// Existing tag doesn't conflict with required tag, so add it back
			newTags = append(newTags, exTag)
		}
	}

	return jsonpatch.NewOperation("replace", patchPath, strings.Join(newTags, ","))
}

// renderService extracts the Service from the incoming request
func (s *ServiceWebhook) renderService(req admissionctl.Request) (*corev1.Service, error) {
	decoder, err := admissionctl.NewDecoder(&s.s)
	if err != nil {
		return nil, err
	}
	service := &corev1.Service{}

	err = decoder.Decode(req, service)
	if err != nil {
		return nil, err
	}
	return service, nil
}

// GetURI implements Webhook interface
func (s *ServiceWebhook) GetURI() string {
	return "/" + WebhookName
}

// Validate implements Webhook interface
func (s *ServiceWebhook) Validate(request admissionctl.Request) bool {
	valid := true
	valid = valid && (request.UserInfo.Username != "")
	valid = valid && (request.Kind.Kind == "Service")

	return valid
}

// Name implements Webhook interface
func (s *ServiceWebhook) Name() string {
	return WebhookName
}

// FailurePolicy implements Webhook interface
func (s *ServiceWebhook) FailurePolicy() admissionregv1.FailurePolicyType {
	return admissionregv1.Ignore
}

// MatchPolicy implements Webhook interface
func (s *ServiceWebhook) MatchPolicy() admissionregv1.MatchPolicyType {
	return admissionregv1.Equivalent
}

// Rules implements Webhook interface
func (s *ServiceWebhook) Rules() []admissionregv1.RuleWithOperations {
	return rules
}

// ObjectSelector implements Webhook interface
func (s *ServiceWebhook) ObjectSelector() *metav1.LabelSelector {
	return nil
}

// SideEffects implements Webhook interface
func (s *ServiceWebhook) SideEffects() admissionregv1.SideEffectClass {
	return admissionregv1.SideEffectClassNone
}

// TimeoutSeconds implements Webhook interface
func (s *ServiceWebhook) TimeoutSeconds() int32 {
	return timeout
}

// Doc implements Webhook interface
func (s *ServiceWebhook) Doc() string {
	return (docString)
}

// SyncSetLabelSelector returns the label selector to use in the SyncSet.
// Return utils.DefaultLabelSelector() to stick with the  default
func (s *ServiceWebhook) SyncSetLabelSelector() metav1.LabelSelector {
	return utils.DefaultLabelSelector()
}

func (s *ServiceWebhook) ClassicEnabled() bool { return false }

// HypershiftEnabled indicates that this webhook is compatible with hosted
// control plane clusters
func (s *ServiceWebhook) HypershiftEnabled() bool { return true }
