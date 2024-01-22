package service

import (
	"fmt"
	"net/http"

	"github.com/openshift/managed-cluster-validating-webhooks/pkg/webhooks/utils"

	admissionregv1 "k8s.io/api/admissionregistration/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	admissionctl "sigs.k8s.io/controller-runtime/pkg/webhook/admission"
)

const (
	WebhookName     string = "service-mutation"
	docString       string = `LoadBalancer-type services on Managed OpenShift clusters must contain an additional annotation for managed policy compliance.`
	annotationKey   string = "service.beta.kubernetes.io/aws-load-balancer-additional-resource-tags"
	annotationValue string = "red-hat-managed=true"
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
	return s.authorized(request)
}

func (s *ServiceWebhook) authorized(request admissionctl.Request) admissionctl.Response {
	var ret admissionctl.Response

	service, err := s.renderService(request)
	if err != nil {
		log.Error(err, "Could not render a Service from the incoming request")
		return admissionctl.Errored(http.StatusBadRequest, err)
	}

	if !isLoadBalancer(service) {
		ret = admissionctl.Allowed("Non-LoadBalancer Services are exempt from compliance annotation requirements")
		ret.UID = request.AdmissionRequest.UID
		return ret
	}

	if hasRedHatManagedAnnotation(service) {
		log.Info(fmt.Sprintf("%s operation detected on compliant service: %s", request.Operation, service.GetName()))
		ret = admissionctl.Allowed(fmt.Sprintf("Service '%s' contains the proper compliance annotation", service.GetName()))
		ret.UID = request.AdmissionRequest.UID
		return ret
	}

	ret = admissionctl.Denied(fmt.Sprintf("Service '%s' is missing a necesssary compliance annotation", service.GetName()))
	ret.UID = request.AdmissionRequest.UID
	return ret
}

// hasRedHatManagedAnnotation checks if the Service has the annotation required for managed policy compliance
func hasRedHatManagedAnnotation(service *corev1.Service) bool {
	return service.GetAnnotations()[annotationKey] == annotationValue
}

// isLoadBalancer checks if the Service is a LoadBalancer
func isLoadBalancer(service *corev1.Service) bool {
	return service.Spec.Type == corev1.ServiceTypeLoadBalancer
}

func (s *ServiceWebhook) renderService(req admissionctl.Request) (*corev1.Service, error) {
	decoder, err := admissionctl.NewDecoder(&s.s)
	if err != nil {
		return nil, err
	}
	service := &corev1.Service{}

	if len(req.OldObject.Raw) > 0 {
		err = decoder.DecodeRaw(req.OldObject, service)
	} else {
		err = decoder.Decode(req, service)
	}
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

// HypershiftEnabled indicates that this webhook is compatible with hosted
// control plane clusters
func (s *ServiceWebhook) HypershiftEnabled() bool { return true }
