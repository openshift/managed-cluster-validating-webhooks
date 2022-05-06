package techpreviewnoupgrade

import (
	"fmt"
	"net/http"

	admissionv1 "k8s.io/api/admission/v1"
	admissionregv1 "k8s.io/api/admissionregistration/v1"
	utils "github.com/openshift/managed-cluster-validating-webhooks/pkg/webhooks/utils"
	corev1 "k8s.io/api/core/v1"
	configv1 "github.com/openshift/api/config/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	admissionctl "sigs.k8s.io/controller-runtime/pkg/webhook/admission"
	"k8s.io/apimachinery/pkg/runtime" 
)

const (
	WebhookName				string = "techpreviewnoupgrade-validation"
	unprivilegedNamespace	string = `(openshift-logging|openshift-operators)`
	docString				string = `Managed OpenShift Customers may use TechPreviewNoUpgrade FeatureGate that could prevent any future ability to do a y-stream upgrade to their clusters.`
)

var (
	log                     = logf.Log.WithName(WebhookName)

	scope = admissionregv1.NamespacedScope
	rules = []admissionregv1.RuleWithOperations{
		{
			Operations: []admissionregv1.OperationType{admissionregv1.Create, admissionregv1.Update, admissionregv1.Delete},
			Rule: admissionregv1.Rule{
				APIGroups:   []string{"v1"},
				APIVersions: []string{"*"},
				Resources:   []string{"featureGates"},
				Scope:       &scope,
			},
		},
	}
)

type TechPreviewNoUpgradeWebhook struct {
	s runtime.Scheme
}

func (s *TechPreviewNoUpgradeWebhook) ObjectSelector() *metav1.LabelSelector { return nil }

func (s *TechPreviewNoUpgradeWebhook) Doc() string {
	return fmt.Sprintf(docString)
}

func (s *TechPreviewNoUpgradeWebhook) TimeoutSeconds() int32 { return 1 }

func (s *TechPreviewNoUpgradeWebhook) MatchPolicy() admissionregv1.MatchPolicyType {
	return admissionregv1.Equivalent
}

func (s *TechPreviewNoUpgradeWebhook) Name() string { return WebhookName }

func (s *TechPreviewNoUpgradeWebhook) FailurePolicy() admissionregv1.FailurePolicyType {
	return admissionregv1.Ignore
}

func (s *TechPreviewNoUpgradeWebhook) Rules() []admissionregv1.RuleWithOperations { return rules }

func (s *TechPreviewNoUpgradeWebhook) GetURI() string { return "/" + WebhookName }

func (s *TechPreviewNoUpgradeWebhook) SideEffects() admissionregv1.SideEffectClass {
	return admissionregv1.SideEffectClassNone
}

func (s *TechPreviewNoUpgradeWebhook) Validate(req admissionctl.Request) bool {
	valid := true
	valid = valid && (req.UserInfo.Username != "")
	valid = valid && (req.Kind.Kind == "FeatureGate")

	return valid
}

func (s *TechPreviewNoUpgradeWebhook) Authorized(request admissionctl.Request) admissionctl.Response {
	return s.authorized(request)
}

func (s *TechPreviewNoUpgradeWebhook) SyncSetLabelSelector() metav1.LabelSelector {
	return utils.DefaultLabelSelector()
}

func (s *TechPreviewNoUpgradeWebhook) renderFeatureGate(request admissionctl.Request) (*configv1.FeatureGate, error) {	
	decoder, err := admissionctl.NewDecoder(&s.s)
	if err != nil {
		return nil, err
	}
	featureGate := &configv1.FeatureGate{}
	if len(request.OldObject.Raw) > 0 {
		err = decoder.DecodeRaw(request.OldObject, featureGate)
	} else {
		err = decoder.DecodeRaw(request.Object, featureGate)
	}
	if err != nil {
		return nil, err
	}

	return featureGate, nil
}

func (s *TechPreviewNoUpgradeWebhook) authorized(request admissionctl.Request) admissionctl.Response {
	featureGate, err := s.renderFeatureGate(request)

	if err != nil {
		return admissionctl.Errored(http.StatusBadRequest, err)
	}

	var ret admissionctl.Response

	if featureGate.Spec.FeatureSet == "TechPreviewNoUpgrade" {
		ret = admissionctl.Denied("The TechPreviewNoUpgrade Feature Gate is not allowed")
		ret.UID = request.AdmissionRequest.UID

		return ret
	}

	log.Info("Allowing access", "request", request.AdmissionRequest)
	ret = admissionctl.Allowed("Features are allowed")
	ret.UID = request.AdmissionRequest.UID

	return ret
}

func hasTechPreviewNoUpgrade(features []string) bool {
	return (utils.SliceContains("TechPreviewNoUpgrade", features))
}

func NewWebhook() *TechPreviewNoUpgradeWebhook {
	scheme := runtime.NewScheme()
	admissionv1.AddToScheme(scheme)
	corev1.AddToScheme(scheme)

	return &TechPreviewNoUpgradeWebhook {
		s: *scheme,
	}
}