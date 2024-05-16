package clusterlogging

import (
	"fmt"
	"net/http"
	"os"
	"regexp"
	"strconv"

	cl "github.com/openshift/cluster-logging-operator/apis/logging/v1"
	utils "github.com/openshift/managed-cluster-validating-webhooks/pkg/webhooks/utils"
	admissionregv1 "k8s.io/api/admissionregistration/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	admissionctl "sigs.k8s.io/controller-runtime/pkg/webhook/admission"
)

const (
	ClusterLoggingKind string = "ClusterLogging"
	WebhookName        string = "clusterlogging-validation"
	docString          string = `Managed OpenShift Customers may set log retention outside the allowed range of 0-7 days`
)

var (
	reTimeUnit = regexp.MustCompile("^(?P<number>\\d+)(?P<unit>[yMwdhHms])$")
	log        = logf.Log.WithName(WebhookName)

	scope = admissionregv1.NamespacedScope
	rules = []admissionregv1.RuleWithOperations{
		{
			Operations: []admissionregv1.OperationType{admissionregv1.Create, admissionregv1.Update},
			Rule: admissionregv1.Rule{
				APIGroups:   []string{"logging.openshift.io"},
				APIVersions: []string{"v1"},
				Resources:   []string{"clusterloggings"},
				Scope:       &scope,
			},
		},
	}
)

type ClusterloggingWebhook struct {
	s runtime.Scheme
}

// ObjectSelector implements Webhook interface
func (s *ClusterloggingWebhook) ObjectSelector() *metav1.LabelSelector { return nil }

func (s *ClusterloggingWebhook) Doc() string {
	return docString
}

// TimeoutSeconds implements Webhook interface
func (s *ClusterloggingWebhook) TimeoutSeconds() int32 { return 1 }

// MatchPolicy implements Webhook interface
func (s *ClusterloggingWebhook) MatchPolicy() admissionregv1.MatchPolicyType {
	return admissionregv1.Equivalent
}

// Name implements Webhook interface
func (s *ClusterloggingWebhook) Name() string { return WebhookName }

// FailurePolicy implements Webhook interface and defines how unrecognized errors and timeout errors from the admission webhook are handled. Allowed values are Ignore or Fail.
// Ignore means that an error calling the webhook is ignored and the API request is allowed to continue.
// It's important to leave the FailurePolicy set to Ignore because otherwise the pod will fail to be created as the API request will be rejected.
func (s *ClusterloggingWebhook) FailurePolicy() admissionregv1.FailurePolicyType {
	return admissionregv1.Ignore
}

// Rules implements Webhook interface
func (s *ClusterloggingWebhook) Rules() []admissionregv1.RuleWithOperations { return rules }

// GetURI implements Webhook interface
func (s *ClusterloggingWebhook) GetURI() string { return "/" + WebhookName }

// SideEffects implements Webhook interface
func (s *ClusterloggingWebhook) SideEffects() admissionregv1.SideEffectClass {
	return admissionregv1.SideEffectClassNone
}

// Validate implements Webhook interface
func (s *ClusterloggingWebhook) Validate(req admissionctl.Request) bool {
	valid := true
	valid = valid && (req.UserInfo.Username != "")
	valid = valid && (req.Kind.Kind == ClusterLoggingKind)

	return valid
}

type TimeUnit string

type retentionPolicyValidator struct {
	name       string
	hint       string
	lowerBound TimeUnit
	upperBound TimeUnit
}

func (r *retentionPolicyValidator) checkPolicy(retentionPolicy *cl.RetentionPolicySpec) (bool, admissionctl.Response) {
	isAllowed, deniedMessage, err := r.isAllowed(retentionPolicy)
	if err != nil {
		return false, admissionctl.Errored(http.StatusBadRequest, err)
	}
	if !isAllowed {
		return false, admissionctl.Denied(deniedMessage)
	}
	return true, admissionctl.Allowed("Allowed to create ClusterLogging")
}

func (r *retentionPolicyValidator) isAllowed(retentionPolicy *cl.RetentionPolicySpec) (bool, string, error) {
	if retentionPolicy == nil {
		return false, "The entered retention policy is not allowed. " + r.name + " must not be unset. Hint: " + r.hint, nil
	}

	isAllowedRetentionDaysLower, err := le(r.lowerBound, TimeUnit(retentionPolicy.MaxAge))
	if err != nil {
		log.Error(err, "Couldn't compare timeunits")
		return false, "", err
	}
	isAllowedRetentionDaysUpper, err := le(TimeUnit(retentionPolicy.MaxAge), r.upperBound)
	if err != nil {
		log.Error(err, "Couldn't compare timeunits")
		return false, "", err
	}

	if !isAllowedRetentionDaysLower || !isAllowedRetentionDaysUpper {
		return false, "The entered RetentionPolicy " + r.name + " is not allowed. " + r.hint, nil
	}

	return true, "", nil
}

// Authorized implements Webhook interface
func (s *ClusterloggingWebhook) Authorized(request admissionctl.Request) admissionctl.Response {
	r := s.authorized(request)
	r.UID = request.AdmissionRequest.UID
	return r
}

func (s *ClusterloggingWebhook) authorized(request admissionctl.Request) admissionctl.Response {
	clusterLogging, err := s.renderClusterLogging(request)
	if err != nil {
		return admissionctl.Errored(http.StatusBadRequest, err)
	}

	retentionPolicy := clusterLogging.Spec.LogStore.RetentionPolicy

	appValidator := retentionPolicyValidator{
		name:       "app",
		hint:       "Set MaxAge to a value <= 7d, >= 1h",
		lowerBound: TimeUnit("1h"),
		upperBound: TimeUnit("7d"),
	}
	ok, ret := appValidator.checkPolicy(retentionPolicy.App)
	if !ok {
		return ret
	}

	infraValidator := retentionPolicyValidator{
		name:       "infra",
		hint:       "MaxAge must be 1h",
		lowerBound: TimeUnit("1h"),
		upperBound: TimeUnit("1h"),
	}
	ok, ret = infraValidator.checkPolicy(retentionPolicy.Infra)
	if !ok {
		return ret
	}

	auditValidator := retentionPolicyValidator{
		name:       "audit",
		hint:       "audit log must be 1h",
		lowerBound: TimeUnit("1h"),
		upperBound: TimeUnit("1h"),
	}
	ok, ret = auditValidator.checkPolicy(retentionPolicy.Audit)
	if !ok {
		return ret
	}

	return ret
}

// renderClusterLogging decodes an *cl.ClusterLogging from the incoming request.
// If the request includes an OldObject (from an update or deletion), it will be
// preferred, otherwise, the Object will be preferred.
func (s *ClusterloggingWebhook) renderClusterLogging(request admissionctl.Request) (*cl.ClusterLogging, error) {
	decoder, err := admissionctl.NewDecoder(&s.s)
	if err != nil {
		return nil, err
	}
	clusterLogging := &cl.ClusterLogging{}
	if len(request.OldObject.Raw) > 0 {
		err = decoder.DecodeRaw(request.OldObject, clusterLogging)
	} else {
		err = decoder.DecodeRaw(request.Object, clusterLogging)
	}
	if err != nil {
		return nil, err
	}
	return clusterLogging, nil
}

func le(lhs TimeUnit, rhs TimeUnit) (bool, error) {
	lhsNumber, lhsUnit, err := parseTimeUnit(lhs)
	if err != nil {
		return false, err
	}

	rhsNumber, rhsUnit, err := parseTimeUnit(rhs)
	if err != nil {
		return false, err
	}

	return convertToSeconds(lhsNumber, lhsUnit) <= convertToSeconds(rhsNumber, rhsUnit), nil
}

func convertToSeconds(number uint64, unit string) uint64 {
	if unit == "y" {
		//This is not correct but will suffice for this webhook, since we have no valid retention > 7d
		number = number * 365
		unit = "d"
	}
	if unit == "M" {
		//This is not correct but will suffice for this webhook, since we have no valid retention > 7d
		number = number * 31
		unit = "d"
	}
	if unit == "w" {
		number = number * 7
		unit = "d"
	}

	if unit == "d" {
		number = number * 24
		unit = "h"
	}

	if unit == "h" || unit == "H" {
		number = number * 60
		unit = "m"
	}

	if unit == "m" {
		number = number * 60
	}

	return number
}

func parseTimeUnit(value TimeUnit) (uint64, string, error) {
	match := reTimeUnit.FindStringSubmatch(string(value))
	if match == nil || len(match) < 2 {
		return 0, "", fmt.Errorf("unable to parse timeunit '%s' for invalid timeunit", value)
	}

	n := match[1]
	number, err := strconv.ParseUint(n, 10, 0)
	if err != nil {
		return 0, "", fmt.Errorf("unable to parse uint '%s' ", n)
	}
	unit := match[2]
	return number, unit, nil
}

// SyncSetLabelSelector returns the label selector to use in the SyncSet.
func (s *ClusterloggingWebhook) SyncSetLabelSelector() metav1.LabelSelector {
	customLabelSelector := utils.DefaultLabelSelector()
	customLabelSelector.MatchExpressions = append(customLabelSelector.MatchExpressions,
		metav1.LabelSelectorRequirement{
			Key:      "hive.openshift.io/version-major-minor",
			Operator: metav1.LabelSelectorOpIn,
			Values: []string{
				"4.4",
				"4.5",
				"4.6",
			},
		})
	return customLabelSelector
}

func (s *ClusterloggingWebhook) ClassicEnabled() bool { return true }

func (s *ClusterloggingWebhook) HypershiftEnabled() bool { return false }

// NewWebhook creates a new webhook
func NewWebhook() *ClusterloggingWebhook {
	scheme := runtime.NewScheme()
	err := cl.AddToScheme(scheme)
	if err != nil {
		log.Error(err, "Fail adding cluster-logging scheme to ClusterloggingWebhook")
		os.Exit(1)
	}

	return &ClusterloggingWebhook{
		s: *scheme,
	}
}
