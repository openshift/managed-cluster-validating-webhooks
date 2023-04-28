package imagecontentpolicies

import (
	"net/http"
	"regexp"

	"github.com/go-logr/logr"
	configv1 "github.com/openshift/api/config/v1"
	operatorv1alpha1 "github.com/openshift/api/operator/v1alpha1"
	"github.com/openshift/managed-cluster-validating-webhooks/pkg/webhooks/utils"
	admissionregv1 "k8s.io/api/admissionregistration/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"
)

const (
	WebhookName = "imagecontentpolicies-validation"
	WebhookDoc  = "Managed OpenShift customers may not create ImageContentPolicy or ImageContentSourcePolicy resources that configure mirrors for quay.io, registry.redhat.com, nor registry.access.redhat.com."
	// unauthorizedRepositoryMirrors is a regex that is used to reject certain specified repository mirrors.
	// Generally all contained regexes follow a similar pattern, i.e. rejecting quay.io or quay.io/.*
	unauthorizedRepositoryMirrors = `(^quay\.io(/.*)?$|^registry\.redhat\.io(/.*)?$|^registry\.access\.redhat\.com(/.*)?)`
)

type ImageContentPoliciesWebhook struct {
	scheme *runtime.Scheme
	log    logr.Logger
}

func NewWebhook() *ImageContentPoliciesWebhook {
	return &ImageContentPoliciesWebhook{
		scheme: runtime.NewScheme(),
		log:    logf.Log.WithName(WebhookName),
	}
}

func (w *ImageContentPoliciesWebhook) Authorized(request admission.Request) admission.Response {
	decoder, err := admission.NewDecoder(w.scheme)
	if err != nil {
		return admission.Errored(http.StatusBadRequest, err)
	}

	switch request.RequestKind.Kind {
	case "ImageContentPolicy":
		icp := configv1.ImageContentPolicy{}
		if err := decoder.Decode(request, &icp); err != nil {
			w.log.Error(err, "failed to render an ImageContentPolicy from request")
			return admission.Errored(http.StatusBadRequest, err)
		}

		if !authorizeImageContentPolicy(icp) {
			w.log.Info("denying ImageContentPolicy", "name", icp.Name)
			return utils.WebhookResponse(request, false, WebhookDoc)
		}
	case "ImageContentSourcePolicy":
		icsp := operatorv1alpha1.ImageContentSourcePolicy{}
		if err := decoder.Decode(request, &icsp); err != nil {
			w.log.Error(err, "failed to render an ImageContentSourcePolicy from request")
			return admission.Errored(http.StatusBadRequest, err)
		}

		if !authorizeImageContentSourcePolicy(icsp) {
			w.log.Info("denying ImageContentSourcePolicy", "name", icsp.Name)
			return utils.WebhookResponse(request, false, WebhookDoc)
		}
	}

	return utils.WebhookResponse(request, true, "")
}

func (w *ImageContentPoliciesWebhook) GetURI() string {
	return "/" + WebhookName
}

func (w *ImageContentPoliciesWebhook) Validate(request admission.Request) bool {
	if len(request.Object.Raw) > 0 {
		// Unexpected, but if the request object is empty we have no hope of decoding it
		return false
	}

	switch {
	case request.Kind.Kind == "ImageContentPolicy":
	case request.Kind.Kind == "ImageContentSourcePolicy":
		return true
	default:
		return false
	}

	return false
}

func (w *ImageContentPoliciesWebhook) Name() string {
	return WebhookName
}

func (w *ImageContentPoliciesWebhook) FailurePolicy() admissionregv1.FailurePolicyType {
	// Fail-closed because if we allow a problematic ImageContentPolicy/ImageContentSourcePolicy through,
	// it will have significant impact on the cluster. We should not modify this to fail-open unless we have
	// other specific observability and guidance to detect misconfigured ImageContentPolicy/ImageContentSourcePolicy
	// resources.
	return admissionregv1.Fail
}

func (w *ImageContentPoliciesWebhook) MatchPolicy() admissionregv1.MatchPolicyType {
	// Equivalent means a request should be intercepted if modifies a resource listed in rules, even via another API group or version.
	// Specifying Equivalent is recommended, and ensures that webhooks continue to intercept the resources they expect when upgrades enable new versions of the resource in the API server.
	return admissionregv1.Equivalent
}

func (w *ImageContentPoliciesWebhook) Rules() []admissionregv1.RuleWithOperations {
	clusterScope := admissionregv1.ClusterScope
	return []admissionregv1.RuleWithOperations{
		{
			Operations: []admissionregv1.OperationType{admissionregv1.Create, admissionregv1.Update},
			Rule: admissionregv1.Rule{
				APIGroups:   []string{configv1.GroupName},
				APIVersions: []string{"*"},
				Resources:   []string{"imagecontentpolicies"},
				Scope:       &clusterScope,
			},
		},
		{
			Operations: []admissionregv1.OperationType{admissionregv1.Create, admissionregv1.Update},
			Rule: admissionregv1.Rule{
				APIGroups:   []string{operatorv1alpha1.GroupName},
				APIVersions: []string{"*"},
				Resources:   []string{"imagecontentsourcepolicies"},
				Scope:       &clusterScope,
			},
		},
	}
}

func (w *ImageContentPoliciesWebhook) ObjectSelector() *metav1.LabelSelector {
	return nil
}

func (w *ImageContentPoliciesWebhook) SideEffects() admissionregv1.SideEffectClass {
	return admissionregv1.SideEffectClassNone
}

func (w *ImageContentPoliciesWebhook) TimeoutSeconds() int32 {
	return 2
}

func (w *ImageContentPoliciesWebhook) Doc() string {
	return WebhookDoc
}

func (w *ImageContentPoliciesWebhook) SyncSetLabelSelector() metav1.LabelSelector {
	return utils.DefaultLabelSelector()
}

func (w *ImageContentPoliciesWebhook) HypershiftEnabled() bool {
	return true
}

// authorizeImageContentPolicy should reject an ImageContentPolicy that sets .spec.repositoryDigestMirrors to any of:
// quay.io or quay.io/*
// registry.redhat.io or registry.redhat.io/*
// registry.access.redhat.com or registry.access.redhat.com/*
func authorizeImageContentPolicy(icp configv1.ImageContentPolicy) bool {
	unauthorizedRepositoryMirrorsRe := regexp.MustCompile(unauthorizedRepositoryMirrors)
	for _, mirror := range icp.Spec.RepositoryDigestMirrors {
		if unauthorizedRepositoryMirrorsRe.Match([]byte(mirror.Source)) {
			return false
		}
	}

	return true
}

// authorizeImageContentSourcePolicy should reject an ImageContentSourcePolicy that sets
// .spec.repositoryDigestMirrors to any of:
// quay.io or quay.io/*
// registry.redhat.io or registry.redhat.io/*
// registry.access.redhat.com or registry.access.redhat.com/*
func authorizeImageContentSourcePolicy(icsp operatorv1alpha1.ImageContentSourcePolicy) bool {
	unauthorizedRepositoryMirrorsRe := regexp.MustCompile(unauthorizedRepositoryMirrors)
	for _, mirror := range icsp.Spec.RepositoryDigestMirrors {
		if unauthorizedRepositoryMirrorsRe.Match([]byte(mirror.Source)) {
			return false
		}
	}

	return true
}
