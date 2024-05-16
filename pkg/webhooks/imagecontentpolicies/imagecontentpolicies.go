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
	WebhookDoc  = "Managed OpenShift customers may not create ImageContentSourcePolicy, ImageDigestMirrorSet, or ImageTagMirrorSet resources that configure mirrors that would conflict with system registries (e.g. quay.io, registry.redhat.io, registry.access.redhat.com, etc). For more details, see https://docs.openshift.com/"
	// unauthorizedRepositoryMirrors is a regex that is used to reject certain specified repository mirrors.
	// Only registry.redhat.io exactly is blocked, while all other contained regexes
	// follow a similar pattern, i.e. rejecting quay.io or quay.io/.*
	unauthorizedRepositoryMirrors = `(^registry\.redhat\.io$|^quay\.io(/.*)?$|^registry\.access\.redhat\.com(/.*)?)`
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
	case "ImageDigestMirrorSet":
		idms := configv1.ImageDigestMirrorSet{}
		if err := decoder.Decode(request, &idms); err != nil {
			w.log.Error(err, "failed to render an ImageDigestMirrorSet from request")
			return admission.Errored(http.StatusBadRequest, err)
		}

		if !authorizeImageDigestMirrorSet(idms) {
			w.log.Info("denying ImageDigestMirrorSet", "name", idms.Name)
			return utils.WebhookResponse(request, false, WebhookDoc)
		}
	case "ImageTagMirrorSet":
		itms := configv1.ImageTagMirrorSet{}
		if err := decoder.Decode(request, &itms); err != nil {
			w.log.Error(err, "failed to render an ImageTagMirrorSet from request")
			return admission.Errored(http.StatusBadRequest, err)
		}

		if !authorizeImageTagMirrorSet(itms) {
			w.log.Info("denying ImageTagMirrorSet", "name", itms.Name)
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
	if len(request.Object.Raw) == 0 {
		// Unexpected, but if the request object is empty we have no hope of decoding it
		return false
	}

	switch request.Kind.Kind {
	case "ImageDigestMirrorSet":
		fallthrough
	case "ImageTagMirrorSet":
		fallthrough
	case "ImageContentSourcePolicy":
		return true
	default:
		return false
	}
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
				Resources:   []string{"imagedigestmirrorsets", "imagetagmirrorsets"},
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

func (w *ImageContentPoliciesWebhook) ClassicEnabled() bool {
	return true
}

func (w *ImageContentPoliciesWebhook) HypershiftEnabled() bool {
	return true
}

// authorizeImageDigestMirrorSet should reject an ImageDigestMirrorSet that matches an unauthorized mirror list
func authorizeImageDigestMirrorSet(idms configv1.ImageDigestMirrorSet) bool {
	unauthorizedRepositoryMirrorsRe := regexp.MustCompile(unauthorizedRepositoryMirrors)
	for _, mirror := range idms.Spec.ImageDigestMirrors {
		if unauthorizedRepositoryMirrorsRe.Match([]byte(mirror.Source)) {
			return false
		}
	}

	return true
}

// authorizeImageTagMirrorSet should reject an ImageTagMirrorSet that matches an unauthorized mirror list
func authorizeImageTagMirrorSet(itms configv1.ImageTagMirrorSet) bool {
	unauthorizedRepositoryMirrorsRe := regexp.MustCompile(unauthorizedRepositoryMirrors)
	for _, mirror := range itms.Spec.ImageTagMirrors {
		if unauthorizedRepositoryMirrorsRe.Match([]byte(mirror.Source)) {
			return false
		}
	}

	return true
}

// authorizeImageContentSourcePolicy should reject an ImageContentSourcePolicy that matches an unauthorized mirror list
func authorizeImageContentSourcePolicy(icsp operatorv1alpha1.ImageContentSourcePolicy) bool {
	unauthorizedRepositoryMirrorsRe := regexp.MustCompile(unauthorizedRepositoryMirrors)
	for _, mirror := range icsp.Spec.RepositoryDigestMirrors {
		if unauthorizedRepositoryMirrorsRe.Match([]byte(mirror.Source)) {
			return false
		}
	}

	return true
}
