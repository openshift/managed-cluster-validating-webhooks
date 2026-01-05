package networkoperator

import (
	"net/http"
	"os"

	operatorv1 "github.com/openshift/api/operator/v1"
	"github.com/openshift/managed-cluster-validating-webhooks/pkg/webhooks/utils"
	admissionv1 "k8s.io/api/admission/v1"
	admissionregv1 "k8s.io/api/admissionregistration/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	admissionctl "sigs.k8s.io/controller-runtime/pkg/webhook/admission"
)

const (
	WebhookName string = "network-operator-validation"
	docString   string = `Managed OpenShift customers may not modify critical fields in the network.operator CRD (such as spec.migration.networkType) because it can disrupt Cluster Network Operator operations and CNI migrations. Even cluster-admin users are blocked from modifying these critical fields.`
)

var (
	log = logf.Log.WithName(WebhookName)

	scope = admissionregv1.ClusterScope
	rules = []admissionregv1.RuleWithOperations{
		{
			Operations: []admissionregv1.OperationType{"UPDATE"},
			Rule: admissionregv1.Rule{
				APIGroups:   []string{"operator.openshift.io"},
				APIVersions: []string{"*"},
				Resources:   []string{"network", "networks"},
				Scope:       &scope,
			},
		},
	}
)

type NetworkOperatorWebhook struct {
	s runtime.Scheme
}

// Authorized will determine if the request is allowed
func (w *NetworkOperatorWebhook) Authorized(request admissionctl.Request) admissionctl.Response {
	// Block ALL users including cluster-admin from modifying critical migration fields
	if request.Operation == admissionv1.Update {
		decoder := admissionctl.NewDecoder(&w.s)
		object := &operatorv1.Network{}
		oldObject := &operatorv1.Network{}

		if err := decoder.Decode(request, object); err != nil {
			log.Error(err, "failed to render a Network from request.Object")
			ret := admissionctl.Errored(http.StatusBadRequest, err)
			ret.UID = request.AdmissionRequest.UID
			return ret
		}
		if err := decoder.DecodeRaw(request.OldObject, oldObject); err != nil {
			log.Error(err, "failed to render a Network from request.OldObject")
			ret := admissionctl.Errored(http.StatusBadRequest, err)
			ret.UID = request.AdmissionRequest.UID
			return ret
		}

		// Check if critical migration fields have been modified
		if hasCriticalMigrationFieldChanges(oldObject, object) {
			return utils.WebhookResponse(
				request,
				false,
				"Modification of critical migration fields (spec.migration.networkType and related migration configuration) is not allowed, even for cluster-admin users. These fields are managed by the Cluster Network Operator and manual changes can disrupt CNI migrations.",
			)
		}

		// Allow modifications to non-critical fields
		return utils.WebhookResponse(request, true, "Non-critical field modifications are allowed")
	}

	// For CREATE and DELETE operations, allow them (CREATE is typically done during installation,
	// DELETE may be needed for certain operations)
	return utils.WebhookResponse(request, true, "CREATE and DELETE operations are allowed")
}

// hasCriticalMigrationFieldChanges checks if any critical migration fields have been modified
func hasCriticalMigrationFieldChanges(oldObj, newObj *operatorv1.Network) bool {
	oldMigration := oldObj.Spec.Migration
	newMigration := newObj.Spec.Migration

	// If migration was nil and now it's set, that's a change
	if oldMigration == nil && newMigration != nil {
		return true
	}

	// If migration was set and now it's nil, that's a change
	if oldMigration != nil && newMigration == nil {
		return true
	}

	// If both are nil, no migration changes
	if oldMigration == nil && newMigration == nil {
		return false
	}

	// Check for changes in critical migration fields
	if oldMigration.NetworkType != newMigration.NetworkType {
		return true
	}

	if oldMigration.Mode != newMigration.Mode {
		return true
	}

	// Check if Features field has changed (pointer comparison for nil, then deep comparison)
	if (oldMigration.Features == nil) != (newMigration.Features == nil) {
		return true
	}
	if oldMigration.Features != nil && newMigration.Features != nil {
		// FeaturesMigration is a struct, so we compare the values
		if *oldMigration.Features != *newMigration.Features {
			return true
		}
	}

	// MTU migration changes are also critical
	if (oldMigration.MTU == nil) != (newMigration.MTU == nil) {
		return true
	}
	if oldMigration.MTU != nil && newMigration.MTU != nil {
		// Compare MTUMigration Network field
		if (oldMigration.MTU.Network == nil) != (newMigration.MTU.Network == nil) {
			return true
		}
		if oldMigration.MTU.Network != nil && newMigration.MTU.Network != nil {
			if *oldMigration.MTU.Network != *newMigration.MTU.Network {
				return true
			}
		}
		// Compare MTUMigration Machine field
		if (oldMigration.MTU.Machine == nil) != (newMigration.MTU.Machine == nil) {
			return true
		}
		if oldMigration.MTU.Machine != nil && newMigration.MTU.Machine != nil {
			if *oldMigration.MTU.Machine != *newMigration.MTU.Machine {
				return true
			}
		}
	}

	return false
}

// GetURI returns the URI for the webhook
func (w *NetworkOperatorWebhook) GetURI() string { return "/network-operator-validation" }

// Validate will validate the incoming request
func (w *NetworkOperatorWebhook) Validate(req admissionctl.Request) bool {
	valid := true
	valid = valid && (req.UserInfo.Username != "")
	valid = valid && (req.Kind.Kind == "Network")
	valid = valid && (req.Kind.Group == "operator.openshift.io")

	return valid
}

// Name is the name of the webhook
func (w *NetworkOperatorWebhook) Name() string { return WebhookName }

// FailurePolicy is how the hook config should react if k8s can't access it
func (w *NetworkOperatorWebhook) FailurePolicy() admissionregv1.FailurePolicyType {
	return admissionregv1.Ignore
}

// MatchPolicy mirrors validatingwebhookconfiguration.webhooks[].matchPolicy
// If it is important to the webhook, be sure to check subResource vs
// requestSubResource.
func (w *NetworkOperatorWebhook) MatchPolicy() admissionregv1.MatchPolicyType {
	return admissionregv1.Equivalent
}

// Rules is a slice of rules on which this hook should trigger
func (w *NetworkOperatorWebhook) Rules() []admissionregv1.RuleWithOperations { return rules }

// ObjectSelector uses a *metav1.LabelSelector to augment the webhook's
// Rules() to match only on incoming requests which match the specific
// LabelSelector.
func (w *NetworkOperatorWebhook) ObjectSelector() *metav1.LabelSelector { return nil }

// SideEffects are what side effects, if any, this hook has. Refer to
// https://kubernetes.io/docs/reference/access-authn-authz/extensible-admission-controllers/#side-effects
func (w *NetworkOperatorWebhook) SideEffects() admissionregv1.SideEffectClass {
	return admissionregv1.SideEffectClassNone
}

// TimeoutSeconds returns an int32 representing how long to wait for this hook to complete
func (w *NetworkOperatorWebhook) TimeoutSeconds() int32 { return 2 }

// Doc returns a string for end-customer documentation purposes.
func (w *NetworkOperatorWebhook) Doc() string { return docString }

// SyncSetLabelSelector returns the label selector to use in the SyncSet.
// Return utils.DefaultLabelSelector() to stick with the default
func (w *NetworkOperatorWebhook) SyncSetLabelSelector() metav1.LabelSelector {
	return utils.DefaultLabelSelector()
}

func (w *NetworkOperatorWebhook) ClassicEnabled() bool { return true }

// HypershiftEnabled will return boolean value for hypershift enabled configurations
func (w *NetworkOperatorWebhook) HypershiftEnabled() bool { return true }

// NewWebhook creates a new webhook
func NewWebhook() *NetworkOperatorWebhook {
	scheme := runtime.NewScheme()

	// Add admission types
	err := admissionv1.AddToScheme(scheme)
	if err != nil {
		log.Error(err, "Failed adding admissionv1 scheme to NetworkOperatorWebhook")
		os.Exit(1)
	}

	// Add operator.openshift.io/v1 types
	utilruntime.Must(operatorv1.Install(scheme))

	return &NetworkOperatorWebhook{
		s: *scheme,
	}
}
