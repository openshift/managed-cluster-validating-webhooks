package namespace

import (
	"fmt"
	"net/http"
	"os"
	"regexp"
	"slices"
	"sync"

	hookconfig "github.com/openshift/managed-cluster-validating-webhooks/pkg/config"
	"github.com/openshift/managed-cluster-validating-webhooks/pkg/webhooks/utils"
	admissionv1 "k8s.io/api/admission/v1"
	admissionregv1 "k8s.io/api/admissionregistration/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	admissionctl "sigs.k8s.io/controller-runtime/pkg/webhook/admission"
)

const (
	WebhookName                  string = "namespace-validation"
	badNamespace                 string = `(^com$|^io$|^in$)`
	layeredProductNamespace      string = `^redhat.*`
	layeredProductAdminGroupName string = "layered-sre-cluster-admins"
	docString                    string = `Managed OpenShift Customers may not modify namespaces specified in the %v ConfigMaps because customer workloads should be placed in customer-created namespaces. Customers may not create namespaces identified by this regular expression %s because it could interfere with critical DNS resolution. Additionally, customers may not set or change the values of these Namespace labels %s.`
	clusterAdminGroup            string = "cluster-admins"
)

// exported vars to be used across packages
var (
	BadNamespaceRe = regexp.MustCompile(badNamespace)
)

var (
	clusterAdminUsers           = []string{"kube:admin", "system:admin", "backplane-cluster-admin"}
	sreAdminGroups              = []string{"system:serviceaccounts:openshift-backplane-srep"}
	privilegedServiceAccountsRe = regexp.MustCompile(utils.PrivilegedServiceAccountGroups)
	layeredProductNamespaceRe   = regexp.MustCompile(layeredProductNamespace)
	// protectedLabels are labels which managed customers should not be allowed
	// change by dedicated-admins.
	protectedLabels = []string{
		// https://github.com/openshift/managed-cluster-config/tree/master/deploy/resource-quotas
		"managed.openshift.io/storage-pv-quota-exempt",
		"managed.openshift.io/service-lb-quota-exempt",
	}

	log = logf.Log.WithName(WebhookName)

	scope = admissionregv1.ClusterScope
	rules = []admissionregv1.RuleWithOperations{
		{
			Operations: []admissionregv1.OperationType{"CREATE", "UPDATE", "DELETE"},
			Rule: admissionregv1.Rule{
				APIGroups:   []string{""},
				APIVersions: []string{"*"},
				Resources:   []string{"namespaces"},
				Scope:       &scope,
			},
		},
	}
)

// NamespaceWebhook validates a Namespace change
type NamespaceWebhook struct {
	mu sync.Mutex
	s  runtime.Scheme
}

// ObjectSelector implements Webhook interface
func (s *NamespaceWebhook) ObjectSelector() *metav1.LabelSelector { return nil }

func (s *NamespaceWebhook) Doc() string {
	return fmt.Sprintf(docString, hookconfig.ConfigMapSources, badNamespace, protectedLabels)
}

// TimeoutSeconds implements Webhook interface
func (s *NamespaceWebhook) TimeoutSeconds() int32 { return 2 }

// MatchPolicy implements Webhook interface
func (s *NamespaceWebhook) MatchPolicy() admissionregv1.MatchPolicyType {
	return admissionregv1.Equivalent
}

// Name implements Webhook interface
func (s *NamespaceWebhook) Name() string { return WebhookName }

// FailurePolicy implements Webhook interface
func (s *NamespaceWebhook) FailurePolicy() admissionregv1.FailurePolicyType {
	return admissionregv1.Ignore
}

// Rules implements Webhook interface
func (s *NamespaceWebhook) Rules() []admissionregv1.RuleWithOperations { return rules }

// GetURI implements Webhook interface
func (s *NamespaceWebhook) GetURI() string { return "/namespace-validation" }

// SideEffects implements Webhook interface
func (s *NamespaceWebhook) SideEffects() admissionregv1.SideEffectClass {
	return admissionregv1.SideEffectClassNone
}

// Validate - Make sure we're working with a well-formed Admission Request object
func (s *NamespaceWebhook) Validate(req admissionctl.Request) bool {
	valid := true
	valid = valid && (req.UserInfo.Username != "")
	valid = valid && (req.Kind.Kind == "Namespace")

	return valid
}

// renderNamespace decodes a *corev1.Namespace from the incoming request and
// gives preference to the OldObject (if it exists) over the Object. This method
// is functionally similar to the renderOldAndNewNamespaces method except we
// want to use this method when the assertions do not necessarily care which
// verb is being performed. That is, if the assertion is for a CREATE we want to
// use the request.Object, if it is for an UPDATE verb, we want to reference
// what the object was prior to the change (request.OldObject). This view can be
// seen similar to an "authenticated" check because the output of this method is
// used to determine if the requestor can make any kind of change whatsoever
// (ignoring the particulars of the change). Later, in unauthorizedLabelChanges,
// we use renderOldAndNewNamespaces to take into account the particulars of the
// kinds of changes we care about, with the current (request.Object) and former
// (request.OldObject) objects returned. See the renderOldAndNewNamespaces
// documentation for more.
func (s *NamespaceWebhook) renderNamespace(req admissionctl.Request) (*corev1.Namespace, error) {
	decoder, err := admissionctl.NewDecoder(&s.s)
	if err != nil {
		return nil, err
	}
	namespace := &corev1.Namespace{}
	if len(req.OldObject.Raw) > 0 {
		err = decoder.DecodeRaw(req.OldObject, namespace)
	} else {
		err = decoder.Decode(req, namespace)
	}
	if err != nil {
		return nil, err
	}
	return namespace, nil
}

// renderOldAndNewNamespaces decodes both OldObject and Object representations
// of corev1.Namespace objects from the incoming request. This is most commonly
// needed when dealing with UPDATE operations, which may want to inspect the old
// and new versions of the request. This method is also used in
// unauthorizedLabelChanges for CREATE operations.
// Return order is: new, old, error.
// If there is no corresponding namespace, this method will return nil in the
// appropriate position.
func (s *NamespaceWebhook) renderOldAndNewNamespaces(req admissionctl.Request) (*corev1.Namespace, *corev1.Namespace, error) {
	decoder, err := admissionctl.NewDecoder(&s.s)
	if err != nil {
		return nil, nil, err
	}
	oldNamespace := &corev1.Namespace{}

	if len(req.OldObject.Raw) == 0 {
		oldNamespace = nil
	} else {
		err = decoder.DecodeRaw(req.OldObject, oldNamespace)
		if err != nil {
			return nil, nil, err
		}
	}

	newNamespace := &corev1.Namespace{}
	if len(req.Object.Raw) == 0 {
		newNamespace = nil
	} else {
		err = decoder.Decode(req, newNamespace)
		if err != nil {
			return nil, nil, err
		}
	}
	return newNamespace, oldNamespace, nil
}

// Authorized implements Webhook interface
func (s *NamespaceWebhook) Authorized(request admissionctl.Request) admissionctl.Response {
	return s.authorized(request)
}

// Is the request authorized?
func (s *NamespaceWebhook) authorized(request admissionctl.Request) admissionctl.Response {
	var ret admissionctl.Response

	// Picking OldObject or Object will suffice for most validation concerns
	ns, err := s.renderNamespace(request)
	if err != nil {
		log.Error(err, "Couldn't render a Namespace from the incoming request")
		return admissionctl.Errored(http.StatusBadRequest, err)
	}
	// service accounts making requests will include their name in the group
	for _, group := range request.UserInfo.Groups {
		if privilegedServiceAccountsRe.Match([]byte(group)) {
			ret = admissionctl.Allowed("Privileged service accounts may access")
			ret.UID = request.AdmissionRequest.UID
			return ret
		}
	}
	// This must be prior to privileged namespace check
	if slices.Contains(request.UserInfo.Groups, layeredProductAdminGroupName) &&
		layeredProductNamespaceRe.Match([]byte(ns.GetName())) {
		ret = admissionctl.Allowed("Layered product admins may access")
		ret.UID = request.AdmissionRequest.UID
		return ret
	}

	// L64-73
	if hookconfig.IsPrivilegedNamespace(ns.GetName()) {

		if amIAdmin(request) {
			ret = admissionctl.Allowed("Cluster and SRE admins may access")
			ret.UID = request.AdmissionRequest.UID
			return ret
		}
		log.Info("Non-admin attempted to access a privileged namespace matching a regex from this list", "list", hookconfig.PrivilegedNamespaces, "request", request.AdmissionRequest)
		ret = admissionctl.Denied(fmt.Sprintf("Prevented from accessing Red Hat managed namespaces. Customer workloads should be placed in customer namespaces, and should not match an entry in this list of regular expressions: %v", hookconfig.PrivilegedNamespaces))
		ret.UID = request.AdmissionRequest.UID
		return ret
	}
	if BadNamespaceRe.Match([]byte(ns.GetName())) {

		if amIAdmin(request) {
			ret = admissionctl.Allowed("Cluster and SRE admins may access")
			ret.UID = request.AdmissionRequest.UID
			return ret
		}
		log.Info("Non-admin attempted to access a potentially harmful namespace (eg matching this regex)", "regex", badNamespace, "request", request.AdmissionRequest)
		ret = admissionctl.Denied(fmt.Sprintf("Prevented from creating a potentially harmful namespace. Customer namespaces should not match this regular expression, as this would impact DNS resolution: %s", badNamespace))
		ret.UID = request.AdmissionRequest.UID
		return ret
	}
	// Check labels.
	unauthorized, err := s.unauthorizedLabelChanges(request)
	if !amIAdmin(request) && unauthorized {
		ret = admissionctl.Denied(fmt.Sprintf("Denied. Err %+v", err))
		ret.UID = request.AdmissionRequest.UID
		return ret
	}
	// L75-L77
	ret = admissionctl.Allowed("RBAC allowed")
	ret.UID = request.AdmissionRequest.UID
	return ret
}

// unauthorizedLabelChanges returns true if the request should be denied because of a label violation. The error is the reason for denial.
func (s *NamespaceWebhook) unauthorizedLabelChanges(req admissionctl.Request) (bool, error) {
	// When there's a delete operation there are no meaningful changes to protected labels
	if req.Operation == admissionv1.Delete {
		return false, nil
	}

	newNamespace, oldNamespace, err := s.renderOldAndNewNamespaces(req)
	if err != nil {
		return true, err
	}
	if req.Operation == admissionv1.Create {
		// For creations, we look to newNamespace and ensure no protectedLabels are set
		// We don't care about oldNamespace.
		protectedLabelsFound := doesNamespaceContainProtectedLabels(newNamespace)
		if len(protectedLabelsFound) == 0 {
			return false, nil
		}
		// There were some found
		return true, fmt.Errorf("Managed OpenShift customers may not directly set certain protected labels (%s) on Namespaces", protectedLabels)
	} else if req.Operation == admissionv1.Update {
		// For Updates we must see if the new object is making a change to the old one for any protected labels.
		// First, let's see if the old object had any protected labels we ought to
		// care about. If it has, then we can use that resulting list to compare to
		// the newNamespace for any changes. However, just because the oldNamespace
		// did not have any protected labels doesn't necessarily mean that we can
		// ignore potential setting of those labels' values in the newNamespace.

		// protectedLabelsFoundInOld is a slice of all instances of protectedLabels
		// that appeared in the oldNamespace that we need to be sure have not
		// changed.
		protectedLabelsFoundInOld := doesNamespaceContainProtectedLabels(oldNamespace)
		// protectedLabelsFoundInNew is a slice of all instances of protectedLabels
		// that appeared in the newNamespace that we need to be sure do not have a
		// value different than oldNamespace.
		protectedLabelsFoundInNew := doesNamespaceContainProtectedLabels(newNamespace)

		// First check: Were any protectedLabels deleted?
		if len(protectedLabelsFoundInOld) != len(protectedLabelsFoundInNew) {
			// If we have x protectedLabels in the oldNamespace then we expect to also
			// have x protectedLabels in the newNamespace. Any difference is a removal or addition
			return true, fmt.Errorf("Managed OpenShift customers may not add or remove protected labels (%s) from Namespaces", protectedLabels)
		}
		// Next check: Compare values to ensure there are no changes in the protected labels
		for _, labelKey := range protectedLabelsFoundInOld {
			if oldNamespace.Labels[labelKey] != newNamespace.ObjectMeta.Labels[labelKey] {
				return true, fmt.Errorf("Managed OpenShift customers may not change the value or certain protected labels (%s) on Namespaces. %s changed from %s to %s", protectedLabels, labelKey, oldNamespace.Labels[labelKey], newNamespace.ObjectMeta.Labels[labelKey])
			}
		}
	}
	return false, nil
}

// doesNamespaceContainProtectedLabels checks the namespace for any instances of
// protectedLabels and returns a slice of any instances of matches
func doesNamespaceContainProtectedLabels(ns *corev1.Namespace) []string {
	foundLabelNames := make([]string, 0)
	for _, label := range protectedLabels {
		if _, found := ns.ObjectMeta.Labels[label]; found {
			foundLabelNames = append(foundLabelNames, label)
		}
	}
	return foundLabelNames
}

// SyncSetLabelSelector returns the label selector to use in the SyncSet.
func (s *NamespaceWebhook) SyncSetLabelSelector() metav1.LabelSelector {
	return utils.DefaultLabelSelector()
}

func (s *NamespaceWebhook) ClassicEnabled() bool { return true }

func (s *NamespaceWebhook) HypershiftEnabled() bool { return true }

// NewWebhook creates a new webhook
func NewWebhook() *NamespaceWebhook {
	scheme := runtime.NewScheme()
	err := admissionv1.AddToScheme(scheme)
	if err != nil {
		log.Error(err, "Fail adding admissionsv1 scheme to NamespaceWebhook")
		os.Exit(1)
	}

	err = corev1.AddToScheme(scheme)
	if err != nil {
		log.Error(err, "Fail adding corev1 scheme to NamespaceWebhook")
		os.Exit(1)
	}

	return &NamespaceWebhook{
		s: *scheme,
	}
}

func amIAdmin(request admissionctl.Request) bool {
	if slices.Contains(clusterAdminUsers, request.UserInfo.Username) || slices.Contains(request.UserInfo.Groups, clusterAdminGroup) {
		return true
	}

	for _, group := range sreAdminGroups {
		if slices.Contains(request.UserInfo.Groups, group) {
			return true
		}
	}

	return false
}
