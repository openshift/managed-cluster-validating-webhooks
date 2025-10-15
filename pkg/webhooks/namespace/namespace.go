package namespace

import (
	"fmt"
	"maps"
	"net/http"
	"os"
	"regexp"
	"slices"
	"strings"
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
	layeredProductNamespace      string = `^redhat-.*`
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
	// protectedLabels are labels which managed customers should not be allowed change
	protectedLabels = []string{
		// https://github.com/openshift/managed-cluster-config/tree/master/deploy/resource-quotas
		"managed.openshift.io/storage-pv-quota-exempt",
		"managed.openshift.io/service-lb-quota-exempt",
	}
	// removableProtectedLabels defines labels that unprivileged users can remove (but not add!) to unprivileged namespaces
	removableProtectedLabels = []string{
		"openshift.io/cluster-monitoring",
	}
	// https://issues.redhat.com/browse/SREP-1770 - nvidia-gpu-operator should be allowed to label namespaces
	labelUserExceptions = []string{"system:serviceaccount:nvidia-gpu-operator:gpu-operator"}

	// https://issues.redhat.com/browse/SREP-2070 - multiclusterhub-operator should be allowed to label namespaces
	// labelUserRegExceptions is the list of service account names that have exceptions to modify namespace labels. The service account names here is the last column of the full service account name, and the exception will grant on any namespace.
	labelUserRegExceptions = []string{"multiclusterhub-operator"}

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
	decoder := admissionctl.NewDecoder(&s.s)
	namespace := &corev1.Namespace{}
	var err error
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
	decoder := admissionctl.NewDecoder(&s.s)
	oldNamespace := &corev1.Namespace{}

	var err error
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
	// Admins are allowed to perform any operation
	if amIAdmin(request) {
		ret = admissionctl.Allowed("Cluster and SRE admins may access")
		ret.UID = request.AdmissionRequest.UID
		return ret
	}
	// Privileged ServiceAccounts are allowed to perform any operation
	for _, group := range request.UserInfo.Groups {
		if privilegedServiceAccountsRe.Match([]byte(group)) {
			ret = admissionctl.Allowed("Privileged service accounts may access")
			ret.UID = request.AdmissionRequest.UID
			return ret
		}
	}

	ns, err := s.renderNamespace(request)
	if err != nil {
		log.Error(err, "Couldn't render a Namespace from the incoming request")
		return admissionctl.Errored(http.StatusBadRequest, err)
	}

	// Layered Product SRE can access their own namespaces
	if slices.Contains(request.UserInfo.Groups, layeredProductAdminGroupName) &&
		layeredProductNamespaceRe.Match([]byte(ns.GetName())) {
		ret = admissionctl.Allowed("Layered product admins may access")
		ret.UID = request.AdmissionRequest.UID
		return ret
	}

	// Unprivileged users cannot modify privileged namespaces
	// L64-73
	if hookconfig.IsPrivilegedNamespace(ns.GetName()) {
		log.Info("Non-admin attempted to access a privileged namespace matching a regex from this list", "list", hookconfig.PrivilegedNamespaces, "request", request.AdmissionRequest)
		ret = admissionctl.Denied(fmt.Sprintf("Prevented from accessing Red Hat managed namespaces. Customer workloads should be placed in customer namespaces, and should not match an entry in this list of regular expressions: %v", hookconfig.PrivilegedNamespaces))
		ret.UID = request.AdmissionRequest.UID
		return ret
	}
	// Unprivileged users cannot create namespaces with certain names
	if BadNamespaceRe.Match([]byte(ns.GetName())) {
		log.Info("Non-admin attempted to access a potentially harmful namespace (eg matching this regex)", "regex", badNamespace, "request", request.AdmissionRequest)
		ret = admissionctl.Denied(fmt.Sprintf("Prevented from creating a potentially harmful namespace. Customer namespaces should not match this regular expression, as this would impact DNS resolution: %s", badNamespace))
		ret.UID = request.AdmissionRequest.UID
		return ret
	}

	// If the user making the request has a specific exception, allow them to change labels on non-platform and non-protected namespaces
	if allowLabelChanges(request) {
		ret = admissionctl.Allowed("User allowed to modify namespace labels")
		ret.UID = request.AdmissionRequest.UID
		return ret
	}

	// Unprivileged users cannot modify certain labels on unprivileged namespaces
	unauthorized, err := s.unauthorizedLabelChanges(request)
	if unauthorized {
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
		// Ensure no protected labels are set at creation-time
		protectedLabelsFound := protectedLabelsOnNamespace(newNamespace)
		removableProtectedLabelsFound := removableProtectedLabelsOnNamespace(newNamespace)

		if len(protectedLabelsFound) == 0 && len(removableProtectedLabelsFound) == 0 {
			return false, nil
		}
		return true, fmt.Errorf("Managed OpenShift customers may not directly set certain protected labels (%s) on Namespaces", strings.Join(append(protectedLabels, removableProtectedLabels...), ", "))
	}
	if req.Operation == admissionv1.Update {
		// Check whether protected labels had their key or value altered
		protectedLabelsFoundInOld := protectedLabelsOnNamespace(oldNamespace)
		protectedLabelsFoundInNew := protectedLabelsOnNamespace(newNamespace)
		protectedLabelsUnchanged := maps.Equal(protectedLabelsFoundInOld, protectedLabelsFoundInNew)
		if !protectedLabelsUnchanged {
			return true, fmt.Errorf("Managed OpenShift customers may not add or remove the following protected labels from Namespaces: (%s)", protectedLabels)
		}

		// Check whether a removableProtectedLabel was added
		removableProtectedLabelsFoundInOld := removableProtectedLabelsOnNamespace(oldNamespace)
		removableProtectedLabelsFoundInNew := removableProtectedLabelsOnNamespace(newNamespace)
		removableProtectedLabelsAdded := unauthorizedRemovableProtectedLabelChange(removableProtectedLabelsFoundInOld, removableProtectedLabelsFoundInNew)

		if removableProtectedLabelsAdded {
			return true, fmt.Errorf("Managed OpenShift customers may only remove the following protected labels from Namespaces: (%s)", removableProtectedLabels)
		}
	}
	return false, nil
}

// unauthorizedRemovableProtectedLabelChange returns true if a protectedRemovableLabel was added or had it's value changed
func unauthorizedRemovableProtectedLabelChange(oldLabels, newLabels map[string]string) bool {
	// All we need to validate is that every given new label was present in the set of old labels
	for key, newValue := range newLabels {
		oldValue, found := oldLabels[key]
		if !found {
			return true
		}
		if newValue != oldValue {
			return true
		}
	}
	return false
}

// protectedLabelsInNamespace returns any protectedLabels present in the namespace object
func protectedLabelsOnNamespace(ns *corev1.Namespace) map[string]string {
	return labelSetInNamespace(ns, protectedLabels)
}

// removableProtectedLabelsInNamespace returns any removableProtectedLabels in the namespace object
func removableProtectedLabelsOnNamespace(ns *corev1.Namespace) map[string]string {
	return labelSetInNamespace(ns, removableProtectedLabels)
}

func labelSetInNamespace(ns *corev1.Namespace, labels []string) map[string]string {
	foundLabels := map[string]string{}
	for _, label := range labels {
		value, found := ns.Labels[label]
		if found {
			foundLabels[label] = value
		}
	}
	return foundLabels
}

// SyncSetLabelSelector returns the label selector to use in the SyncSet.
func (s *NamespaceWebhook) SyncSetLabelSelector() metav1.LabelSelector {
	return utils.DefaultLabelSelector()
}

func (s *NamespaceWebhook) ClassicEnabled() bool { return true }

func (s *NamespaceWebhook) HypershiftEnabled() bool { return false }

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

func allowLabelChanges(request admissionctl.Request) bool {
	if slices.Contains(labelUserExceptions, request.UserInfo.Username) {
		return true
	}

	parts := strings.Split(request.UserInfo.Username, ":")
	if len(parts) > 0 && slices.Contains(labelUserRegExceptions, parts[len(parts)-1]) {
		return true
	}
	return false
}
