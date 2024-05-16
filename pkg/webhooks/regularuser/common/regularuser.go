package common

import (
	"fmt"
	"os"
	"slices"
	"strings"

	networkv1 "github.com/openshift/api/network/v1"
	hookconfig "github.com/openshift/managed-cluster-validating-webhooks/pkg/config"
	"github.com/openshift/managed-cluster-validating-webhooks/pkg/webhooks/namespace"
	"github.com/openshift/managed-cluster-validating-webhooks/pkg/webhooks/utils"
	admissionv1 "k8s.io/api/admission/v1"
	admissionregv1 "k8s.io/api/admissionregistration/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	admissionctl "sigs.k8s.io/controller-runtime/pkg/webhook/admission"
)

// This webhook is intended for performing any webhook protection that is
// common across all Managed OpenShift platforms (OSD, ROSA and HyperShift).
//
// Regular user actions that should NOT be prevented in HyperShift hosted clusters
// should instead be placed in the 'regular-user-validation-osd' webhook situated
// in the 'osd' package.

const (
	WebhookName         = "regular-user-validation"
	docString           = `Managed OpenShift customers may not manage any objects in the following APIGroups %s, nor may Managed OpenShift customers alter the APIServer, KubeAPIServer, OpenShiftAPIServer, ClusterVersion, Proxy or SubjectPermission objects.`
	mustGatherKind      = "MustGather"
	mustGatherGroup     = "managed.openshift.io"
	clusterVersionKind  = "ClusterVersion"
	clusterVersionGroup = "config.openshit.io"
	customDomainKind    = "CustomDomain"
	customDomainGroup   = "managed.openshift.io"
	netNamespaceKind    = "NetNamespace"
	netNamespaceGroup   = "network.openshift.io"
)

var (
	adminGroups         = []string{"system:serviceaccounts:openshift-backplane-srep"}
	adminUsers          = []string{"backplane-cluster-admin"}
	clusterVersionUsers = []string{
		"system:serviceaccount:openshift-managed-upgrade-operator:managed-upgrade-operator",
		"system:serviceaccount:openshift-cluster-version:default",
	}
	ceeGroup = "system:serviceaccounts:openshift-backplane-cee"

	scope = admissionregv1.AllScopes
	rules = []admissionregv1.RuleWithOperations{
		{
			Operations: []admissionregv1.OperationType{"*"},
			Rule: admissionregv1.Rule{
				APIGroups: []string{
					"cloudcredential.openshift.io",
					"machine.openshift.io",
					"admissionregistration.k8s.io",
					// Deny ability to manage SRE resources
					// oc get --raw /apis | jq -r '.groups[] | select(.name | contains("managed")) | .name'
					"addons.managed.openshift.io",
					"cloudingress.managed.openshift.io",
					"managed.openshift.io",
					"ocmagent.managed.openshift.io",
					"splunkforwarder.managed.openshift.io",
					"upgrade.managed.openshift.io",
				},
				APIVersions: []string{"*"},
				Resources:   []string{"*/*"},
				Scope:       &scope,
			},
		},
		{
			Operations: []admissionregv1.OperationType{"*"},
			Rule: admissionregv1.Rule{
				APIGroups:   []string{"autoscaling.openshift.io"},
				APIVersions: []string{"*"},
				Resources:   []string{"clusterautoscalers", "machineautoscalers"},
				Scope:       &scope,
			},
		},
		{
			Operations: []admissionregv1.OperationType{"*"},
			Rule: admissionregv1.Rule{
				APIGroups:   []string{"config.openshift.io"},
				APIVersions: []string{"*"},
				Resources:   []string{"clusterversions", "clusterversions/status", "schedulers", "apiservers", "proxies"},
				Scope:       &scope,
			},
		},
		{
			Operations: []admissionregv1.OperationType{"CREATE", "UPDATE", "DELETE"},
			Rule: admissionregv1.Rule{
				APIGroups:   []string{""},
				APIVersions: []string{"*"},
				Resources:   []string{"configmaps"},
				Scope:       &scope,
			},
		},
		{
			Operations: []admissionregv1.OperationType{"*"},
			Rule: admissionregv1.Rule{
				APIGroups:   []string{"machineconfiguration.openshift.io"},
				APIVersions: []string{"*"},
				Resources:   []string{"machineconfigs", "machineconfigpools"},
				Scope:       &scope,
			},
		},
		{
			Operations: []admissionregv1.OperationType{"*"},
			Rule: admissionregv1.Rule{
				APIGroups:   []string{"operator.openshift.io"},
				APIVersions: []string{"*"},
				Resources:   []string{"kubeapiservers", "openshiftapiservers"},
				Scope:       &scope,
			},
		},
		{
			Operations: []admissionregv1.OperationType{"*"},
			Rule: admissionregv1.Rule{
				APIGroups:   []string{"managed.openshift.io"},
				APIVersions: []string{"*"},
				Resources:   []string{"subjectpermissions", "subjectpermissions/*"},
				Scope:       &scope,
			},
		},
		{
			Operations: []admissionregv1.OperationType{"*"},
			Rule: admissionregv1.Rule{
				APIGroups:   []string{"network.openshift.io"},
				APIVersions: []string{"*"},
				Resources:   []string{"netnamespaces", "netnamespaces/*"},
				Scope:       &scope,
			},
		},
	}
	log = logf.Log.WithName(WebhookName)
)

// RegularuserWebhook protects various objects from unauthorized manipulation
type RegularuserWebhook struct {
	s runtime.Scheme
}

func (s *RegularuserWebhook) Doc() string {
	hist := make(map[string]bool)
	for _, rule := range rules {
		for _, group := range rule.APIGroups {
			if group != "" {
				// If there's an empty API group let's not include it because it would be confusing.
				hist[group] = true
			}
		}
	}
	//dedup
	allGroups := make([]string, 0)
	for k := range hist {
		allGroups = append(allGroups, k)
	}

	return fmt.Sprintf(docString, allGroups)
}

// ObjectSelector implements Webhook interface
func (s *RegularuserWebhook) ObjectSelector() *metav1.LabelSelector { return nil }

// TimeoutSeconds implements Webhook interface
func (s *RegularuserWebhook) TimeoutSeconds() int32 { return 2 }

// MatchPolicy implements Webhook interface
func (s *RegularuserWebhook) MatchPolicy() admissionregv1.MatchPolicyType {
	return admissionregv1.Equivalent
}

// Name implements Webhook interface
func (s *RegularuserWebhook) Name() string { return WebhookName }

// FailurePolicy implements Webhook interface
func (s *RegularuserWebhook) FailurePolicy() admissionregv1.FailurePolicyType {
	return admissionregv1.Ignore
}

// Rules implements Webhook interface
func (s *RegularuserWebhook) Rules() []admissionregv1.RuleWithOperations { return rules }

// GetURI implements Webhook interface
func (s *RegularuserWebhook) GetURI() string { return "/regularuser-validation" }

// SideEffects implements Webhook interface
func (s *RegularuserWebhook) SideEffects() admissionregv1.SideEffectClass {
	return admissionregv1.SideEffectClassNone
}

// Validate is the incoming request even valid?
func (s *RegularuserWebhook) Validate(req admissionctl.Request) bool {
	valid := true
	valid = valid && (req.UserInfo.Username != "")

	return valid
}

// Authorized implements Webhook interface
func (s *RegularuserWebhook) Authorized(request admissionctl.Request) admissionctl.Response {
	return s.authorized(request)
}

func (s *RegularuserWebhook) authorized(request admissionctl.Request) admissionctl.Response {
	var ret admissionctl.Response

	if request.AdmissionRequest.UserInfo.Username == "system:unauthenticated" {
		// This could highlight a significant problem with RBAC since an
		// unauthenticated user should have no permissions.
		log.Info("system:unauthenticated made a webhook request. Check RBAC rules", "request", request.AdmissionRequest)
		ret = admissionctl.Denied("Unauthenticated")
		ret.UID = request.AdmissionRequest.UID
		return ret
	}

	if strings.HasPrefix(request.AdmissionRequest.UserInfo.Username, "kube:") {
		ret = admissionctl.Allowed("kube: users are allowed")
		ret.UID = request.AdmissionRequest.UID
		return ret
	}

	switch {
	case utils.RequestMatchesGroupKind(request, mustGatherKind, mustGatherGroup):
		if isMustGatherAuthorized(request) {
			ret = admissionctl.Allowed("Management of MustGather CR is authorized")
			ret.UID = request.AdmissionRequest.UID
			return ret
		}
	case utils.RequestMatchesGroupKind(request, customDomainKind, customDomainGroup):
		if isCustomDomainAuthorized(request) {
			ret = admissionctl.Allowed("Management of CustomDomain CR is authorized")
			ret.UID = request.AdmissionRequest.UID
			return ret
		}
	case utils.RequestMatchesGroupKind(request, clusterVersionKind, clusterVersionGroup):
		if isClusterVersionAuthorized(request) {
			return utils.WebhookResponse(request, true, "")
		} else {
			log.Info("Denying access", "request", request.AdmissionRequest)
			return utils.WebhookResponse(request, false, "Prevented from accessing Red Hat managed resources. This is in an effort to prevent harmful actions that may cause unintended consequences or affect the stability of the cluster. If you have any questions about this, please reach out to Red Hat support at https://access.redhat.com/support")
		}
	case utils.RequestMatchesGroupKind(request, netNamespaceKind, netNamespaceGroup):
		if isNetNamespaceAuthorized(s, request) {
			ret = admissionctl.Allowed("Management of NetNamespace CR is authorized")
			ret.UID = request.AdmissionRequest.UID
			return ret
		}
	}

	// TODO: Do not allow all system:serviceaccount:* users or belong to system:serviceaccounts:* groups
	// https://kubernetes.io/docs/reference/access-authn-authz/rbac/
	if strings.HasPrefix(request.AdmissionRequest.UserInfo.Username, "system:") {
		ret = admissionctl.Allowed("authenticated system: users are allowed")
		ret.UID = request.AdmissionRequest.UID
		return ret
	}

	if slices.Contains(adminUsers, request.AdmissionRequest.UserInfo.Username) {
		ret = admissionctl.Allowed("Specified admin users are allowed")
		ret.UID = request.AdmissionRequest.UID
		return ret
	}

	for _, userGroup := range request.UserInfo.Groups {
		if slices.Contains(adminGroups, userGroup) {
			ret = admissionctl.Allowed("Members of admin groups are allowed")
			ret.UID = request.AdmissionRequest.UID
			return ret
		}
	}

	if request.Kind.Kind == "ConfigMap" && shouldAllowConfigMapChange(s, request) {
		ret = admissionctl.Allowed("Modification of Config Maps that are not user-ca-bundle are allowed")
		ret.UID = request.AdmissionRequest.UID
		return ret
	}

	log.Info("Denying access", "request", request.AdmissionRequest)
	ret = admissionctl.Denied("Prevented from accessing Red Hat managed resources. This is in an effort to prevent harmful actions that may cause unintended consequences or affect the stability of the cluster. If you have any questions about this, please reach out to Red Hat support at https://access.redhat.com/support")
	ret.UID = request.AdmissionRequest.UID
	return ret
}

// isMustGatherAuthorized check if request is authorized for MustGather CR
func isMustGatherAuthorized(request admissionctl.Request) bool {
	return slices.Contains(request.UserInfo.Groups, ceeGroup)
}

// isCustomDomainAuthorized check if request is authorized for CustomDomain CR
func isCustomDomainAuthorized(request admissionctl.Request) bool {
	return slices.Contains(request.UserInfo.Groups, "cluster-admins") ||
		slices.Contains(request.UserInfo.Groups, "dedicated-admins")
}

// isNetNamespaceAuthorized check if request is authorized for NetNamespace CR
func isNetNamespaceAuthorized(s *RegularuserWebhook, request admissionctl.Request) bool {
	return (slices.Contains(request.UserInfo.Groups, "cluster-admins") ||
		slices.Contains(request.UserInfo.Groups, "dedicated-admins")) &&
		isNetNamespaceValid(s, request)
}

// isClusterVersionAuthorized only allows specific K8s serviceaccounts to modify ClusterVersion resources
func isClusterVersionAuthorized(request admissionctl.Request) bool {
	if slices.Contains(clusterVersionUsers, request.UserInfo.Username) {
		return true
	}

	if slices.Contains(adminUsers, request.AdmissionRequest.UserInfo.Username) {
		return true
	}

	for _, userGroup := range request.UserInfo.Groups {
		if slices.Contains(adminGroups, userGroup) {
			return true
		}
	}

	if strings.HasPrefix(request.AdmissionRequest.UserInfo.Username, "system:") && !strings.HasPrefix(request.AdmissionRequest.UserInfo.Username, "system:serviceaccount:") {
		return true
	}

	return false
}

// isNetNamespaceValid check if the NetNamespace is valid
func isNetNamespaceValid(s *RegularuserWebhook, request admissionctl.Request) bool {
	// Decode object into a NetNamespace object
	decoder, err := admissionctl.NewDecoder(&s.s)
	if err != nil {
		return false
	}
	netNamespace := &networkv1.NetNamespace{}
	if len(request.Object.Raw) == 0 {
		return false
	}
	err = decoder.Decode(request, netNamespace)
	if err != nil {
		return false
	}
	// Check if the name is bad or is privileged
	if namespace.BadNamespaceRe.Match([]byte(netNamespace.Name)) ||
		hookconfig.IsPrivilegedNamespace(netNamespace.Name) {
		return false
	}
	return true
}

// allow if a ConfigMap is being updated that does not live under openshift-config or is not called user-ca-bundle under openshift-config
func shouldAllowConfigMapChange(s *RegularuserWebhook, request admissionctl.Request) bool {
	decoder, err := admissionctl.NewDecoder(&s.s)
	if err != nil {
		return false
	}
	configMap := &corev1.ConfigMap{}
	if admissionregv1.OperationType(request.Operation) == admissionregv1.Delete {
		err = decoder.DecodeRaw(request.OldObject, configMap)
	} else {
		err = decoder.DecodeRaw(request.Object, configMap)
	}
	if err != nil {
		return false
	}

	if configMap.ObjectMeta.Name != "user-ca-bundle" || configMap.ObjectMeta.Namespace != "openshift-config" {
		return true
	}

	return false
}

// SyncSetLabelSelector returns the label selector to use in the SyncSet.
func (s *RegularuserWebhook) SyncSetLabelSelector() metav1.LabelSelector {
	return utils.DefaultLabelSelector()
}

func (s *RegularuserWebhook) ClassicEnabled() bool { return true }

func (s *RegularuserWebhook) HypershiftEnabled() bool { return true }

// NewWebhook creates a new webhook
func NewWebhook() *RegularuserWebhook {

	scheme := runtime.NewScheme()
	err := admissionv1.AddToScheme(scheme)
	if err != nil {
		log.Error(err, "Fail adding admissionv1 scheme to RegularuserWebhook")
		os.Exit(1)
	}

	err = corev1.AddToScheme(scheme)
	if err != nil {
		log.Error(err, "Fail adding corev1 scheme to RegularuserWebhook")
		os.Exit(1)
	}

	err = networkv1.Install(scheme)
	if err != nil {
		log.Error(err, "Fail adding networkv1 scheme to RegularuserWebhook")
		os.Exit(1)
	}

	return &RegularuserWebhook{
		s: *scheme,
	}
}
