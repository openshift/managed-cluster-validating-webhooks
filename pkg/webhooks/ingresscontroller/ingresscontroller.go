package ingresscontroller

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"net/http"
	"os"
	"slices"
	"strings"

	operatorv1 "github.com/openshift/api/operator/v1"
	"github.com/openshift/managed-cluster-validating-webhooks/pkg/k8sutil"
	"github.com/openshift/managed-cluster-validating-webhooks/pkg/webhooks/utils"
	"github.com/pkg/errors"
	admissionv1 "k8s.io/api/admission/v1"
	admissionregv1 "k8s.io/api/admissionregistration/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/yaml"
	"sigs.k8s.io/controller-runtime/pkg/client"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	admissionctl "sigs.k8s.io/controller-runtime/pkg/webhook/admission"
)

const (
	WebhookName                     string = "ingresscontroller-validation"
	docString                       string = `Managed OpenShift Customer may create IngressControllers without necessary taints. This can cause those workloads to be provisioned on master nodes.`
	legacyIngressSupportFeatureFlag        = "ext-managed.openshift.io/legacy-ingress-support"
	installConfigMap                       = "cluster-config-v1"
	installConfigNamespace                 = "kube-system"
	installConfigKeyName                   = "install-config"
)

var (
	log   = logf.Log.WithName(WebhookName)
	scope = admissionregv1.NamespacedScope
	rules = []admissionregv1.RuleWithOperations{
		{
			Operations: []admissionregv1.OperationType{admissionregv1.Create, admissionregv1.Update},
			Rule: admissionregv1.Rule{
				APIGroups:   []string{"operator.openshift.io"},
				APIVersions: []string{"*"},
				Resources:   []string{"ingresscontroller", "ingresscontrollers"},
				Scope:       &scope,
			},
		},
	}
	allowedUsers = []string{
		"backplane-cluster-admin",
	}
)

type IngressControllerWebhook struct {
	s          runtime.Scheme
	kubeClient client.Client
	// Allow caching install config and machineCIDR values...
	machineCIDRIP  net.IP
	machineCIDRNet *net.IPNet
}

// installConfig struct to load the min values needed from the install-config data.
// Alternative would be to vendor all of github.com/openshift/installer/pkg/types to import the proper struct.
// Required values: machineCidr info, anything else we gather from this? hcp vs classic, privatelink info, etc?
type installConfig struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata"`
	Networking        struct {
		MachineCIDR string `json:"machineCIDR"`
	} `json:"networking"`
}

// ObjectSelector implements Webhook interface
func (wh *IngressControllerWebhook) ObjectSelector() *metav1.LabelSelector { return nil }

func (wh *IngressControllerWebhook) Doc() string {
	return fmt.Sprintf(docString)
}

// TimeoutSeconds implements Webhook interface
func (wh *IngressControllerWebhook) TimeoutSeconds() int32 { return 1 }

// MatchPolicy implements Webhook interface
func (wh *IngressControllerWebhook) MatchPolicy() admissionregv1.MatchPolicyType {
	return admissionregv1.Equivalent
}

// Name implements Webhook interface
func (wh *IngressControllerWebhook) Name() string { return WebhookName }

// FailurePolicy implements Webhook interface and defines how unrecognized errors and timeout errors from the admission webhook are handled. Allowed values are Ignore or Fail.
// Ignore means that an error calling the webhook is ignored and the API request is allowed to continue.
// It's important to leave the FailurePolicy set to Ignore because otherwise the pod will fail to be created as the API request will be rejected.
func (wh *IngressControllerWebhook) FailurePolicy() admissionregv1.FailurePolicyType {
	return admissionregv1.Ignore
}

// Rules implements Webhook interface
func (wh *IngressControllerWebhook) Rules() []admissionregv1.RuleWithOperations { return rules }

// GetURI implements Webhook interface
func (wh *IngressControllerWebhook) GetURI() string { return "/" + WebhookName }

// SideEffects implements Webhook interface
func (wh *IngressControllerWebhook) SideEffects() admissionregv1.SideEffectClass {
	return admissionregv1.SideEffectClassNone
}

// Validate implements Webhook interface
func (wh *IngressControllerWebhook) Validate(req admissionctl.Request) bool {
	valid := true
	valid = valid && (req.UserInfo.Username != "")
	valid = valid && (req.Kind.Kind == "IngressController")

	return valid
}

func (wh *IngressControllerWebhook) renderIngressController(req admissionctl.Request) (*operatorv1.IngressController, error) {
	decoder, err := admissionctl.NewDecoder(&wh.s)
	if err != nil {
		return nil, err
	}
	ic := &operatorv1.IngressController{}
	err = decoder.DecodeRaw(req.Object, ic)

	if err != nil {
		return nil, err
	}

	return ic, nil
}

func (wh *IngressControllerWebhook) authorized(request admissionctl.Request) admissionctl.Response {
	var ret admissionctl.Response
	ic, err := wh.renderIngressController(request)
	if err != nil {
		log.Error(err, "Couldn't render an IngressController from the incoming request")
		return admissionctl.Errored(http.StatusBadRequest, err)
	}

	log.Info("Checking if user is unauthenticated")
	if request.AdmissionRequest.UserInfo.Username == "system:unauthenticated" {
		// This could highlight a significant problem with RBAC since an
		// unauthenticated user should have no permissions.
		log.Info("system:unauthenticated made a webhook request. Check RBAC rules", "request", request.AdmissionRequest)
		ret = admissionctl.Denied("Unauthenticated")
		ret.UID = request.AdmissionRequest.UID
		return ret
	}

	log.Info("Checking if user is authenticated system: user")
	if strings.HasPrefix(request.AdmissionRequest.UserInfo.Username, "system:") {
		ret = admissionctl.Allowed("authenticated system: users are allowed")
		ret.UID = request.AdmissionRequest.UID
		return ret
	}

	log.Info("Checking if user is kube: user")
	if strings.HasPrefix(request.AdmissionRequest.UserInfo.Username, "kube:") {
		ret = admissionctl.Allowed("kube: users are allowed")
		ret.UID = request.AdmissionRequest.UID
		return ret
	}

	// Check if the group does not have exceptions
	if !isAllowedUser(request) {
		for _, toleration := range ic.Spec.NodePlacement.Tolerations {
			if strings.Contains(toleration.Key, "node-role.kubernetes.io/master") {
				ret = admissionctl.Denied("Not allowed to provision ingress controller pods with toleration for master nodes.")
				ret.UID = request.AdmissionRequest.UID

				return ret
			}
		}
	}

	/* TODO:
	 * 1) ONLY check for privatelink clusters? How?
	 * 2) HCP vs Classic, etc.. ...any other cluster type this should apply to? Is this handled by the
	 * HypershiftEnabled vs ClassicEnabled flags set in this module? Currently HCP disabled.
	 * If HCP is to be enabled for allowed source ranges, should this part of a 2nd ingress validator to
	 * allow separation of validations between cluster install types? Is there a run time method available
	 * to this validator to determine classic vs hcp?
	 * 3) What other specifics should be checked here for this cidr check to be applicable?m
	 */
	// Only check for machine cidr in allowed ranges if creating or updating resource...
	reqOp := request.AdmissionRequest.Operation
	if reqOp == admissionv1.Create || reqOp == admissionv1.Update {
		//TODO: Will these need to iterate over more than just the default IngressController config?
		if ic.ObjectMeta.Name == "default" && ic.ObjectMeta.Namespace == "openshift-ingress-operator" {
			ret := wh.checkAllowsMachineCIDR(ic.Spec.EndpointPublishingStrategy.LoadBalancer.AllowedSourceRanges)
			ret.UID = request.AdmissionRequest.UID
			if !ret.Allowed {
				log.Info("Error checking minimum AllowedSourceRange", "err", ret.AdmissionResponse.String())
			}
			return ret
		}
	}
	log.Info("############# DEBUG LOG: IngressController operation is allowed ###########")
	ret = admissionctl.Allowed("IngressController operation is allowed, machineCIDR n/a")
	ret.UID = request.AdmissionRequest.UID

	return ret
}

func (wh *IngressControllerWebhook) getMachineCIDR() (net.IP, *net.IPNet, error) {
	if wh.machineCIDRIP == nil || wh.machineCIDRNet == nil {
		instConf, err := wh.getClusterConfig()
		if err != nil {
			log.Error(err, "Failed to fetch machineCIDR", "namespace", installConfigNamespace, "configmap", installConfigMap)
			return nil, nil, err
		}
		if instConf == nil {
			err := fmt.Errorf("can not fetch machineCIDR from empty '%s' install config", installConfigMap)
			log.Error(err, "getMachineCIDR failed to find CIDR value")
			return nil, nil, err
		}
		if len(instConf.Networking.MachineCIDR) <= 0 {
			err := fmt.Errorf("empty machineCIDR string value parsed from '%s' install config", installConfigMap)
			log.Error(err, "getMachineCIDR found empty CIDR value")
			return nil, nil, err
		}
		machIP, machNet, err := net.ParseCIDR(string(instConf.Networking.MachineCIDR))
		if err != nil {
			log.Error(err, "err parsing machineCIDR into network cidr", "machineCIDR", string(instConf.Networking.MachineCIDR))
			return nil, nil, err
		}
		if machIP == nil || machNet == nil {
			err := fmt.Errorf("failed to parse machineCIDR string:'%s' into network structures", string(instConf.Networking.MachineCIDR))
			log.Error(err, "failed to parse install-config machineCIDR")
			return nil, nil, err
		}
		// Successfully fetched, parsed, and converted the machineCIDR string into net structures...
		wh.machineCIDRIP = machIP
		wh.machineCIDRNet = machNet
	}
	return wh.machineCIDRIP, wh.machineCIDRNet, nil
}

/* Fetch the install-config from the kube-system config map's data.
 * this requires proper role, rolebinding for this service account's get() request
 * to succeed. (see toplevel selectorsyncset).  This config should not change during runtime so
 * this operation should cache this if possible.
 * TODO: Should it retry fetching the config if there are any failures/errors encountered while
 * parsing out the the desired values?
 */
func (wh *IngressControllerWebhook) getClusterConfig() (*installConfig, error) {
	var err error
	if wh.kubeClient == nil {
		wh.kubeClient, err = k8sutil.KubeClient(&wh.s)
		if err != nil {
			log.Error(err, "Fail creating KubeClient for IngressControllerWebhook")
			return nil, err
		}
	}
	clusterConfig := &corev1.ConfigMap{}
	err = wh.kubeClient.Get(context.Background(), client.ObjectKey{Name: installConfigMap, Namespace: installConfigNamespace}, clusterConfig)
	if err != nil {
		log.Error(err, "Failed to fetch configmap: 'cluster-config-v1' for cluster config")
		return nil, err
	}
	data, ok := clusterConfig.Data[installConfigKeyName]
	if !ok {
		return nil, fmt.Errorf("did not find key %s in configmap %s/%s", installConfigKeyName, installConfigNamespace, installConfigMap)
	}
	instConf := &installConfig{}

	decoder := yaml.NewYAMLOrJSONDecoder(bytes.NewReader([]byte(data)), 4096)
	if err := decoder.Decode(instConf); err != nil {
		return nil, errors.Wrap(err, "failed to decode install config")
	}
	return instConf, nil
}

func (wh *IngressControllerWebhook) checkAllowsMachineCIDR(ipRanges []operatorv1.CIDR) admissionctl.Response {
	// https://docs.openshift.com/container-platform/4.13/networking/configuring_ingress_cluster_traffic/configuring-ingress-cluster-traffic-load-balancer-allowed-source-ranges.html
	// Note: From docs it appears a missing ASR value/attr allows all. However...
	// once ASR values have been added to an ingresscontroller, later deleting all the ASRs can expose an issue
	// where the IGC will remaining in progressing state indefinitely.
	// For now return Allowed with a warning?
	if ipRanges == nil || len(ipRanges) <= 0 {
		return admissionctl.Allowed("Allowing empty 'AllowedSourceRanges'. Populate this value if operator remains in 'progressing' state")
	}
	machIP, machNet, err := wh.getMachineCIDR()
	if err != nil {
		// This represents a fault in either the webhook itself, webhook permissions, or install config.
		// Might be nice to have an env var etc we can set to allow proceeding w/o the immediate need to roll new code?
		return admissionctl.Errored(http.StatusInternalServerError, err)
	}
	machNetSize, machNetBits := machNet.Mask.Size()
	log.Info("Checking AllowedSourceRanges", "MachineCIDR", fmt.Sprintf("%s/%d", machIP.String(), machNetSize), "NetBits", machNetBits, "AllowedSourceRanges", ipRanges)
	for _, OpV1CIDR := range ipRanges {
		// Clean up the operatorV1.CIDR value into trimmed CIDR 'a.b.c.d/x' string
		ASRstring := strings.TrimSpace(string(OpV1CIDR))
		log.Info(fmt.Sprintf("Checking allowed source:'%s'", ASRstring))
		if len(ASRstring) <= 0 {
			continue
		}
		// Parse the Allowed Source Range Cidr entry into network structures...
		_, ASRNet, err := net.ParseCIDR(ASRstring)
		if err != nil {
			log.Info(fmt.Sprintf("failed to parse AllowedSourceRanges value: '%s'. Err: %s", string(ASRstring), err))
			return admissionctl.Errored(http.StatusBadRequest, fmt.Errorf("failed to parse AllowedSourceRanges value: '%s'. Err: %s", string(ASRstring), err))
		}
		// First check if this AlloweSourceRange entry network contains the machine cidr ip...
		if !ASRNet.Contains(machIP) {
			log.Info(fmt.Sprintf("AllowedSourceRange:'%s' does not contain machine CIDR:'%s/%d'", ASRstring, machIP.String(), machNetSize))
			continue
		}
		// Check if this AlloweSourceRange entry mask includes the network.
		ASRNetSize, ASRNetBits := ASRNet.Mask.Size()
		if machNetBits == ASRNetBits && ASRNetSize <= machNetSize {
			log.Info(fmt.Sprintf("Found machineCidr:'%s/%d' within AllowedSourceRange:'%s'", machIP.String(), machNetSize, ASRstring))
			return admissionctl.Allowed(fmt.Sprintf("Found machineCidr:'%s/%d' within AllowedSourceRange:'%s'", machIP.String(), machNetSize, ASRstring))
			//return admissionctl.Allowed("IngressController operation is allowed. Minimum AllowedSourceRanges are met.")
		}
	}
	log.Info(fmt.Sprintf("machineCidr:'%s/%d' not found within networks provided by AllowedSourceRanges:'%v'", machIP.String(), machNetSize, ipRanges))
	return admissionctl.Denied(fmt.Sprintf("At least one AllowedSourceRange must allow machine cidr:'%s/%d'", machIP.String(), machNetSize))
}

// isAllowedUser checks if the user is allowed to perform the action
func isAllowedUser(request admissionctl.Request) bool {
	log.Info(fmt.Sprintf("Checking username %s on whitelist", request.UserInfo.Username))
	if slices.Contains(allowedUsers, request.UserInfo.Username) {
		log.Info(fmt.Sprintf("%s is listed in whitelist", request.UserInfo.Username))
		return true
	}

	log.Info("No allowed user found")

	return false
}

// Authorized implements Webhook interface
func (wh *IngressControllerWebhook) Authorized(request admissionctl.Request) admissionctl.Response {
	return wh.authorized(request)
}

// SyncSetLabelSelector returns the label selector to use in the SyncSet.
// We turn on 'managed ingress v2' by setting legacy ingress to 'false'
// See https://github.com/openshift/cloud-ingress-operator/blob/master/hack/olm-registry/olm-artifacts-template.yaml
// and
// https://github.com/openshift/custom-domains-operator/blob/master/hack/olm-registry/olm-artifacts-template.yaml
// For examples of use.
func (s *IngressControllerWebhook) SyncSetLabelSelector() metav1.LabelSelector {
	customLabelSelector := utils.DefaultLabelSelector()
	customLabelSelector.MatchExpressions = append(customLabelSelector.MatchExpressions,
		metav1.LabelSelectorRequirement{
			Key:      legacyIngressSupportFeatureFlag,
			Operator: metav1.LabelSelectorOpIn,
			Values: []string{
				"false",
			},
		})
	return customLabelSelector
}

func (s *IngressControllerWebhook) ClassicEnabled() bool { return true }

func (s *IngressControllerWebhook) HypershiftEnabled() bool { return false }

// NewWebhook creates a new webhook
func NewWebhook() *IngressControllerWebhook {
	scheme := runtime.NewScheme()
	err := corev1.AddToScheme(scheme)
	if err != nil {
		log.Error(err, "Fail adding corev1 scheme to IngressControllerWebhook")
		os.Exit(1)
	}
	return &IngressControllerWebhook{
		s:          *scheme,
		kubeClient: nil,
	}
}
