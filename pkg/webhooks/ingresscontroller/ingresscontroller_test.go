package ingresscontroller

import (
	"encoding/json"
	"fmt"
	"net"
	"testing"

	operatorv1 "github.com/openshift/api/operator/v1"
	"github.com/openshift/managed-cluster-validating-webhooks/pkg/testutils"
	admissionv1 "k8s.io/api/admission/v1"
	admissionregv1 "k8s.io/api/admissionregistration/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
)

const template string = `{
    "apiVersion": "operator.openshift.io/v1",
    "kind": "IngressController",
    "metadata": {
        "name": "%s",
        "namespace": "%s"
    },
    "spec": {
        "clientTLS": {
            "clientCA": {
                "name": ""
            },
            "clientCertificatePolicy": ""
        },
        "defaultCertificate": {
            "name": "dummy-default-cert"
        },
        "domain": "apps.dummy.devshift.org",
        "endpointPublishingStrategy": {
            "loadBalancer": {
				%s
                "providerParameters": {
                    "aws": {
                        "classicLoadBalancer": {
                            "connectionIdleTimeout": "30m0s"
                        },
                        "type": "Classic"
                    },
                    "type": "AWS"
                },
                "scope": "External"
            },
            "type": "LoadBalancerService"
        },
        "httpCompression": {},
        "httpEmptyRequestsPolicy": "Respond",
        "httpErrorCodePages": {
            "name": ""
        },
        "nodePlacement": {
            "nodeSelector": %s,
            "tolerations": %s
        },
        "replicas": 2,
        "routeSelector": {},
        "tuningOptions": {}
    }
  }
  `

func createRawIngressControllerJSON(name string, namespace string, nodeSelector corev1.NodeSelector, tolerations []corev1.Toleration, allowedRanges []operatorv1.CIDR) (string, error) {
	var AllowedSourceRangesPartial string = ""
	nodeSelectorPartial, err := json.Marshal(nodeSelector)
	if err != nil {
		return "", err
	}
	tolerationsPartial, err := json.Marshal(tolerations)
	if err != nil {
		return "", err
	}
	// Allow a nil value to exclude the 'allowedSourceRanges' param from the request.
	if allowedRanges != nil {
		ASRString, err := json.Marshal(allowedRanges)
		if err != nil {
			return "", err
		}
		AllowedSourceRangesPartial = fmt.Sprintf("\"allowedSourceRanges\": %s,", ASRString)
	}

	output := fmt.Sprintf(template, name, namespace, string(AllowedSourceRangesPartial), string(nodeSelectorPartial), string(tolerationsPartial))
	return output, nil
}

type ingressControllerTestSuites struct {
	testID              string
	name                string
	namespace           string
	username            string
	userGroups          []string
	operation           admissionv1.Operation
	nodeSelector        corev1.NodeSelector
	tolerations         []corev1.Toleration
	allowedSourceRanges []operatorv1.CIDR
	machineCIDR         string
	shouldBeAllowed     bool
	errorContains       string
}

func runIngressControllerTests(t *testing.T, tests []ingressControllerTestSuites) {
	gvk := metav1.GroupVersionKind{
		Group:   "",
		Version: "v1",
		Kind:    "IngressController",
	}
	gvr := metav1.GroupVersionResource{
		Group:    "",
		Version:  "v1",
		Resource: "ingresscontroller",
	}
	for _, test := range tests {
		rawObjString, err := createRawIngressControllerJSON(test.name, test.namespace, test.nodeSelector, test.tolerations, test.allowedSourceRanges)
		if err != nil {
			t.Fatalf("Couldn't create a JSON fragment %s", err.Error())
		}

		obj := runtime.RawExtension{
			Raw: []byte(rawObjString),
		}

		oldObj := runtime.RawExtension{
			Raw: []byte(rawObjString),
		}

		hook := NewWebhook()
		err = setMachineCidr(t, test, hook)
		if err != nil {
			t.Fatalf("Expected no error, got err parsing machineCIDR:'%s', got '%s'", string(test.machineCIDR), err.Error())
		}
		httprequest, err := testutils.CreateHTTPRequest(hook.GetURI(), test.testID, gvk, gvr, test.operation, test.username, test.userGroups, "", &obj, &oldObj)

		if err != nil {
			t.Logf("Request object:'%s'", obj)
			t.Fatalf("Expected no error, got %s", err.Error())
		}

		response, err := testutils.SendHTTPRequest(httprequest, hook)
		if err != nil {
			t.Fatalf("Expected no error, got %s", err.Error())
		}
		if response.UID == "" {
			//t.Logf("Request object:'%s'", obj)
			t.Logf("Response object:'%v'", response)
			t.Fatalf("No tracking UID associated with the response.")
		}

		if response.Allowed != test.shouldBeAllowed {
			t.Logf("%s", obj)
			t.Logf("Response.reason:'%v'", response)
			t.Fatalf("[%s] Mismatch: %s (groups=%s) %s %s the ingress controller. Test's expectation is that the user %s", test.testID, test.username, test.userGroups, testutils.CanCanNot(response.Allowed), test.operation, testutils.CanCanNot(test.shouldBeAllowed))
		}
	}
}

func setMachineCidr(t *testing.T, test ingressControllerTestSuites, hook *IngressControllerWebhook) error {
	if len(test.machineCIDR) > 0 {
		ip, net, err := net.ParseCIDR(string(test.machineCIDR))
		if err != nil {
			return err
		}
		hook.machineCIDRIP = ip
		hook.machineCIDRNet = net
	} else {
		hook.machineCIDRIP = nil
		hook.machineCIDRNet = nil
	}
	return nil
}

func TestIngressControllerTolerations(t *testing.T) {
	tests := []ingressControllerTestSuites{
		{
			testID:     "toleration-test-create-1",
			name:       "shiny-newingress",
			namespace:  "openshift-ingress-operator",
			username:   "admin",
			userGroups: []string{"system:authenticated", "dedicated-admin"},
			operation:  admissionv1.Create,
			nodeSelector: corev1.NodeSelector{
				NodeSelectorTerms: []corev1.NodeSelectorTerm{},
			},
			tolerations: []corev1.Toleration{
				{
					Key:      "node-role.kubernetes.io/master",
					Operator: "Exists",
					Effect:   "NoSchedule",
				},
			},
			shouldBeAllowed: false,
		},
		{
			testID:     "toleration-test-create-2",
			name:       "shiny-newingress",
			namespace:  "openshift-ingress-operator",
			username:   "admin",
			userGroups: []string{"system:authenticated", "cluster-admins"},
			operation:  admissionv1.Create,
			nodeSelector: corev1.NodeSelector{
				NodeSelectorTerms: []corev1.NodeSelectorTerm{},
			},
			tolerations: []corev1.Toleration{
				{
					Key:      "node-role.kubernetes.io/infra",
					Operator: "Exists",
					Effect:   "NoSchedule",
				},
			},
			shouldBeAllowed: true,
		},
		{
			testID:     "toleration-test-create-3",
			name:       "shiny-newingress",
			namespace:  "openshift-ingress-operator",
			username:   "admin",
			userGroups: []string{"system:authenticated", "cluster-admins"},
			operation:  admissionv1.Create,
			nodeSelector: corev1.NodeSelector{
				NodeSelectorTerms: []corev1.NodeSelectorTerm{},
			},
			tolerations:     []corev1.Toleration{},
			shouldBeAllowed: true,
		},
		{
			testID:     "toleration-test-update-1",
			name:       "shiny-newingress",
			namespace:  "openshift-ingress-operator",
			username:   "admin",
			userGroups: []string{"system:authenticated", "dedicated-admin"},
			operation:  admissionv1.Update,
			nodeSelector: corev1.NodeSelector{
				NodeSelectorTerms: []corev1.NodeSelectorTerm{},
			},
			tolerations: []corev1.Toleration{
				{
					Key:      "node-role.kubernetes.io/master",
					Operator: "Exists",
					Effect:   "NoSchedule",
				},
			},
			shouldBeAllowed: false,
		},
		{
			testID:     "toleration-test-update-2",
			name:       "shiny-newingress",
			namespace:  "openshift-ingress-operator",
			username:   "admin",
			userGroups: []string{"system:authenticated", "cluster-admins"},
			operation:  admissionv1.Update,
			nodeSelector: corev1.NodeSelector{
				NodeSelectorTerms: []corev1.NodeSelectorTerm{},
			},
			tolerations: []corev1.Toleration{
				{
					Key:      "node-role.kubernetes.io/infra",
					Operator: "Exists",
					Effect:   "NoSchedule",
				},
			},
			shouldBeAllowed: true,
		},
		{
			testID:     "toleration-test-update-3",
			name:       "shiny-newingress",
			namespace:  "openshift-ingress-operator",
			username:   "admin",
			userGroups: []string{"system:authenticated", "cluster-admins"},
			operation:  admissionv1.Update,
			nodeSelector: corev1.NodeSelector{
				NodeSelectorTerms: []corev1.NodeSelectorTerm{},
			},
			tolerations:     []corev1.Toleration{},
			shouldBeAllowed: true,
		},
	}
	runIngressControllerTests(t, tests)
}

func TestIngressControllerExceptions(t *testing.T) {
	tests := []ingressControllerTestSuites{
		{
			testID:     "exception-test-create-serviceaccounts",
			name:       "shiny-newingress",
			namespace:  "openshift-ingress-operator",
			username:   "system:serviceaccount:openshift-ingress-operator",
			userGroups: []string{"system:serviceaccounts:openshift-ingress-operator"},
			operation:  admissionv1.Create,
			nodeSelector: corev1.NodeSelector{
				NodeSelectorTerms: []corev1.NodeSelectorTerm{},
			},
			tolerations: []corev1.Toleration{
				{
					Key:      "node-role.kubernetes.io/infra",
					Operator: "Exists",
					Effect:   "NoSchedule",
				},
			},
			shouldBeAllowed: true,
		},
		{
			testID:     "exception-test-update-serviceaccounts",
			name:       "shiny-newingress",
			namespace:  "openshift-ingress-operator",
			username:   "system:serviceaccount:openshift-ingress-operator",
			userGroups: []string{"system:serviceaccounts:openshift-ingress-operator"},
			operation:  admissionv1.Update,
			nodeSelector: corev1.NodeSelector{
				NodeSelectorTerms: []corev1.NodeSelectorTerm{},
			},
			tolerations: []corev1.Toleration{
				{
					Key:      "node-role.kubernetes.io/infra",
					Operator: "Exists",
					Effect:   "NoSchedule",
				},
			},
			shouldBeAllowed: true,
		},
		{
			testID:     "exception-test-create-backplane-cluster-admin",
			name:       "shiny-newingress",
			namespace:  "openshift-ingress-operator",
			username:   "backplane-cluster-admin",
			userGroups: []string{},
			operation:  admissionv1.Create,
			nodeSelector: corev1.NodeSelector{
				NodeSelectorTerms: []corev1.NodeSelectorTerm{},
			},
			tolerations: []corev1.Toleration{
				{
					Key:      "node-role.kubernetes.io/infra",
					Operator: "Exists",
					Effect:   "NoSchedule",
				},
			},
			shouldBeAllowed: true,
		},
		{
			testID:     "exception-test-update-backplane-cluster-admin",
			name:       "shiny-newingress",
			namespace:  "openshift-ingress-operator",
			username:   "backplane-cluster-admin",
			userGroups: []string{},
			operation:  admissionv1.Update,
			nodeSelector: corev1.NodeSelector{
				NodeSelectorTerms: []corev1.NodeSelectorTerm{},
			},
			tolerations: []corev1.Toleration{
				{
					Key:      "node-role.kubernetes.io/infra",
					Operator: "Exists",
					Effect:   "NoSchedule",
				},
			},
			shouldBeAllowed: true,
		},
		{
			testID:     "exception-test-create-hive",
			name:       "shiny-newingress",
			namespace:  "openshift-ingress-operator",
			username:   "system:serviceaccount:hive:hive-controllers",
			userGroups: []string{"system;serviceaccounts", "system:serviceaccounts:hive", "system:authenticated"},
			operation:  admissionv1.Create,
			nodeSelector: corev1.NodeSelector{
				NodeSelectorTerms: []corev1.NodeSelectorTerm{},
			},
			tolerations: []corev1.Toleration{
				{
					Key:      "node-role.kubernetes.io/infra",
					Operator: "Exists",
					Effect:   "NoSchedule",
				},
			},
			shouldBeAllowed: true,
		},
		{
			testID:     "exception-test-update-hive",
			name:       "shiny-newingress",
			namespace:  "openshift-ingress-operator",
			username:   "system:serviceaccount:hive:hive-controllers",
			userGroups: []string{"system;serviceaccounts", "system:serviceaccounts:hive", "system:authenticated"},
			operation:  admissionv1.Update,
			nodeSelector: corev1.NodeSelector{
				NodeSelectorTerms: []corev1.NodeSelectorTerm{},
			},
			tolerations: []corev1.Toleration{
				{
					Key:      "node-role.kubernetes.io/infra",
					Operator: "Exists",
					Effect:   "NoSchedule",
				},
			},
			shouldBeAllowed: true,
		},
	}
	runIngressControllerTests(t, tests)
}

func runIngressControllerAllowedSourceRangesTests(t *testing.T, op admissionv1.Operation) {
	tests := []ingressControllerTestSuites{
		{
			testID:      fmt.Sprintf("allowedSourceRanges-test-missing-allowedSourceRanges-%s", op),
			name:        "default",
			namespace:   "openshift-ingress-operator",
			username:    "admin",
			userGroups:  []string{"system:authenticated", "cluster-admins"},
			operation:   op,
			machineCIDR: "10.0.0.0/16",
			//AllowedSourceRanges: nil,
			nodeSelector: corev1.NodeSelector{
				NodeSelectorTerms: []corev1.NodeSelectorTerm{},
			},
			tolerations:     []corev1.Toleration{},
			shouldBeAllowed: true,
		},
		{
			testID:     fmt.Sprintf("allowedSourceRanges-test-missing-allowedSourceRanges-and-machineCIDR-%s", op),
			name:       "default",
			namespace:  "openshift-ingress-operator",
			username:   "admin",
			userGroups: []string{"system:authenticated", "cluster-admins"},
			operation:  op,
			//machineCIDR: "10.0.0.0/16",
			//AllowedSourceRanges: nil,
			nodeSelector: corev1.NodeSelector{
				NodeSelectorTerms: []corev1.NodeSelectorTerm{},
			},
			tolerations:     []corev1.Toleration{},
			shouldBeAllowed: true,
		},
		{
			testID:              fmt.Sprintf("allowedSourceRanges-test-empty-allowedSourceRanges-%s", op),
			name:                "default",
			namespace:           "openshift-ingress-operator",
			username:            "admin",
			userGroups:          []string{"system:authenticated", "cluster-admins"},
			operation:           op,
			machineCIDR:         "10.0.0.0/16",
			allowedSourceRanges: []operatorv1.CIDR{},
			nodeSelector: corev1.NodeSelector{
				NodeSelectorTerms: []corev1.NodeSelectorTerm{},
			},
			tolerations:     []corev1.Toleration{},
			shouldBeAllowed: true,
		},
		{
			testID:     fmt.Sprintf("allowedSourceRanges-test-empty-ASR-no-machineCIDR-%s", op),
			name:       "default",
			namespace:  "openshift-ingress-operator",
			username:   "admin",
			userGroups: []string{"system:authenticated", "cluster-admins"},
			operation:  op,
			//machineCIDR: "10.0.0.0/16",
			allowedSourceRanges: []operatorv1.CIDR{},
			nodeSelector: corev1.NodeSelector{
				NodeSelectorTerms: []corev1.NodeSelectorTerm{},
			},
			tolerations:     []corev1.Toleration{},
			shouldBeAllowed: true,
		},
		{
			testID:              fmt.Sprintf("allowedSourceRanges-test-include-only-machineCIDR-%s", op),
			name:                "default",
			namespace:           "openshift-ingress-operator",
			username:            "admin",
			userGroups:          []string{"system:authenticated", "cluster-admins"},
			operation:           op,
			machineCIDR:         "10.0.0.0/16",
			allowedSourceRanges: []operatorv1.CIDR{"10.0.0.0/8"},
			nodeSelector: corev1.NodeSelector{
				NodeSelectorTerms: []corev1.NodeSelectorTerm{},
			},
			tolerations:     []corev1.Toleration{},
			shouldBeAllowed: true,
		},
		{
			testID:              fmt.Sprintf("allowedSourceRanges-test-include-many-before-machineCIDR-%s", op),
			name:                "default",
			namespace:           "openshift-ingress-operator",
			username:            "admin",
			userGroups:          []string{"system:authenticated", "cluster-admins"},
			operation:           op,
			machineCIDR:         "10.0.0.0/16",
			allowedSourceRanges: []operatorv1.CIDR{"10.0.0.0/8", "192.168.1.0/24", "172.20.4.0/16"},
			nodeSelector: corev1.NodeSelector{
				NodeSelectorTerms: []corev1.NodeSelectorTerm{},
			},
			tolerations:     []corev1.Toleration{},
			shouldBeAllowed: true,
		},
		{
			testID:              fmt.Sprintf("allowedSourceRanges-test-include-many-after-machineCIDR-%s", op),
			name:                "default",
			namespace:           "openshift-ingress-operator",
			username:            "admin",
			userGroups:          []string{"system:authenticated", "cluster-admins"},
			operation:           op,
			machineCIDR:         "10.0.0.0/16",
			allowedSourceRanges: []operatorv1.CIDR{"192.168.1.0/24", "172.20.4.0/16", "10.0.0.0/8"},
			nodeSelector: corev1.NodeSelector{
				NodeSelectorTerms: []corev1.NodeSelectorTerm{},
			},
			tolerations:     []corev1.Toleration{},
			shouldBeAllowed: true,
		},
		{
			testID:              fmt.Sprintf("allowedSourceRanges-test-exclude-single-machineCIDR-%s", op),
			name:                "default",
			namespace:           "openshift-ingress-operator",
			username:            "admin",
			userGroups:          []string{"system:authenticated", "cluster-admins"},
			operation:           op,
			machineCIDR:         "10.0.0.0/16",
			allowedSourceRanges: []operatorv1.CIDR{"192.168.1.0/24"},
			nodeSelector: corev1.NodeSelector{
				NodeSelectorTerms: []corev1.NodeSelectorTerm{},
			},
			tolerations:     []corev1.Toleration{},
			shouldBeAllowed: false,
		},
		{
			testID:              fmt.Sprintf("allowedSourceRanges-test-exclude-many-machineCIDR-%s", op),
			name:                "default",
			namespace:           "openshift-ingress-operator",
			username:            "admin",
			userGroups:          []string{"system:authenticated", "cluster-admins"},
			operation:           op,
			machineCIDR:         "10.0.0.0/16",
			allowedSourceRanges: []operatorv1.CIDR{"192.168.1.0/24", "192.168.1.0/16", "172.20.4.5/32", "10.0.0.0/17"},
			nodeSelector: corev1.NodeSelector{
				NodeSelectorTerms: []corev1.NodeSelectorTerm{},
			},
			tolerations:     []corev1.Toleration{},
			shouldBeAllowed: false,
		},
		{
			testID:              fmt.Sprintf("allowedSourceRanges-test-invalid-network-value-%s", op),
			name:                "default",
			namespace:           "openshift-ingress-operator",
			username:            "admin",
			userGroups:          []string{"system:authenticated", "cluster-admins"},
			operation:           op,
			machineCIDR:         "10.0.0.0/16",
			allowedSourceRanges: []operatorv1.CIDR{"10"},
			nodeSelector: corev1.NodeSelector{
				NodeSelectorTerms: []corev1.NodeSelectorTerm{},
			},
			tolerations:     []corev1.Toleration{},
			shouldBeAllowed: false,
		},
		{
			testID:              fmt.Sprintf("allowedSourceRanges-test-invalid-input-%s", op),
			name:                "default",
			namespace:           "openshift-ingress-operator",
			username:            "admin",
			userGroups:          []string{"system:authenticated", "cluster-admins"},
			operation:           op,
			machineCIDR:         "10.0.0.0/16",
			allowedSourceRanges: []operatorv1.CIDR{"ABC"},
			nodeSelector: corev1.NodeSelector{
				NodeSelectorTerms: []corev1.NodeSelectorTerm{},
			},
			tolerations:     []corev1.Toleration{},
			shouldBeAllowed: false,
		},
		{
			testID:              fmt.Sprintf("allowedSourceRanges-test-include-machineCIDR-with-ipv6-%s", op),
			name:                "default",
			namespace:           "openshift-ingress-operator",
			username:            "admin",
			userGroups:          []string{"system:authenticated", "cluster-admins"},
			operation:           op,
			machineCIDR:         "10.0.0.0/16",
			allowedSourceRanges: []operatorv1.CIDR{"2001:db8:abcd:1234::1/64", "10.0.0.0/16"},
			nodeSelector: corev1.NodeSelector{
				NodeSelectorTerms: []corev1.NodeSelectorTerm{},
			},
			tolerations:     []corev1.Toleration{},
			shouldBeAllowed: true,
		},
		{
			testID:     fmt.Sprintf("allowedSourceRanges-test-valid-input-no-machineCIDR-%s", op),
			name:       "default",
			namespace:  "openshift-ingress-operator",
			username:   "admin",
			userGroups: []string{"system:authenticated", "cluster-admins"},
			operation:  op,
			//machineCIDR:         "10.0.0.0/16",
			allowedSourceRanges: []operatorv1.CIDR{"192.168.1.0/24", "10.0.0.0/16"},
			nodeSelector: corev1.NodeSelector{
				NodeSelectorTerms: []corev1.NodeSelectorTerm{},
			},
			tolerations:     []corev1.Toleration{},
			shouldBeAllowed: false,
			errorContains:   "",
		},
	}
	runIngressControllerTests(t, tests)
}

func TestIngressControllerAllowedSourceRangesCreate(t *testing.T) {
	// Test the update and create operations in parallel?
	t.Parallel()
	runIngressControllerAllowedSourceRangesTests(t, admissionv1.Create)
}

func TestIngressControllerAllowedSourceRangesUpdate(t *testing.T) {
	// Test the update and create operations in parallel?
	t.Parallel()
	runIngressControllerAllowedSourceRangesTests(t, admissionv1.Update)
}

func runIngressControllerAllowedSourceRangesNonDefaultTest(t *testing.T, op admissionv1.Operation) {
	tests := []ingressControllerTestSuites{
		{
			testID:              fmt.Sprintf("allowedSourceRanges-test-non-default-exclude-machineCIDR-%s", op),
			name:                "shiny-newingress",
			namespace:           "openshift-ingress-operator",
			username:            "admin",
			userGroups:          []string{"system:authenticated", "cluster-admins"},
			operation:           op,
			machineCIDR:         "10.0.0.0/16",
			allowedSourceRanges: []operatorv1.CIDR{"192.168.1.0/24", "172.20.4.0/24"},
			nodeSelector: corev1.NodeSelector{
				NodeSelectorTerms: []corev1.NodeSelectorTerm{},
			},
			tolerations:     []corev1.Toleration{},
			shouldBeAllowed: true,
			errorContains:   "",
		},
		{
			testID:              fmt.Sprintf("allowedSourceRanges-test-non-os-namespace-exclude-machineCIDR-%s", op),
			name:                "default",
			namespace:           "shiny-newingress-namespace", //May not be a valid test beyond testing  the webhook.
			username:            "admin",
			userGroups:          []string{"system:authenticated", "cluster-admins"},
			operation:           op,
			machineCIDR:         "10.0.0.0/16",
			allowedSourceRanges: []operatorv1.CIDR{"192.168.1.0/24", "172.20.4.0/24"},
			nodeSelector: corev1.NodeSelector{
				NodeSelectorTerms: []corev1.NodeSelectorTerm{},
			},
			tolerations:     []corev1.Toleration{},
			shouldBeAllowed: true,
			errorContains:   "",
		},
	}
	runIngressControllerTests(t, tests)
}

func TestIngressControllerAllowedSourceRangesNonDefaultCreate(t *testing.T) {
	runIngressControllerAllowedSourceRangesTests(t, admissionv1.Create)
}
func TestIngressControllerAllowedSourceRangesNonDefaultUpdate(t *testing.T) {
	runIngressControllerAllowedSourceRangesTests(t, admissionv1.Update)
}
func TestIngressControllerCheckDeleteSupport(t *testing.T) {
	hook := NewWebhook()
	rules := hook.Rules()
	for _, rule := range rules {
		for _, op := range rule.Operations {
			if op == admissionregv1.OperationType(admissionv1.Delete) {
				t.Fatalf("IngressController web hook is supporting the Delete operation. Replace this check with unit tests supporting 'Delete'")
			}
		}
	}
}
