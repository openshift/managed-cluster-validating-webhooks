package ingresscontroller

import (
	"encoding/json"
	"fmt"
	"testing"

	"github.com/openshift/managed-cluster-validating-webhooks/pkg/testutils"
	admissionv1 "k8s.io/api/admission/v1"
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

func createRawIngressControllerJSON(name string, namespace string, nodeSelector corev1.NodeSelector, tolerations []corev1.Toleration) (string, error) {
	nodeSelectorPartial, err := json.Marshal(nodeSelector)
	if err != nil {
		return "", err
	}
	tolerationsPartial, err := json.Marshal(tolerations)
	if err != nil {
		return "", err
	}

	output := fmt.Sprintf(template, name, namespace, string(nodeSelectorPartial), string(tolerationsPartial))

	return output, nil
}

type ingressControllerTestSuites struct {
	testID          string
	name            string
	namespace       string
	username        string
	userGroups      []string
	operation       admissionv1.Operation
	nodeSelector    corev1.NodeSelector
	tolerations     []corev1.Toleration
	shouldBeAllowed bool
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
		rawObjString, err := createRawIngressControllerJSON(test.name, test.namespace, test.nodeSelector, test.tolerations)
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
		httprequest, err := testutils.CreateHTTPRequest(hook.GetURI(), test.testID, gvk, gvr, test.operation, test.username, test.userGroups, &obj, &oldObj)

		if err != nil {
			t.Fatalf("Expected no error, got %s", err.Error())
		}

		response, err := testutils.SendHTTPRequest(httprequest, hook)
		if err != nil {
			t.Fatalf("Expected no error, got %s", err.Error())
		}
		if response.UID == "" {
			t.Fatalf("No tracking UID associated with the response.")
		}

		if response.Allowed != test.shouldBeAllowed {
			t.Fatalf("[%s] Mismatch: %s (groups=%s) %s %s the ingress controller. Test's expectation is that the user %s", test.testID, test.username, test.userGroups, testutils.CanCanNot(response.Allowed), test.operation, testutils.CanCanNot(test.shouldBeAllowed))

		}
	}
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
			shouldBeAllowed: false,
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
			shouldBeAllowed: false,
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
			username:   "anywho",
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
			username:   "anywho",
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
			username:   "anywho",
			userGroups: []string{"system:serviceaccounts:hive"},
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
			username:   "anywho",
			userGroups: []string{"system:serviceaccounts:hive"},
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
