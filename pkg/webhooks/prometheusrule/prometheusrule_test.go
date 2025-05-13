package prometheusrule

import (
	"fmt"
	"testing"

	admissionv1 "k8s.io/api/admission/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"

	"github.com/openshift/managed-cluster-validating-webhooks/pkg/testutils"
)

const testObjectRaw string = `
{
	"apiVersion": "monitoring.coreos.com/v1",
	"kind": "PrometheusRule",
	"metadata": {
        "name": "test",
		"namespace": "%s",
		"uid": "1234"
	}
}`

type prometheusruleTestSuites struct {
	testID          string
	username        string
	userGroups      []string
	targetNamespace string
	targetResource  string
	operation       admissionv1.Operation
	shouldBeAllowed bool
}

func createRawJSONString(namespace string) string {
	s := fmt.Sprintf(testObjectRaw, namespace)
	return s
}

func runPrometheusRuleTests(t *testing.T, tests []prometheusruleTestSuites) {
	gvk := metav1.GroupVersionKind{
		Group:   "monitoring.coreos.com",
		Version: "v1",
		Kind:    "PrometheusRule",
	}
	gvr := metav1.GroupVersionResource{
		Group:    "monitoring.coreos.com",
		Version:  "v1",
		Resource: "prometheusrules",
	}

	for _, test := range tests {
		rawObjString := createRawJSONString(test.targetNamespace)

		obj := runtime.RawExtension{
			Raw: []byte(rawObjString),
		}

		oldObj := runtime.RawExtension{
			Raw: []byte(rawObjString),
		}

		hook := NewWebhook()
		httprequest, err := testutils.CreateHTTPRequest(hook.GetURI(),
			test.testID, gvk, gvr, test.operation, test.username, test.userGroups, "", &obj, &oldObj)
		if err != nil {
			t.Fatalf("Expected no error, got %s", err.Error())
		}

		response, err := testutils.SendHTTPRequest(httprequest, hook)
		if err != nil {
			t.Fatalf("Expected no error, got %s", err.Error())
		}

		if response.Allowed != test.shouldBeAllowed {
			t.Fatalf("Mismatch: %s (groups=%s) %s %s the Test's expectation is that the user %s", test.username, test.userGroups, testutils.CanCanNot(response.Allowed), test.operation, testutils.CanCanNot(test.shouldBeAllowed))
		}
	}
}
func TestUsers(t *testing.T) {
	tests := []prometheusruleTestSuites{
		{
			testID:          "regular-user-cant-create-prometheusrule-in-managed-namespaces",
			targetNamespace: "openshift-kube-apiserver",
			targetResource:  "prometheusrule",
			username:        "user1",
			userGroups:      []string{"system:authenticated", "system:authenticated:oauth"},
			operation:       admissionv1.Create,
			shouldBeAllowed: false,
		},
		{
			testID:          "regular-user-cant-delete-prometheusrule-in-managed-namespaces",
			targetNamespace: "openshift-kube-apiserver",
			targetResource:  "prometheusrule",
			username:        "user2",
			userGroups:      []string{"system:authenticated", "system:authenticated:oauth"},
			operation:       admissionv1.Delete,
			shouldBeAllowed: false,
		},
		{
			testID:          "regular-user-cant-update-prometheusrule-in-managed-namespaces",
			targetNamespace: "openshift-kube-apiserver",
			targetResource:  "prometheusrule",
			username:        "user3",
			userGroups:      []string{"system:authenticated", "system:authenticated:oauth"},
			operation:       admissionv1.Update,
			shouldBeAllowed: false,
		},
		{
			testID:          "regular-user-can-create-prometheusrule-in-user-managed-namespaces",
			targetNamespace: "my-monitoring",
			targetResource:  "prometheusrule",
			username:        "user4",
			userGroups:      []string{"system:authenticated", "system:authenticated:oauth"},
			operation:       admissionv1.Create,
			shouldBeAllowed: true,
		},
		{
			testID:          "regular-user-can-update-prometheusrule-in-user-managed-namespaces",
			targetNamespace: "my-monitoring",
			targetResource:  "prometheusrule",
			username:        "user5",
			userGroups:      []string{"system:authenticated", "system:authenticated:oauth"},
			operation:       admissionv1.Update,
			shouldBeAllowed: true,
		},
		{
			testID:          "regular-user-can-delete-prometheusrule-in-user-managed-namespaces",
			targetNamespace: "my-monitoring",
			targetResource:  "prometheusrule",
			username:        "user6",
			userGroups:      []string{"system:authenticated", "system:authenticated:oauth"},
			operation:       admissionv1.Delete,
			shouldBeAllowed: true,
		},
		{
			testID:          "regular-user-cant-create-prometheusrule-in-managed-namespaces",
			targetNamespace: "openshift-kube-apiserver",
			targetResource:  "prometheusrule",
			username:        "system:serviceaccounts:unpriv-ns",
			userGroups:      []string{"system:serviceaccounts:unpriv-ns", "cluster-admins", "system:authenticated", "system:authenticated:oauth"},
			operation:       admissionv1.Create,
			shouldBeAllowed: false,
		},
		{
			testID:          "regular-user-cant-delete-prometheusrule-in-managed-namespaces",
			targetNamespace: "openshift-kube-apiserver",
			targetResource:  "prometheusrule",
			username:        "system:serviceaccounts:unpriv-ns",
			userGroups:      []string{"system:serviceaccounts:unpriv-ns", "cluster-admins", "system:authenticated", "system:authenticated:oauth"},
			operation:       admissionv1.Delete,
			shouldBeAllowed: false,
		},
		{
			testID:          "regular-user-cant-update-prometheusrule-in-managed-namespaces",
			targetNamespace: "openshift-kube-apiserver",
			targetResource:  "prometheusrule",
			username:        "system:serviceaccounts:unpriv-ns",
			userGroups:      []string{"system:serviceaccounts:unpriv-ns", "cluster-admins", "system:authenticated", "system:authenticated:oauth"},
			operation:       admissionv1.Update,
			shouldBeAllowed: false,
		},

		{
			testID:          "blackplane-admin-can-create-prometheusrule-in-managed-namespaces",
			targetNamespace: "openshift-kube-apiserver",
			targetResource:  "prometheusrule",
			username:        "backplane-cluster-admin",
			userGroups:      []string{"system:authenticated", "system:authenticated:oauth"},
			operation:       admissionv1.Create,
			shouldBeAllowed: true,
		},
		{
			testID:          "blackplane-admin-can-delete-prometheusrule-in-managed-namespaces",
			targetNamespace: "openshift-kube-apiserver",
			targetResource:  "prometheusrule",
			username:        "backplane-cluster-admin",
			userGroups:      []string{"system:authenticated", "system:authenticated:oauth"},
			operation:       admissionv1.Delete,
			shouldBeAllowed: true,
		},
		{
			testID:          "blackplane-admin-can-update-prometheusrule-in-managed-namespaces",
			targetNamespace: "openshift-kube-apiserver",
			targetResource:  "prometheusrule",
			username:        "backplane-cluster-admin",
			userGroups:      []string{"system:authenticated", "system:authenticated:oauth"},
			operation:       admissionv1.Update,
			shouldBeAllowed: true,
		},
		{

			testID:          "Allowed-can-create-prometheusrule-in-managed-namespaces",
			targetNamespace: "openshift-kube-apiserver",
			targetResource:  "prometheusrule",
			username:        "system:serviceaccounts:openshift-test-ns",
			userGroups:      []string{"system:serviceaccounts:openshift-test-ns", "system:authenticated", "system:authenticated:oauth"},
			operation:       admissionv1.Create,
			shouldBeAllowed: true,
		},
		{

			testID:          "Allowed-can-delete-prometheusrule-in-managed-namespaces",
			targetNamespace: "openshift-kube-apiserver",
			targetResource:  "prometheusrule",
			username:        "system:serviceaccounts:openshift-test-ns",
			userGroups:      []string{"system:serviceaccounts:openshift-test-ns", "system:authenticated", "system:authenticated:oauth"},
			operation:       admissionv1.Delete,
			shouldBeAllowed: true,
		},
		{

			testID:          "Allowed-can-update-prometheusrule-in-managed-namespaces",
			targetNamespace: "openshift-kube-apiserver",
			username:        "system:serviceaccounts:openshift-test-ns",
			targetResource:  "prometheusrule",
			userGroups:      []string{"system:serviceaccounts:openshift-test-ns", "system:authenticated", "system:authenticated:oauth"},
			operation:       admissionv1.Update,
			shouldBeAllowed: true,
		},
		{

			testID:          "admin-can-create-prometheusrule-in-managed-namespaces",
			targetNamespace: "openshift-kube-apiserver",
			username:        "kube:admin",
			targetResource:  "prometheusrule",
			userGroups:      []string{"system:authenticated", "system:authenticated:oauth"},
			operation:       admissionv1.Create,
			shouldBeAllowed: true,
		},
		{

			testID:          "admin-can-create-prometheusrule-in-managed-namespaces",
			targetNamespace: "openshift-kube-apiserver",
			username:        "kube:admin",
			targetResource:  "prometheusrule",
			userGroups:      []string{"system:authenticated", "system:authenticated:oauth"},
			operation:       admissionv1.Update,
			shouldBeAllowed: true,
		},
		{

			testID:          "admin-can-create-prometheusrule-in-managed-namespaces",
			targetNamespace: "openshift-kube-apiserver",
			username:        "kube:admin",
			targetResource:  "prometheusrule",
			userGroups:      []string{"system:authenticated", "system:authenticated:oauth"},
			operation:       admissionv1.Delete,
			shouldBeAllowed: true,
		},
		{
			testID:          "regular-user-can-create-prometheusrule-in-openshift-user-workload-monitoring",
			targetNamespace: "openshift-user-workload-monitoring",
			targetResource:  "prometheusrule",
			username:        "prometheus-user-workload",
			userGroups:      []string{"cluster-admins", "system:authenticated", "system:authenticated:oauth"},
			operation:       admissionv1.Create,
			shouldBeAllowed: true,
		},
		{
			testID:          "regular-user-can-create-prometheusrule-in-openshift-customer-monitoring",
			targetNamespace: "openshift-customer-monitoring",
			targetResource:  "prometheusrule",
			username:        "prometheus-user-workload",
			userGroups:      []string{"cluster-admins", "system:authenticated", "system:authenticated:oauth"},
			operation:       admissionv1.Delete,
			shouldBeAllowed: true,
		},
		{
			testID:          "serviceaccount-in-managed-namespaces-can-create-prometheusrule-in-openshift-user-workload-monitoring",
			targetNamespace: "openshift-user-workload-monitoring",
			targetResource:  "prometheusrule",
			username:        "prometheus-user-workload",
			userGroups:      []string{"cluster-admins", "system:authenticated", "system:authenticated:oauth"},
			operation:       admissionv1.Update,
			shouldBeAllowed: true,
		},
		{
			testID:          "serviceaccount-in-managed-namespaces-can-create-prometheusrule-in-redhat-rhoam-observability",
			targetNamespace: "redhat-rhoam-observability",
			targetResource:  "prometheusrule",
			username:        "system:serviceaccounts:redhat-ns:test-operator",
			userGroups:      []string{"system:serviceaccounts:redhat-ns:test-operator", "system:authenticated", "system:authenticated:oauth"},
			operation:       admissionv1.Create,
			shouldBeAllowed: true,
		},
		{
			testID:          "serviceaccount-in-managed-namespaces-can-create-prometheusrule-in-redhat-rhoam-observability",
			targetNamespace: "redhat-rhoam-observability",
			targetResource:  "prometheusrule",
			username:        "system:serviceaccounts:redhat-ns:test-operator",
			userGroups:      []string{"system:serviceaccounts:redhat-ns:test-operator", "system:authenticated", "system:authenticated:oauth"},
			operation:       admissionv1.Update,
			shouldBeAllowed: true,
		},
		{
			testID:          "regular-user-can-delete-prometheusrule-in-redhat-rhoam-observability",
			targetNamespace: "redhat-rhoam-observability",
			targetResource:  "prometheusrule",
			username:        "system:serviceaccounts:redhat-ns:test-operator",
			userGroups:      []string{"system:serviceaccounts:redhat-ns:test-operator", "system:authenticated", "system:authenticated:oauth"},
			operation:       admissionv1.Update,
			shouldBeAllowed: true,
		},
	}
	runPrometheusRuleTests(t, tests)
}
