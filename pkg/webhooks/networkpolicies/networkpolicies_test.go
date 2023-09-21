package networkpolicies

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
	"apiVersion": "networking.k8s.io/v1",
	"kind": "NetworkPolicy",
	"metadata": {
        "name": "test",
		"namespace": "%s",
		"uid": "1234"
	}
}`

type networkPolicyTestSuites struct {
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

func runNetworkPolicyTests(t *testing.T, tests []networkPolicyTestSuites) {
	gvk := metav1.GroupVersionKind{
		Group:   "networking.k8s.io",
		Version: "v1",
		Kind:    "NetworkPolicy",
	}
	gvr := metav1.GroupVersionResource{
		Group:    "networking.k8s.io",
		Version:  "v1",
		Resource: "networkpolicies",
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
	tests := []networkPolicyTestSuites{
		{
			testID:          "regular-user-cant-create-networkpolicy-in-managed-namespaces",
			targetNamespace: "openshift-kube-apiserver",
			targetResource:  "networkpolicy",
			username:        "user1",
			userGroups:      []string{"system:authenticated", "system:authenticated:oauth"},
			operation:       admissionv1.Create,
			shouldBeAllowed: false,
		},
		{
			testID:          "regular-user-cant-delete-networkpolicy-in-managed-namespaces",
			targetNamespace: "openshift-kube-apiserver",
			targetResource:  "networkpolicy",
			username:        "user2",
			userGroups:      []string{"system:authenticated", "system:authenticated:oauth"},
			operation:       admissionv1.Delete,
			shouldBeAllowed: false,
		},
		{
			testID:          "regular-user-cant-update-networkpolicy-in-managed-namespaces",
			targetNamespace: "openshift-kube-apiserver",
			targetResource:  "networkpolicy",
			username:        "user3",
			userGroups:      []string{"system:authenticated", "system:authenticated:oauth"},
			operation:       admissionv1.Update,
			shouldBeAllowed: false,
		},
		{
			testID:          "regular-user-can-create-networkpolicy-in-user-managed-namespaces",
			targetNamespace: "my-monitoring",
			targetResource:  "networkpolicy",
			username:        "user4",
			userGroups:      []string{"system:authenticated", "system:authenticated:oauth"},
			operation:       admissionv1.Create,
			shouldBeAllowed: true,
		},
		{
			testID:          "regular-user-can-update-networkpolicy-in-user-managed-namespaces",
			targetNamespace: "my-monitoring",
			targetResource:  "networkpolicy",
			username:        "user5",
			userGroups:      []string{"system:authenticated", "system:authenticated:oauth"},
			operation:       admissionv1.Update,
			shouldBeAllowed: true,
		},
		{
			testID:          "regular-user-can-delete-networkpolicy-in-user-managed-namespaces",
			targetNamespace: "my-monitoring",
			targetResource:  "networkpolicy",
			username:        "user6",
			userGroups:      []string{"system:authenticated", "system:authenticated:oauth"},
			operation:       admissionv1.Delete,
			shouldBeAllowed: true,
		},
		{
			testID:          "regular-user-cant-create-networkpolicy-in-managed-namespaces",
			targetNamespace: "openshift-kube-apiserver",
			targetResource:  "networkpolicy",
			username:        "system:serviceaccounts:unpriv-ns",
			userGroups:      []string{"system:serviceaccounts:unpriv-ns", "cluster-admins", "system:authenticated", "system:authenticated:oauth"},
			operation:       admissionv1.Create,
			shouldBeAllowed: false,
		},
		{
			testID:          "regular-user-cant-delete-networkpolicy-in-managed-namespaces",
			targetNamespace: "openshift-kube-apiserver",
			targetResource:  "networkpolicy",
			username:        "system:serviceaccounts:unpriv-ns",
			userGroups:      []string{"system:serviceaccounts:unpriv-ns", "cluster-admins", "system:authenticated", "system:authenticated:oauth"},
			operation:       admissionv1.Delete,
			shouldBeAllowed: false,
		},
		{
			testID:          "regular-user-cant-update-networkpolicy-in-managed-namespaces",
			targetNamespace: "openshift-kube-apiserver",
			targetResource:  "networkpolicy",
			username:        "system:serviceaccounts:unpriv-ns",
			userGroups:      []string{"system:serviceaccounts:unpriv-ns", "cluster-admins", "system:authenticated", "system:authenticated:oauth"},
			operation:       admissionv1.Update,
			shouldBeAllowed: false,
		},

		{
			testID:          "blackplane-admin-can-create-networkpolicy-in-managed-namespaces",
			targetNamespace: "openshift-kube-apiserver",
			targetResource:  "networkpolicy",
			username:        "backplane-cluster-admin",
			userGroups:      []string{"system:authenticated", "system:authenticated:oauth"},
			operation:       admissionv1.Create,
			shouldBeAllowed: true,
		},
		{
			testID:          "blackplane-admin-can-delete-networkpolicy-in-managed-namespaces",
			targetNamespace: "openshift-kube-apiserver",
			targetResource:  "networkpolicy",
			username:        "backplane-cluster-admin",
			userGroups:      []string{"system:authenticated", "system:authenticated:oauth"},
			operation:       admissionv1.Delete,
			shouldBeAllowed: true,
		},
		{
			testID:          "blackplane-admin-can-update-networkpolicy-in-managed-namespaces",
			targetNamespace: "openshift-kube-apiserver",
			targetResource:  "networkpolicy",
			username:        "backplane-cluster-admin",
			userGroups:      []string{"system:authenticated", "system:authenticated:oauth"},
			operation:       admissionv1.Update,
			shouldBeAllowed: true,
		},
		{

			testID:          "Allowed-can-create-networkpolicy-in-managed-namespaces",
			targetNamespace: "openshift-kube-apiserver",
			targetResource:  "networkpolicy",
			username:        "system:serviceaccounts:openshift-test-ns",
			userGroups:      []string{"system:serviceaccounts:openshift-test-ns", "system:authenticated", "system:authenticated:oauth"},
			operation:       admissionv1.Create,
			shouldBeAllowed: true,
		},
		{

			testID:          "Allowed-can-delete-networkpolicy-in-managed-namespaces",
			targetNamespace: "openshift-kube-apiserver",
			targetResource:  "networkpolicy",
			username:        "system:serviceaccounts:openshift-test-ns",
			userGroups:      []string{"system:serviceaccounts:openshift-test-ns", "system:authenticated", "system:authenticated:oauth"},
			operation:       admissionv1.Delete,
			shouldBeAllowed: true,
		},
		{

			testID:          "Allowed-can-update-networkpolicy-in-managed-namespaces",
			targetNamespace: "openshift-kube-apiserver",
			username:        "system:serviceaccounts:openshift-test-ns",
			targetResource:  "networkpolicy",
			userGroups:      []string{"system:serviceaccounts:openshift-test-ns", "system:authenticated", "system:authenticated:oauth"},
			operation:       admissionv1.Update,
			shouldBeAllowed: true,
		},
		{

			testID:          "admin-can-create-networkpolicy-in-managed-namespaces",
			targetNamespace: "openshift-kube-apiserver",
			username:        "kube:admin",
			targetResource:  "networkpolicy",
			userGroups:      []string{"system:authenticated", "system:authenticated:oauth"},
			operation:       admissionv1.Create,
			shouldBeAllowed: true,
		},
		{

			testID:          "admin-can-create-networkpolicy-in-managed-namespaces",
			targetNamespace: "openshift-kube-apiserver",
			username:        "kube:admin",
			targetResource:  "networkpolicy",
			userGroups:      []string{"system:authenticated", "system:authenticated:oauth"},
			operation:       admissionv1.Update,
			shouldBeAllowed: true,
		},
		{

			testID:          "admin-can-create-networkpolicy-in-managed-namespaces",
			targetNamespace: "openshift-kube-apiserver",
			username:        "kube:admin",
			targetResource:  "networkpolicy",
			userGroups:      []string{"system:authenticated", "system:authenticated:oauth"},
			operation:       admissionv1.Delete,
			shouldBeAllowed: true,
		},
		{
			testID:          "serviceaccount-in-managed-namespaces-can-create-networkpolicy-in-redhat-rhoam-observability",
			targetNamespace: "redhat-rhoam-observability",
			targetResource:  "networkpolicy",
			username:        "system:serviceaccounts:redhat-ns:test-operator",
			userGroups:      []string{"system:serviceaccounts:redhat-ns:test-operator", "system:authenticated", "system:authenticated:oauth"},
			operation:       admissionv1.Create,
			shouldBeAllowed: true,
		},
		{
			testID:          "serviceaccount-in-managed-namespaces-can-create-networkpolicy-in-redhat-rhoam-observability",
			targetNamespace: "redhat-rhoam-observability",
			targetResource:  "networkpolicy",
			username:        "system:serviceaccounts:redhat-ns:test-operator",
			userGroups:      []string{"system:serviceaccounts:redhat-ns:test-operator", "system:authenticated", "system:authenticated:oauth"},
			operation:       admissionv1.Update,
			shouldBeAllowed: true,
		},
		{
			testID:          "regular-user-can-delete-networkpolicy-in-redhat-rhoam-observability",
			targetNamespace: "redhat-rhoam-observability",
			targetResource:  "networkpolicy",
			username:        "system:serviceaccounts:redhat-ns:test-operator",
			userGroups:      []string{"system:serviceaccounts:redhat-ns:test-operator", "system:authenticated", "system:authenticated:oauth"},
			operation:       admissionv1.Update,
			shouldBeAllowed: true,
		},
	}
	runNetworkPolicyTests(t, tests)
}
