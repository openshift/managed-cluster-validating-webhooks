package customresourcedefinitions

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
	"apiVersion": "apiextensions.k8s.io/v1",
	"kind": "CustomResourceDefinition",
	"metadata": {
        "name": "test",
		"namespace": "%s",
		"uid": "1234"
	}
}`

type customResourceDefinitionTestSuites struct {
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

func runCustomResourceDefinitionTests(t *testing.T, tests []customResourceDefinitionTestSuites) {
	gvk := metav1.GroupVersionKind{
		Group:   "apiextensions.k8s.io",
		Version: "v1",
		Kind:    "CustomResourceDefinition",
	}
	gvr := metav1.GroupVersionResource{
		Group:    "apiextensions.k8s.io",
		Version:  "v1",
		Resource: "customresourcedefinitions",
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
	tests := []customResourceDefinitionTestSuites{
		{
			testID:          "regular-user-cant-create-customresourcedefinition-in-managed-namespaces",
			targetNamespace: "openshift-monitoring",
			targetResource:  "customresourcedefinition",
			username:        "user1",
			userGroups:      []string{"system:authenticated", "system:authenticated:oauth"},
			operation:       admissionv1.Create,
			shouldBeAllowed: false,
		},
		{
			testID:          "regular-user-cant-delete-customresourcedefinition-in-managed-namespaces",
			targetNamespace: "openshift-monitoring",
			targetResource:  "customresourcedefinition",
			username:        "user2",
			userGroups:      []string{"system:authenticated", "system:authenticated:oauth"},
			operation:       admissionv1.Delete,
			shouldBeAllowed: false,
		},
		{
			testID:          "regular-user-cant-update-customresourcedefinition-in-managed-namespaces",
			targetNamespace: "openshift-monitoring",
			targetResource:  "customresourcedefinition",
			username:        "user3",
			userGroups:      []string{"system:authenticated", "system:authenticated:oauth"},
			operation:       admissionv1.Update,
			shouldBeAllowed: false,
		},
		{
			testID:          "regular-user-can-create-customresourcedefinition-in-user-managed-namespaces",
			targetNamespace: "my-monitoring",
			targetResource:  "customresourcedefinition",
			username:        "user4",
			userGroups:      []string{"system:authenticated", "system:authenticated:oauth"},
			operation:       admissionv1.Create,
			shouldBeAllowed: true,
		},
		{
			testID:          "regular-user-can-update-customresourcedefinition-in-user-managed-namespaces",
			targetNamespace: "my-monitoring",
			targetResource:  "customresourcedefinition",
			username:        "user5",
			userGroups:      []string{"system:authenticated", "system:authenticated:oauth"},
			operation:       admissionv1.Update,
			shouldBeAllowed: true,
		},
		{
			testID:          "regular-user-can-delete-customresourcedefinition-in-user-managed-namespaces",
			targetNamespace: "my-monitoring",
			targetResource:  "customresourcedefinition",
			username:        "user6",
			userGroups:      []string{"system:authenticated", "system:authenticated:oauth"},
			operation:       admissionv1.Delete,
			shouldBeAllowed: true,
		},
		{
			testID:          "regular-user-cant-create-customresourcedefinition-in-managed-namespaces",
			targetNamespace: "openshift-monitoring",
			targetResource:  "customresourcedefinition",
			username:        "system:serviceaccounts:unpriv-ns",
			userGroups:      []string{"system:serviceaccounts:unpriv-ns", "cluster-admins", "system:authenticated", "system:authenticated:oauth"},
			operation:       admissionv1.Create,
			shouldBeAllowed: false,
		},
		{
			testID:          "regular-user-cant-delete-customresourcedefinition-in-managed-namespaces",
			targetNamespace: "openshift-monitoring",
			targetResource:  "customresourcedefinition",
			username:        "system:serviceaccounts:unpriv-ns",
			userGroups:      []string{"system:serviceaccounts:unpriv-ns", "cluster-admins", "system:authenticated", "system:authenticated:oauth"},
			operation:       admissionv1.Delete,
			shouldBeAllowed: false,
		},
		{
			testID:          "regular-user-cant-update-customresourcedefinition-in-managed-namespaces",
			targetNamespace: "openshift-monitoring",
			targetResource:  "customresourcedefinition",
			username:        "system:serviceaccounts:unpriv-ns",
			userGroups:      []string{"system:serviceaccounts:unpriv-ns", "cluster-admins", "system:authenticated", "system:authenticated:oauth"},
			operation:       admissionv1.Update,
			shouldBeAllowed: false,
		},

		{
			testID:          "blackplane-admin-can-create-customresourcedefinition-in-managed-namespaces",
			targetNamespace: "openshift-monitoring",
			targetResource:  "customresourcedefinition",
			username:        "backplane-cluster-admin",
			userGroups:      []string{"system:authenticated", "system:authenticated:oauth"},
			operation:       admissionv1.Create,
			shouldBeAllowed: true,
		},
		{
			testID:          "blackplane-admin-can-delete-customresourcedefinition-in-managed-namespaces",
			targetNamespace: "openshift-monitoring",
			targetResource:  "customresourcedefinition",
			username:        "backplane-cluster-admin",
			userGroups:      []string{"system:authenticated", "system:authenticated:oauth"},
			operation:       admissionv1.Delete,
			shouldBeAllowed: true,
		},
		{
			testID:          "blackplane-admin-can-update-customresourcedefinition-in-managed-namespaces",
			targetNamespace: "openshift-monitoring",
			targetResource:  "customresourcedefinition",
			username:        "backplane-cluster-admin",
			userGroups:      []string{"system:authenticated", "system:authenticated:oauth"},
			operation:       admissionv1.Update,
			shouldBeAllowed: true,
		},
		{

			testID:          "Allowed-can-create-customresourcedefinition-in-managed-namespaces",
			targetNamespace: "openshift-monitoring",
			targetResource:  "customresourcedefinition",
			username:        "system:serviceaccounts:openshift-test-ns",
			userGroups:      []string{"system:serviceaccounts:openshift-test-ns", "system:authenticated", "system:authenticated:oauth"},
			operation:       admissionv1.Create,
			shouldBeAllowed: true,
		},
		{

			testID:          "Allowed-can-delete-customresourcedefinition-in-managed-namespaces",
			targetNamespace: "openshift-monitoring",
			targetResource:  "customresourcedefinition",
			username:        "system:serviceaccounts:openshift-test-ns",
			userGroups:      []string{"system:serviceaccounts:openshift-test-ns", "system:authenticated", "system:authenticated:oauth"},
			operation:       admissionv1.Delete,
			shouldBeAllowed: true,
		},
		{

			testID:          "Allowed-can-update-customresourcedefinition-in-managed-namespaces",
			targetNamespace: "openshift-monitoring",
			username:        "system:serviceaccounts:openshift-test-ns",
			targetResource:  "customresourcedefinition",
			userGroups:      []string{"system:serviceaccounts:openshift-test-ns", "system:authenticated", "system:authenticated:oauth"},
			operation:       admissionv1.Update,
			shouldBeAllowed: true,
		},
		{
			testID:          "serviceaccount-in-managed-namespaces-can-create-customresourcedefinition-in-unmanaged-namespace",
			targetNamespace: "unmanaged-namespace",
			targetResource:  "customresourcedefinition",
			username:        "system:serviceaccounts:redhat-ns:test-operator",
			userGroups:      []string{"system:serviceaccounts:redhat-ns:test-operator", "system:authenticated", "system:authenticated:oauth"},
			operation:       admissionv1.Create,
			shouldBeAllowed: true,
		},
		{
			testID:          "serviceaccount-in-managed-namespaces-can-create-customresourcedefinition-in-unmanaged-namespace",
			targetNamespace: "unmanaged-namespace",
			targetResource:  "customresourcedefinition",
			username:        "system:serviceaccounts:redhat-ns:test-operator",
			userGroups:      []string{"system:serviceaccounts:redhat-ns:test-operator", "system:authenticated", "system:authenticated:oauth"},
			operation:       admissionv1.Update,
			shouldBeAllowed: true,
		},
		{
			testID:          "regular-user-can-delete-customresourcedefinition-in-unmanaged-namespace",
			targetNamespace: "unmanaged-namespace",
			targetResource:  "customresourcedefinition",
			username:        "system:serviceaccounts:redhat-ns:test-operator",
			userGroups:      []string{"system:serviceaccounts:redhat-ns:test-operator", "system:authenticated", "system:authenticated:oauth"},
			operation:       admissionv1.Update,
			shouldBeAllowed: true,
		},
	}
	runCustomResourceDefinitionTests(t, tests)
}
