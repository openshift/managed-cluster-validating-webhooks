package serviceaccount

import (
	"fmt"
	"testing"

	admissionv1 "k8s.io/api/admission/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"

	"github.com/openshift/managed-cluster-validating-webhooks/pkg/testutils"
)

type serviceAccountTestSuites struct {
	testID          string
	targetSA        string
	username        string
	operation       admissionv1.Operation
	userGroups      []string
	namespace       string
	shouldBeAllowed bool
}

const testObjectRaw string = `
{
	"apiVersion": "v1",
	"kind": "ServiceAccount",
	"metadata": {
		"name": "%s",
		"namespace": "%s",
		"uid": "1234"
	}
}`

func createRawJSONString(name, namespace string) string {
	s := fmt.Sprintf(testObjectRaw, name, namespace)
	return s
}

func runServiceAccountTests(t *testing.T, tests []serviceAccountTestSuites) {
	gvk := metav1.GroupVersionKind{
		Group:   "",
		Version: "v1",
		Kind:    "ServiceAccount",
	}
	gvr := metav1.GroupVersionResource{
		Group:    "",
		Version:  "v1",
		Resource: "serviceaccounts",
	}

	for _, test := range tests {
		rawObjString := createRawJSONString(test.targetSA, test.namespace)

		obj := runtime.RawExtension{
			Raw: []byte(rawObjString),
		}

		oldObj := runtime.RawExtension{
			Raw: []byte(rawObjString),
		}

		hook := NewWebhook()
		httpRequest, err := testutils.CreateHTTPRequest(hook.GetURI(),
			test.testID, gvk, gvr, test.operation, test.username, test.userGroups, test.namespace, &obj, &oldObj)
		if err != nil {
			t.Fatalf("Expected no error, got %s", err.Error())
		}

		response, err := testutils.SendHTTPRequest(httpRequest, hook)
		if err != nil {
			t.Fatalf("Expected no error, got %s", err.Error())
		}
		if response.UID == "" {
			t.Fatalf("No tracking UID associated with the response.")
		}

		if response.Allowed != test.shouldBeAllowed {
			t.Fatalf("Mismatch: %s (groups=%s) %s %s the serviceaccount. Test's expectation is that the user %s", test.username, test.userGroups, testutils.CanCanNot(response.Allowed), test.operation, testutils.CanCanNot(test.shouldBeAllowed))
		}
	}
}
func TestSADeletion(t *testing.T) {
	tests := []serviceAccountTestSuites{
		{
			targetSA:        "whatever",
			testID:          "user-cant-delete-protected-sa-in-protected-ns",
			username:        "user1",
			userGroups:      []string{"system:authenticated", "system:authenticated:oauth"},
			namespace:       "openshift-ingress-operator",
			operation:       admissionv1.Delete,
			shouldBeAllowed: false,
		},
		{
			targetSA:        "default",
			testID:          "user-can-delete-normal-sa-in-protected-ns",
			username:        "user1",
			operation:       admissionv1.Delete,
			userGroups:      []string{"system:authenticated", "system:authenticated:oauth"},
			namespace:       "openshift-ingress-operator",
			shouldBeAllowed: true,
		},
		{
			targetSA:        "whatever",
			testID:          "user-can-delete-sa-in-normal-ns",
			username:        "user1",
			operation:       admissionv1.Delete,
			userGroups:      []string{"system:authenticated", "system:authenticated:oauth"},
			namespace:       "whatever",
			shouldBeAllowed: true,
		},
		{
			targetSA:        "whatever",
			testID:          "user-can-delete-sa-in-exception-ns",
			username:        "user1",
			operation:       admissionv1.Delete,
			userGroups:      []string{"system:authenticated", "system:authenticated:oauth"},
			namespace:       "openshift-operators",
			shouldBeAllowed: true,
		},
		{
			targetSA:        "whatever",
			testID:          "sre-can-delete-sa-in-protected-ns",
			username:        "user1",
			operation:       admissionv1.Delete,
			userGroups:      []string{"system:serviceaccounts:openshift-backplane-srep"},
			namespace:       "openshift-ingress-operator",
			shouldBeAllowed: true,
		},
	}
	runServiceAccountTests(t, tests)
}
