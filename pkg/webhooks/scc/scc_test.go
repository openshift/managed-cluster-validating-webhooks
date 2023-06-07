package scc

import (
	"fmt"
	"testing"

	"github.com/openshift/managed-cluster-validating-webhooks/pkg/testutils"
	admissionv1 "k8s.io/api/admission/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"k8s.io/apimachinery/pkg/runtime"
)

type sccTestSuites struct {
	testID          string
	targetSCC       string
	username        string
	operation       admissionv1.Operation
	userGroups      []string
	shouldBeAllowed bool
}

const testObjectRaw string = `
{
	"apiVersion": "security.openshift.io/v1",
	"kind": "SecurityContextConstraints",
	"metadata": {
		"name": "%s",
		"uid": "1234"
	}
}`

func createRawJSONString(name string) string {
	s := fmt.Sprintf(testObjectRaw, name)
	return s
}

func runSCCTests(t *testing.T, tests []sccTestSuites) {
	gvk := metav1.GroupVersionKind{
		Group:   "security.openshift.io",
		Version: "v1",
		Kind:    "SecurityContextConstraints",
	}
	gvr := metav1.GroupVersionResource{
		Group:    "security.openshift.io",
		Version:  "v1",
		Resource: "securitycontextcontraints",
	}

	for _, test := range tests {
		rawObjString := createRawJSONString(test.targetSCC)

		obj := runtime.RawExtension{
			Raw: []byte(rawObjString),
		}

		oldObj := runtime.RawExtension{
			Raw: []byte(rawObjString),
		}

		hook := NewWebhook()
		httprequest, err := testutils.CreateHTTPRequest(hook.GetURI(),
			test.testID, gvk, gvr, test.operation, test.username, test.userGroups, &obj, &oldObj)
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
			t.Fatalf("Mismatch: %s (groups=%s) %s %s the scc. Test's expectation is that the user %s", test.username, test.userGroups, testutils.CanCanNot(response.Allowed), test.operation, testutils.CanCanNot(test.shouldBeAllowed))
		}
	}
}
func TestUserNegative(t *testing.T) {
	tests := []sccTestSuites{
		{
			targetSCC:       "hostnetwork",
			testID:          "user-cant-delete-hostnetwork",
			username:        "user1",
			operation:       admissionv1.Delete,
			userGroups:      []string{"system:authenticated", "system:authenticated:oauth"},
			shouldBeAllowed: false,
		},
		{
			targetSCC:       "hostaccess",
			testID:          "user-cant-delete-hostaccess",
			username:        "user2",
			operation:       admissionv1.Delete,
			userGroups:      []string{"system:authenticated", "system:authenticated:oauth"},
			shouldBeAllowed: false,
		},
		{
			targetSCC:       "anyuid",
			testID:          "user-cant-delete-anyuid",
			username:        "user3",
			operation:       admissionv1.Delete,
			userGroups:      []string{"system:authenticated", "system:authenticated:oauth"},
			shouldBeAllowed: false,
		},
		{
			targetSCC:       "anyuid",
			testID:          "user-cant-modify-hostnetwork",
			username:        "user4",
			operation:       admissionv1.Update,
			userGroups:      []string{"system:authenticated", "system:authenticated:oauth"},
			shouldBeAllowed: false,
		},
		{
			targetSCC:       "hostnetwork-v2",
			testID:          "user-cant-delete-hostnetwork-v2",
			username:        "user1",
			operation:       admissionv1.Delete,
			userGroups:      []string{"system:authenticated", "system:authenticated:oauth"},
			shouldBeAllowed: false,
		},
	}
	runSCCTests(t, tests)
}

func TestUserPositive(t *testing.T) {
	tests := []sccTestSuites{
		{
			targetSCC:       "testscc",
			testID:          "user-can-modify-normal",
			username:        "user1",
			operation:       admissionv1.Update,
			userGroups:      []string{"system:authenticated", "system:authenticated:oauth"},
			shouldBeAllowed: true,
		},
		{
			targetSCC:       "hostaccess",
			testID:          "allowed-user-can-modify-default",
			username:        "system:serviceaccount:openshift-monitoring:cluster-monitoring-operator",
			operation:       admissionv1.Update,
			userGroups:      []string{"system:authenticated", "system:authenticated:oauth"},
			shouldBeAllowed: true,
		},
		{
			targetSCC:       "hostaccess",
			testID:          "allowed-system-admin-can-modify-default",
			username:        "system:admin",
			operation:       admissionv1.Update,
			userGroups:      []string{"system:authenticated", "system:authenticated:oauth"},
			shouldBeAllowed: true,
		},
		{
			targetSCC:       "testscc",
			testID:          "user-can-delete-normal",
			username:        "user1",
			operation:       admissionv1.Delete,
			userGroups:      []string{"system:authenticated", "system:authenticated:oauth"},
			shouldBeAllowed: true,
		},
		{
			targetSCC:       "hostaccess",
			testID:          "allowed-user-can-delete-default",
			username:        "system:serviceaccount:openshift-monitoring:cluster-monitoring-operator",
			operation:       admissionv1.Delete,
			userGroups:      []string{"system:authenticated", "system:authenticated:oauth"},
			shouldBeAllowed: true,
		},
	}
	runSCCTests(t, tests)
}
