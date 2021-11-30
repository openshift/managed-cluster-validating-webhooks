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
	priority        int32
}

const testObjectRaw string = `
{
	"apiVersion": "security.openshift.io/v1",
	"kind": "SecurityContextConstraints",
	"metadata": {
		"name": "%s",
		"uid": "1234"
	},
	"priority": %d
}`

func createRawJSONString(name string, pri int32) string {
	s := fmt.Sprintf(testObjectRaw, name, pri)
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
		rawObjString := createRawJSONString(test.targetSCC, test.priority)

		obj := runtime.RawExtension{
			Raw: []byte(rawObjString),
		}

		hook := NewWebhook()
		httprequest, err := testutils.CreateHTTPRequest(hook.GetURI(),
			test.testID, gvk, gvr, test.operation, test.username, test.userGroups, &obj, nil)
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
			t.Fatalf("Mismatch: %s (groups=%s) %s %s the pod. Test's expectation is that the user %s", test.username, test.userGroups, testutils.CanCanNot(response.Allowed), test.operation, testutils.CanCanNot(test.shouldBeAllowed))
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
			username:        "user1",
			operation:       admissionv1.Delete,
			userGroups:      []string{"system:authenticated", "system:authenticated:oauth"},
			shouldBeAllowed: false,
		},
		{
			targetSCC:       "anyuid",
			testID:          "user-cant-delete-anyuid",
			username:        "user1",
			operation:       admissionv1.Delete,
			userGroups:      []string{"system:authenticated", "system:authenticated:oauth"},
			shouldBeAllowed: false,
		},
		{
			targetSCC:       "anyuid",
			testID:          "user-cant-modify-hostnetwork",
			username:        "user1",
			operation:       admissionv1.Update,
			userGroups:      []string{"system:authenticated", "system:authenticated:oauth"},
			shouldBeAllowed: false,
		},
		{
			targetSCC:       "test-high-pri",
			testID:          "user-cant-create-high-priority",
			username:        "user1",
			priority:        20,
			operation:       admissionv1.Create,
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
			testID:          "user-can-delete-normal",
			username:        "user1",
			operation:       admissionv1.Delete,
			userGroups:      []string{"system:authenticated", "system:authenticated:oauth"},
			shouldBeAllowed: true,
		},
		{
			targetSCC:       "testscc",
			testID:          "user-can-modify-normal",
			username:        "user1",
			operation:       admissionv1.Update,
			userGroups:      []string{"system:authenticated", "system:authenticated:oauth"},
			shouldBeAllowed: true,
		},
		{
			targetSCC:       "testscc",
			testID:          "user-can-create-low-pri",
			username:        "user1",
			priority:        9,
			operation:       admissionv1.Create,
			userGroups:      []string{"system:authenticated", "system:authenticated:oauth"},
			shouldBeAllowed: true,
		},
	}
	runSCCTests(t, tests)
}
