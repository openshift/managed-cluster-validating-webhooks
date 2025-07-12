package clusterrole

import (
	"testing"

	"github.com/openshift/managed-cluster-validating-webhooks/pkg/testutils"
	admissionv1 "k8s.io/api/admission/v1"
	authenticationv1 "k8s.io/api/authentication/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	admissionctl "sigs.k8s.io/controller-runtime/pkg/webhook/admission"
)

type ClusterRoleTestSuites struct {
	testID            string
	targetClusterRole string
	username          string
	operation         admissionv1.Operation
	userGroups        []string
	shouldBeAllowed   bool
}

var (
	// testClusterRoleJSON represents a minimal ClusterRole JSON object for testing
	testClusterRoleJSON = `{
		"apiVersion": "rbac.authorization.k8s.io/v1",
		"kind": "ClusterRole",
		"metadata": {
			"name": "cluster-admin"
		},
		"rules": [
			{
				"apiGroups": ["*"],
				"resources": ["*"],
				"verbs": ["*"]
			}
		]
	}`

	// testOtherClusterRoleJSON represents a non-protected ClusterRole
	testOtherClusterRoleJSON = `{
		"apiVersion": "rbac.authorization.k8s.io/v1",
		"kind": "ClusterRole",
		"metadata": {
			"name": "some-custom-role"
		},
		"rules": [
			{
				"apiGroups": [""],
				"resources": ["pods"],
				"verbs": ["get", "list"]
			}
		]
	}`
)

func runClusterRoleTests(t *testing.T, tests []ClusterRoleTestSuites) {
	for _, test := range tests {
		gvk := metav1.GroupVersionKind{
			Group:   "rbac.authorization.k8s.io",
			Version: "v1",
			Kind:    "ClusterRole",
		}
		gvr := metav1.GroupVersionResource{
			Group:    "rbac.authorization.k8s.io",
			Version:  "v1",
			Resource: "clusterroles",
		}

		var clusterRoleJSON string
		if test.targetClusterRole == "cluster-admin" {
			clusterRoleJSON = testClusterRoleJSON
		} else {
			clusterRoleJSON = testOtherClusterRoleJSON
		}

		rawOldObject := []byte(clusterRoleJSON)
		req := admissionctl.Request{
			AdmissionRequest: admissionv1.AdmissionRequest{
				UID:       "test-uid",
				Kind:      gvk,
				Resource:  gvr,
				Operation: admissionv1.Delete,
				UserInfo: authenticationv1.UserInfo{
					Username: test.username,
					Groups:   test.userGroups,
				},
				OldObject: runtime.RawExtension{
					Raw: rawOldObject,
				},
			},
		}

		hook := NewWebhook()
		response := hook.Authorized(req)

		if response.Allowed != test.shouldBeAllowed {
			t.Fatalf("Mismatch: %s (groups=%s) %s %s the clusterrole. Test's expectation is that the user %s", test.username, test.userGroups, testutils.CanCanNot(response.Allowed), test.operation, testutils.CanCanNot(test.shouldBeAllowed))
		}
	}
}

func TestClusterRoleDeletionNegative(t *testing.T) {
	tests := []ClusterRoleTestSuites{
		{
			testID:            "regular-user-deny",
			username:          "test-user",
			userGroups:        []string{"system:authenticated"},
			operation:         admissionv1.Delete,
			shouldBeAllowed:   false,
			targetClusterRole: "cluster-admin",
		},
		{
			testID:            "cluster-admin-user-deny",
			username:          "cluster-admin",
			userGroups:        []string{"system:authenticated"},
			operation:         admissionv1.Delete,
			shouldBeAllowed:   false,
			targetClusterRole: "cluster-admin",
		},
		{
			testID:            "customer-admin-deny",
			username:          "customer-user",
			userGroups:        []string{"system:authenticated", "customer-admin"},
			operation:         admissionv1.Delete,
			shouldBeAllowed:   false,
			targetClusterRole: "cluster-admin",
		},
	}

	runClusterRoleTests(t, tests)
}

func TestClusterRoleDeletionPositive(t *testing.T) {
	tests := []ClusterRoleTestSuites{
		{
			testID:            "backplane-admin-allow",
			username:          "backplane-cluster-admin",
			userGroups:        []string{"system:authenticated"},
			operation:         admissionv1.Delete,
			shouldBeAllowed:   true,
			targetClusterRole: "cluster-admin",
		},
		{
			testID:            "backplane-srep-allow",
			username:          "test-user",
			userGroups:        []string{"system:authenticated", "system:serviceaccounts:openshift-backplane-srep"},
			operation:         admissionv1.Delete,
			shouldBeAllowed:   true,
			targetClusterRole: "cluster-admin",
		},
		{
			testID:            "other-role-allow",
			username:          "regular-user",
			userGroups:        []string{"system:authenticated"},
			operation:         admissionv1.Delete,
			shouldBeAllowed:   true,
			targetClusterRole: "some-custom-role",
		},
		{
			testID:            "system-user-allow",
			username:          "system:kube-controller-manager",
			userGroups:        []string{"system:authenticated"},
			operation:         admissionv1.Delete,
			shouldBeAllowed:   true,
			targetClusterRole: "cluster-admin",
		},
	}

	runClusterRoleTests(t, tests)
}
