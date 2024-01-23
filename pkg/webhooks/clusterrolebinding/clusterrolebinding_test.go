package clusterrolebinding

import (
	"encoding/json"
	"fmt"
	"testing"

	admissionv1 "k8s.io/api/admission/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/openshift/managed-cluster-validating-webhooks/pkg/testutils"

	"k8s.io/apimachinery/pkg/runtime"
)

type ClusterRoleBindingTestSuites struct {
	testID                   string
	targetClusterRoleBinding string
	subjects                 []rbacv1.Subject
	template                 string
	username                 string
	operation                admissionv1.Operation
	userGroups               []string
	shouldBeAllowed          bool
}

const testObjectRaw string = `
{
	"apiVersion": "rbac.authorization.k8s.io/v1",
	"kind": "ClusterRoleBinding",
	"metadata": {
		"name": "%s",
		"uid": "1234"
	},
	"subjects": %s
}`

const testObjectRawWithAnnotation string = `
{
	"apiVersion": "rbac.authorization.k8s.io/v1",
	"kind": "ClusterRoleBinding",
	"metadata": {
		"name": "%s",
		"uid": "1234",
		"annotations":
			{"oc.openshift.io/command": "oc adm must-gather"}
	},
	"subjects": %s
}`

func createRawJSONString(
	name string,
	subjects []rbacv1.Subject,
	template string,
) (string, error) {
	partial, err := json.Marshal(subjects)
	return fmt.Sprintf(template, name, string(partial)), err
}

func runClusterRoleBindingTests(t *testing.T, tests []ClusterRoleBindingTestSuites) {
	gvk := metav1.GroupVersionKind{
		Group:   "rbac.authorization.k8s.io",
		Version: "v1",
		Kind:    "ClusterRoleBinding",
	}
	gvr := metav1.GroupVersionResource{
		Group:    "rbac.authorization.k8s.io",
		Version:  "v1",
		Resource: "ClusterRoleBinding",
	}

	for _, test := range tests {
		rawObjString, err := createRawJSONString(
			test.targetClusterRoleBinding,
			test.subjects,
			test.template,
		)

		if err != nil {
			t.Fatalf("Expected no error, got %s", err.Error())
		}

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
			fmt.Print(test.testID)
			t.Fatalf("Expected no error, got %s from test: %s", err.Error(), test.testID)
		}

		response, err := testutils.SendHTTPRequest(httprequest, hook)
		if err != nil {
			t.Fatalf("Expected no error, got %s", err.Error())
		}
		if response.UID == "" {
			t.Fatalf("No tracking UID associated with the response.")
		}

		if response.Allowed != test.shouldBeAllowed {
			t.Fatalf("Mismatch: %s (groups=%s) %s %s the clusterrolebinding. Test's expectation is that the user %s", test.username, test.userGroups, testutils.CanCanNot(response.Allowed), test.operation, testutils.CanCanNot(test.shouldBeAllowed))
		}
	}
}
func TestClusterRoleBindingDeletionNegative(t *testing.T) {
	tests := []ClusterRoleBindingTestSuites{
		{
			template:                 testObjectRaw,
			targetClusterRoleBinding: "whatever",
			testID:                   "user-cant-delete-protected-cluster-role-binding-in-protected-openshift-ns",
			username:                 "user1",
			operation:                admissionv1.Delete,
			userGroups:               []string{"system:authenticated", "system:authenticated:oauth"},
			shouldBeAllowed:          false,
			subjects: []rbacv1.Subject{
				{
					Kind:      "ServiceAccount",
					Name:      "whatever",
					Namespace: "openshift-ingress-operator",
				},
			},
		},
		{
			template:                 testObjectRaw,
			targetClusterRoleBinding: "whatever",
			testID:                   "user-cant-delete-protected-cluster-role-binding-in-protected-kube-system-ns",
			username:                 "user1",
			operation:                admissionv1.Delete,
			userGroups:               []string{"system:authenticated", "system:authenticated:oauth"},
			shouldBeAllowed:          false,
			subjects: []rbacv1.Subject{
				{
					Kind:      "ServiceAccount",
					Name:      "whatever",
					Namespace: "kube-system",
				},
			},
		},
		{
			template:                 testObjectRaw,
			targetClusterRoleBinding: "whatever",
			testID:                   "cluster-admin-can-not-delete-cluster-role-binding-in-protected-ns-without-annotation",
			username:                 "cluster-admin",
			operation:                admissionv1.Delete,
			userGroups:               []string{"system:authenticated"},
			subjects: []rbacv1.Subject{
				{
					Kind:      "ServiceAccount",
					Name:      "default",
					Namespace: "openshift-must-gather-mm4tf",
				},
			},
			shouldBeAllowed: false,
		},
	}
	runClusterRoleBindingTests(t, tests)
}

func TestClusterRoleBindingDeletionPositive(t *testing.T) {
	tests := []ClusterRoleBindingTestSuites{
		{
			template:                 testObjectRaw,
			targetClusterRoleBinding: "whatever",
			testID:                   "user-can-delete-cluster-role-binding-in-non-protected-ns",
			username:                 "user1",
			operation:                admissionv1.Delete,
			userGroups:               []string{"system:authenticated", "system:authenticated:oauth"},
			shouldBeAllowed:          true,
			subjects: []rbacv1.Subject{
				{
					Kind:      "ServiceAccount",
					Name:      "whatever",
					Namespace: "whatever",
				},
			},
		},
		{
			template:                 testObjectRaw,
			targetClusterRoleBinding: "whatever",
			testID:                   "user-can-delete-cluster-role-binding-in-non-namespace-subject",
			username:                 "user1",
			operation:                admissionv1.Delete,
			userGroups:               []string{"system:authenticated", "system:authenticated:oauth"},
			shouldBeAllowed:          true,
			subjects: []rbacv1.Subject{
				{
					Kind:      "User",
					Name:      "whatever",
					Namespace: "",
				},
			},
		},
		{
			template:                 testObjectRaw,
			targetClusterRoleBinding: "whatever",
			testID:                   "user-can-modify-cluster-role-binding-in-protected-ns",
			username:                 "user1",
			operation:                admissionv1.Update,
			userGroups:               []string{"system:authenticated", "system:authenticated:oauth"},
			shouldBeAllowed:          true,
			subjects: []rbacv1.Subject{
				{
					Kind:      "ServiceAccount",
					Name:      "whatever",
					Namespace: "openshift-ingress-operator",
				},
			},
		},
		{
			template:                 testObjectRaw,
			targetClusterRoleBinding: "whatever",
			testID:                   "user-can-modify-cluster-role-binding-in-exception-ns",
			username:                 "user1",
			operation:                admissionv1.Delete,
			userGroups:               []string{"system:authenticated", "system:authenticated:oauth"},
			shouldBeAllowed:          true,
			subjects: []rbacv1.Subject{
				{
					Kind:      "ServiceAccount",
					Name:      "whatever",
					Namespace: "openshift-operators",
				},
			},
		},
		{
			template:                 testObjectRaw,
			targetClusterRoleBinding: "whatever",
			testID:                   "elevated-sre-can-delete-cluster-role-binding-in-protected-ns",
			username:                 "backplane-cluster-admin",
			operation:                admissionv1.Delete,
			userGroups:               []string{"system:authenticated", "system:authenticated:oauth"},
			subjects: []rbacv1.Subject{
				{
					Kind:      "ServiceAccount",
					Name:      "whatever",
					Namespace: "openshift-operators",
				},
			},
			shouldBeAllowed: true,
		},
		{
			template:                 testObjectRaw,
			targetClusterRoleBinding: "whatever",
			testID:                   "kube-account-can-delete-cluster-role-binding-in-protected-ns",
			username:                 "kube:admin",
			operation:                admissionv1.Delete,
			userGroups:               []string{"system:authenticated"},
			subjects: []rbacv1.Subject{
				{
					Kind:      "ServiceAccount",
					Name:      "whatever",
					Namespace: "openshift-operators",
				},
			},
			shouldBeAllowed: true,
		},
		{
			template:                 testObjectRawWithAnnotation,
			targetClusterRoleBinding: "whatever",
			testID:                   "cluster-admin-can-delete-cluster-role-binding-in-protected-ns-with-annotation",
			username:                 "cluster-admin",
			operation:                admissionv1.Delete,
			userGroups:               []string{"system:authenticated"},
			subjects: []rbacv1.Subject{
				{
					Kind:      "ServiceAccount",
					Name:      "default",
					Namespace: "openshift-must-gather-mm4tf",
				},
			},
			shouldBeAllowed: true,
		},
	}
	runClusterRoleBindingTests(t, tests)
}
