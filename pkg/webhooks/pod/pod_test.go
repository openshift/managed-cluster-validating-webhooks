package pod

import (
	"encoding/json"
	"fmt"
	"testing"

	"github.com/openshift/managed-cluster-validating-webhooks/pkg/testutils"
	"k8s.io/api/admission/v1beta1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
)

func createRawPodJSON(name string, tolerations []corev1.Toleration, uid string, namespace string) (string, error) {
	str := `{
		"metadata": {
			"name": "%s",
			"namespace": "%s",
			"uid": "%s"
		},
		"spec": {
			"tolerations": %s
		},
		"users": null
	}`

	partial, err := json.Marshal(tolerations)
	return fmt.Sprintf(str, name, namespace, uid, string(partial)), err
}

type podTestSuites struct {
	testID          string
	targetPod       string
	namespace       string
	username        string
	operation       v1beta1.Operation
	userGroups      []string
	tolerations     []corev1.Toleration
	shouldBeAllowed bool
}

func runPodTests(t *testing.T, tests []podTestSuites) {
	gvk := metav1.GroupVersionKind{
		Group:   "",
		Version: "v1",
		Kind:    "Pod",
	}
	gvr := metav1.GroupVersionResource{
		Group:    "",
		Version:  "v1",
		Resource: "pods",
	}

	for _, test := range tests {
		rawObjString, err := createRawPodJSON(test.targetPod, test.tolerations, test.testID, test.namespace)
		if err != nil {
			t.Fatalf("Couldn't create a JSON fragment %s", err.Error())
		}

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

func TestDedicatedAdminNegative(t *testing.T) {
	tests := []podTestSuites{
		{ //Dedicated admin can not deploy pod on master on infra nodes in openshift-operators, openshift-logging namespace or any other namespace that is not a core namespace like openshift-*, redhat-*, default, kube-*.
			targetPod:  "my-test-pod",
			testID:     "dedicated-admin-cant-deploy1",
			namespace:  "random-project",
			username:   "dedicated-admin",
			userGroups: []string{"system:authenticated", "dedicated-admin"},
			tolerations: []corev1.Toleration{
				{
					Key:      "node-role.kubernetes.io/master",
					Operator: corev1.TolerationOpEqual,
					Value:    "toleration key value",
					Effect:   corev1.TaintEffectPreferNoSchedule,
				},
				{
					Key:      "node-role.kubernetes.io/infra",
					Operator: corev1.TolerationOpEqual,
					Value:    "toleration key value2",
					Effect:   corev1.TaintEffectNoSchedule,
				},
			},
			operation:       v1beta1.Create,
			shouldBeAllowed: false,
		},
		{
			targetPod:  "my-test-pod",
			testID:     "dedicated-admin-cant-deploy2",
			namespace:  "openshift-operators",
			username:   "dedicated-admin",
			userGroups: []string{"system:authenticated", "dedicated-admin"},
			tolerations: []corev1.Toleration{
				{
					Key:      "node-role.kubernetes.io/master",
					Operator: corev1.TolerationOpEqual,
					Value:    "toleration key value",
					Effect:   corev1.TaintEffectPreferNoSchedule,
				},
				{
					Key:      "node-role.kubernetes.io/infra",
					Operator: corev1.TolerationOpEqual,
					Value:    "toleration key value2",
					Effect:   corev1.TaintEffectNoSchedule,
				},
			},
			operation:       v1beta1.Create,
			shouldBeAllowed: false,
		},
		{
			targetPod:  "my-test-pod",
			testID:     "dedicated-admin-cant-deploy3",
			namespace:  "openshift-logging",
			username:   "dedicated-admin",
			userGroups: []string{"system:authenticated", "dedicated-admin"},
			tolerations: []corev1.Toleration{
				{
					Key:      "node-role.kubernetes.io/master",
					Operator: corev1.TolerationOpEqual,
					Value:    "toleration key value",
					Effect:   corev1.TaintEffectNoSchedule,
				},
				{
					Key:      "node-role.kubernetes.io/infra",
					Operator: corev1.TolerationOpEqual,
					Value:    "toleration key value2",
					Effect:   corev1.TaintEffectNoSchedule,
				},
			},
			operation:       v1beta1.Create,
			shouldBeAllowed: false,
		},
		{
			targetPod:  "my-test-pod",
			testID:     "dedicated-admin-cant-deploy4",
			namespace:  "openshift-logging",
			username:   "dedicated-admin",
			userGroups: []string{"system:authenticated", "dedicated-admin"},
			tolerations: []corev1.Toleration{
				{
					Key:      "node-role.kubernetes.io/master",
					Operator: corev1.TolerationOpEqual,
					Value:    "toleration key value",
					Effect:   corev1.TaintEffectNoExecute,
				},
				{
					Key:      "node-role.kubernetes.io/infra",
					Operator: corev1.TolerationOpEqual,
					Value:    "toleration key value2",
					Effect:   corev1.TaintEffectPreferNoSchedule,
				},
			},
			operation:       v1beta1.Create,
			shouldBeAllowed: false,
		},
		{
			targetPod:  "my-test-pod",
			testID:     "dedicated-admin-cant-deploy5",
			namespace:  "openshift-logging",
			username:   "dedicated-admin",
			userGroups: []string{"system:authenticated", "dedicated-admin"},
			tolerations: []corev1.Toleration{
				{
					Key:      "node-role.kubernetes.io/infra",
					Operator: corev1.TolerationOpEqual,
					Value:    "toleration key value2",
					Effect:   corev1.TaintEffectNoSchedule,
				},
			},
			operation:       v1beta1.Create,
			shouldBeAllowed: false,
		},
	}
	runPodTests(t, tests)
}

func TestDedicatedAdminPositive(t *testing.T) {
	tests := []podTestSuites{
		{ //Dedicated admin can deploy pod on master on infra if it is in a core namespace like openshift-*, redhat-*, default, kube-* with exceptions of openshift-operators and openshift-logging namespace.
			targetPod:  "my-test-pod",
			testID:     "dedicated-admin-can-deploy1",
			namespace:  "openshift-apiserver",
			username:   "dedicated-admin",
			userGroups: []string{"system:authenticated", "dedicated-admin"},
			tolerations: []corev1.Toleration{
				{
					Key:      "node-role.kubernetes.io/master",
					Operator: corev1.TolerationOpEqual,
					Value:    "toleration key value",
					Effect:   corev1.TaintEffectNoSchedule,
				},
				{
					Key:      "node-role.kubernetes.io/infra",
					Operator: corev1.TolerationOpEqual,
					Value:    "toleration key value2",
					Effect:   corev1.TaintEffectNoSchedule,
				},
			},
			operation:       v1beta1.Create,
			shouldBeAllowed: true,
		},
		{
			targetPod:  "my-test-pod",
			testID:     "dedicated-admin-can-deploy2",
			namespace:  "kube-system",
			username:   "dedicated-admin",
			userGroups: []string{"system:authenticated", "dedicated-admin"},
			tolerations: []corev1.Toleration{
				{
					Key:      "node-role.kubernetes.io/master",
					Operator: corev1.TolerationOpEqual,
					Value:    "toleration key value",
					Effect:   corev1.TaintEffectPreferNoSchedule,
				},
				{
					Key:      "node-role.kubernetes.io/infra",
					Operator: corev1.TolerationOpEqual,
					Value:    "toleration key value2",
					Effect:   corev1.TaintEffectNoSchedule,
				},
			},
			operation:       v1beta1.Create,
			shouldBeAllowed: true,
		},
		{
			targetPod:  "my-test-pod",
			testID:     "dedicated-admin-can-deploy3",
			namespace:  "redhat-config",
			username:   "dedicated-admin",
			userGroups: []string{"system:authenticated", "dedicated-admin"},
			tolerations: []corev1.Toleration{
				{
					Key:      "node-role.kubernetes.io/master",
					Operator: corev1.TolerationOpEqual,
					Value:    "toleration key value",
					Effect:   corev1.TaintEffectPreferNoSchedule,
				},
				{
					Key:      "node-role.kubernetes.io/infra",
					Operator: corev1.TolerationOpEqual,
					Value:    "toleration key value2",
					Effect:   corev1.TaintEffectPreferNoSchedule,
				},
			},
			operation:       v1beta1.Create,
			shouldBeAllowed: true,
		},
		{
			targetPod:  "my-test-pod",
			testID:     "dedicated-admin-can-deploy4",
			namespace:  "default",
			username:   "dedicated-admin",
			userGroups: []string{"system:authenticated", "dedicated-admin"},
			tolerations: []corev1.Toleration{
				{
					Key:      "node-role.kubernetes.io/master",
					Operator: corev1.TolerationOpEqual,
					Value:    "toleration key value",
					Effect:   corev1.TaintEffectNoSchedule,
				},
				{
					Key:      "node-role.kubernetes.io/infra",
					Operator: corev1.TolerationOpEqual,
					Value:    "toleration key value2",
					Effect:   corev1.TaintEffectPreferNoSchedule,
				},
			},
			operation:       v1beta1.Delete,
			shouldBeAllowed: true,
		},
		{
			targetPod:  "my-test-pod",
			testID:     "dedicated-admin-can-deploy5",
			namespace:  "default",
			username:   "dedicated-admin",
			userGroups: []string{"system:authenticated", "dedicated-admin"},
			tolerations: []corev1.Toleration{
				{
					Key:      "node-role.kubernetes.io/infra",
					Operator: corev1.TolerationOpEqual,
					Value:    "toleration key value2",
					Effect:   corev1.TaintEffectNoSchedule,
				},
			},
			operation:       v1beta1.Create,
			shouldBeAllowed: true,
		},
	}
	runPodTests(t, tests)
}

func TestUserNegative(t *testing.T) {
	tests := []podTestSuites{
		{ //User can not deploy pod on master on infra nodes in openshift-operators, openshift-logging namespace or any other namespace that is not a core namespace like openshift-*, redhat-*, default, kube-*.
			targetPod:  "my-test-pod",
			testID:     "user-alice-cant-deploy1",
			namespace:  "openshift-logging",
			username:   "alice",
			userGroups: []string{"system:authenticated", "system:authenticated:oauth"},
			tolerations: []corev1.Toleration{
				{
					Key:      "node-role.kubernetes.io/master",
					Operator: corev1.TolerationOpEqual,
					Value:    "toleration key value",
					Effect:   corev1.TaintEffectPreferNoSchedule,
				},
				{
					Key:      "node-role.kubernetes.io/infra",
					Operator: corev1.TolerationOpEqual,
					Value:    "toleration key value2",
					Effect:   corev1.TaintEffectNoSchedule,
				},
			},
			operation:       v1beta1.Create,
			shouldBeAllowed: false,
		},
		{
			targetPod:  "my-test-pod",
			testID:     "user-alice-cant-deploy2",
			namespace:  "openshift-operators",
			username:   "alice",
			userGroups: []string{"system:authenticated", "system:authenticated:oauth"},
			tolerations: []corev1.Toleration{
				{
					Key:      "node-role.kubernetes.io/master",
					Operator: corev1.TolerationOpEqual,
					Value:    "toleration key value",
					Effect:   corev1.TaintEffectPreferNoSchedule,
				},
				{
					Key:      "node-role.kubernetes.io/infra",
					Operator: corev1.TolerationOpEqual,
					Value:    "toleration key value2",
					Effect:   corev1.TaintEffectPreferNoSchedule,
				},
			},
			operation:       v1beta1.Create,
			shouldBeAllowed: false,
		},
		{
			targetPod:  "my-test-pod",
			testID:     "user-alice-cant-deploy3",
			namespace:  "my-little-project",
			username:   "alice",
			userGroups: []string{"system:authenticated", "system:authenticated:oauth"},
			tolerations: []corev1.Toleration{
				{
					Key:      "node-role.kubernetes.io/infra",
					Operator: corev1.TolerationOpEqual,
					Value:    "toleration key value2",
					Effect:   corev1.TaintEffectNoSchedule,
				},
			},
			operation:       v1beta1.Delete,
			shouldBeAllowed: false,
		},
		{
			targetPod:  "my-test-pod",
			testID:     "user-alice-cant-deploy4",
			namespace:  "default-configs",
			username:   "Alice",
			userGroups: []string{"system:authenticated", "system:authenticated:oauth"},
			tolerations: []corev1.Toleration{
				{
					Key:      "node-role.kubernetes.io/master",
					Operator: corev1.TolerationOpEqual,
					Value:    "toleration key value",
					Effect:   corev1.TaintEffectNoSchedule,
				},
				{
					Key:      "node-role.kubernetes.io/infra",
					Operator: corev1.TolerationOpEqual,
					Value:    "toleration key value2",
					Effect:   corev1.TaintEffectNoSchedule,
				},
			},
			operation:       v1beta1.Create,
			shouldBeAllowed: false,
		},
	}
	runPodTests(t, tests)

}

// Normal user won't be able to create pods in privileged namespaces as RBAC will disallow it.
func TestUserPositive(t *testing.T) {
	tests := []podTestSuites{
		{ //User can deploy pod on master on infra if it is in a core namespace like openshift-*, redhat-*, default, kube-* with exceptions of openshift-operators and openshift-logging namespace.
			targetPod:  "my-test-pod",
			testID:     "user-bob-can-deploy1",
			namespace:  "openshift-apiserver",
			username:   "bob",
			userGroups: []string{"system:authenticated", "system:authenticated:oauth"},
			tolerations: []corev1.Toleration{
				{
					Key:      "node-role.kubernetes.io/master",
					Operator: corev1.TolerationOpEqual,
					Value:    "toleration key value",
					Effect:   corev1.TaintEffectNoSchedule,
				},
				{
					Key:      "node-role.kubernetes.io/infra",
					Operator: corev1.TolerationOpEqual,
					Value:    "toleration key value2",
					Effect:   corev1.TaintEffectNoSchedule,
				},
			},
			operation:       v1beta1.Create,
			shouldBeAllowed: true,
		},
		{
			targetPod:  "my-test-pod",
			testID:     "user-bob-can-deploy2",
			namespace:  "kube-system",
			username:   "bob",
			userGroups: []string{"system:authenticated", "system:authenticated:oauth"},
			tolerations: []corev1.Toleration{
				{
					Key:      "node-role.kubernetes.io/master",
					Operator: corev1.TolerationOpEqual,
					Value:    "toleration key value",
					Effect:   corev1.TaintEffectPreferNoSchedule,
				},
				{
					Key:      "node-role.kubernetes.io/infra",
					Operator: corev1.TolerationOpEqual,
					Value:    "toleration key value2",
					Effect:   corev1.TaintEffectNoSchedule,
				},
			},
			operation:       v1beta1.Create,
			shouldBeAllowed: true,
		},
		{
			targetPod:  "my-test-pod",
			testID:     "user-bob-can-deploy3",
			namespace:  "redhat-config",
			username:   "bob",
			userGroups: []string{"system:authenticated", "system:authenticated:oauth"},
			tolerations: []corev1.Toleration{

				{
					Key:      "node-role.kubernetes.io/infra",
					Operator: corev1.TolerationOpEqual,
					Value:    "toleration key value2",
					Effect:   corev1.TaintEffectNoSchedule,
				},
			},
			operation:       v1beta1.Create,
			shouldBeAllowed: true,
		},
		{
			targetPod:  "my-test-pod",
			testID:     "user-bob-can-deploy4",
			namespace:  "default",
			username:   "bob",
			userGroups: []string{"system:authenticated", "system:authenticated:oauth"},
			tolerations: []corev1.Toleration{
				{
					Key:      "node-role.kubernetes.io/master",
					Operator: corev1.TolerationOpEqual,
					Value:    "toleration key value",
					Effect:   corev1.TaintEffectNoSchedule,
				},
				{
					Key:      "node-role.kubernetes.io/infra",
					Operator: corev1.TolerationOpEqual,
					Value:    "toleration key value2",
					Effect:   corev1.TaintEffectPreferNoSchedule,
				},
			},
			operation:       v1beta1.Create,
			shouldBeAllowed: true,
		},
		{
			targetPod:  "my-test-pod",
			testID:     "user-bob-can-deploy4",
			namespace:  "default",
			username:   "bob",
			userGroups: []string{"system:authenticated", "system:authenticated:oauth"},
			tolerations: []corev1.Toleration{
				{
					Key:      "node-role.kubernetes.io/master",
					Operator: corev1.TolerationOpEqual,
					Value:    "toleration key value",
					Effect:   corev1.TaintEffectNoSchedule,
				},
				{
					Key:      "node-role.kubernetes.io/infra",
					Operator: corev1.TolerationOpEqual,
					Value:    "toleration key value2",
					Effect:   corev1.TaintEffectPreferNoSchedule,
				},
			},
			operation:       v1beta1.Delete,
			shouldBeAllowed: true,
		},
		{
			targetPod:  "my-test-pod",
			testID:     "user-bob-can-deploy4",
			namespace:  "default",
			username:   "bob",
			userGroups: []string{"system:authenticated", "system:authenticated:oauth"},
			tolerations: []corev1.Toleration{
				{
					Key:      "node-role.kubernetes.io/master",
					Operator: corev1.TolerationOpEqual,
					Value:    "toleration key value2",
					Effect:   corev1.TaintEffectNoSchedule,
				},
			},
			operation:       v1beta1.Delete,
			shouldBeAllowed: true,
		},
	}
	runPodTests(t, tests)
}
