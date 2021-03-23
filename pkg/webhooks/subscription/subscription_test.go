package subscription

import (
	"fmt"
	"testing"

	"github.com/openshift/managed-cluster-validating-webhooks/pkg/testutils"
	"k8s.io/api/admission/v1beta1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
)

const testSubscriptionRaw string = `{
	"metadata": {
		"uid": "%s"
	},
	"spec": {
		"channel": "%s",
		"name": "%s"
	}
}`

type subscriptionTestSuites struct {
	testID           string
	username         string
	userGroups       []string
	channel          string
	subscriptionName string
	operation        v1beta1.Operation
	oldObject        *runtime.RawExtension
	shouldBeAllowed  bool
}

func runSubscriptionTests(t *testing.T, tests []subscriptionTestSuites) {
	gvk := metav1.GroupVersionKind{
		Group:   "operators.coreos.com",
		Version: "*",
		Kind:    "Subscription",
	}
	gvr := metav1.GroupVersionResource{
		Group:    "operators.coreos.com",
		Version:  "*",
		Resource: "subscriptions",
	}

	for _, test := range tests {
		rawObjString := fmt.Sprintf(testSubscriptionRaw, test.testID, test.channel, test.subscriptionName)
		obj := runtime.RawExtension{
			Raw: []byte(rawObjString),
		}

		hook := NewWebhook()
		httprequest, err := testutils.CreateHTTPRequest(hook.GetURI(),
			test.testID,
			gvk, gvr, test.operation, test.username, test.userGroups, &obj, test.oldObject)
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
			t.Fatalf("%s Mismatch: %s (groups=%s) %s %s the %s subscription. Test's expectation is that the use %s. Reason: %s",
				test.testID,
				test.username, test.userGroups,
				testutils.CanCanNot(response.Allowed), string(test.operation),
				test.subscriptionName, testutils.CanCanNot(test.shouldBeAllowed),
				response.Result.Reason)
		}
	}
}

func TestDedicatedAdmins(t *testing.T) {
	tests := []subscriptionTestSuites{
		{
			testID:           "ded-admin-can-upgrade-ES-logging-44",
			username:         "testuser@testgroup.com",
			userGroups:       []string{"dedicated-admin", "system:authenticated", "system:authenticated:oauth"},
			operation:        v1beta1.Update,
			subscriptionName: "elasticsearch-operator",
			channel:          "4.4",
			shouldBeAllowed:  true,
		},
		{
			testID:           "ded-admin-can-upgrade-cluster-logging-44",
			username:         "testuser@testgroup.com",
			userGroups:       []string{"dedicated-admin", "system:authenticated", "system:authenticated:oauth"},
			operation:        v1beta1.Update,
			subscriptionName: "cluster-logging",
			channel:          "4.4",
			shouldBeAllowed:  true,
		},
		{
			testID:           "ded-admin-can-upgrade-other-45",
			username:         "testuser@testgroup.com",
			userGroups:       []string{"dedicated-admin", "system:authenticated", "system:authenticated:oauth"},
			operation:        v1beta1.Update,
			subscriptionName: "random-cool-operator",
			channel:          "4.5",
			shouldBeAllowed:  true,
		},
		{
			testID:           "ded-admin-can-upgrade-other",
			username:         "testuser@testgroup.com",
			userGroups:       []string{"dedicated-admin", "system:authenticated", "system:authenticated:oauth"},
			operation:        v1beta1.Update,
			subscriptionName: "other-cool-operator",
			channel:          "43.2",
			shouldBeAllowed:  true,
		},
		{
			testID:           "ded-admin-cannot-upgrade-cluster-logging-45",
			username:         "testuser@testgroup.com",
			userGroups:       []string{"dedicated-admin", "system:authenticated", "system:authenticated:oauth"},
			operation:        v1beta1.Update,
			subscriptionName: "cluster-logging",
			channel:          "4.5",
			shouldBeAllowed:  false,
		},
		{
			testID:           "ded-admin-cannot-upgrade-ES-logging-45",
			username:         "testuser@testgroup.com",
			userGroups:       []string{"dedicated-admin", "system:authenticated", "system:authenticated:oauth"},
			operation:        v1beta1.Update,
			subscriptionName: "elasticsearch-operator",
			channel:          "4.5",
			shouldBeAllowed:  false,
		},
		{
			testID:           "ded-admin-cannot-upgrade-cluster-logging-46",
			username:         "testuser@testgroup.com",
			userGroups:       []string{"dedicated-admin", "system:authenticated", "system:authenticated:oauth"},
			operation:        v1beta1.Update,
			subscriptionName: "cluster-logging",
			channel:          "4.6",
			shouldBeAllowed:  false,
		},
		{
			testID:           "ded-admin-cannot-upgrade-ES-logging-46",
			username:         "testuser@testgroup.com",
			userGroups:       []string{"dedicated-admin", "system:authenticated", "system:authenticated:oauth"},
			operation:        v1beta1.Update,
			subscriptionName: "elasticsearch-operator",
			channel:          "4.6",
			shouldBeAllowed:  false,
		},
	}
	runSubscriptionTests(t, tests)
}

func TestNormalUser(t *testing.T) {
	// these are basically the same tests as the dedicated-admin tests
	// and those that shouldBeAllowed will fail due to RBAC (but not due
	// to this webhook)
	tests := []subscriptionTestSuites{
		{
			testID:           "normal-user-can-upgrade-ES-logging-44",
			username:         "testuser@testgroup.com",
			userGroups:       []string{"system:authenticated", "system:authenticated:oauth"},
			operation:        v1beta1.Update,
			subscriptionName: "elasticsearch-operator",
			channel:          "4.4",
			shouldBeAllowed:  true,
		},
		{
			testID:           "normal-user-can-upgrade-cluster-logging-44",
			username:         "testuser@testgroup.com",
			userGroups:       []string{"system:authenticated", "system:authenticated:oauth"},
			operation:        v1beta1.Update,
			subscriptionName: "cluster-logging",
			channel:          "4.4",
			shouldBeAllowed:  true,
		},
		{
			testID:           "normal-user-can-upgrade-other-45",
			username:         "testuser@testgroup.com",
			userGroups:       []string{"system:authenticated", "system:authenticated:oauth"},
			operation:        v1beta1.Update,
			subscriptionName: "random-cool-operator",
			channel:          "4.5",
			shouldBeAllowed:  true,
		},
		{
			testID:           "normal-user-can-upgrade-other",
			username:         "testuser@testgroup.com",
			userGroups:       []string{"system:authenticated", "system:authenticated:oauth"},
			operation:        v1beta1.Update,
			subscriptionName: "other-cool-operator",
			channel:          "43.2",
			shouldBeAllowed:  true,
		},
		{
			testID:           "normal-user-cannot-upgrade-cluster-logging-45",
			username:         "testuser@testgroup.com",
			userGroups:       []string{"system:authenticated", "system:authenticated:oauth"},
			operation:        v1beta1.Update,
			subscriptionName: "cluster-logging",
			channel:          "4.5",
			shouldBeAllowed:  false,
		},
		{
			testID:           "normal-user-cannot-upgrade-ES-logging-45",
			username:         "testuser@testgroup.com",
			userGroups:       []string{"system:authenticated", "system:authenticated:oauth"},
			operation:        v1beta1.Update,
			subscriptionName: "elasticsearch-operator",
			channel:          "4.5",
			shouldBeAllowed:  false,
		},
		{
			testID:           "normal-user-cannot-upgrade-cluster-logging-46",
			username:         "testuser@testgroup.com",
			userGroups:       []string{"system:authenticated", "system:authenticated:oauth"},
			operation:        v1beta1.Update,
			subscriptionName: "cluster-logging",
			channel:          "4.6",
			shouldBeAllowed:  false,
		},
		{
			testID:           "normal-user-cannot-upgrade-ES-logging-46",
			username:         "testuser@testgroup.com",
			userGroups:       []string{"system:authenticated", "system:authenticated:oauth"},
			operation:        v1beta1.Update,
			subscriptionName: "elasticsearch-operator",
			channel:          "4.6",
			shouldBeAllowed:  false,
		},
	}
	runSubscriptionTests(t, tests)
}

func TestLayeredAdmins(t *testing.T) {
	// these are basically the same tests as the dedicated-admin tests
	// and those that shouldBeAllowed will fail due to RBAC (but not due
	// to this webhook)
	tests := []subscriptionTestSuites{
		{
			testID:           "lp-can-upgrade-ES-logging-44",
			username:         "testuser@redhat.com",
			userGroups:       []string{"layered-sre-cluster-admins", "system:authenticated", "system:authenticated:oauth"},
			operation:        v1beta1.Update,
			subscriptionName: "elasticsearch-operator",
			channel:          "4.4",
			shouldBeAllowed:  true,
		},
		{
			testID:           "lp-can-upgrade-cluster-logging-44",
			username:         "testuser@redhat.com",
			userGroups:       []string{"layered-sre-cluster-admins", "system:authenticated", "system:authenticated:oauth"},
			operation:        v1beta1.Update,
			subscriptionName: "cluster-logging",
			channel:          "4.4",
			shouldBeAllowed:  true,
		},
		{
			testID:           "lp-can-upgrade-other-45",
			username:         "testuser@redhat.com",
			userGroups:       []string{"layered-sre-cluster-admins", "system:authenticated", "system:authenticated:oauth"},
			operation:        v1beta1.Update,
			subscriptionName: "random-cool-operator",
			channel:          "4.5",
			shouldBeAllowed:  true,
		},
		{
			testID:           "lp-can-upgrade-other",
			username:         "testuser@redhat.com",
			userGroups:       []string{"layered-sre-cluster-admins", "system:authenticated", "system:authenticated:oauth"},
			operation:        v1beta1.Update,
			subscriptionName: "other-cool-operator",
			channel:          "43.2",
			shouldBeAllowed:  true,
		},
		{
			testID:           "lp-cannot-upgrade-cluster-logging-45",
			username:         "testuser@redhat.com",
			userGroups:       []string{"layered-sre-cluster-admins", "system:authenticated", "system:authenticated:oauth"},
			operation:        v1beta1.Update,
			subscriptionName: "cluster-logging",
			channel:          "4.5",
			shouldBeAllowed:  false,
		},
		{
			testID:           "lp-cannot-upgrade-ES-logging-45",
			username:         "testuser@redhat.com",
			userGroups:       []string{"layered-sre-cluster-admins", "system:authenticated", "system:authenticated:oauth"},
			operation:        v1beta1.Update,
			subscriptionName: "elasticsearch-operator",
			channel:          "4.5",
			shouldBeAllowed:  false,
		},
		{
			testID:           "lp-cannot-upgrade-cluster-logging-46",
			username:         "testuser@redhat.com",
			userGroups:       []string{"layered-sre-cluster-admins", "system:authenticated", "system:authenticated:oauth"},
			operation:        v1beta1.Update,
			subscriptionName: "cluster-logging",
			channel:          "4.6",
			shouldBeAllowed:  false,
		},
		{
			testID:           "lp-cannot-upgrade-ES-logging-46",
			username:         "testuser@redhat.com",
			userGroups:       []string{"layered-sre-cluster-admins", "system:authenticated", "system:authenticated:oauth"},
			operation:        v1beta1.Update,
			subscriptionName: "elasticsearch-operator",
			channel:          "4.6",
			shouldBeAllowed:  false,
		},
	}
	runSubscriptionTests(t, tests)
}

func TestPrivilegedUsers(t *testing.T) {
	tests := []subscriptionTestSuites{
		{
			testID:           "kube-admin-can-upgrade-ES-logging-44",
			username:         "kube:admin",
			userGroups:       []string{"kube:system", "system:authenticated", "system:authenticated:oauth"},
			operation:        v1beta1.Update,
			subscriptionName: "elasticsearch-operator",
			channel:          "4.4",
			shouldBeAllowed:  true,
		},
		{
			testID:           "kube-admin-can-upgrade-cluster-logging-44",
			username:         "kube:admin",
			userGroups:       []string{"kube:system", "system:authenticated", "system:authenticated:oauth"},
			operation:        v1beta1.Update,
			subscriptionName: "cluster-logging",
			channel:          "4.4",
			shouldBeAllowed:  true,
		},
		{
			testID:           "kube-admin-can-upgrade-other-45",
			username:         "kube:admin",
			userGroups:       []string{"kube:system", "system:authenticated", "system:authenticated:oauth"},
			operation:        v1beta1.Update,
			subscriptionName: "random-cool-operator",
			channel:          "4.5",
			shouldBeAllowed:  true,
		},
		{
			testID:           "kube-admin-can-upgrade-other",
			username:         "kube:admin",
			userGroups:       []string{"kube:system", "system:authenticated", "system:authenticated:oauth"},
			operation:        v1beta1.Update,
			subscriptionName: "other-cool-operator",
			channel:          "43.2",
			shouldBeAllowed:  true,
		},
		{
			testID:           "kube-admin-can-upgrade-cluster-logging-45",
			username:         "kube:admin",
			userGroups:       []string{"kube:system", "system:authenticated", "system:authenticated:oauth"},
			operation:        v1beta1.Update,
			subscriptionName: "cluster-logging",
			channel:          "4.5",
			shouldBeAllowed:  true,
		},
		{
			testID:           "kube-admin-can-upgrade-ES-logging-45",
			username:         "kube:admin",
			userGroups:       []string{"kube:system", "system:authenticated", "system:authenticated:oauth"},
			operation:        v1beta1.Update,
			subscriptionName: "elasticsearch-operator",
			channel:          "4.5",
			shouldBeAllowed:  true,
		},
		{
			testID:           "kube-admin-can-upgrade-cluster-logging-46",
			username:         "kube:admin",
			userGroups:       []string{"kube:system", "system:authenticated", "system:authenticated:oauth"},
			operation:        v1beta1.Update,
			subscriptionName: "cluster-logging",
			channel:          "4.6",
			shouldBeAllowed:  true,
		},
		{
			testID:           "kube-admin-can-upgrade-ES-logging-46",
			username:         "kube:admin",
			userGroups:       []string{"kube:system", "system:authenticated", "system:authenticated:oauth"},
			operation:        v1beta1.Update,
			subscriptionName: "elasticsearch-operator",
			channel:          "4.6",
			shouldBeAllowed:  true,
		},
		{
			testID:           "system-admin-can-upgrade-ES-logging-44",
			username:         "system:admin",
			userGroups:       []string{"system:authenticated", "system:authenticated:oauth"},
			operation:        v1beta1.Update,
			subscriptionName: "elasticsearch-operator",
			channel:          "4.4",
			shouldBeAllowed:  true,
		},
		{
			testID:           "system-admin-can-upgrade-cluster-logging-44",
			username:         "system:admin",
			userGroups:       []string{"system:authenticated", "system:authenticated:oauth"},
			operation:        v1beta1.Update,
			subscriptionName: "cluster-logging",
			channel:          "4.4",
			shouldBeAllowed:  true,
		},
		{
			testID:           "system-admin-can-upgrade-other-45",
			username:         "system:admin",
			userGroups:       []string{"system:authenticated", "system:authenticated:oauth"},
			operation:        v1beta1.Update,
			subscriptionName: "random-cool-operator",
			channel:          "4.5",
			shouldBeAllowed:  true,
		},
		{
			testID:           "system-admin-can-upgrade-other",
			username:         "system:admin",
			userGroups:       []string{"system:authenticated", "system:authenticated:oauth"},
			operation:        v1beta1.Update,
			subscriptionName: "other-cool-operator",
			channel:          "43.2",
			shouldBeAllowed:  true,
		},
		{
			testID:           "system-admin-can-upgrade-cluster-logging-45",
			username:         "system:admin",
			userGroups:       []string{"system:authenticated", "system:authenticated:oauth"},
			operation:        v1beta1.Update,
			subscriptionName: "cluster-logging",
			channel:          "4.5",
			shouldBeAllowed:  true,
		},
		{
			testID:           "system-admin-can-upgrade-ES-logging-45",
			username:         "system:admin",
			userGroups:       []string{"system:authenticated", "system:authenticated:oauth"},
			operation:        v1beta1.Update,
			subscriptionName: "elasticsearch-operator",
			channel:          "4.5",
			shouldBeAllowed:  true,
		},
		{
			testID:           "system-admin-can-upgrade-cluster-logging-46",
			username:         "system:admin",
			userGroups:       []string{"system:authenticated", "system:authenticated:oauth"},
			operation:        v1beta1.Update,
			subscriptionName: "cluster-logging",
			channel:          "4.6",
			shouldBeAllowed:  true,
		},
		{
			testID:           "system-admin-can-upgrade-ES-logging-46",
			username:         "system:admin",
			userGroups:       []string{"system:authenticated", "system:authenticated:oauth"},
			operation:        v1beta1.Update,
			subscriptionName: "elasticsearch-operator",
			channel:          "4.6",
			shouldBeAllowed:  true,
		},
		{
			testID:           "sre-admin-can-upgrade-ES-logging-44",
			username:         "testuser@redhat.com",
			userGroups:       []string{"osd-sre-admins", "system:authenticated", "system:authenticated:oauth"},
			operation:        v1beta1.Update,
			subscriptionName: "elasticsearch-operator",
			channel:          "4.4",
			shouldBeAllowed:  true,
		},
		{
			testID:           "sre-admin-can-upgrade-cluster-logging-44",
			username:         "testuser@redhat.com",
			userGroups:       []string{"osd-sre-admins", "system:authenticated", "system:authenticated:oauth"},
			operation:        v1beta1.Update,
			subscriptionName: "cluster-logging",
			channel:          "4.4",
			shouldBeAllowed:  true,
		},
		{
			testID:           "sre-admin-can-upgrade-other-45",
			username:         "testuser@redhat.com",
			userGroups:       []string{"osd-sre-admins", "system:authenticated", "system:authenticated:oauth"},
			operation:        v1beta1.Update,
			subscriptionName: "random-cool-operator",
			channel:          "4.5",
			shouldBeAllowed:  true,
		},
		{
			testID:           "sre-admin-can-upgrade-other",
			username:         "testuser@redhat.com",
			userGroups:       []string{"osd-sre-admins", "system:authenticated", "system:authenticated:oauth"},
			operation:        v1beta1.Update,
			subscriptionName: "other-cool-operator",
			channel:          "43.2",
			shouldBeAllowed:  true,
		},
		{
			testID:           "sre-admin-can-upgrade-cluster-logging-45",
			username:         "testuser@redhat.com",
			userGroups:       []string{"osd-sre-admins", "system:authenticated", "system:authenticated:oauth"},
			operation:        v1beta1.Update,
			subscriptionName: "cluster-logging",
			channel:          "4.5",
			shouldBeAllowed:  true,
		},
		{
			testID:           "sre-admin-can-upgrade-ES-logging-45",
			username:         "testuser@redhat.com",
			userGroups:       []string{"osd-sre-admins", "system:authenticated", "system:authenticated:oauth"},
			operation:        v1beta1.Update,
			subscriptionName: "elasticsearch-operator",
			channel:          "4.5",
			shouldBeAllowed:  true,
		},
		{
			testID:           "sre-admin-can-upgrade-cluster-logging-46",
			username:         "testuser@redhat.com",
			userGroups:       []string{"osd-sre-admins", "system:authenticated", "system:authenticated:oauth"},
			operation:        v1beta1.Update,
			subscriptionName: "cluster-logging",
			channel:          "4.6",
			shouldBeAllowed:  true,
		},
		{
			testID:           "sre-admin-can-upgrade-ES-logging-46",
			username:         "testuser@redhat.com",
			userGroups:       []string{"osd-sre-admins", "system:authenticated", "system:authenticated:oauth"},
			operation:        v1beta1.Update,
			subscriptionName: "elasticsearch-operator",
			channel:          "4.6",
			shouldBeAllowed:  true,
		},
		{
			testID:           "sre-cluster-admin-can-upgrade-ES-logging-44",
			username:         "testuser@redhat.com",
			userGroups:       []string{"osd-sre-cluster-admins", "system:authenticated", "system:authenticated:oauth"},
			operation:        v1beta1.Update,
			subscriptionName: "elasticsearch-operator",
			channel:          "4.4",
			shouldBeAllowed:  true,
		},
		{
			testID:           "sre-cluster-admin-can-upgrade-cluster-logging-44",
			username:         "testuser@redhat.com",
			userGroups:       []string{"osd-sre-cluster-admins", "system:authenticated", "system:authenticated:oauth"},
			operation:        v1beta1.Update,
			subscriptionName: "cluster-logging",
			channel:          "4.4",
			shouldBeAllowed:  true,
		},
		{
			testID:           "sre-cluster-admin-can-upgrade-other-45",
			username:         "testuser@redhat.com",
			userGroups:       []string{"osd-sre-cluster-admins", "system:authenticated", "system:authenticated:oauth"},
			operation:        v1beta1.Update,
			subscriptionName: "random-cool-operator",
			channel:          "4.5",
			shouldBeAllowed:  true,
		},
		{
			testID:           "sre-cluster-admin-can-upgrade-other",
			username:         "testuser@redhat.com",
			userGroups:       []string{"osd-sre-cluster-admins", "system:authenticated", "system:authenticated:oauth"},
			operation:        v1beta1.Update,
			subscriptionName: "other-cool-operator",
			channel:          "43.2",
			shouldBeAllowed:  true,
		},
		{
			testID:           "sre-cluster-admin-can-upgrade-cluster-logging-45",
			username:         "testuser@redhat.com",
			userGroups:       []string{"osd-sre-cluster-admins", "system:authenticated", "system:authenticated:oauth"},
			operation:        v1beta1.Update,
			subscriptionName: "cluster-logging",
			channel:          "4.5",
			shouldBeAllowed:  true,
		},
		{
			testID:           "sre-cluster-admin-can-upgrade-ES-logging-45",
			username:         "testuser@redhat.com",
			userGroups:       []string{"osd-sre-cluster-admins", "system:authenticated", "system:authenticated:oauth"},
			operation:        v1beta1.Update,
			subscriptionName: "elasticsearch-operator",
			channel:          "4.5",
			shouldBeAllowed:  true,
		},
		{
			testID:           "sre-cluster-admin-can-upgrade-cluster-logging-46",
			username:         "testuser@redhat.com",
			userGroups:       []string{"osd-sre-cluster-admins", "system:authenticated", "system:authenticated:oauth"},
			operation:        v1beta1.Update,
			subscriptionName: "cluster-logging",
			channel:          "4.6",
			shouldBeAllowed:  true,
		},
		{
			testID:           "sre-cluster-admin-can-upgrade-ES-logging-46",
			username:         "testuser@redhat.com",
			userGroups:       []string{"osd-sre-cluster-admins", "system:authenticated", "system:authenticated:oauth"},
			operation:        v1beta1.Update,
			subscriptionName: "elasticsearch-operator",
			channel:          "4.6",
			shouldBeAllowed:  true,
		},
		{
			testID:           "cluster-admin-can-upgrade-ES-logging-44",
			username:         "testuser@testgroup.com",
			userGroups:       []string{"cluster-admins", "system:authenticated", "system:authenticated:oauth"},
			operation:        v1beta1.Update,
			subscriptionName: "elasticsearch-operator",
			channel:          "4.4",
			shouldBeAllowed:  true,
		},
		{
			testID:           "cluster-admin-can-upgrade-cluster-logging-44",
			username:         "testuser@testgroup.com",
			userGroups:       []string{"cluster-admins", "system:authenticated", "system:authenticated:oauth"},
			operation:        v1beta1.Update,
			subscriptionName: "cluster-logging",
			channel:          "4.4",
			shouldBeAllowed:  true,
		},
		{
			testID:           "cluster-admin-can-upgrade-other-45",
			username:         "testuser@testgroup.com",
			userGroups:       []string{"cluster-admins", "system:authenticated", "system:authenticated:oauth"},
			operation:        v1beta1.Update,
			subscriptionName: "random-cool-operator",
			channel:          "4.5",
			shouldBeAllowed:  true,
		},
		{
			testID:           "cluster-admin-can-upgrade-other",
			username:         "testuser@testgroup.com",
			userGroups:       []string{"cluster-admins", "system:authenticated", "system:authenticated:oauth"},
			operation:        v1beta1.Update,
			subscriptionName: "other-cool-operator",
			channel:          "43.2",
			shouldBeAllowed:  true,
		},
		{
			testID:           "cluster-admin-can-upgrade-cluster-logging-45",
			username:         "testuser@testgroup.com",
			userGroups:       []string{"cluster-admins", "system:authenticated", "system:authenticated:oauth"},
			operation:        v1beta1.Update,
			subscriptionName: "cluster-logging",
			channel:          "4.5",
			shouldBeAllowed:  true,
		},
		{
			testID:           "cluster-admin-can-upgrade-ES-logging-45",
			username:         "testuser@testgroup.com",
			userGroups:       []string{"cluster-admins", "system:authenticated", "system:authenticated:oauth"},
			operation:        v1beta1.Update,
			subscriptionName: "elasticsearch-operator",
			channel:          "4.5",
			shouldBeAllowed:  true,
		},
		{
			testID:           "cluster-admin-can-upgrade-cluster-logging-46",
			username:         "testuser@testgroup.com",
			userGroups:       []string{"cluster-admins", "system:authenticated", "system:authenticated:oauth"},
			operation:        v1beta1.Update,
			subscriptionName: "cluster-logging",
			channel:          "4.6",
			shouldBeAllowed:  true,
		},
		{
			testID:           "cluster-admin-can-upgrade-ES-logging-46",
			username:         "testuser@testgroup.com",
			userGroups:       []string{"cluster-admins", "system:authenticated", "system:authenticated:oauth"},
			operation:        v1beta1.Update,
			subscriptionName: "elasticsearch-operator",
			channel:          "4.6",
			shouldBeAllowed:  true,
		},
	}
	runSubscriptionTests(t, tests)
}

func TestGCServiceAccount(t *testing.T) {
	tests := []subscriptionTestSuites{
		{
			testID:           "serviceaccount-can-upgrade-ES-logging-44",
			username:         "system:serviceaccount:kube-system:generic-garbage-collector",
			userGroups:       []string{"system:serviceaccount:kube-system", "system:authenticated", "system:authenticated:oauth"},
			operation:        v1beta1.Update,
			subscriptionName: "elasticsearch-operator",
			channel:          "4.4",
			shouldBeAllowed:  true,
		},
		{
			testID:           "serviceaccount-can-upgrade-cluster-logging-44",
			username:         "system:serviceaccount:kube-system:generic-garbage-collector",
			userGroups:       []string{"system:serviceaccount:kube-system", "system:authenticated", "system:authenticated:oauth"},
			operation:        v1beta1.Update,
			subscriptionName: "cluster-logging",
			channel:          "4.4",
			shouldBeAllowed:  true,
		},
		{
			testID:           "serviceaccount-can-upgrade-other-45",
			username:         "system:serviceaccount:kube-system:generic-garbage-collector",
			userGroups:       []string{"system:serviceaccount:kube-system", "system:authenticated", "system:authenticated:oauth"},
			operation:        v1beta1.Update,
			subscriptionName: "random-cool-operator",
			channel:          "4.5",
			shouldBeAllowed:  true,
		},
		{
			testID:           "serviceaccount-can-upgrade-other",
			username:         "system:serviceaccount:kube-system:generic-garbage-collector",
			userGroups:       []string{"system:serviceaccount:kube-system", "system:authenticated", "system:authenticated:oauth"},
			operation:        v1beta1.Update,
			subscriptionName: "other-cool-operator",
			channel:          "43.2",
			shouldBeAllowed:  true,
		},
		{
			testID:           "serviceaccount-can-upgrade-cluster-logging-45",
			username:         "system:serviceaccount:kube-system:generic-garbage-collector",
			userGroups:       []string{"system:serviceaccount:kube-system", "system:authenticated", "system:authenticated:oauth"},
			operation:        v1beta1.Update,
			subscriptionName: "cluster-logging",
			channel:          "4.5",
			shouldBeAllowed:  true,
		},
		{
			testID:           "serviceaccount-can-upgrade-ES-logging-45",
			username:         "system:serviceaccount:kube-system:generic-garbage-collector",
			userGroups:       []string{"system:serviceaccount:kube-system", "system:authenticated", "system:authenticated:oauth"},
			operation:        v1beta1.Update,
			subscriptionName: "elasticsearch-operator",
			channel:          "4.5",
			shouldBeAllowed:  true,
		},
	}
	runSubscriptionTests(t, tests)
}
