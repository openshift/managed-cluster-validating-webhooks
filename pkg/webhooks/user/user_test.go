package user

import (
	"fmt"
	"testing"

	"github.com/openshift/managed-cluster-validating-webhooks/pkg/testutils"

	"k8s.io/api/admission/v1beta1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
)

const testUserRaw string = `{
  "metadata": {
    "name": "%s",
    "uid": "%s",
    "creationTimestamp": "2020-05-10T07:51:00Z"
  },
	"users": null
}`

type userTestSuites struct {
	testID          string
	subjectUserName string
	username        string
	userGroups      []string
	operation       v1beta1.Operation
	shouldBeAllowed bool
}

func runUserTests(t *testing.T, tests []userTestSuites) {
	gvk := metav1.GroupVersionKind{
		Group:   "user.openshift.io",
		Version: "v1",
		Kind:    "Identity",
	}
	gvr := metav1.GroupVersionResource{
		Group:    "user.openshift.io",
		Version:  "v1",
		Resource: "identities",
	}

	for _, test := range tests {
		rawObjString := fmt.Sprintf(testUserRaw, test.subjectUserName, test.testID)

		obj := runtime.RawExtension{
			Raw: []byte(rawObjString),
		}
		hook := NewWebhook()
		httprequest, err := testutils.CreateHTTPRequest(hook.GetURI(),
			test.testID,
			gvk, gvr, test.operation, test.username, test.userGroups, obj)
		if err != nil {
			t.Fatalf("Expected no error, got %s", err.Error())
		}

		response, err := testutils.SendHTTPRequest(httprequest, hook)
		if err != nil {
			t.Fatalf("Expected no error, got %s", err.Error())
		}
		if response.UID == "" {
			t.Fatalf("No tracking UID associated with the response: %+v", response)
		}

		if response.Allowed != test.shouldBeAllowed {
			t.Fatalf("Mismatch: %s (groups=%s) %s %s the %s user. Test's expectation is that the user %s",
				test.username, test.userGroups,
				testutils.CanCanNot(response.Allowed), string(test.operation),
				test.subjectUserName, testutils.CanCanNot(test.shouldBeAllowed))
		}
	}
}

func TestAdminUsers(t *testing.T) {
	tests := []userTestSuites{
		{
			testID:          "kube-admin-can-do-it-all",
			subjectUserName: "some-user",
			username:        "kube:admin",
			userGroups:      []string{"system:authenticated"},
			operation:       v1beta1.Create,
			shouldBeAllowed: true,
		},
		{
			testID:          "priv-oauth-service-account",
			subjectUserName: "no-reply@redhat.com",
			username:        "system:serviceaccount:openshift-authentication:oauth-openshift",
			userGroups:      []string{"system:authenticated", "system:serviceaccount:openshift-authentication:oauth-openshift"},
			operation:       v1beta1.Delete,
			shouldBeAllowed: true,
		},
		{
			testID:          "priv-sre-admin",
			subjectUserName: "no-reply@redhat.com",
			username:        "sre-admin",
			userGroups:      []string{"system:authenticated", "osd-sre-admins"},
			operation:       v1beta1.Create,
			shouldBeAllowed: true,
		},
		{
			testID:          "priv-sre-cluster-admin",
			subjectUserName: "no-reply@redhat.com",
			username:        "sre-cluster-admin",
			userGroups:      []string{"system:authenticated", "osd-sre-cluster-admins"},
			operation:       v1beta1.Create,
			shouldBeAllowed: true,
		},
		{
			testID:          "priv-cluster-admin-cant-delete",
			subjectUserName: "no-reply@redhat.com",
			username:        "sre-cluster-admin",
			userGroups:      []string{"system:authenticated", "cluster-admins"},
			operation:       v1beta1.Update,
			shouldBeAllowed: false,
		},
		{
			testID:          "priv-cluster-admin-cant-create",
			subjectUserName: "no-reply@redhat.com",
			username:        "sre-cluster-admin",
			userGroups:      []string{"system:authenticated", "cluster-admins"},
			operation:       v1beta1.Create,
			shouldBeAllowed: false,
		},
		{
			testID:          "priv-cluster-admin-cant-edit",
			subjectUserName: "no-reply@redhat.com",
			username:        "sre-cluster-admin",
			userGroups:      []string{"system:authenticated", "cluster-admins"},
			operation:       v1beta1.Update,
			shouldBeAllowed: false,
		},
	}
	runUserTests(t, tests)
}

func TestNonAdminUsers(t *testing.T) {
	tests := []userTestSuites{
		// can't manage the protected
		{
			testID:          "priv-dedi-admin-failure",
			subjectUserName: "no-reply@redhat.com",
			username:        "dedicated-admin",
			userGroups:      []string{"system:authenticated", "dedicated-admins"},
			operation:       v1beta1.Update,
			shouldBeAllowed: false,
		},
		// dedicated-admins can manage their own
		{
			testID:          "nonpriv-dedi-admin",
			subjectUserName: "no-reply@example.com",
			username:        "dedicated-admin",
			userGroups:      []string{"system:authenticated", "dedicated-admins"},
			operation:       v1beta1.Delete,
			shouldBeAllowed: true,
		},
	}
	runUserTests(t, tests)
}

func TestName(t *testing.T) {
	if NewWebhook().Name() == "" {
		t.Fatalf("Empty hook name")
	}
}

func TestRules(t *testing.T) {
	if len(NewWebhook().Rules()) == 0 {
		t.Log("No rules for this webhook?")
	}
}

func TestGetURI(t *testing.T) {
	if NewWebhook().GetURI()[0] != '/' {
		t.Fatalf("Hook URI does not begin with a /")
	}
}
