package group

import (
	"fmt"
	"testing"

	"github.com/openshift/managed-cluster-validating-webhooks/pkg/testutils"

	"k8s.io/api/admission/v1beta1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
)

// Raw JSON for a Group, used as runtime.RawExtension, and represented here
// because sometimes we need it for OldObject as well as Object.
const testGroupRaw string = `{
  "metadata": {
    "name": "%s",
    "uid": "%s",
    "creationTimestamp": "2020-05-10T07:51:00Z"
  },
  "users": null
}`

type groupTestsuites struct {
	testID          string
	groupName       string
	username        string
	userGroups      []string
	oldObject       *runtime.RawExtension
	operation       v1beta1.Operation
	shouldBeAllowed bool
}

func runGroupTests(t *testing.T, tests []groupTestsuites) {
	gvk := metav1.GroupVersionKind{
		Group:   "",
		Version: "v1beta1",
		Kind:    "Group",
	}
	gvr := metav1.GroupVersionResource{
		Group:    "",
		Version:  "v1beta1",
		Resource: "groups",
	}
	for _, test := range tests {
		rawObjString := fmt.Sprintf(testGroupRaw, test.groupName, test.testID)
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
			t.Fatalf("Mismatch: %s (groups=%s) %s %s the %s Group. Test's expectation is that the user %s",
				test.username, test.userGroups, testutils.CanCanNot(response.Allowed), string(test.operation), test.groupName, testutils.CanCanNot(test.shouldBeAllowed))
		}

	}
}

func TestAdminUsers(t *testing.T) {
	tests := []groupTestsuites{
		{
			// Should be able to do everything
			testID:          "admin-create-priv-group",
			groupName:       "osd-sre-admins",
			username:        "kube:admin",
			userGroups:      []string{"system:authenticated", "system:authenticated:oauth"},
			operation:       v1beta1.Create,
			shouldBeAllowed: true,
		},
		{
			// Admins should be able to do everything
			testID:          "admin-update-impersonator-group",
			groupName:       "osd-impersonators",
			username:        "kube:admin",
			userGroups:      []string{"system:authenticated", "system:authenticated:oauth"},
			operation:       v1beta1.Update,
			shouldBeAllowed: true,
		},
		{
			// Admins should be able to do everything
			testID:          "admin-delete-impersonator-group",
			groupName:       "osd-impersonators",
			username:        "kube:admin",
			userGroups:      []string{"system:authenticated", "system:authenticated:oauth"},
			operation:       v1beta1.Delete,
			shouldBeAllowed: true,
		},
	}
	runGroupTests(t, tests)
}
func TestDedicatedAdminUsers(t *testing.T) {
	tests := []groupTestsuites{
		{
			// Should not be able to create priv group
			testID:          "dedi-create-priv-group",
			groupName:       "osd-sre-admins",
			username:        "dedi-admin",
			userGroups:      []string{"dedicated-admins", "system:authenticated", "system:authenticated:oauth"},
			operation:       v1beta1.Create,
			shouldBeAllowed: false,
		},
		{
			// Should be able to create non-priv group
			testID:          "dedi-create-nonpriv-group",
			groupName:       "my-group",
			username:        "dedi-admin",
			userGroups:      []string{"dedicated-admins", "system:authenticated", "system:authenticated:oauth"},
			operation:       v1beta1.Create,
			shouldBeAllowed: true,
		},
		{
			// Should be able to update non-priv group
			testID:          "dedi-update-nonpriv-group",
			groupName:       "my-group",
			username:        "dedi-admin",
			userGroups:      []string{"dedicated-admins", "system:authenticated", "system:authenticated:oauth"},
			operation:       v1beta1.Update,
			shouldBeAllowed: true,
		},
		{
			// Should be able to update impersonator group
			testID:          "dedi-update-impersonator-group",
			groupName:       "osd-impersonators",
			username:        "dedi-admin",
			userGroups:      []string{"dedicated-admins", "system:authenticated", "system:authenticated:oauth"},
			operation:       v1beta1.Update,
			shouldBeAllowed: true,
		},
		{
			// Should not be able to update devaccess group
			testID:          "dedi-update-impersonator-group",
			groupName:       "osd-devaccess",
			username:        "dedi-admin",
			userGroups:      []string{"dedicated-admins", "system:authenticated", "system:authenticated:oauth"},
			operation:       v1beta1.Update,
			shouldBeAllowed: false,
		},
		{
			// Should not be able to delete priv group
			testID:          "dedi-delete-priv-group",
			groupName:       "osd-sre-admins",
			username:        "dedi-admin",
			userGroups:      []string{"dedicated-admins", "system:authenticated", "system:authenticated:oauth"},
			operation:       v1beta1.Delete,
			shouldBeAllowed: false,
		},
		{
			// Should be able to delete nonpriv group
			testID:          "dedi-delete-nonpriv-group",
			groupName:       "my-group",
			username:        "dedi-admin",
			userGroups:      []string{"dedicated-admins", "system:authenticated", "system:authenticated:oauth"},
			operation:       v1beta1.Delete,
			shouldBeAllowed: true,
		},
	}
	runGroupTests(t, tests)
}
func TestSREAdminUsers(t *testing.T) {
	tests := []groupTestsuites{
		{
			// Should be able to do everything
			testID:          "sre-create-priv-group",
			groupName:       "osd-sre-admins",
			username:        "test-user",
			userGroups:      []string{"osd-sre-admins", "system:authenticated", "system:authenticated:oauth"},
			operation:       v1beta1.Create,
			shouldBeAllowed: true,
		},
		{
			testID:          "sre-create-nonpriv-group",
			groupName:       "my-group",
			username:        "test-user",
			userGroups:      []string{"osd-sre-admins", "system:authenticated", "system:authenticated:oauth"},
			operation:       v1beta1.Create,
			shouldBeAllowed: true,
		},
		{
			testID:          "sre-admin-modify-dedicated-admins-group",
			groupName:       "dedicated-admins",
			username:        "osd-sre-admin",
			userGroups:      []string{"osd-sre-admins", "system:authenticated", "system:authenticated:oauth"},
			operation:       v1beta1.Update,
			shouldBeAllowed: true,
		},
		{
			testID:          "sre-admin-modify-impersonator-group",
			groupName:       "osd-impersonators",
			username:        "osd-sre-admin",
			userGroups:      []string{"osd-sre-admins", "system:authenticated", "system:authenticated:oauth"},
			operation:       v1beta1.Update,
			shouldBeAllowed: true,
		},
		{
			testID:          "sre-delete-priv-group",
			groupName:       "osd-sre-admins",
			username:        "test-user",
			userGroups:      []string{"osd-sre-admins", "system:authenticated", "system:authenticated:oauth"},
			operation:       v1beta1.Delete,
			shouldBeAllowed: true,
		},
		{
			testID:          "sre-delete-nonpriv-group",
			groupName:       "my-group",
			username:        "test-user",
			userGroups:      []string{"osd-sre-admins", "system:authenticated", "system:authenticated:oauth"},
			operation:       v1beta1.Delete,
			shouldBeAllowed: true,
		},
	}
	runGroupTests(t, tests)
}

func TestOSDDevAccess(t *testing.T) {
	tests := []groupTestsuites{
		{
			// Should not be able to edit their own group
			testID:          "osd-devaccess-update",
			groupName:       "osd-devaccess",
			username:        "cee-123",
			userGroups:      []string{"osd-devaccess", "system:authenticated", "system:authenticated:oauth"},
			operation:       v1beta1.Update,
			shouldBeAllowed: false,
		},
		{
			// Should not be able to delete their own group
			testID:          "osd-devaccess-delete",
			groupName:       "osd-devaccess",
			username:        "cee-123",
			userGroups:      []string{"osd-devaccess", "system:authenticated", "system:authenticated:oauth"},
			operation:       v1beta1.Delete,
			shouldBeAllowed: false,
		},
		{
			// Should be able to create a random group
			testID:          "osd-devaccess-create-nonpriv",
			groupName:       "my-group",
			username:        "cee-123",
			userGroups:      []string{"osd-devaccess", "system:authenticated", "system:authenticated:oauth"},
			operation:       v1beta1.Create,
			shouldBeAllowed: true,
		},
		{
			// Dedicated admin should not be able to edit osd-devaccess group
			testID:          "osd-dedi-admin-cant-edit-osd-devaccess",
			groupName:       "osd-devaccess",
			username:        "dedi-admin",
			userGroups:      []string{"dedicated-admins", "system:authenticated", "system:authenticated:oauth"},
			operation:       v1beta1.Update,
			shouldBeAllowed: false,
		},
	}
	runGroupTests(t, tests)
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
