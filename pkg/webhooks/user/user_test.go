package user

import (
	"fmt"
	"testing"

	"github.com/openshift/managed-cluster-validating-webhooks/pkg/testutils"
	"github.com/openshift/managed-cluster-validating-webhooks/pkg/userloader"

	"k8s.io/api/admission/v1beta1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
)

// We currently allow for a single identity in testing, but in the real world we could have more than one.
const testUserRaw string = `{
  "metadata": {
    "name": "%s",
    "uid": "%s",
    "creationTimestamp": "2020-05-10T07:51:00Z"
	},
	"identities": [
		"%s"
	],
	"users": null
}`

// rename it here so it makes sense in this context
const testRedHatIdentity string = redHatIDP + ":foo"
const testOtherIdentity string = "otherIDP:testing_string"

// testRedHatUsers is our list of allowed Red Hat users for our various groups.
// This serves as a test fixture.
var testRedHatUsers = map[string][]string{
	"osd-devaccess":         {"no-reply+devaccess1@redhat.com", "no-reply+devaccess2@redhat.com"},
	"osd-sre-admins":        {"no-reply+osdsreadmin1@redhat.com", "no-reply+osdsreadmin2@redhat.com"},
	"layered-cs-sre-admins": {"no-reply+lcssre+1@redhat.com", "no-reply@redhat.com"},
}

// testUserLoader implements Loader
type testUserLoader struct{}

// GetUsersFromGroups implements userloader.Loader and is very minimal so as to
// isolate this user package from whatever the userloader package is doing
func (l *testUserLoader) GetUsersFromGroups(groups ...string) (map[string][]string, error) {
	return testRedHatUsers, nil
}

func testUserLoaderBuilder() (userloader.Loader, error) { return &testUserLoader{}, nil }

// makeTestHook sets up our fake data with our fake testUserLoader's
// implementation of userloader.Loader
func makeTestHook(t *testing.T) *UserWebhook {
	userLoaderBuilder = testUserLoaderBuilder
	return NewWebhook()
}

type userTestSuites struct {
	testID          string
	subjectUserName string
	username        string
	userGroups      []string
	identity        string
	operation       v1beta1.Operation
	oldObject       *runtime.RawExtension
	shouldBeAllowed bool
}

func runUserTests(t *testing.T, tests []userTestSuites) {
	gvk := metav1.GroupVersionKind{
		Group:   "user.openshift.io",
		Version: "v1",
		Kind:    "User",
	}
	gvr := metav1.GroupVersionResource{
		Group:    "user.openshift.io",
		Version:  "v1",
		Resource: "users",
	}

	for _, test := range tests {
		rawObjString := fmt.Sprintf(testUserRaw, test.subjectUserName, test.testID, test.identity)

		obj := runtime.RawExtension{
			Raw: []byte(rawObjString),
		}
		hook := makeTestHook(t)
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
			t.Fatalf("No tracking UID associated with the response: %+v", response)
		}
		t.Logf("Response %+v", response)
		if response.Allowed != test.shouldBeAllowed {
			t.Fatalf("%s Mismatch: %s (groups=%s) %s %s the %s user. Test's expectation is that the user %s. Reason: %s",
				test.testID,
				test.username, test.userGroups,
				testutils.CanCanNot(response.Allowed), string(test.operation),
				test.subjectUserName, testutils.CanCanNot(test.shouldBeAllowed),
				response.Result.Reason)
		}
	}
}

func TestMissingUsers(t *testing.T) {
	orig := testRedHatUsers
	defer func() {
		testRedHatUsers = orig
	}()
	testRedHatUsers = map[string][]string{}
	tests := []userTestSuites{
		{
			// Can't create with SRE IDP because because there's no users there
			testID:          "missing-redhat-users",
			subjectUserName: "no-reply@redhat.com",
			username:        "system:serviceaccount:openshift-authentication:oauth-openshift",
			userGroups:      []string{"system:authenticated", "system:serviceaccounts:openshift-authentication"},
			operation:       v1beta1.Create,
			identity:        testRedHatIdentity,
			shouldBeAllowed: false,
		},
	}
	runUserTests(t, tests)
}

func TestAdminUsers(t *testing.T) {
	tests := []userTestSuites{
		{
			testID:          "kube-admin-can-do-it-all",
			subjectUserName: "some-user",
			username:        "kube:admin",
			userGroups:      []string{"system:authenticated"},
			operation:       v1beta1.Create,
			identity:        testRedHatIdentity,
			shouldBeAllowed: true,
		},
		{
			testID:          "priv-oauth-service-account",
			subjectUserName: "no-reply@redhat.com",
			username:        "system:serviceaccount:openshift-authentication:oauth-openshift",
			userGroups:      []string{"system:authenticated", "system:serviceaccounts:openshift-authentication"},
			operation:       v1beta1.Delete,
			identity:        testRedHatIdentity,
			shouldBeAllowed: true,
		},
		// SRE can create a User with the SRE idp because no-reply@redhat.com is a
		// member of layered-cs-sre-admins
		{
			testID:          "priv-sre-admin",
			subjectUserName: "no-reply@redhat.com",
			username:        "sre-admin",
			userGroups:      []string{"system:authenticated", "osd-sre-admins"},
			identity:        testRedHatIdentity,
			operation:       v1beta1.Create,
			shouldBeAllowed: true,
		},
		// Allowed because creator is a member of an admin group, and the subject is
		// using the sre IDP and a member of layered-cs-sre-admins
		{
			testID:          "priv-sre-cluster-admin",
			subjectUserName: "no-reply@redhat.com",
			username:        "sre-cluster-admin",
			userGroups:      []string{"system:authenticated", "osd-sre-cluster-admins"},
			identity:        testRedHatIdentity,
			operation:       v1beta1.Create,
			shouldBeAllowed: true,
		},
		{
			testID:          "priv-cluster-admin-cant-delete",
			subjectUserName: "no-reply@redhat.com",
			username:        "sre-cluster-admin",
			userGroups:      []string{"system:authenticated", "cluster-admins"},
			identity:        testRedHatIdentity,
			operation:       v1beta1.Update,
			shouldBeAllowed: false,
		},
		{
			testID:          "priv-cluster-admin-cant-create",
			subjectUserName: "no-reply@redhat.com",
			username:        "sre-cluster-admin",
			userGroups:      []string{"system:authenticated", "cluster-admins"},
			identity:        testRedHatIdentity,
			operation:       v1beta1.Create,
			shouldBeAllowed: false,
		},
		{
			testID:          "priv-cluster-admin-cant-edit",
			subjectUserName: "no-reply@redhat.com",
			username:        "sre-cluster-admin",
			userGroups:      []string{"system:authenticated", "cluster-admins"},
			identity:        testRedHatIdentity,
			operation:       v1beta1.Update,
			shouldBeAllowed: false,
		},
		{
			// SA is authorized, but the User is not a member of any redhatGroup and so can't use the redhat idp.
			testID:          "priv-oauth-disallow",
			subjectUserName: "no-reply+disallow@redhat.com",
			username:        "system:serviceaccount:openshift-authentication:oauth-openshift",
			userGroups:      []string{"system:authenticated", "system:serviceaccounts:openshift-authentication"},
			identity:        testRedHatIdentity,
			operation:       v1beta1.Create,
			shouldBeAllowed: false,
		},
		{
			// oauth service account should be able to create this user because the ID
			// is in one of the approved groups
			testID:          "priv-oauth-allowed",
			subjectUserName: "no-reply+devaccess1@redhat.com",
			username:        "system:serviceaccount:openshift-authentication:oauth-openshift",
			userGroups:      []string{"system:authenticated", "system:serviceaccounts:openshift-authentication"},
			identity:        testRedHatIdentity,
			operation:       v1beta1.Create,
			shouldBeAllowed: true,
		},
		{
			// Can create an account for this user because they're a redhat user not in a redhatGroup and thus using a non-sre idp.
			testID:          "oauth-create-non-sre-user",
			subjectUserName: "no-reply+developername@redhat.com",
			username:        "system:serviceaccount:openshift-authentication:oauth-openshift",
			userGroups:      []string{"system:authenticated", "system:serviceaccounts:openshift-authentication"},
			identity:        testOtherIdentity,
			operation:       v1beta1.Create,
			shouldBeAllowed: true,
		},
		{
			// protected users must use SRE IDP
			testID:          "protected-user-must-use-sre-idp",
			subjectUserName: "no-reply@redhat.com",
			username:        "system:serviceaccount:openshift-authentication:oauth-openshift",
			userGroups:      []string{"system:authenticated", "system:serviceaccounts:openshift-authentication"},
			identity:        testOtherIdentity,
			operation:       v1beta1.Create,
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
			identity:        testRedHatIdentity,
			operation:       v1beta1.Update,
			shouldBeAllowed: false,
		},
		// dedicated-admins can manage their own
		{
			testID:          "nonpriv-dedi-admin",
			subjectUserName: "no-reply@example.com",
			username:        "dedicated-admin",
			userGroups:      []string{"system:authenticated", "dedicated-admins"},
			identity:        testOtherIdentity,
			operation:       v1beta1.Delete,
			shouldBeAllowed: true,
		},
	}
	runUserTests(t, tests)
}

func TestRename(t *testing.T) {
	// dedicated-admin trying to rename example.com user to a privileged
	// redhat.com user should be denied, even if the redhat.com account is known
	// to be allowed in the cluster.
	oldRawStr := fmt.Sprintf(testUserRaw, "no-reply@example.com", "test-rename", testOtherIdentity)
	oldRawObj := runtime.RawExtension{
		Raw: []byte(oldRawStr),
	}

	tests := []userTestSuites{
		{
			testID:          "dedi-renames-to-priv",
			subjectUserName: "no-reply+devaccess2@redhat.com",
			username:        "dedicated-admin",
			userGroups:      []string{"system:authenticated", "dedicated-admins"},
			operation:       v1beta1.Update,
			identity:        testRedHatIdentity,
			oldObject:       &oldRawObj,
			shouldBeAllowed: false,
		},
		// privileged SRE cluster admin should be allowed to do the same, however (they can delete+create, too)
		{
			testID:          "dedi-renames-to-priv",
			subjectUserName: "no-reply+devaccess2@redhat.com",
			username:        "sre-cluster-admin",
			userGroups:      []string{"system:authenticated", "osd-sre-admins"},
			operation:       v1beta1.Update,
			identity:        testRedHatIdentity,
			oldObject:       &oldRawObj,
			shouldBeAllowed: true,
		},
	}
	runUserTests(t, tests)
}

func TestName(t *testing.T) {
	if makeTestHook(t).Name() == "" {
		t.Fatalf("Empty hook name")
	}
}

func TestRules(t *testing.T) {
	if len(NewWebhook().Rules()) == 0 {
		t.Log("No rules for this webhook?")
	}
}

func TestGetURI(t *testing.T) {
	if makeTestHook(t).GetURI()[0] != '/' {
		t.Fatalf("Hook URI does not begin with a /")
	}
}
