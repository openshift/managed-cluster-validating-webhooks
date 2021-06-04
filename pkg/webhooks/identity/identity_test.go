package identity

import (
	"fmt"
	"testing"

	"github.com/openshift/managed-cluster-validating-webhooks/pkg/testutils"

	admissionv1 "k8s.io/api/admission/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
)

const testIdentityRaw string = `{
  "metadata": {
    "name": "%s",
    "uid": "%s",
    "creationTimestamp": "2020-05-10T07:51:00Z"
  },
	"users": null,
	"providerName": "%s"
}`

type identityTestSuites struct {
	testID          string
	identityName    string
	providerName    string
	username        string
	userGroups      []string
	oldObject       *runtime.RawExtension
	operation       admissionv1.Operation
	shouldBeAllowed bool
}

func runIdentityTests(t *testing.T, tests []identityTestSuites) {
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
		rawObjString := fmt.Sprintf(testIdentityRaw, test.identityName, test.testID, test.providerName)
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
			t.Fatalf("No tracking UID associated with the response: %+v", response)
		}

		if response.Allowed != test.shouldBeAllowed {
			t.Fatalf("Mismatch: %s (groups=%s) %s %s the %s identity. Test's expectation is that the user %s",
				test.username, test.userGroups,
				testutils.CanCanNot(response.Allowed), string(test.operation),
				test.providerName, testutils.CanCanNot(test.shouldBeAllowed))
		}
	}
}

func TestThing(t *testing.T) {
	tests := []identityTestSuites{
		{
			testID:          "kube-admin-test",
			identityName:    "github:test",
			providerName:    "github",
			username:        "kube:admin",
			userGroups:      []string{"kube:system", "system:authenticated", "system:authenticated:oauth"},
			operation:       admissionv1.Create,
			shouldBeAllowed: true,
		},
		{
			testID:          "backplane-cluster-admin-test",
			identityName:    "github:test",
			providerName:    "github",
			username:        "backplane-cluster-admin",
			userGroups:      []string{"system:authenticated", "system:authenticated:oauth"},
			operation:       admissionv1.Create,
			shouldBeAllowed: true,
		},
		{
			testID:          "dedi-admin-create-default",
			identityName:    fmt.Sprintf("%s:test", DefaultIdentityProvider),
			providerName:    DefaultIdentityProvider,
			username:        "ded-admin",
			userGroups:      []string{adminGroups[0], "system:authenticated", "system:authenticated:oauth"},
			operation:       admissionv1.Update,
			shouldBeAllowed: true,
		},
		{
			// no special privileges, only an authenticated user. This is allowed by RBAC
			testID:          "unpriv-create-test",
			identityName:    "test-provider:test",
			providerName:    "test-provider",
			username:        "unpriv-user",
			userGroups:      []string{"system:authenticated", "system:authenticated:oauth"},
			operation:       admissionv1.Create,
			shouldBeAllowed: true,
		},
		{
			// service account can update sre idp
			testID:          "sa-update-sre-provider",
			identityName:    fmt.Sprintf("%s:test", DefaultIdentityProvider),
			providerName:    DefaultIdentityProvider,
			username:        "system:serviceaccount:openshift-authentication:oauth-openshift",
			userGroups:      []string{"system:serviceaccount:openshift-authentication:oauth-openshift", "system:authenticated", "system:authenticated:oauth"},
			operation:       admissionv1.Update,
			shouldBeAllowed: true,
		},
		{
			// system:admin update sre idp
			testID:          "system:admin-update-sre-provider",
			identityName:    fmt.Sprintf("%s:test", DefaultIdentityProvider),
			providerName:    DefaultIdentityProvider,
			username:        "system:admin",
			userGroups:      []string{"system:authenticated", "system:authenticated:oauth"},
			operation:       admissionv1.Update,
			shouldBeAllowed: true,
		},
		{
			// backplane-cluster-admin update sre idp
			testID:          "system:admin-update-sre-provider",
			identityName:    fmt.Sprintf("%s:test", DefaultIdentityProvider),
			providerName:    DefaultIdentityProvider,
			username:        "backplane-cluster-admin",
			userGroups:      []string{"system:authenticated", "system:authenticated:oauth"},
			operation:       admissionv1.Update,
			shouldBeAllowed: true,
		},
		{
			// deny dedicated-admins to sre idp
			testID:          "deny-dedi-admin-update",
			identityName:    fmt.Sprintf("%s:test", DefaultIdentityProvider),
			providerName:    DefaultIdentityProvider,
			username:        "dedicaded-admin-user",
			userGroups:      []string{"dedicated-admins", "system:authenticated", "system:authenticated:oauth"},
			operation:       admissionv1.Update,
			shouldBeAllowed: false,
		},
		{
			// dedicated-admins can create a custom idp
			testID:          "allow-dedi-non-priv-idp",
			identityName:    "customer-idp:test",
			providerName:    "customer-idp",
			username:        "dedicaded-admin-user",
			userGroups:      []string{"dedicated-admins", "system:authenticated", "system:authenticated:oauth"},
			operation:       admissionv1.Create,
			shouldBeAllowed: true,
		},
	}
	runIdentityTests(t, tests)
}

func TestBadRequests(t *testing.T) {
	t.Skip()
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
