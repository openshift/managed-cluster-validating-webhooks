package osd

import (
	"fmt"
	"testing"

	"github.com/openshift/managed-cluster-validating-webhooks/pkg/testutils"

	admissionv1 "k8s.io/api/admission/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
)

const (
	privilegedNamespace string = "openshift-backplane"
)

const (
	objectStringResource string = `{
		"metadata": {
			"kind": "%s",
			"name": "%s",
			"namespace": "%s",
			"uid": "%s",
			"creationTimestamp": "2020-05-10T07:51:00Z"
		},
		"users": null
	}`
	objectStringSubResource string = `{
		"metadata": {
			"kind": "%s",
			"name": "%s",
			"uid": "%s",
			"requestSubResource": "%s",
			"creationTimestamp": "2020-05-10T07:51:00Z"
		},
		"users": null
	}`
)

type regularuserTests struct {
	testID            string
	targetSubResource string
	targetKind        string
	targetResource    string
	targetVersion     string
	targetGroup       string
	targetName        string
	targetNamespace   string
	username          string
	userGroups        []string
	oldObject         *runtime.RawExtension
	operation         admissionv1.Operation
	skip              bool // skip this particular test?
	skipReason        string
	shouldBeAllowed   bool
}

func runRegularuserTests(t *testing.T, tests []regularuserTests) {

	for _, test := range tests {
		if test.skip {
			t.Logf("SKIP: Skipping test %s: %s", test.testID, test.skipReason)
			continue
		}
		gvk := metav1.GroupVersionKind{
			Group:   test.targetGroup,
			Version: test.targetVersion,
			Kind:    test.targetKind,
		}
		gvr := metav1.GroupVersionResource{
			Group:    test.targetGroup,
			Version:  test.targetVersion,
			Resource: test.targetResource,
		}
		hook := NewWebhook()
		var rawObjString string
		if test.targetName == "" {
			test.targetName = test.testID
		}
		// https://kubernetes.io/docs/reference/access-authn-authz/extensible-admission-controllers/#webhook-request-and-response
		if test.targetSubResource != "" {
			rawObjString = fmt.Sprintf(objectStringSubResource, test.targetKind, test.targetName, test.testID, test.targetSubResource)
		} else {
			rawObjString = fmt.Sprintf(objectStringResource, test.targetKind, test.targetName, test.targetNamespace, test.testID)
		}
		obj := runtime.RawExtension{
			Raw: []byte(rawObjString),
		}

		httprequest, err := testutils.CreateHTTPRequest(hook.GetURI(),
			test.testID,
			gvk, gvr, test.operation, test.username, test.userGroups, test.targetNamespace, &obj, test.oldObject)
		if err != nil {
			t.Fatalf("%s Expected no error, got %s", test.testID, err.Error())
		}

		response, err := testutils.SendHTTPRequest(httprequest, hook)
		if err != nil {
			t.Fatalf("%s Expected no error, got %s", test.testID, err.Error())
		}

		if response.Allowed != test.shouldBeAllowed {
			t.Fatalf("%s Mismatch: %s (groups=%s) %s %s the %s %s. Test's expectation is that the user %s. Reason %s", test.testID, test.username, test.userGroups, testutils.CanCanNot(response.Allowed), string(test.operation), test.targetKind, test.targetName, testutils.CanCanNot(test.shouldBeAllowed), response.Result.Reason)
		}
		if response.UID == "" {
			t.Fatalf("%s No tracking UID associated with the response.", test.testID)
		}
	}
	t.Skip()
}

// TestInvalidRequest a hook that isn't handled by this hook
func TestInvalidRequest(t *testing.T) {
	tests := []regularuserTests{
		{
			testID:          "node-unpriv-user",
			targetResource:  "nodes",
			targetKind:      "Node",
			targetVersion:   "v1",
			targetGroup:     "",
			username:        "kube:system",
			userGroups:      []string{"system:authenticated", "system:authenticated:oauth"},
			operation:       admissionv1.Delete,
			skip:            true,
			skipReason:      "Skipping invalid request because at present, Validate will allow it since it isn't written to check ought but the username",
			shouldBeAllowed: false,
		},
		{
			testID:          "node-no-username",
			targetResource:  "nodes",
			targetKind:      "Node",
			targetVersion:   "v1",
			targetGroup:     "",
			username:        "",
			userGroups:      []string{""},
			operation:       admissionv1.Delete,
			shouldBeAllowed: false,
		},
	}
	runRegularuserTests(t, tests)
}

// These resources follow a similar pattern with a specific Resource is
// specified, and then some subresources
func TestNodes(t *testing.T) {
	tests := []regularuserTests{
		{
			testID:            "sa-node-status-update",
			targetResource:    "nodes",
			targetSubResource: "status",
			targetKind:        "Node",
			targetVersion:     "v1",
			targetGroup:       "",
			username:          "system:node:ip-10-0-0-1.test",
			userGroups:        []string{"system:nodes", "system:authenticated"},
			operation:         admissionv1.Update,
			shouldBeAllowed:   true,
		},
		{
			testID:          "node-unauth-user",
			targetResource:  "nodes",
			targetKind:      "Node",
			targetVersion:   "v1",
			targetGroup:     "",
			username:        "system:unauthenticated",
			userGroups:      []string{"system:unauthenticated"},
			operation:       admissionv1.Delete,
			shouldBeAllowed: false,
		},
		{
			testID:          "node-unpriv-user",
			targetResource:  "nodes",
			targetKind:      "Node",
			targetVersion:   "v1",
			targetGroup:     "",
			username:        "my-name",
			userGroups:      []string{"system:authenticated", "system:authenticated:oauth"},
			operation:       admissionv1.Delete,
			shouldBeAllowed: false,
		},
		{
			testID:          "node-priv-group",
			targetResource:  "nodes",
			targetKind:      "Node",
			targetVersion:   "v1",
			targetGroup:     "",
			username:        "my-name",
			userGroups:      []string{"system:serviceaccounts:openshift-backplane-srep", "system:authenticated", "system:authenticated:oauth"},
			operation:       admissionv1.Delete,
			shouldBeAllowed: true,
		},
		{
			testID:          "node-priv-backplane-cluster-admin",
			targetResource:  "nodes",
			targetKind:      "Node",
			targetVersion:   "v1",
			targetGroup:     "",
			username:        "backplane-cluster-admin",
			userGroups:      []string{"system:authenticated", "system:authenticated:oauth"},
			operation:       admissionv1.Delete,
			shouldBeAllowed: true,
		},
		{
			testID:          "node-admin-user",
			targetResource:  "nodes",
			targetKind:      "Node",
			targetVersion:   "v1",
			targetGroup:     "",
			username:        "kube:admin",
			userGroups:      []string{"system:authenticated", "system:authenticated:oauth"},
			operation:       admissionv1.Delete,
			shouldBeAllowed: true,
		},
		{
			testID:          "node-unauth-user-update",
			targetResource:  "nodes",
			targetKind:      "Node",
			targetVersion:   "v1",
			targetGroup:     "",
			username:        "system:unauthenticated",
			userGroups:      []string{"system:unauthenticated"},
			operation:       admissionv1.Update,
			shouldBeAllowed: false,
		},
		{
			testID:          "node-unpriv-user-update",
			targetResource:  "nodes",
			targetKind:      "Node",
			targetVersion:   "v1",
			targetGroup:     "",
			username:        "my-name",
			userGroups:      []string{"system:authenticated", "system:authenticated:oauth"},
			operation:       admissionv1.Update,
			shouldBeAllowed: false,
		},
		{
			testID:          "node-priv-group-update",
			targetResource:  "nodes",
			targetKind:      "Node",
			targetVersion:   "v1",
			targetGroup:     "",
			username:        "my-name",
			userGroups:      []string{"system:serviceaccounts:openshift-backplane-srep", "system:authenticated", "system:authenticated:oauth"},
			operation:       admissionv1.Update,
			shouldBeAllowed: true,
		},
		{
			testID:          "node-priv-backplane-cluster-admin-update",
			targetResource:  "nodes",
			targetKind:      "Node",
			targetVersion:   "v1",
			targetGroup:     "",
			username:        "backplane-cluster-admin",
			userGroups:      []string{"system:authenticated", "system:authenticated:oauth"},
			operation:       admissionv1.Update,
			shouldBeAllowed: true,
		},
		{
			testID:          "node-admin-user-update",
			targetResource:  "nodes",
			targetKind:      "Node",
			targetVersion:   "v1",
			targetGroup:     "",
			username:        "kube:admin",
			userGroups:      []string{"system:authenticated", "system:authenticated:oauth"},
			operation:       admissionv1.Update,
			shouldBeAllowed: true,
		},
	}
	runRegularuserTests(t, tests)
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
