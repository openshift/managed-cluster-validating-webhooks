package hiveownership

import (
	"encoding/json"
	"fmt"
	"reflect"
	"testing"

	"github.com/openshift/managed-cluster-validating-webhooks/pkg/testutils"

	"k8s.io/api/admission/v1beta1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
)

type hiveOwnershipTestSuites struct {
	testName        string
	testID          string
	username        string
	userGroups      []string
	oldObject       *runtime.RawExtension
	operation       v1beta1.Operation
	labels          map[string]string
	shouldBeAllowed bool
}

const testObjectRaw string = `{
	"metadata": {
	  "name": "%s",
	  "uid": "%s",
	  "creationTimestamp": "2020-05-10T07:51:00Z",
	  "labels": %s
	},
	"users": null
  }`

// labelsMapToString is a helper to turn a map into a JSON fragment to be
// inserted into the testNamespaceRaw const. See createRawJSONString.
func labelsMapToString(labels map[string]string) string {
	ret, _ := json.Marshal(labels)
	return string(ret)
}

func createRawJSONString(name, uid string, labels map[string]string) string {
	return fmt.Sprintf(testObjectRaw, name, uid, labelsMapToString(labels))
}
func createOldObject(name, uid string, labels map[string]string) *runtime.RawExtension {
	return &runtime.RawExtension{
		Raw: []byte(createRawJSONString(name, uid, labels)),
	}
}

func runTests(t *testing.T, tests []hiveOwnershipTestSuites) {
	gvk := metav1.GroupVersionKind{
		Group:   "quota.openshift.io",
		Version: "v1",
		Kind:    "ClusterResourceQuota",
	}
	gvr := metav1.GroupVersionResource{
		Group:    "quota.openshift.io",
		Version:  "v1",
		Resource: "clusterresourcequotas",
	}

	for _, test := range tests {
		obj := createOldObject(test.testName, test.testID, test.labels)
		hook := NewWebhook()
		httprequest, err := testutils.CreateHTTPRequest(hook.GetURI(),
			test.testID,
			gvk, gvr, test.operation, test.username, test.userGroups, obj, test.oldObject)
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
			t.Fatalf("Mismatch: %s (groups=%s) %s %s. Test's expectation is that the user %s",
				test.username, test.userGroups,
				testutils.CanCanNot(response.Allowed), string(test.operation),
				testutils.CanCanNot(test.shouldBeAllowed))
		}
	}
}

func TestThing(t *testing.T) {
	tests := []hiveOwnershipTestSuites{
		{
			testID:          "kube-admin-test",
			username:        "kube:admin",
			userGroups:      []string{"kube:system", "system:authenticated", "system:authenticated:oauth"},
			operation:       v1beta1.Create,
			shouldBeAllowed: true,
		},
		{
			testID:          "kube-admin-test",
			username:        "backplane-cluster-admin",
			userGroups:      []string{"system:authenticated", "system:authenticated:oauth"},
			operation:       v1beta1.Create,
			shouldBeAllowed: true,
		},
		{
			testID:          "sre-test",
			username:        "sre-foo@redhat.com",
			userGroups:      []string{adminGroups[0], "system:authenticated", "system:authenticated:oauth"},
			operation:       v1beta1.Update,
			shouldBeAllowed: true,
		},
		{
			// dedicated-admin users. This should be blocked as making changes as CU on clusterresourcequota which are managed are prohibited.
			testID:          "dedicated-admin-test",
			username:        "bob@foo.com",
			userGroups:      []string{"dedicated-admins", "system:authenticated", "system:authenticated:oauth"},
			operation:       v1beta1.Update,
			labels:          map[string]string{"hive.openshift.io/managed": "true"},
			shouldBeAllowed: false,
		},
		{
			// no special privileges, only an authenticated user. This should be blocked as making changes on clusterresourcequota which are managed are prohibited.
			testID:          "unpriv-update-test",
			username:        "unpriv-user",
			userGroups:      []string{"system:authenticated", "system:authenticated:oauth"},
			operation:       v1beta1.Update,
			labels:          map[string]string{"hive.openshift.io/managed": "true"},
			shouldBeAllowed: false,
		},
	}
	runTests(t, tests)
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

func TestObjectSelector(t *testing.T) {
	obj := &metav1.LabelSelector{
		MatchLabels: map[string]string{
			"hive.openshift.io/managed": "true",
		},
	}

	if !reflect.DeepEqual(NewWebhook().ObjectSelector(), obj) {
		t.Fatalf("hive managed resources label name is not correct.")
	}
}
