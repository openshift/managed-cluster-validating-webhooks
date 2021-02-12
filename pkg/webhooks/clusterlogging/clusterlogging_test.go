package clusterlogging_test

import (
	"fmt"
	"testing"

	"github.com/openshift/managed-cluster-validating-webhooks/pkg/testutils"
	"github.com/openshift/managed-cluster-validating-webhooks/pkg/webhooks/clusterlogging"

	"k8s.io/api/admission/v1beta1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
)

type clusterloggingTestSuite struct {
	testName        string
	testID          string
	username        string
	userGroups      []string
	oldObject       *runtime.RawExtension
	operation       v1beta1.Operation
	appMaxAge       string
	infraMaxAge     string
	auditMaxAge     string
	shouldBeAllowed bool
}

const testObjectRaw string = `
{
	"apiVersion": "logging.openshift.io/v1",
	"kind": "ClusterLogging",
	"metadata": {
		"name": "test-subject",
		"uid": "1234",
		"creationTimestamp": "2020-05-10T07:51:00Z",
		"labels": {}
	},
	"spec": {
		"managementState": "Managed" ,
		"logStore": {
			"type": "elasticsearch",
			"retentionPolicy": {
				"application": {
					"maxAge": "%s"
				},
				"infra": {
					"maxAge": "%s"
				},
				"audit": {
					"maxAge": "%s"
				}
			}
		}
	}
}`

func NewTestSuite(appMaxAge, infraMaxAge, auditMaxAge string) clusterloggingTestSuite {
	return clusterloggingTestSuite{
		testID:          "1234",
		operation:       v1beta1.Create,
		appMaxAge:       appMaxAge,
		infraMaxAge:     infraMaxAge,
		auditMaxAge:     auditMaxAge,
		shouldBeAllowed: true,
	}
}

func (s clusterloggingTestSuite) ExpectNotAllowed() clusterloggingTestSuite {
	s.shouldBeAllowed = false
	return s
}

func createOldObject(appMaxAge, infraMaxAge, auditMaxAge string) *runtime.RawExtension {
	return &runtime.RawExtension{
		Raw: []byte(createRawJSONString(appMaxAge, infraMaxAge, auditMaxAge)),
	}
}

func createRawJSONString(appMaxAge, infraMaxAge, auditMaxAge string) string {
	s := fmt.Sprintf(testObjectRaw, appMaxAge, infraMaxAge, auditMaxAge)
	return s
}

func Test_InvalidTimeUnit(t *testing.T) {
	testSuites := []clusterloggingTestSuite{
		NewTestSuite("7x", "0d", "0d").ExpectNotAllowed(),
		NewTestSuite("7D", "0d", "0d").ExpectNotAllowed(),
		NewTestSuite("7S", "0d", "0d").ExpectNotAllowed(),
		NewTestSuite("m", "0d", "0d").ExpectNotAllowed(),
	}

	runTests(t, testSuites)
}

func Test_RetentionPeriodNotAllowed(t *testing.T) {
	testSuites := []clusterloggingTestSuite{
		NewTestSuite("8d", "0d", "0d").ExpectNotAllowed(),
		NewTestSuite("169h", "0d", "0d").ExpectNotAllowed(),
		NewTestSuite("1h", "1m", "0d").ExpectNotAllowed(),
		NewTestSuite("1h", "1s", "0d").ExpectNotAllowed(),
		NewTestSuite("1h", "0s", "8d").ExpectNotAllowed(),
		NewTestSuite("7M", "0d", "0d").ExpectNotAllowed(),
	}

	runTests(t, testSuites)
}

func Test_RetentionPeriodAllowed(t *testing.T) {
	testSuites := []clusterloggingTestSuite{
		NewTestSuite("7d", "0d", "1d"),
		NewTestSuite("168h", "0d", "0d"),
		NewTestSuite("1h", "0m", "1d"),
		NewTestSuite("1h", "0s", "7d"),
		NewTestSuite("1h", "0s", "7m"),
		NewTestSuite("1h", "0s", "7s"),
	}

	runTests(t, testSuites)
}

func runTests(t *testing.T, tests []clusterloggingTestSuite) {
	for _, test := range tests {
		obj := createOldObject(test.appMaxAge, test.infraMaxAge, test.auditMaxAge)
		hook := clusterlogging.NewWebhook()
		httprequest, err := testutils.CreateHTTPRequest(hook.GetURI(),
			test.testID,
			metav1.GroupVersionKind{}, metav1.GroupVersionResource{}, test.operation, test.username, test.userGroups, obj, test.oldObject)
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
			t.Fatalf("Mismatch: %v %s %s. Test's expectation is that the user %s. Reason: %s, Message: %v",
				test,
				testutils.CanCanNot(response.Allowed), string(test.operation),
				testutils.CanCanNot(test.shouldBeAllowed), response.Result.Reason, response.Result.Message)
		}
	}
}
