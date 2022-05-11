package techpreviewnoupgrade_test

import (
	"fmt"
	"testing"

	"github.com/openshift/managed-cluster-validating-webhooks/pkg/testutils"
	"github.com/openshift/managed-cluster-validating-webhooks/pkg/webhooks/techpreviewnoupgrade"
	admissionv1 "k8s.io/api/admission/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
)

type techpreviewnoupgradeTestSuite struct {
	testName        string
	testID          string
	username        string
	userGroups      []string
	oldObject       *runtime.RawExtension
	operation       admissionv1.Operation
	featureSet      string
	shouldBeAllowed bool
}

const testObjectRaw string = `
{
	"apiVersion": "config.openshift.io/v1",
	"kind": "FeatureGate",
	"metadata": {
		"name": "test-subject",
		"uid": "1234",
		"creationTimestamp": "2020-05-10T07:51:00Z",
		"labels": {}
	},
	"spec": {
		"featureSet": "%s"
	}
}
`

func NewTestSuite(operation admissionv1.Operation, featureSet string) techpreviewnoupgradeTestSuite {
	return techpreviewnoupgradeTestSuite{
		testID:          "1234",
		operation:       operation,
		featureSet:      featureSet,
		shouldBeAllowed: true,
	}
}

func (s techpreviewnoupgradeTestSuite) ExpectNotAllowed() techpreviewnoupgradeTestSuite {
	s.shouldBeAllowed = false
	return s
}

func createOldObject(featureSet string) *runtime.RawExtension {
	return &runtime.RawExtension{
		Raw: []byte(createRawJSONString(featureSet)),
	}
}

func createRawJSONString(featureSet string) string {
	s := fmt.Sprintf(testObjectRaw, featureSet)

	return s
}

func Test_AllowAnythingOtherThanTechPreviewNoUpgrade(t *testing.T) {
	testSuites := []techpreviewnoupgradeTestSuite{
		NewTestSuite(admissionv1.Create, "AnythingOtherThanTechPreviewNoUpgrade"),
		NewTestSuite(admissionv1.Update, "AnythingOtherThanTechPreviewNoUpgrade"),
		NewTestSuite(admissionv1.Delete, "AnythingOtherThanTechPreviewNoUpgrade"),
	}

	runTests(t, testSuites)
}

func Test_DoNotAllowTechPreviewNoUpgrade(t *testing.T) {
	testSuites := []techpreviewnoupgradeTestSuite{
		NewTestSuite(admissionv1.Create, "TechPreviewNoUpgrade").ExpectNotAllowed(),
		NewTestSuite(admissionv1.Update, "TechPreviewNoUpgrade").ExpectNotAllowed(),
		NewTestSuite(admissionv1.Delete, "TechPreviewNoUpgrade").ExpectNotAllowed(),
	}

	runTests(t, testSuites)
}

func runTests(t *testing.T, tests []techpreviewnoupgradeTestSuite) {
	for _, test := range tests {
		obj := createOldObject(test.featureSet)
		hook := techpreviewnoupgrade.NewWebhook()
		httprequest, err := testutils.CreateHTTPRequest(hook.GetURI(), test.testID, metav1.GroupVersionKind{}, metav1.GroupVersionResource{}, test.operation, test.username, test.userGroups, obj, test.oldObject)

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
