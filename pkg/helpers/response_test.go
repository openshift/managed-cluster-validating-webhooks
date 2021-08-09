package helpers

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"testing"

	admissionapi "k8s.io/api/admission/v1"
	"k8s.io/apimachinery/pkg/types"
	admissionctl "sigs.k8s.io/controller-runtime/pkg/webhook/admission"
)

func makeBuffer() *bytes.Buffer {
	return new(bytes.Buffer)
}

func formatOutput(s string) string {
	return fmt.Sprintf("%s\n", s)
}

func makeResponseObj(uid string, allowed bool, e error) *admissionctl.Response {
	if e == nil {
		return &admissionctl.Response{
			AdmissionResponse: admissionapi.AdmissionResponse{
				UID:     types.UID(uid),
				Allowed: allowed,
			},
		}
	} else {
		n := admissionctl.Errored(http.StatusBadRequest, e)
		return &n
	}
}

func TestBadResponse(t *testing.T) {
	t.Skip("Not quite sure how to test json encoding error")
}

func TestResponse(t *testing.T) {
	tests := []struct {
		allowed        bool
		uid            string
		e              error
		status         int32
		expectedResult string
	}{
		{
			allowed: true,
			uid:     "test-uid",
			e:       nil,
			status:  http.StatusOK,
			// the writer sends a newline
			expectedResult: formatOutput(`{"kind":"AdmissionReview","apiVersion":"admission.k8s.io/v1","response":{"uid":"test-uid","allowed":true,"auditAnnotations":{"owner":"srep-managed-webhook"}}}`),
		},
		{
			allowed:        false,
			uid:            "test-fail-with-error",
			e:              fmt.Errorf("request body is empty"),
			status:         http.StatusBadRequest,
			expectedResult: formatOutput(`{"kind":"AdmissionReview","apiVersion":"admission.k8s.io/v1","response":{"uid":"","allowed":false,"status":{"metadata":{},"message":"request body is empty","code":400},"auditAnnotations":{"owner":"srep-managed-webhook"}}}`),
		},
	}
	for _, test := range tests {
		buf := makeBuffer()
		respObj := makeResponseObj(test.uid, test.allowed, test.e)
		SendResponse(buf, *respObj)
		if buf.String() != test.expectedResult {
			t.Fatalf("Expected to have `%s` but got `%s`", test.expectedResult, buf.String())
		}
		decodedResult := &admissionapi.AdmissionReview{}
		err := json.Unmarshal([]byte(buf.String()), decodedResult)
		if err != nil {
			t.Errorf("Couldn't unmarshal the JSON blob: %s", err.Error())
		}
		t.Logf("Response body = %s", buf.String())

		if test.e != nil {
			if test.status == http.StatusOK {
				t.Errorf("It is weird to have an error result and a 200 OK. Check test's status field.")
			}
			// check for the Response.Result
			if decodedResult.Response.Result == nil {
				t.Fatalf("Error responses need a Response.Result, and this one didn't have one")
			} else {
				if decodedResult.Response.Result.Code != test.status {
					t.Fatalf("Expected HTTP status code of the Result to be %d, but got %d instead", test.status, decodedResult.Response.Result.Code)
				}
			}
		}

	}

}
