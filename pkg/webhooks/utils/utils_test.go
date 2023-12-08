package utils

import (
	"testing"

	admissionv1 "k8s.io/api/admission/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	admissionctl "sigs.k8s.io/controller-runtime/pkg/webhook/admission"
)

func TestRequestMatchesGroupKind(t *testing.T) {
	tests := []struct {
		name     string
		req      admissionctl.Request
		kind     string
		group    string
		expected bool
	}{
		{
			name: "matches",
			req: admissionctl.Request{
				AdmissionRequest: admissionv1.AdmissionRequest{
					Kind: metav1.GroupVersionKind{
						Kind:  "testkind",
						Group: "testgroup",
					},
				},
			},
			kind:     "testkind",
			group:    "testgroup",
			expected: true,
		},
		{
			name: "doesn't match",
			req: admissionctl.Request{
				AdmissionRequest: admissionv1.AdmissionRequest{
					Kind: metav1.GroupVersionKind{
						Kind:  "testkind",
						Group: "testgroup",
					},
				},
			},
			kind:     "otherkind",
			group:    "testgroup",
			expected: false,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			actual := RequestMatchesGroupKind(test.req, test.kind, test.group)
			if test.expected != actual {
				t.Errorf("expected: %v, got %v", test.expected, actual)
			}
		})
	}
}
