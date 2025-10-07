package hcpnamespace

import (
	"testing"

	admissionv1 "k8s.io/api/admission/v1"
	authenticationv1 "k8s.io/api/authentication/v1"
	admissionctl "sigs.k8s.io/controller-runtime/pkg/webhook/admission"
)

func TestAuthorized(t *testing.T) {
	tests := []struct {
		name          string
		username      string
		namespace     string
		operation     admissionv1.Operation
		shouldBeValid bool
	}{
		{
			name:          "Allowed user can delete protected namespace",
			username:      "system:admin",
			namespace:     "ocm-staging-test",
			operation:     admissionv1.Delete,
			shouldBeValid: true,
		},
		{
			name:          "Klusterlet SA can delete protected namespace",
			username:      "system:serviceaccount:open-cluster-management-agent:klusterlet-work-sa",
			namespace:     "klusterlet-test",
			operation:     admissionv1.Delete,
			shouldBeValid: true,
		},
		{
			name:          "Hypershift operator can delete protected namespace",
			username:      "system:serviceaccount:hypershift:operator",
			namespace:     "hs-mc-test",
			operation:     admissionv1.Delete,
			shouldBeValid: true,
		},
		{
			name:          "Random user cannot delete protected namespace",
			username:      "unknown-user",
			namespace:     "ocm-staging-test",
			operation:     admissionv1.Delete,
			shouldBeValid: false,
		},
		{
			name:          "Random user can delete unprotected namespace",
			username:      "unknown-user",
			namespace:     "test-namespace",
			operation:     admissionv1.Delete,
			shouldBeValid: true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			webhook := NewWebhook()
			request := admissionctl.Request{
				AdmissionRequest: admissionv1.AdmissionRequest{
					Name: test.namespace,
					UserInfo: authenticationv1.UserInfo{
						Username: test.username,
					},
					Operation: test.operation,
				},
			}

			response := webhook.Authorized(request)
			if response.Allowed != test.shouldBeValid {
				t.Errorf("Unexpected response. Got %v, expected %v", response.Allowed, test.shouldBeValid)
			}
		})
	}
}
