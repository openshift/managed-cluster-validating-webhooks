package hostedcluster

import (
	"testing"

	admissionv1 "k8s.io/api/admission/v1"
	authenticationv1 "k8s.io/api/authentication/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	admissionctl "sigs.k8s.io/controller-runtime/pkg/webhook/admission"
)

func TestHostedClusterAuthorized(t *testing.T) {
	tests := []struct {
		name          string
		username      string
		operation     admissionv1.Operation
		shouldBeValid bool
	}{
		{
			name:          "Allowed service account can delete hostedcluster",
			username:      "system:serviceaccount:open-cluster-management-agent:klusterlet-work-sa",
			operation:     admissionv1.Delete,
			shouldBeValid: true,
		},
		{
			name:          "Random user cannot delete hostedcluster",
			username:      "unknown-user",
			operation:     admissionv1.Delete,
			shouldBeValid: false,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			webhook := NewWebhook()
			request := admissionctl.Request{
				AdmissionRequest: admissionv1.AdmissionRequest{
					UserInfo: authenticationv1.UserInfo{
						Username: test.username,
					},
					Operation: test.operation,
					Kind: metav1.GroupVersionKind{
						Group: "hypershift.openshift.io",
						Kind:  "HostedCluster",
					},
				},
			}

			response := webhook.Authorized(request)
			if response.Allowed != test.shouldBeValid {
				t.Errorf("Unexpected response for %s. Got %v, expected %v", test.name, response.Allowed, test.shouldBeValid)
			}
		})
	}
}
