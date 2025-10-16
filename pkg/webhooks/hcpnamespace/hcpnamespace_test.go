package hcpnamespace

import (
	"testing"

	admissionv1 "k8s.io/api/admission/v1"
	authenticationv1 "k8s.io/api/authentication/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	admissionctl "sigs.k8s.io/controller-runtime/pkg/webhook/admission"
)

func TestAuthorized(t *testing.T) {
	tests := []struct {
		name            string
		username        string
		namespace       string
		operation       admissionv1.Operation
		shouldBeAllowed bool
	}{
		{
			name:            "Allowed user can delete protected namespace",
			username:        "system:admin",
			namespace:       "ocm-staging-test",
			operation:       admissionv1.Delete,
			shouldBeAllowed: true,
		},
		{
			name:            "Klusterlet SA can delete protected namespace",
			username:        "system:serviceaccount:open-cluster-management-agent:klusterlet-work-sa",
			namespace:       "klusterlet-test",
			operation:       admissionv1.Delete,
			shouldBeAllowed: true,
		},
		{
			name:            "Hypershift operator can delete protected namespace",
			username:        "system:serviceaccount:hypershift:operator",
			namespace:       "hs-mc-test",
			operation:       admissionv1.Delete,
			shouldBeAllowed: true,
		},
		{
			name:            "Random user cannot delete protected namespace",
			username:        "unknown-user",
			namespace:       "ocm-staging-test",
			operation:       admissionv1.Delete,
			shouldBeAllowed: false,
		},
		{
			name:            "Random user can delete unprotected namespace",
			username:        "unknown-user",
			namespace:       "test-namespace",
			operation:       admissionv1.Delete,
			shouldBeAllowed: true,
		},
		{
			name:            "Non-DELETE operation should be allowed on protected namespace",
			username:        "unknown-user",
			namespace:       "ocm-production-test",
			operation:       admissionv1.Update,
			shouldBeAllowed: true,
		},
		{
			name:            "Klusterlet SA can delete protected namespace",
			username:        "system:serviceaccount:open-cluster-management-agent:klusterlet",
			namespace:       "ocm-integration-test",
			operation:       admissionv1.Delete,
			shouldBeAllowed: true,
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
			if response.Allowed != test.shouldBeAllowed {
				t.Errorf("Unexpected response. Got %v, expected %v", response.Allowed, test.shouldBeAllowed)
			}
		})
	}
}

func TestName(t *testing.T) {
	webhook := NewWebhook()
	if webhook.Name() != WebhookName {
		t.Errorf("Expected webhook name to be %s, got %s", WebhookName, webhook.Name())
	}
}

func TestGetURI(t *testing.T) {
	webhook := NewWebhook()
	uri := webhook.GetURI()
	if uri[0] != '/' {
		t.Errorf("Expected URI to start with '/', got %s", uri)
	}
	if uri != "/hcpnamespace-validation" {
		t.Errorf("Expected URI to be /hcpnamespace-validation, got %s", uri)
	}
}

func TestRules(t *testing.T) {
	webhook := NewWebhook()
	rules := webhook.Rules()
	if len(rules) == 0 {
		t.Fatal("Expected at least one rule")
	}
}

func TestDoc(t *testing.T) {
	webhook := NewWebhook()
	doc := webhook.Doc()
	if doc == "" {
		t.Error("Expected non-empty documentation string")
	}
}

func TestTimeoutSeconds(t *testing.T) {
	webhook := NewWebhook()
	timeout := webhook.TimeoutSeconds()
	if timeout != 2 {
		t.Errorf("Expected timeout to be 2, got %d", timeout)
	}
}

func TestValidate(t *testing.T) {
	tests := []struct {
		name     string
		request  admissionctl.Request
		expected bool
	}{
		{
			name: "Valid request",
			request: admissionctl.Request{
				AdmissionRequest: admissionv1.AdmissionRequest{
					UserInfo: authenticationv1.UserInfo{
						Username: "test-user",
					},
					Kind: metav1.GroupVersionKind{
						Kind: "Namespace",
					},
				},
			},
			expected: true,
		},
		{
			name: "Invalid request without username",
			request: admissionctl.Request{
				AdmissionRequest: admissionv1.AdmissionRequest{
					UserInfo: authenticationv1.UserInfo{
						Username: "",
					},
					Kind: metav1.GroupVersionKind{
						Kind: "Namespace",
					},
				},
			},
			expected: false,
		},
		{
			name: "Invalid request with wrong kind",
			request: admissionctl.Request{
				AdmissionRequest: admissionv1.AdmissionRequest{
					UserInfo: authenticationv1.UserInfo{
						Username: "test-user",
					},
					Kind: metav1.GroupVersionKind{
						Kind: "Pod",
					},
				},
			},
			expected: false,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			webhook := NewWebhook()
			result := webhook.Validate(test.request)
			if result != test.expected {
				t.Errorf("Expected %v, got %v", test.expected, result)
			}
		})
	}
}
