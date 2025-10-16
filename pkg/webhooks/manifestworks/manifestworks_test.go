package manifestworks

import (
	"testing"

	admissionv1 "k8s.io/api/admission/v1"
	authenticationv1 "k8s.io/api/authentication/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	admissionctl "sigs.k8s.io/controller-runtime/pkg/webhook/admission"
)

func TestManifestWorksAuthorized(t *testing.T) {
	tests := []struct {
		name            string
		username        string
		operation       admissionv1.Operation
		shouldBeAllowed bool
	}{
		{
			name:            "Klusterlet work SA can delete manifestworks",
			username:        "system:serviceaccount:open-cluster-management-agent:klusterlet-work-sa",
			operation:       admissionv1.Delete,
			shouldBeAllowed: true,
		},
		{
			name:            "Klusterlet SA can delete manifestworks",
			username:        "system:serviceaccount:open-cluster-management-agent:klusterlet",
			operation:       admissionv1.Delete,
			shouldBeAllowed: true,
		},
		{
			name:            "Hypershift operator can delete manifestworks",
			username:        "system:serviceaccount:hypershift:operator",
			operation:       admissionv1.Delete,
			shouldBeAllowed: true,
		},
		{
			name:            "Random user cannot delete manifestworks",
			username:        "unknown-user",
			operation:       admissionv1.Delete,
			shouldBeAllowed: false,
		},
		{
			name:            "Non-DELETE operation should be allowed",
			username:        "unknown-user",
			operation:       admissionv1.Create,
			shouldBeAllowed: true,
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
						Group: "work.open-cluster-management.io",
						Kind:  "ManifestWork",
					},
				},
			}

			response := webhook.Authorized(request)
			if response.Allowed != test.shouldBeAllowed {
				t.Errorf("Unexpected response for %s. Got %v, expected %v", test.name, response.Allowed, test.shouldBeAllowed)
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
	if uri != "/manifestworks-validation" {
		t.Errorf("Expected URI to be /manifestworks-validation, got %s", uri)
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
						Group: "work.open-cluster-management.io",
						Kind:  "ManifestWork",
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
						Group: "work.open-cluster-management.io",
						Kind:  "ManifestWork",
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
						Group: "work.open-cluster-management.io",
						Kind:  "Pod",
					},
				},
			},
			expected: false,
		},
		{
			name: "Invalid request with wrong group",
			request: admissionctl.Request{
				AdmissionRequest: admissionv1.AdmissionRequest{
					UserInfo: authenticationv1.UserInfo{
						Username: "test-user",
					},
					Kind: metav1.GroupVersionKind{
						Group: "apps",
						Kind:  "ManifestWork",
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
