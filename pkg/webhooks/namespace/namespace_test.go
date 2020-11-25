package namespace

import (
	"fmt"
	"testing"

	"github.com/openshift/managed-cluster-validating-webhooks/pkg/testutils"

	"k8s.io/api/admission/v1beta1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
)

// Raw JSON for a Namespace, used as runtime.RawExtension, and represented here
// because sometimes we need it for OldObject as well as Object.
const testNamespaceRaw string = `{
  "metadata": {
    "name": "%s",
    "uid": "%s",
    "creationTimestamp": "2020-05-10T07:51:00Z"
  },
  "users": null
}`

type namespaceTestSuites struct {
	testID          string
	targetNamespace string
	username        string
	userGroups      []string
	oldObject       *runtime.RawExtension
	operation       v1beta1.Operation
	shouldBeAllowed bool
}

func runNamespaceTests(t *testing.T, tests []namespaceTestSuites) {
	gvk := metav1.GroupVersionKind{
		Group:   "",
		Version: "v1",
		Kind:    "Namespace",
	}
	gvr := metav1.GroupVersionResource{
		Group:    "",
		Version:  "v1",
		Resource: "namespaces",
	}

	for _, test := range tests {
		rawObjString := fmt.Sprintf(testNamespaceRaw, test.targetNamespace, test.testID)
		obj := runtime.RawExtension{
			Raw: []byte(rawObjString),
		}
		hook := NewWebhook()
		httprequest, err := testutils.CreateHTTPRequest(hook.GetURI(),
			test.testID,
			gvk, gvr, test.operation, test.username, test.userGroups, &obj, test.oldObject)
		if err != nil {
			t.Fatalf("Expected no error, got %s", err.Error())
		}

		response, err := testutils.SendHTTPRequest(httprequest, hook)
		if err != nil {
			t.Fatalf("Expected no error, got %s", err.Error())
		}
		if response.UID == "" {
			t.Fatalf("No tracking UID associated with the response.")
		}

		if response.Allowed != test.shouldBeAllowed {
			t.Fatalf("Mismatch: %s (groups=%s) %s %s the %s namespace. Test's expectation is that the user %s", test.username, test.userGroups, testutils.CanCanNot(response.Allowed), string(test.operation), test.targetNamespace, testutils.CanCanNot(test.shouldBeAllowed))
		}
	}
}

// TestDedicatedAdmins will test everything a dedicated admin can and can not do
func TestDedicatedAdmins(t *testing.T) {
	tests := []namespaceTestSuites{
		{
			// Should be able to create an unprivileged namespace
			testID:          "dedi-create-nonpriv-ns",
			targetNamespace: "my-ns",
			username:        "test-user",
			userGroups:      []string{"dedicated-admins", "system:authenticated", "system:authenticated:oauth"},
			operation:       v1beta1.Create,
			shouldBeAllowed: true,
		},
		{
			// Should not be able to delete a privileged namespace
			testID:          "dedi-delete-priv-ns",
			targetNamespace: "kube-system",
			username:        "test-user",
			userGroups:      []string{"dedicated-admins", "system:authenticated", "system:authenticated:oauth"},
			operation:       v1beta1.Delete,
			shouldBeAllowed: false,
		},
		{
			// Should not be able to create a privileged namespace
			testID:          "dedi-create-priv-ns",
			targetNamespace: "openshift-test-namespace",
			username:        "test-user",
			userGroups:      []string{"dedicated-admins", "system:authenticated", "system:authenticated:oauth"},
			operation:       v1beta1.Create,
			shouldBeAllowed: false,
		},
		{
			// Should not be able to update layered product ecnamespa
			testID:          "dedi-update-layered-prod-ns",
			targetNamespace: "redhat-layered-product-ns",
			username:        "test-user",
			userGroups:      []string{"dedicated-admins", "system:authenticated", "system:authenticated:oauth"},
			operation:       v1beta1.Update,
			shouldBeAllowed: false,
		},
		{
			// Should be able to delete a general namespace
			testID:          "dedi-delete-random-ns",
			targetNamespace: "my-ns",
			username:        "test-user",
			userGroups:      []string{"dedicated-admins", "system:authenticated", "system:authenticated:oauth"},
			operation:       v1beta1.Delete,
			shouldBeAllowed: true,
		},
		{
			// Should be able to updte a general namespace
			testID:          "dedi-update-random-ns",
			targetNamespace: "my-ns",
			username:        "test-user",
			userGroups:      []string{"dedicated-admins", "system:authenticated", "system:authenticated:oauth"},
			operation:       v1beta1.Update,
			shouldBeAllowed: true,
		},
		{
			// Should not be able to create an privileged namespace
			testID:          "dedi-create-com-ns",
			targetNamespace: "com",
			username:        "test-user",
			userGroups:      []string{"dedicated-admins", "system:authenticated", "system:authenticated:oauth"},
			operation:       v1beta1.Create,
			shouldBeAllowed: false,
		},
		{
			// Should not be able to create an privileged namespace
			testID:          "dedi-create-io-ns",
			targetNamespace: "io",
			username:        "test-user",
			userGroups:      []string{"dedicated-admins", "system:authenticated", "system:authenticated:oauth"},
			operation:       v1beta1.Create,
			shouldBeAllowed: false,
		},
		{
			// Should not be able to create an privileged namespace
			testID:          "dedi-create-in-ns",
			targetNamespace: "in",
			username:        "test-user",
			userGroups:      []string{"dedicated-admins", "system:authenticated", "system:authenticated:oauth"},
			operation:       v1beta1.Create,
			shouldBeAllowed: false,
		},
	}
	runNamespaceTests(t, tests)
}

// TestNormalUser will test everything a normal user can and can not do
func TestNormalUser(t *testing.T) {
	tests := []namespaceTestSuites{
		{
			// Should be able to create an unprivileged namespace
			testID:          "nonpriv-create-nonpriv-ns",
			targetNamespace: "my-ns",
			username:        "test-user",
			userGroups:      []string{"system:authenticated", "system:authenticated:oauth"},
			operation:       v1beta1.Create,
			shouldBeAllowed: true,
		},
		{
			// Should be able to create an unprivileged namespace
			testID:          "nonpriv-update-nonpriv-ns",
			targetNamespace: "my-ns",
			username:        "test-user",
			userGroups:      []string{"system:authenticated", "system:authenticated:oauth"},
			operation:       v1beta1.Update,
			shouldBeAllowed: true,
		},
		{
			// Should be able to create an unprivileged namespace
			testID:          "nonpriv-delete-nonpriv-ns",
			targetNamespace: "my-ns",
			username:        "test-user",
			userGroups:      []string{"system:authenticated", "system:authenticated:oauth"},
			operation:       v1beta1.Delete,
			shouldBeAllowed: true,
		},
		{
			// Shouldn't be able to create a privileged namespace
			testID:          "nonpriv-create-priv-ns",
			targetNamespace: "kube-system",
			username:        "test-user",
			userGroups:      []string{"system:authenticated", "system:authenticated:oauth"},
			operation:       v1beta1.Create,
			shouldBeAllowed: false,
		},
		{
			// Shouldn't be able to delete a privileged namespace
			testID:          "nonpriv-delete-priv-ns",
			targetNamespace: "kube-system",
			username:        "test-user",
			userGroups:      []string{"system:authenticated", "system:authenticated:oauth"},
			operation:       v1beta1.Delete,
			shouldBeAllowed: false,
		},
		{
			// Should not be able to create an privileged namespace
			testID:          "nonpriv-create-com-ns",
			targetNamespace: "com",
			username:        "test-user",
			userGroups:      []string{"system:authenticated", "system:authenticated:oauth"},
			operation:       v1beta1.Create,
			shouldBeAllowed: false,
		},
		{
			// Should not be able to create an privileged namespace
			testID:          "nonpriv-create-io-ns",
			targetNamespace: "io",
			username:        "test-user",
			userGroups:      []string{"system:authenticated", "system:authenticated:oauth"},
			operation:       v1beta1.Create,
			shouldBeAllowed: false,
		},
		{
			// Should not be able to create an privileged namespace
			testID:          "nonpriv-create-in-ns",
			targetNamespace: "in",
			username:        "test-user",
			userGroups:      []string{"system:authenticated", "system:authenticated:oauth"},
			operation:       v1beta1.Create,
			shouldBeAllowed: false,
		},
	}
	runNamespaceTests(t, tests)
}

// TestLayeredProducts
func TestLayeredProducts(t *testing.T) {
	tests := []namespaceTestSuites{
		{
			// Layered admins can manipulate in the lp ns, but not privileged ones
			// note: ^redhat.* is a privileged ns, but lp admins have an exception in
			// it (but not other privileged ns)
			testID:          "lp-create-layered-ns",
			targetNamespace: "redhat-layered-product",
			username:        "test-user",
			userGroups:      []string{"layered-sre-cluster-admins", "system:authenticated", "system:authenticated:oauth"},
			operation:       v1beta1.Create,
			shouldBeAllowed: true,
		},
		{
			// Layered admins can't create a privileged ns
			testID:          "lp-create-priv-ns",
			targetNamespace: "openshift-test",
			username:        "test-user",
			userGroups:      []string{"layered-sre-cluster-admins", "system:authenticated", "system:authenticated:oauth"},
			operation:       v1beta1.Create,
			shouldBeAllowed: false,
		},
		{
			// Layered admins can make an unprivileged ns
			testID:          "lp-create-priv-ns",
			targetNamespace: "my-ns",
			username:        "test-user",
			userGroups:      []string{"layered-sre-cluster-admins", "system:authenticated", "system:authenticated:oauth"},
			operation:       v1beta1.Create,
			shouldBeAllowed: true,
		},
		{
			// Layered admins can not make an privileged ns
			testID:          "lp-create-com-ns",
			targetNamespace: "com",
			username:        "test-user",
			userGroups:      []string{"layered-sre-cluster-admins", "system:authenticated", "system:authenticated:oauth"},
			operation:       v1beta1.Create,
			shouldBeAllowed: false,
		},
		{
			// Layered admins can not make an privileged ns
			testID:          "lp-create-io-ns",
			targetNamespace: "io",
			username:        "test-user",
			userGroups:      []string{"layered-sre-cluster-admins", "system:authenticated", "system:authenticated:oauth"},
			operation:       v1beta1.Create,
			shouldBeAllowed: false,
		},
		{
			// Layered admins can not make an privileged ns
			testID:          "lp-create-in-ns",
			targetNamespace: "in",
			username:        "test-user",
			userGroups:      []string{"layered-sre-cluster-admins", "system:authenticated", "system:authenticated:oauth"},
			operation:       v1beta1.Create,
			shouldBeAllowed: false,
		},
		{
			// RHOAM admins can manipulate in the rhoam ns, but not privileged ones
			// note: ^redhat.* is a privileged ns, but rhoam admins have an exception in
			// it (but not other privileged ns)
			testID:          "rhoam-create-layered-ns",
			targetNamespace: "redhat-layered-product",
			username:        "test-user",
			userGroups:      []string{"rhoam-sre-cluster-admins", "system:authenticated", "system:authenticated:oauth"},
			operation:       v1beta1.Create,
			shouldBeAllowed: true,
		},
		{
			// RHOAM admins can't create a privileged ns
			testID:          "rhoam-create-priv-ns",
			targetNamespace: "openshift-test",
			username:        "test-user",
			userGroups:      []string{"rhoam-sre-cluster-admins", "system:authenticated", "system:authenticated:oauth"},
			operation:       v1beta1.Create,
			shouldBeAllowed: false,
		},
		{
			// RHOAM admins can make an unprivileged ns
			testID:          "rhoam-create-priv-ns",
			targetNamespace: "my-ns",
			username:        "test-user",
			userGroups:      []string{"rhoam-sre-cluster-admins", "system:authenticated", "system:authenticated:oauth"},
			operation:       v1beta1.Create,
			shouldBeAllowed: true,
		},
		{
			// RHOAM admins can not make an privileged ns
			testID:          "rhoam-create-com-ns",
			targetNamespace: "com",
			username:        "test-user",
			userGroups:      []string{"rhoam-sre-cluster-admins", "system:authenticated", "system:authenticated:oauth"},
			operation:       v1beta1.Create,
			shouldBeAllowed: false,
		},
		{
			// RHOAM admins can not make an privileged ns
			testID:          "rhoam-create-io-ns",
			targetNamespace: "io",
			username:        "test-user",
			userGroups:      []string{"rhoam-sre-cluster-admins", "system:authenticated", "system:authenticated:oauth"},
			operation:       v1beta1.Create,
			shouldBeAllowed: false,
		},
		{
			// RHOAM admins can not make an privileged ns
			testID:          "rhoam-create-in-ns",
			targetNamespace: "in",
			username:        "test-user",
			userGroups:      []string{"rhoam-sre-cluster-admins", "system:authenticated", "system:authenticated:oauth"},
			operation:       v1beta1.Create,
			shouldBeAllowed: false,
		},
	}
	runNamespaceTests(t, tests)
}

// TestServiceAccounts
func TestServiceAccounts(t *testing.T) {
	tests := []namespaceTestSuites{
		{
			// serviceaccounts in privileged namespaces can interact with privileged namespaces
			testID:          "sa-create-priv-ns",
			targetNamespace: "openshift-test-ns",
			username:        "system:serviceaccounts:openshift-test-ns",
			userGroups:      []string{"system:serviceaccounts:openshift-test-ns", "system:authenticated", "system:authenticated:oauth"},
			operation:       v1beta1.Create,
			shouldBeAllowed: true,
		},
		{
			// serviceaccounts in privileged namespaces can interact with customer namespaces
			// this is counterintuitive because they shouldn't. Recall that RBAC would
			// deny any disallowed access, so the "true" here is deferring to
			// Kubernetes RBAC
			testID:          "sa-create-priv-ns",
			targetNamespace: "customer-ns",
			username:        "system:serviceaccounts:openshift-test-ns",
			userGroups:      []string{"system:serviceaccounts:openshift-test-ns", "system:authenticated", "system:authenticated:oauth"},
			operation:       v1beta1.Delete,
			shouldBeAllowed: true,
		},
	}
	runNamespaceTests(t, tests)
}

// TestAdminUser
func TestAdminUser(t *testing.T) {
	tests := []namespaceTestSuites{
		{
			// admin users gonna admin
			testID:          "admin-test",
			targetNamespace: "kube-system",
			username:        "kube:admin",
			userGroups:      []string{"kube:system", "system:authenticated", "system:authenticated:oauth"},
			operation:       v1beta1.Update,
			shouldBeAllowed: true,
		}, {

			// admin users gonna admin
			testID:          "sre-test",
			targetNamespace: "kube-system",
			username:        "lisa",
			userGroups:      []string{"osd-sre-admins", "system:authenticated", "system:authenticated:oauth"},
			operation:       v1beta1.Update,
			shouldBeAllowed: true,
		},
		{
			// Admins should be able to create a privileged namespace
			testID:          "admin-com-ns-test",
			targetNamespace: "com",
			username:        "kube:admin",
			userGroups:      []string{"osd-sre-admins", "system:authenticated", "system:authenticated:oauth"},
			operation:       v1beta1.Create,
			shouldBeAllowed: true,
		},
		{
			// Admins should be able to create a privileged namespace
			testID:          "admin-com-io-test",
			targetNamespace: "io",
			username:        "kube:admin",
			userGroups:      []string{"osd-sre-admins", "system:authenticated", "system:authenticated:oauth"},
			operation:       v1beta1.Create,
			shouldBeAllowed: true,
		},
		{
			// Admins should be able to create a privileged namespace
			testID:          "admin-in-ns-test",
			targetNamespace: "in",
			username:        "kube:admin",
			userGroups:      []string{"osd-sre-admins", "system:authenticated", "system:authenticated:oauth"},
			operation:       v1beta1.Create,
			shouldBeAllowed: true,
		},
	}
	runNamespaceTests(t, tests)
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
