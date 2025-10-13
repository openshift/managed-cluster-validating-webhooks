package namespace

import (
	"encoding/json"
	"fmt"
	"testing"

	"github.com/openshift/managed-cluster-validating-webhooks/pkg/testutils"

	admissionv1 "k8s.io/api/admission/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
)

const (
	privilegedNamespace string = "openshift-backplane"
)

// Raw JSON for a Namespace, used as runtime.RawExtension, and represented here
// because sometimes we need it for OldObject as well as Object.
const testNamespaceRaw string = `{
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
	return fmt.Sprintf(testNamespaceRaw, name, uid, labelsMapToString(labels))
}
func createOldObject(name, uid string, labels map[string]string) *runtime.RawExtension {
	return &runtime.RawExtension{
		Raw: []byte(createRawJSONString(name, uid, labels)),
	}
}

type namespaceTestSuites struct {
	testID          string
	targetNamespace string
	username        string
	userGroups      []string
	oldObject       *runtime.RawExtension
	operation       admissionv1.Operation
	labels          map[string]string
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
		obj := createOldObject(test.targetNamespace, test.testID, test.labels)
		hook := NewWebhook()
		httprequest, err := testutils.CreateHTTPRequest(hook.GetURI(),
			test.testID,
			gvk, gvr, test.operation, test.username, test.userGroups, "", obj, test.oldObject)
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
			t.Fatalf("Mismatch: %s (groups=%s) %s %s the %s namespace. Test's expectation is that the user %s. Reason: %+v", test.username, test.userGroups, testutils.CanCanNot(response.Allowed), string(test.operation), test.targetNamespace, testutils.CanCanNot(test.shouldBeAllowed), response)
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
			operation:       admissionv1.Create,
			shouldBeAllowed: true,
		},
		{
			// Should not be able to delete a privileged namespace
			testID:          "dedi-delete-priv-ns",
			targetNamespace: privilegedNamespace,
			username:        "test-user",
			userGroups:      []string{"dedicated-admins", "system:authenticated", "system:authenticated:oauth"},
			operation:       admissionv1.Delete,
			shouldBeAllowed: false,
		},
		{
			// Should not be able to create a privileged namespace
			testID:          "dedi-create-priv-ns",
			targetNamespace: privilegedNamespace,
			username:        "test-user",
			userGroups:      []string{"dedicated-admins", "system:authenticated", "system:authenticated:oauth"},
			operation:       admissionv1.Create,
			shouldBeAllowed: false,
		},
		{
			// Should be able to create a namespace starting with 'openshift-' but not listed in the PrivilegedNamespaces list
			testID:          "dedi-create-nonpriv-openshift-ns",
			targetNamespace: "openshift-unpriv-ns",
			username:        "test-user",
			userGroups:      []string{"dedicated-admins", "system:authenticated", "system:authenticated:oauth"},
			operation:       admissionv1.Create,
			shouldBeAllowed: true,
		},
		{
			// Should not be able to update layered product namespace
			testID:          "dedi-update-layered-prod-ns",
			targetNamespace: "redhat-layered-product-ns",
			username:        "test-user",
			userGroups:      []string{"dedicated-admins", "system:authenticated", "system:authenticated:oauth"},
			operation:       admissionv1.Update,
			shouldBeAllowed: false,
		},
		{
			// Should not be able to kube-system
			testID:          "dedi-update-kube-system-ns",
			targetNamespace: "kube-system",
			username:        "test-user",
			userGroups:      []string{"dedicated-admins", "system:authenticated", "system:authenticated:oauth"},
			operation:       admissionv1.Update,
			shouldBeAllowed: false,
		},
		{
			// Should not be able to default
			testID:          "dedi-update-default-ns",
			targetNamespace: "default",
			username:        "test-user",
			userGroups:      []string{"dedicated-admins", "system:authenticated", "system:authenticated:oauth"},
			operation:       admissionv1.Update,
			shouldBeAllowed: false,
		},
		{
			// Should be able to delete a general namespace
			testID:          "dedi-delete-random-ns",
			targetNamespace: "my-ns",
			username:        "test-user",
			userGroups:      []string{"dedicated-admins", "system:authenticated", "system:authenticated:oauth"},
			operation:       admissionv1.Delete,
			shouldBeAllowed: true,
		},
		{
			// Should be able to updte a general namespace
			testID:          "dedi-update-random-ns",
			targetNamespace: "my-ns",
			username:        "test-user",
			userGroups:      []string{"dedicated-admins", "system:authenticated", "system:authenticated:oauth"},
			operation:       admissionv1.Update,
			shouldBeAllowed: true,
		},
		{
			// Should not be able to create an privileged namespace
			testID:          "dedi-create-com-ns",
			targetNamespace: "com",
			username:        "test-user",
			userGroups:      []string{"dedicated-admins", "system:authenticated", "system:authenticated:oauth"},
			operation:       admissionv1.Create,
			shouldBeAllowed: false,
		},
		{
			// Should not be able to create an privileged namespace
			testID:          "dedi-create-io-ns",
			targetNamespace: "io",
			username:        "test-user",
			userGroups:      []string{"dedicated-admins", "system:authenticated", "system:authenticated:oauth"},
			operation:       admissionv1.Create,
			shouldBeAllowed: false,
		},
		{
			// Should not be able to create an privileged namespace
			testID:          "dedi-create-in-ns",
			targetNamespace: "in",
			username:        "test-user",
			userGroups:      []string{"dedicated-admins", "system:authenticated", "system:authenticated:oauth"},
			operation:       admissionv1.Create,
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
			operation:       admissionv1.Create,
			shouldBeAllowed: true,
		},
		{
			// Should be able to create an unprivileged namespace
			testID:          "nonpriv-update-nonpriv-ns",
			targetNamespace: "my-ns",
			username:        "test-user",
			userGroups:      []string{"system:authenticated", "system:authenticated:oauth"},
			operation:       admissionv1.Update,
			shouldBeAllowed: true,
		},
		{
			// Should be able to create an unprivileged namespace
			testID:          "nonpriv-delete-nonpriv-ns",
			targetNamespace: "my-ns",
			username:        "test-user",
			userGroups:      []string{"system:authenticated", "system:authenticated:oauth"},
			operation:       admissionv1.Delete,
			shouldBeAllowed: true,
		},
		{
			// Shouldn't be able to create a privileged namespace
			testID:          "nonpriv-create-priv-ns",
			targetNamespace: privilegedNamespace,
			username:        "test-user",
			userGroups:      []string{"system:authenticated", "system:authenticated:oauth"},
			operation:       admissionv1.Create,
			shouldBeAllowed: false,
		},
		{
			// Shouldn't be able to delete a privileged namespace
			testID:          "nonpriv-delete-priv-ns",
			targetNamespace: privilegedNamespace,
			username:        "test-user",
			userGroups:      []string{"system:authenticated", "system:authenticated:oauth"},
			operation:       admissionv1.Delete,
			shouldBeAllowed: false,
		},
		{
			// Should not be able to create an privileged namespace
			testID:          "nonpriv-create-com-ns",
			targetNamespace: "com",
			username:        "test-user",
			userGroups:      []string{"system:authenticated", "system:authenticated:oauth"},
			operation:       admissionv1.Create,
			shouldBeAllowed: false,
		},
		{
			// Should not be able to create an privileged namespace
			testID:          "nonpriv-create-io-ns",
			targetNamespace: "io",
			username:        "test-user",
			userGroups:      []string{"system:authenticated", "system:authenticated:oauth"},
			operation:       admissionv1.Create,
			shouldBeAllowed: false,
		},
		{
			// Should not be able to create an privileged namespace
			testID:          "nonpriv-create-in-ns",
			targetNamespace: "in",
			username:        "test-user",
			userGroups:      []string{"system:authenticated", "system:authenticated:oauth"},
			operation:       admissionv1.Create,
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
			// note: ^redhat-.* is a privileged ns, but lp admins have an exception in
			// it (but not other privileged ns)
			testID:          "lp-create-layered-ns",
			targetNamespace: "redhat-layered-product",
			username:        "test-user",
			userGroups:      []string{"layered-sre-cluster-admins", "system:authenticated", "system:authenticated:oauth"},
			operation:       admissionv1.Create,
			shouldBeAllowed: true,
		},
		{
			// Layered admins can create a ns that starts with 'openshift-' and is not listed in the managed namespaces list
			testID:          "lp-create-unpriv-ns",
			targetNamespace: "openshift-unpriv-ns",
			username:        "test-user",
			userGroups:      []string{"layered-sre-cluster-admins", "system:authenticated", "system:authenticated:oauth"},
			operation:       admissionv1.Create,
			shouldBeAllowed: true,
		},
		{
			// Layered admins can not create a ns listed in the managed namespaces list
			testID:          "lp-create-priv-ns",
			targetNamespace: privilegedNamespace,
			username:        "test-user",
			userGroups:      []string{"layered-sre-cluster-admins", "system:authenticated", "system:authenticated:oauth"},
			operation:       admissionv1.Create,
			shouldBeAllowed: false,
		},
		{
			// Layered admins can make an unprivileged ns
			testID:          "lp-create-priv-ns",
			targetNamespace: "my-ns",
			username:        "test-user",
			userGroups:      []string{"layered-sre-cluster-admins", "system:authenticated", "system:authenticated:oauth"},
			operation:       admissionv1.Create,
			shouldBeAllowed: true,
		},
		{
			// Layered admins can not make an privileged ns
			testID:          "lp-create-com-ns",
			targetNamespace: "com",
			username:        "test-user",
			userGroups:      []string{"layered-sre-cluster-admins", "system:authenticated", "system:authenticated:oauth"},
			operation:       admissionv1.Create,
			shouldBeAllowed: false,
		},
		{
			// Layered admins can not make an privileged ns
			testID:          "lp-create-io-ns",
			targetNamespace: "io",
			username:        "test-user",
			userGroups:      []string{"layered-sre-cluster-admins", "system:authenticated", "system:authenticated:oauth"},
			operation:       admissionv1.Create,
			shouldBeAllowed: false,
		},
		{
			// Layered admins can not make an privileged ns
			testID:          "lp-create-in-ns",
			targetNamespace: "in",
			username:        "test-user",
			userGroups:      []string{"layered-sre-cluster-admins", "system:authenticated", "system:authenticated:oauth"},
			operation:       admissionv1.Create,
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
			targetNamespace: "openshift-ingress",
			username:        "system:serviceaccounts:openshift-test-ns",
			userGroups:      []string{"system:serviceaccounts:openshift-test-ns", "system:authenticated", "system:authenticated:oauth"},
			operation:       admissionv1.Create,
			shouldBeAllowed: true,
		},
		{
			// serviceaccounts in privileged namespaces can interact with privileged namespaces
			testID:          "sa-create-priv-ns",
			targetNamespace: "openshift-ingress",
			username:        "system:serviceaccounts:openshift-test-ns",
			userGroups:      []string{"system:serviceaccounts:openshift-test-ns", "system:authenticated", "system:authenticated:oauth"},
			operation:       admissionv1.Delete,
			shouldBeAllowed: true,
		},
		{
			// serviceaccounts in privileged namespaces can interact with privileged namespaces
			testID:          "sa-create-priv-ns",
			targetNamespace: "openshift-ingress",
			username:        "system:serviceaccounts:openshift-test-ns",
			userGroups:      []string{"system:serviceaccounts:openshift-test-ns", "system:authenticated", "system:authenticated:oauth"},
			operation:       admissionv1.Update,
			shouldBeAllowed: true,
		},
		{
			// serviceaccounts in privileged namespaces can interact with privileged namespaces
			testID:          "sa-create-priv-ns",
			targetNamespace: "default",
			username:        "system:serviceaccounts:openshift-test-ns",
			userGroups:      []string{"system:serviceaccounts:openshift-test-ns", "system:authenticated", "system:authenticated:oauth"},
			operation:       admissionv1.Create,
			shouldBeAllowed: true,
		},
		{
			// serviceaccounts in privileged namespaces can interact with privileged namespaces
			testID:          "sa-create-priv-ns",
			targetNamespace: "default",
			username:        "system:serviceaccounts:openshift-test-ns",
			userGroups:      []string{"system:serviceaccounts:openshift-test-ns", "system:authenticated", "system:authenticated:oauth"},
			operation:       admissionv1.Delete,
			shouldBeAllowed: true,
		},
		{
			// serviceaccounts in privileged namespaces can interact with privileged namespaces
			testID:          "sa-create-priv-ns",
			targetNamespace: "default",
			username:        "system:serviceaccounts:openshift-test-ns",
			userGroups:      []string{"system:serviceaccounts:openshift-test-ns", "system:authenticated", "system:authenticated:oauth"},
			operation:       admissionv1.Update,
			shouldBeAllowed: true,
		},
		{
			// serviceaccounts in privileged namespaces can interact with privileged namespaces
			testID:          "sa-create-priv-ns",
			targetNamespace: "kube-system",
			username:        "system:serviceaccounts:openshift-test-ns",
			userGroups:      []string{"system:serviceaccounts:openshift-test-ns", "system:authenticated", "system:authenticated:oauth"},
			operation:       admissionv1.Create,
			shouldBeAllowed: true,
		},
		{
			// serviceaccounts in privileged namespaces can interact with privileged namespaces
			testID:          "sa-create-priv-ns",
			targetNamespace: "kube-system",
			username:        "system:serviceaccounts:openshift-test-ns",
			userGroups:      []string{"system:serviceaccounts:openshift-test-ns", "system:authenticated", "system:authenticated:oauth"},
			operation:       admissionv1.Delete,
			shouldBeAllowed: true,
		},
		{
			// serviceaccounts in privileged namespaces can interact with privileged namespaces
			testID:          "sa-create-priv-ns",
			targetNamespace: "kube-system",
			username:        "system:serviceaccounts:openshift-test-ns",
			userGroups:      []string{"system:serviceaccounts:openshift-test-ns", "system:authenticated", "system:authenticated:oauth"},
			operation:       admissionv1.Update,
			shouldBeAllowed: true,
		},
		{
			// serviceaccounts in privileged namespaces can interact with privileged namespaces
			testID:          "sa-create-priv-ns",
			targetNamespace: "redhat-user",
			username:        "system:serviceaccounts:openshift-test-ns",
			userGroups:      []string{"system:serviceaccounts:openshift-test-ns", "system:authenticated", "system:authenticated:oauth"},
			operation:       admissionv1.Create,
			shouldBeAllowed: true,
		},
		{
			// serviceaccounts in privileged namespaces can interact with privileged namespaces
			testID:          "sa-create-priv-ns",
			targetNamespace: "redhat-user",
			username:        "system:serviceaccounts:openshift-test-ns",
			userGroups:      []string{"system:serviceaccounts:openshift-test-ns", "system:authenticated", "system:authenticated:oauth"},
			operation:       admissionv1.Delete,
			shouldBeAllowed: true,
		},
		{
			// serviceaccounts in privileged namespaces can interact with privileged namespaces
			testID:          "sa-create-priv-ns",
			targetNamespace: "redhat-user",
			username:        "system:serviceaccounts:openshift-test-ns",
			userGroups:      []string{"system:serviceaccounts:openshift-test-ns", "system:authenticated", "system:authenticated:oauth"},
			operation:       admissionv1.Update,
			shouldBeAllowed: true,
		},
		{
			// serviceaccounts in privileged namespaces can interact with privileged namespaces
			testID:          "sa-create-priv-ns",
			targetNamespace: "osde2e-xyz43",
			username:        "system:serviceaccounts:openshift-test-ns",
			userGroups:      []string{"system:serviceaccounts:openshift-test-ns", "system:authenticated", "system:authenticated:oauth"},
			operation:       admissionv1.Create,
			shouldBeAllowed: true,
		},
		{
			// serviceaccounts in privileged namespaces can interact with privileged namespaces
			testID:          "sa-create-priv-ns",
			targetNamespace: "osde2e-xyz43",
			username:        "system:serviceaccounts:openshift-test-ns",
			userGroups:      []string{"system:serviceaccounts:openshift-test-ns", "system:authenticated", "system:authenticated:oauth"},
			operation:       admissionv1.Delete,
			shouldBeAllowed: true,
		},
		{
			// serviceaccounts in privileged namespaces can interact with privileged namespaces
			testID:          "sa-create-priv-ns",
			targetNamespace: "osde2e-xyz43",
			username:        "system:serviceaccounts:openshift-test-ns",
			userGroups:      []string{"system:serviceaccounts:openshift-test-ns", "system:authenticated", "system:authenticated:oauth"},
			operation:       admissionv1.Update,
			shouldBeAllowed: true,
		},
		{
			// serviceaccounts in privileged namespaces can interact with privileged namespaces
			testID:          "sa-create-priv-ns",
			targetNamespace: privilegedNamespace,
			username:        "system:serviceaccounts:openshift-test-ns",
			userGroups:      []string{"system:serviceaccounts:openshift-test-ns", "system:authenticated", "system:authenticated:oauth"},
			operation:       admissionv1.Create,
			shouldBeAllowed: true,
		},
		{
			// serviceaccounts in privileged namespaces can interact with privileged namespaces
			testID:          "sa-create-priv-ns",
			targetNamespace: privilegedNamespace,
			username:        "system:serviceaccounts:openshift-test-ns",
			userGroups:      []string{"system:serviceaccounts:openshift-test-ns", "system:authenticated", "system:authenticated:oauth"},
			operation:       admissionv1.Delete,
			shouldBeAllowed: true,
		},
		{
			// serviceaccounts in privileged namespaces can interact with privileged namespaces
			testID:          "sa-create-priv-ns",
			targetNamespace: privilegedNamespace,
			username:        "system:serviceaccounts:openshift-test-ns",
			userGroups:      []string{"system:serviceaccounts:openshift-test-ns", "system:authenticated", "system:authenticated:oauth"},
			operation:       admissionv1.Update,
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
			operation:       admissionv1.Delete,
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
			operation:       admissionv1.Update,
			shouldBeAllowed: true,
		},
		{
			// osde2e-related things can create a ns for must-gather
			testID:          "sa-create-ns-for-must-gather",
			targetNamespace: "openshift-must-gather-qbjtf",
			username:        "system:serviceaccount:osde2e-9a47q:cluster-admin", // This does *NOT* mean cluster-admin as in that ClusterRole
			userGroups:      []string{"system:serviceaccounts:osde2e-9a47q", "system:authenticated", "system:authenticated:oauth"},
			operation:       admissionv1.Create,
			shouldBeAllowed: true,
		},
		{
			// serviceaccounts in unprivileged namespaces can not interact with privileged namespaces
			testID:          "sa-create-priv-ns",
			targetNamespace: privilegedNamespace,
			username:        "system:serviceaccounts:unpriv-ns",
			userGroups:      []string{"system:serviceaccounts:unpriv-ns", "system:authenticated", "system:authenticated:oauth"},
			operation:       admissionv1.Create,
			shouldBeAllowed: false,
		},
		{
			// serviceaccounts in unprivileged namespaces can not interact with privileged namespaces
			testID:          "sa-create-priv-ns",
			targetNamespace: privilegedNamespace,
			username:        "system:serviceaccounts:unpriv-ns",
			userGroups:      []string{"system:serviceaccounts:unpriv-ns", "system:authenticated", "system:authenticated:oauth"},
			operation:       admissionv1.Delete,
			shouldBeAllowed: false,
		},
		{
			// serviceaccounts in unprivileged namespaces can not interact with privileged namespaces
			testID:          "sa-create-priv-ns",
			targetNamespace: privilegedNamespace,
			username:        "system:serviceaccounts:unpriv-ns",
			userGroups:      []string{"system:serviceaccounts:unpriv-ns", "system:authenticated", "system:authenticated:oauth"},
			operation:       admissionv1.Update,
			shouldBeAllowed: false,
		},
		{
			// serviceaccounts in unprivileged namespaces can not interact with privileged namespaces
			testID:          "sa-create-priv-ns",
			targetNamespace: "kube-system",
			username:        "system:serviceaccounts:unpriv-ns",
			userGroups:      []string{"system:serviceaccounts:unpriv-ns", "system:authenticated", "system:authenticated:oauth"},
			operation:       admissionv1.Create,
			shouldBeAllowed: false,
		},
		{
			// serviceaccounts in unprivileged namespaces can not interact with privileged namespaces
			testID:          "sa-create-priv-ns",
			targetNamespace: "kube-system",
			username:        "system:serviceaccounts:unpriv-ns",
			userGroups:      []string{"system:serviceaccounts:unpriv-ns", "system:authenticated", "system:authenticated:oauth"},
			operation:       admissionv1.Delete,
			shouldBeAllowed: false,
		},
		{
			// serviceaccounts in unprivileged namespaces can not interact with privileged namespaces
			testID:          "sa-create-priv-ns",
			targetNamespace: "kube-system",
			username:        "system:serviceaccounts:unpriv-ns",
			userGroups:      []string{"system:serviceaccounts:unpriv-ns", "system:authenticated", "system:authenticated:oauth"},
			operation:       admissionv1.Update,
			shouldBeAllowed: false,
		},
		{
			// serviceaccounts in unprivileged namespaces can not interact with privileged namespaces
			testID:          "sa-create-priv-ns",
			targetNamespace: "openshift-ingress",
			username:        "system:serviceaccounts:unpriv-ns",
			userGroups:      []string{"system:serviceaccounts:unpriv-ns", "system:authenticated", "system:authenticated:oauth"},
			operation:       admissionv1.Create,
			shouldBeAllowed: false,
		},
		{
			// serviceaccounts in unprivileged namespaces can not interact with privileged namespaces
			testID:          "sa-create-priv-ns",
			targetNamespace: "openshift-ingress",
			username:        "system:serviceaccounts:unpriv-ns",
			userGroups:      []string{"system:serviceaccounts:unpriv-ns", "system:authenticated", "system:authenticated:oauth"},
			operation:       admissionv1.Delete,
			shouldBeAllowed: false,
		},
		{
			// serviceaccounts in unprivileged namespaces can not interact with privileged namespaces
			testID:          "sa-create-priv-ns",
			targetNamespace: "openshift-ingress",
			username:        "system:serviceaccounts:unpriv-ns",
			userGroups:      []string{"system:serviceaccounts:unpriv-ns", "system:authenticated", "system:authenticated:oauth"},
			operation:       admissionv1.Update,
			shouldBeAllowed: false,
		},
		{
			// serviceaccounts in unprivileged namespaces can not interact with privileged namespaces
			testID:          "sa-create-priv-ns",
			targetNamespace: "default",
			username:        "system:serviceaccounts:unpriv-ns",
			userGroups:      []string{"system:serviceaccounts:unpriv-ns", "system:authenticated", "system:authenticated:oauth"},
			operation:       admissionv1.Create,
			shouldBeAllowed: false,
		},
		{
			// serviceaccounts in unprivileged namespaces can not interact with privileged namespaces
			testID:          "sa-create-priv-ns",
			targetNamespace: "default",
			username:        "system:serviceaccounts:unpriv-ns",
			userGroups:      []string{"system:serviceaccounts:unpriv-ns", "system:authenticated", "system:authenticated:oauth"},
			operation:       admissionv1.Delete,
			shouldBeAllowed: false,
		},
		{
			// serviceaccounts in unprivileged namespaces can not interact with privileged namespaces
			testID:          "sa-create-priv-ns",
			targetNamespace: "default",
			username:        "system:serviceaccounts:unpriv-ns",
			userGroups:      []string{"system:serviceaccounts:unpriv-ns", "system:authenticated", "system:authenticated:oauth"},
			operation:       admissionv1.Update,
			shouldBeAllowed: false,
		},
		{
			// serviceaccounts in unprivileged namespaces can not interact with privileged namespaces
			testID:          "sa-create-priv-ns",
			targetNamespace: "redhat-user",
			username:        "system:serviceaccounts:unpriv-ns",
			userGroups:      []string{"system:serviceaccounts:unpriv-ns", "system:authenticated", "system:authenticated:oauth"},
			operation:       admissionv1.Create,
			shouldBeAllowed: false,
		},
		{
			// serviceaccounts in unprivileged namespaces can not interact with privileged namespaces
			testID:          "sa-create-priv-ns",
			targetNamespace: "redhat-user",
			username:        "system:serviceaccounts:unpriv-ns",
			userGroups:      []string{"system:serviceaccounts:unpriv-ns", "system:authenticated", "system:authenticated:oauth"},
			operation:       admissionv1.Delete,
			shouldBeAllowed: false,
		},
		{
			// serviceaccounts in unprivileged namespaces can not interact with privileged namespaces
			testID:          "sa-create-priv-ns",
			targetNamespace: "redhat-user",
			username:        "system:serviceaccounts:unpriv-ns",
			userGroups:      []string{"system:serviceaccounts:unpriv-ns", "system:authenticated", "system:authenticated:oauth"},
			operation:       admissionv1.Update,
			shouldBeAllowed: false,
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
			targetNamespace: privilegedNamespace,
			username:        "kube:admin",
			userGroups:      []string{"kube:system", "system:authenticated", "system:authenticated:oauth"},
			operation:       admissionv1.Update,
			shouldBeAllowed: true,
		},
		{
			// admin users gonna admin
			testID:          "sre-test",
			targetNamespace: privilegedNamespace,
			username:        "lisa",
			userGroups:      []string{"system:serviceaccounts:openshift-backplane-srep", "system:authenticated", "system:authenticated:oauth"},
			operation:       admissionv1.Update,
			shouldBeAllowed: true,
		},
		{
			// cluster-admin users cannot update privilegedNamespaces
			testID:          "cluster-admin-test",
			targetNamespace: privilegedNamespace,
			username:        "lisa",
			userGroups:      []string{"cluster-admins", "system:authenticated", "system:authenticated:oauth"},
			operation:       admissionv1.Update,
			shouldBeAllowed: false,
		},
		{
			// admin users gonna admin
			testID:          "backplane-cluster-admin-test",
			targetNamespace: privilegedNamespace,
			username:        "backplane-cluster-admin",
			userGroups:      []string{"system:authenticated", "system:authenticated:oauth"},
			operation:       admissionv1.Update,
			shouldBeAllowed: true,
		},
		{
			// Admins should be able to create a privileged namespace
			testID:          "admin-com-ns-test",
			targetNamespace: "com",
			username:        "backplane-cluster-admin",
			userGroups:      []string{"system:authenticated", "system:authenticated:oauth"},
			operation:       admissionv1.Create,
			shouldBeAllowed: true,
		},
		{
			// Admins should be able to create a privileged namespace
			testID:          "admin-com-ns-test",
			targetNamespace: "com",
			username:        "lisa",
			userGroups:      []string{"system:serviceaccounts:openshift-backplane-srep", "system:authenticated", "system:authenticated:oauth"},
			operation:       admissionv1.Create,
			shouldBeAllowed: true,
		},
		{
			// Admins should be able to create a privileged namespace
			testID:          "admin-com-io-test",
			targetNamespace: "io",
			username:        "kube:admin",
			userGroups:      []string{"kube:system", "system:authenticated", "system:authenticated:oauth"},
			operation:       admissionv1.Create,
			shouldBeAllowed: true,
		},
		{
			// cluster-admin group members should not be able to create a privileged namespace
			testID:          "cluster-admin-group-in-ns-test",
			targetNamespace: "in",
			username:        "lisa",
			userGroups:      []string{"cluster-admins", "system:authenticated", "system:authenticated:oauth"},
			operation:       admissionv1.Create,
			shouldBeAllowed: false,
		},
		{
			// cluster-admin group members should not be able to update a privileged namespace
			testID:          "cluster-admin-in-ns-test",
			targetNamespace: privilegedNamespace,
			username:        "lisa",
			userGroups:      []string{"cluster-admins", "system:authenticated", "system:authenticated:oauth"},
			operation:       admissionv1.Update,
			shouldBeAllowed: false,
		},
		{
			// cluster-admins group members should not be able to delete a privileged namespace
			testID:          "cluster-admin-in-ns-test",
			targetNamespace: privilegedNamespace,
			username:        "lisa",
			userGroups:      []string{"cluster-admins", "system:authenticated", "system:authenticated:oauth"},
			operation:       admissionv1.Delete,
			shouldBeAllowed: false,
		},
	}
	runNamespaceTests(t, tests)
}

func TestLabelCreates(t *testing.T) {
	tests := []namespaceTestSuites{
		{
			testID:          "sre-can-create-priv-labelled-ns",
			targetNamespace: privilegedNamespace,
			username:        "no-reply@redhat.com",
			userGroups:      []string{"system:serviceaccounts:openshift-backplane-srep", "system:authenticated", "system:authenticated:oauth"},
			operation:       admissionv1.Create,
			labels:          map[string]string{"my-label": "hello"},
			shouldBeAllowed: true,
		},
		{
			testID:          "sre-can-create-priv-labelled-ns",
			targetNamespace: privilegedNamespace,
			username:        "no-reply@redhat.com",
			userGroups:      []string{"system:serviceaccounts:openshift-backplane-srep", "system:authenticated", "system:authenticated:oauth"},
			operation:       admissionv1.Create,
			labels: map[string]string{
				"managed.openshift.io/storage-pv-quota-exempt": "true",
				"managed.openshift.io/storage-lb-quota-exempt": "true",
			},
			shouldBeAllowed: true,
		},
		{
			testID:          "cluster-admins-group-cannot-create-priv-labelled-ns",
			targetNamespace: privilegedNamespace,
			username:        "no-reply@redhat.com",
			userGroups:      []string{"cluster-admins", "system:authenticated", "system:authenticated:oauth"},
			operation:       admissionv1.Create,
			labels:          map[string]string{"my-label": "hello"},
			shouldBeAllowed: false,
		},
		{
			testID:          "admin-test",
			targetNamespace: privilegedNamespace,
			username:        "kube:admin",
			userGroups:      []string{"kube:system", "system:authenticated", "system:authenticated:oauth"},
			operation:       admissionv1.Create,
			labels:          map[string]string{"my-label": "hello"},
			shouldBeAllowed: true,
		},
		{
			testID:          "admin-test",
			targetNamespace: privilegedNamespace,
			username:        "kube:admin",
			userGroups:      []string{"kube:system", "system:authenticated", "system:authenticated:oauth"},
			operation:       admissionv1.Create,
			labels: map[string]string{
				"managed.openshift.io/storage-pv-quota-exempt": "true",
				"managed.openshift.io/storage-lb-quota-exempt": "true",
			},
			shouldBeAllowed: true,
		},
		{
			testID:          "dedicated-admin-can-create-normal-ns",
			targetNamespace: "my-customer-ns",
			username:        "test@user",
			userGroups:      []string{"system:authenticated", "system:authenticated:oauth", "dedicated-admins"},
			operation:       admissionv1.Create,
			labels:          map[string]string{"my-label": "hello"},
			shouldBeAllowed: true,
		},
		{
			testID:          "dedicated-admin-cant-create-normal-ns-with-priv-label",
			targetNamespace: "my-customer-ns",
			username:        "test@user",
			userGroups:      []string{"system:authenticated", "system:authenticated:oauth", "dedicated-admins"},
			operation:       admissionv1.Create,
			labels: map[string]string{
				"my-label": "hello",
				"managed.openshift.io/storage-pv-quota-exempt": "true",
			},
			shouldBeAllowed: false,
		},
		{
			testID:          "dedicated-admin-cant-create-normal-ns-with-priv-label",
			targetNamespace: "my-customer-ns",
			username:        "test@user",
			userGroups:      []string{"system:authenticated", "system:authenticated:oauth", "dedicated-admins"},
			operation:       admissionv1.Create,
			labels: map[string]string{
				"my-label": "hello",
				"managed.openshift.io/storage-pv-quota-exempt": "true",
				"managed.openshift.io/storage-lb-quota-exempt": "true",
			},
			shouldBeAllowed: false,
		},
		{
			testID:          "dedicated-admin-cant-create-normal-ns-with-priv-label",
			targetNamespace: "my-customer-ns",
			username:        "test@user",
			userGroups:      []string{"system:authenticated", "system:authenticated:oauth", "dedicated-admins"},
			operation:       admissionv1.Create,
			labels: map[string]string{
				"managed.openshift.io/storage-pv-quota-exempt": "true",
				"managed.openshift.io/storage-lb-quota-exempt": "true",
			},
			shouldBeAllowed: false,
		},
	}
	runNamespaceTests(t, tests)
}

func TestLabellingUpdates(t *testing.T) {
	tests := []namespaceTestSuites{
		{
			// if for some reason the quota was explicitly set to false we shouldn't allow that to be removed
			testID:          "dedicated-admins-cant-remove-quota-label",
			targetNamespace: "my-customer-ns",
			username:        "test@user",
			userGroups:      []string{"system:authenticated", "system:authenticated:oauth", "dedicated-admins"},
			operation:       admissionv1.Update,
			oldObject: createOldObject("my-customer-ns", "dedicated-admins-cant-remove-quota-label", map[string]string{
				"managed.openshift.io/storage-pv-quota-exempt": "false",
			}),
			labels:          map[string]string{},
			shouldBeAllowed: false,
		},
		{
			// if for some reason the quota was explicitly set to false we shouldn't allow that to be removed (part 2)
			testID:          "dedicated-admins-cant-remove-quota-label2",
			targetNamespace: "my-customer-ns",
			username:        "test@user",
			userGroups:      []string{"system:authenticated", "system:authenticated:oauth", "dedicated-admins"},
			operation:       admissionv1.Update,
			oldObject: createOldObject("my-customer-ns", "dedicated-admins-cant-remove-quota-label2", map[string]string{
				"managed.openshift.io/storage-pv-quota-exempt": "false",
			}),
			labels:          map[string]string{"my-label": "hello"},
			shouldBeAllowed: false,
		},
		{
			// can a dedicated-admin swap explicit falses?
			testID:          "dedicated-admins-cant-swap-quota-label",
			targetNamespace: "my-customer-ns",
			username:        "test@user",
			userGroups:      []string{"system:authenticated", "system:authenticated:oauth", "dedicated-admins"},
			operation:       admissionv1.Update,
			oldObject: createOldObject("my-customer-ns", "dedicated-admins-cant-swap-quota-label", map[string]string{
				"managed.openshift.io/storage-pv-quota-exempt": "false",
			}),
			labels:          map[string]string{"managed.openshift.io/storage-lb-quota-exempt": "false"},
			shouldBeAllowed: false,
		},
		{
			// Nothing is changing here
			testID:          "dedicated-admins-identity-operation",
			targetNamespace: "my-customer-ns",
			username:        "test@user",
			userGroups:      []string{"system:authenticated", "system:authenticated:oauth", "dedicated-admins"},
			operation:       admissionv1.Update,
			oldObject: createOldObject("my-customer-ns", "dedicated-admins-cant-trueify-exemption", map[string]string{
				"managed.openshift.io/storage-pv-quota-exempt": "true",
			}),
			labels: map[string]string{
				"managed.openshift.io/storage-pv-quota-exempt": "true",
			},
			shouldBeAllowed: true,
		},
		{
			testID:          "dedicated-admins-cant-trueify-exemption",
			targetNamespace: "my-customer-ns",
			username:        "test@user",
			userGroups:      []string{"system:authenticated", "system:authenticated:oauth", "dedicated-admins"},
			operation:       admissionv1.Update,
			oldObject: createOldObject("my-customer-ns", "dedicated-admins-cant-trueify-exemption", map[string]string{
				"managed.openshift.io/storage-pv-quota-exempt": "false",
			}),
			labels: map[string]string{
				"managed.openshift.io/storage-pv-quota-exempt": "true",
			},
			shouldBeAllowed: false,
		},
		{
			testID:          "sres-can-exempt-customer-ns",
			targetNamespace: "my-customer-ns",
			username:        "no-reply@redhat.com",
			userGroups:      []string{"system:authenticated", "system:authenticated:oauth", "system:serviceaccounts:openshift-backplane-srep"},
			operation:       admissionv1.Update,
			oldObject:       createOldObject("my-customer-ns", "dedicated-admin-cant-exempt-cust-ns-quota", map[string]string{}),
			labels: map[string]string{
				"managed.openshift.io/storage-pv-quota-exempt": "true",
			},
			shouldBeAllowed: true,
		},
		{
			testID:          "dedicated-admin-cant-exempt-cust-ns-quota",
			targetNamespace: "my-customer-ns",
			username:        "test@user",
			userGroups:      []string{"system:authenticated", "system:authenticated:oauth", "dedicated-admins"},
			operation:       admissionv1.Update,
			oldObject:       createOldObject("my-customer-ns", "dedicated-admin-cant-exempt-cust-ns-quota", map[string]string{}),
			labels: map[string]string{
				"managed.openshift.io/storage-pv-quota-exempt": "true",
			},
			shouldBeAllowed: false,
		},
		{
			testID:          "dedicated-admin-cant-alter-priv-ns",
			targetNamespace: privilegedNamespace,
			username:        "test@user",
			userGroups:      []string{"system:authenticated", "system:authenticated:oauth", "dedicated-admins"},
			operation:       admissionv1.Update,
			oldObject: createOldObject(privilegedNamespace, "dedicated-admin-cant-alter-priv-ns", map[string]string{
				"managed.openshift.io/storage-pv-quota-exempt": "true",
				"managed.openshift.io/storage-lb-quota-exempt": "true",
			}),
			labels: map[string]string{
				"managed.openshift.io/storage-pv-quota-exempt": "true",
			},
			shouldBeAllowed: false,
		},
		{
			testID:          "dedicated-admin-can-alter-unpriv-openshift-ns",
			targetNamespace: "openshift-unpriv-ns",
			username:        "test@user",
			userGroups:      []string{"system:authenticated", "system:authenticated:oauth", "dedicated-admins"},
			operation:       admissionv1.Update,
			oldObject:       createOldObject("openshift-test-ns", "dedicated-admin-cant-alter-priv-ns2", map[string]string{}),
			labels:          map[string]string{"my-label": "hello"},
			shouldBeAllowed: true,
		},
		{
			testID:          "dedicated-admin-can-label-cust-ns",
			targetNamespace: "my-customer-ns",
			username:        "test@user",
			userGroups:      []string{"system:authenticated", "system:authenticated:oauth", "dedicated-admins"},
			operation:       admissionv1.Update,
			oldObject:       createOldObject("my-customer-ns", "dedicated-admin-can-label-cust-ns", map[string]string{}),
			labels: map[string]string{
				"my-cust-label": "true",
			},
			shouldBeAllowed: true,
		},
		{
			testID:          "user-can-remove-removable-label-from-unpriv-ns",
			targetNamespace: "my-customer-ns",
			username:        "test@user",
			userGroups:      []string{"system:authenticated", "system:authenticated:oauth"},
			operation:       admissionv1.Update,
			oldObject: createOldObject("my-customer-ns", "user-can-remove-removable-label-from-unpriv-ns", map[string]string{
				"openshift.io/cluster-monitoring": "true",
			}),
			labels:          map[string]string{},
			shouldBeAllowed: true,
		},
		{
			testID:          "user-cant-alter-removable-label-key-unpriv-ns",
			targetNamespace: "my-customer-ns",
			username:        "test@user",
			userGroups:      []string{"system:authenticated", "system:authenticated:oauth"},
			operation:       admissionv1.Update,
			oldObject: createOldObject("my-customer-ns", "user-can-remove-removable-label-from-unpriv-ns", map[string]string{
				"openshift.io/cluster-monitoring": "true",
			}),
			labels:          map[string]string{"openshift.io/cluster-monitoring": "false"},
			shouldBeAllowed: false,
		},
		{
			testID:          "user-cant-add-removable-label-on-unpriv-ns",
			targetNamespace: "my-customer-ns",
			username:        "test@user",
			userGroups:      []string{"system:authenticated", "system:authenticated:oauth"},
			operation:       admissionv1.Update,
			oldObject:       createOldObject("my-customer-ns", "user-can-remove-removable-label-from-unpriv-ns", map[string]string{}),
			labels:          map[string]string{"openshift.io/cluster-monitoring": "true"},
			shouldBeAllowed: false,
		},
		{
			testID:          "cluster-admin-cant-add-removable-label-on-unpriv-ns",
			targetNamespace: "my-customer-ns",
			username:        "test@user",
			userGroups:      []string{"cluster-admins", "system:authenticated", "system:authenticated:oauth"},
			operation:       admissionv1.Update,
			oldObject:       createOldObject("my-customer-ns", "user-can-remove-removable-label-from-unpriv-ns", map[string]string{}),
			labels:          map[string]string{"openshift.io/cluster-monitoring": "true"},
			shouldBeAllowed: false,
		},
		{
			testID:          "backplane-cluster-admin-can-add-removable-label-on-unpriv-ns",
			targetNamespace: "my-customer-ns",
			username:        "backplane-cluster-admin",
			userGroups:      []string{"system:authenticated", "system:authenticated:oauth"},
			operation:       admissionv1.Update,
			oldObject:       createOldObject("my-customer-ns", "user-can-remove-removable-label-from-unpriv-ns", map[string]string{}),
			labels:          map[string]string{"openshift.io/cluster-monitoring": "true"},
			shouldBeAllowed: true,
		},
		{
			testID:          "backplane-cluster-admin-can-add-removable-label-on-priv-ns",
			targetNamespace: "openshift-kube-apiserver",
			username:        "backplane-cluster-admin",
			userGroups:      []string{"system:authenticated", "system:authenticated:oauth"},
			operation:       admissionv1.Update,
			oldObject:       createOldObject("my-customer-ns", "user-can-remove-removable-label-from-unpriv-ns", map[string]string{}),
			labels:          map[string]string{"openshift.io/cluster-monitoring": "true"},
			shouldBeAllowed: true,
		},
		{
			testID:          "backplane-cluster-admin-can-remove-removable-label-on-priv-ns",
			targetNamespace: "openshift-kube-apiserver",
			username:        "backplane-cluster-admin",
			userGroups:      []string{"system:authenticated", "system:authenticated:oauth"},
			operation:       admissionv1.Update,
			oldObject: createOldObject("my-customer-ns", "user-can-remove-removable-label-from-unpriv-ns", map[string]string{
				"openshift.io/cluster-monitoring": "true",
			}),
			labels:          map[string]string{},
			shouldBeAllowed: true,
		},
		// https://issues.redhat.com/browse/SREP-1770 - test explicit exception for nvidia-gpu-operator
		{
			testID:          "nvidia-gpu-operator-can-add-label-to-unprotected-ns",
			targetNamespace: "nvidia-gpu-operator",
			username:        "system:serviceaccount:nvidia-gpu-operator:gpu-operator",
			userGroups:      []string{"system:authenticated", "system:authenticated:oauth"},
			operation:       admissionv1.Update,
			oldObject:       createOldObject("nvidia-gpu-operator", "nvidia-gpu-operato-can-add-label-to-unprotected-ns", map[string]string{}),
			labels:          map[string]string{"openshift.io/cluster-monitoring": "true"},
			shouldBeAllowed: true,
		},
		{
			testID:          "nvidia-gpu-operator-can-remove-label-from-unprotected-ns",
			targetNamespace: "nvidia-gpu-operator",
			username:        "system:serviceaccount:nvidia-gpu-operator:gpu-operator",
			userGroups:      []string{"system:authenticated", "system:authenticated:oauth"},
			operation:       admissionv1.Update,
			oldObject: createOldObject("nvidia-gpu-operator", "nvidia-gpu-operato-can-remove-label-from-unprotected-ns", map[string]string{
				"openshift.io/cluster-monitoring": "true",
			}),
			labels:          map[string]string{},
			shouldBeAllowed: true,
		},
		{
			testID:          "nvidia-gpu-operator-cannot-remove-label-from-protected-ns",
			targetNamespace: "nvidia-gpu-operator",
			username:        "system:serviceaccount:nvidia-gpu-operator:gpu-operator",
			userGroups:      []string{"system:authenticated", "system:authenticated:oauth"},
			operation:       admissionv1.Update,
			oldObject: createOldObject("openshift-kube-apiserver", "nvidia-gpu-operato-cannot-remove-label-from-protected-ns", map[string]string{
				"openshift.io/cluster-monitoring": "true",
			}),
			labels:          map[string]string{},
			shouldBeAllowed: false,
		},
		// https://issues.redhat.com/browse/SREP-2070 - test explicit exception for multiclusterhub-operator
		{
			testID:          "multiclusterhub-operator-can-add-label-to-unprotected-ns",
			targetNamespace: "open-cluster-management",
			username:        "system:serviceaccount:open-cluster-management:multiclusterhub-operator",
			userGroups:      []string{"system:authenticated", "system:authenticated:oauth"},
			operation:       admissionv1.Update,
			oldObject:       createOldObject("open-cluster-management", "multiclusterhub-operator-can-add-label-to-unprotected-ns", map[string]string{}),
			labels:          map[string]string{"openshift.io/cluster-monitoring": "true"},
			shouldBeAllowed: true,
		},
		{
			testID:          "multiclusterhub-operator-can-remove-label-from-unprotected-ns",
			targetNamespace: "open-cluster-management",
			username:        "system:serviceaccount:open-cluster-management:multiclusterhub-operator",
			userGroups:      []string{"system:authenticated", "system:authenticated:oauth"},
			operation:       admissionv1.Update,
			oldObject: createOldObject("open-cluster-management", "multiclusterhub-operator-can-remove-label-from-unprotected-ns", map[string]string{
				"openshift.io/cluster-monitoring": "true",
			}),
			labels:          map[string]string{},
			shouldBeAllowed: true,
		},
		{
			testID:          "multiclusterhub-operator-can-modify-label-on-unprotected-ns",
			targetNamespace: "open-cluster-management",
			username:        "system:serviceaccount:open-cluster-management:multiclusterhub-operator",
			userGroups:      []string{"system:authenticated", "system:authenticated:oauth"},
			operation:       admissionv1.Update,
			oldObject: createOldObject("open-cluster-management", "multiclusterhub-operator-can-modify-label-on-unprotected-ns", map[string]string{
				"openshift.io/cluster-monitoring": "false",
			}),
			labels:          map[string]string{"openshift.io/cluster-monitoring": "true"},
			shouldBeAllowed: true,
		},
		{
			testID:          "multiclusterhub-operator-different-namespace-can-add-label",
			targetNamespace: "some-other-namespace",
			username:        "system:serviceaccount:different-namespace:multiclusterhub-operator",
			userGroups:      []string{"system:authenticated", "system:authenticated:oauth"},
			operation:       admissionv1.Update,
			oldObject:       createOldObject("some-other-namespace", "multiclusterhub-operator-different-namespace-can-add-label", map[string]string{}),
			labels:          map[string]string{"openshift.io/cluster-monitoring": "true"},
			shouldBeAllowed: true,
		},
		{
			testID:          "multiclusterhub-operator-cannot-access-protected-ns",
			targetNamespace: "openshift-kube-apiserver",
			username:        "system:serviceaccount:open-cluster-management:multiclusterhub-operator",
			userGroups:      []string{"system:authenticated", "system:authenticated:oauth"},
			operation:       admissionv1.Update,
			oldObject: createOldObject("openshift-kube-apiserver", "multiclusterhub-operator-cannot-access-protected-ns", map[string]string{
				"openshift.io/cluster-monitoring": "true",
			}),
			labels:          map[string]string{},
			shouldBeAllowed: false,
		},
		{
			testID:          "non-excepted-operator-cannot-add-label",
			targetNamespace: "some-namespace",
			username:        "system:serviceaccount:some-namespace:some-other-operator",
			userGroups:      []string{"system:authenticated", "system:authenticated:oauth"},
			operation:       admissionv1.Update,
			oldObject:       createOldObject("some-namespace", "non-excepted-operator-cannot-add-label", map[string]string{}),
			labels:          map[string]string{"openshift.io/cluster-monitoring": "true"},
			shouldBeAllowed: false,
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
