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
			gvk, gvr, test.operation, test.username, test.userGroups, obj, test.oldObject)
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
			targetNamespace: "kube-system",
			username:        "test-user",
			userGroups:      []string{"dedicated-admins", "system:authenticated", "system:authenticated:oauth"},
			operation:       admissionv1.Delete,
			shouldBeAllowed: false,
		},
		{
			// Should not be able to create a privileged namespace
			testID:          "dedi-create-priv-ns",
			targetNamespace: "openshift-test-namespace",
			username:        "test-user",
			userGroups:      []string{"dedicated-admins", "system:authenticated", "system:authenticated:oauth"},
			operation:       admissionv1.Create,
			shouldBeAllowed: false,
		},
		{
			// Should not be able to update layered product ecnamespa
			testID:          "dedi-update-layered-prod-ns",
			targetNamespace: "redhat-layered-product-ns",
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
			targetNamespace: "kube-system",
			username:        "test-user",
			userGroups:      []string{"system:authenticated", "system:authenticated:oauth"},
			operation:       admissionv1.Create,
			shouldBeAllowed: false,
		},
		{
			// Shouldn't be able to delete a privileged namespace
			testID:          "nonpriv-delete-priv-ns",
			targetNamespace: "kube-system",
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
			// note: ^redhat.* is a privileged ns, but lp admins have an exception in
			// it (but not other privileged ns)
			testID:          "lp-create-layered-ns",
			targetNamespace: "redhat-layered-product",
			username:        "test-user",
			userGroups:      []string{"layered-sre-cluster-admins", "system:authenticated", "system:authenticated:oauth"},
			operation:       admissionv1.Create,
			shouldBeAllowed: true,
		},
		{
			// Layered admins can't create a privileged ns
			testID:          "lp-create-priv-ns",
			targetNamespace: "openshift-test",
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
			targetNamespace: "openshift-test-ns",
			username:        "system:serviceaccounts:openshift-test-ns",
			userGroups:      []string{"system:serviceaccounts:openshift-test-ns", "system:authenticated", "system:authenticated:oauth"},
			operation:       admissionv1.Create,
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
			// osde2e-related things can create a ns for must-gather
			testID:          "sa-create-ns-for-must-gather",
			targetNamespace: "openshift-must-gather-qbjtf",
			username:        "system:serviceaccount:osde2e-9a47q:cluster-admin", // This does *NOT* mean cluster-admin as in that ClusterRole
			userGroups:      []string{"system:serviceaccounts:osde2e-9a47q", "system:authenticated", "system:authenticated:oauth"},
			operation:       admissionv1.Create,
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
			operation:       admissionv1.Update,
			shouldBeAllowed: true,
		},
		{
			// admin users gonna admin
			testID:          "sre-test",
			targetNamespace: "kube-system",
			username:        "lisa",
			userGroups:      []string{"system:serviceaccounts:openshift-backplane-srep", "system:authenticated", "system:authenticated:oauth"},
			operation:       admissionv1.Update,
			shouldBeAllowed: true,
		},
		{
			// admin users gonna admin
			testID:          "cluster-admin-test",
			targetNamespace: "kube-system",
			username:        "lisa",
			userGroups:      []string{"cluster-admins", "system:authenticated", "system:authenticated:oauth"},
			operation:       admissionv1.Update,
			shouldBeAllowed: true,
		},
		{
			// admin users gonna admin
			testID:          "backplane-cluster-admin-test",
			targetNamespace: "kube-system",
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
			// Admins should be able to create a privileged namespace
			testID:          "cluster-admin-in-ns-test",
			targetNamespace: "in",
			username:        "lisa",
			userGroups:      []string{"cluster-admins", "system:authenticated", "system:authenticated:oauth"},
			operation:       admissionv1.Create,
			shouldBeAllowed: true,
		},
	}
	runNamespaceTests(t, tests)
}

func TestLabelCreates(t *testing.T) {
	tests := []namespaceTestSuites{
		{
			testID:          "sre-can-create-priv-labelled-ns",
			targetNamespace: "openshift-priv-ns",
			username:        "no-reply@redhat.com",
			userGroups:      []string{"system:serviceaccounts:openshift-backplane-srep", "system:authenticated", "system:authenticated:oauth"},
			operation:       admissionv1.Create,
			labels:          map[string]string{"my-label": "hello"},
			shouldBeAllowed: true,
		},
		{
			testID:          "sre-can-create-priv-labelled-ns",
			targetNamespace: "openshift-priv-ns",
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
			testID:          "cluster-admin-can-create-priv-labelled-ns",
			targetNamespace: "openshift-priv-ns",
			username:        "no-reply@redhat.com",
			userGroups:      []string{"cluster-admins", "system:authenticated", "system:authenticated:oauth"},
			operation:       admissionv1.Create,
			labels:          map[string]string{"my-label": "hello"},
			shouldBeAllowed: true,
		},
		{
			testID:          "cluster-admins-can-create-priv-labelled-ns",
			targetNamespace: "openshift-priv-ns",
			username:        "no-reply@redhat.com",
			userGroups:      []string{"cluster-admins", "system:authenticated", "system:authenticated:oauth"},
			operation:       admissionv1.Create,
			labels: map[string]string{
				"managed.openshift.io/storage-pv-quota-exempt": "true",
				"managed.openshift.io/storage-lb-quota-exempt": "true",
			},
			shouldBeAllowed: true,
		},
		{
			testID:          "admin-test",
			targetNamespace: "kube-system",
			username:        "kube:admin",
			userGroups:      []string{"kube:system", "system:authenticated", "system:authenticated:oauth"},
			operation:       admissionv1.Create,
			labels:          map[string]string{"my-label": "hello"},
			shouldBeAllowed: true,
		},
		{
			testID:          "admin-test",
			targetNamespace: "kube-system",
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
			targetNamespace: "openshift-test-ns",
			username:        "test@user",
			userGroups:      []string{"system:authenticated", "system:authenticated:oauth", "dedicated-admins"},
			operation:       admissionv1.Update,
			oldObject: createOldObject("openshift-test-ns", "dedicated-admin-cant-alter-priv-ns", map[string]string{
				"managed.openshift.io/storage-pv-quota-exempt": "true",
				"managed.openshift.io/storage-lb-quota-exempt": "true",
			}),
			labels: map[string]string{
				"managed.openshift.io/storage-pv-quota-exempt": "true",
			},
			shouldBeAllowed: false,
		},
		{
			testID:          "dedicated-admin-cant-alter-priv-ns2",
			targetNamespace: "openshift-test-ns2",
			username:        "test@user",
			userGroups:      []string{"system:authenticated", "system:authenticated:oauth", "dedicated-admins"},
			operation:       admissionv1.Update,
			oldObject:       createOldObject("openshift-test-ns", "dedicated-admin-cant-alter-priv-ns2", map[string]string{}),
			labels:          map[string]string{"my-label": "hello"},
			shouldBeAllowed: false,
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
