package networkpolicies

import (
	"encoding/json"
	"strings"
	"testing"

	admissionv1 "k8s.io/api/admission/v1"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"

	"github.com/openshift/managed-cluster-validating-webhooks/pkg/testutils"
)

type networkPolicyTestSuites struct {
	testID            string
	username          string
	userGroups        []string
	targetNamespace   string
	targetResource    string
	operation         admissionv1.Operation
	shouldBeAllowed   bool
	podSelectorLabels map[string]string
}

type crudTest struct {
	name     string
	testData networkPolicyTestSuites
}

func newCrudTest(name string) crudTest {
	return crudTest{
		name: name,
		testData: networkPolicyTestSuites{
			testID:            "regular-user-cant-update-networkpolicy-in-managed-namespaces",
			targetNamespace:   "default",
			targetResource:    "networkpolicy",
			username:          "someuser",
			userGroups:        []string{"system:serviceaccounts:redhat-ns:test-operator", "system:authenticated", "system:authenticated:oauth"},
			operation:         admissionv1.Update,
			shouldBeAllowed:   false,
			podSelectorLabels: map[string]string{},
		},
	}
}

func (t crudTest) regularUser() crudTest {
	t.testData.username = "testregularuser"
	t.testData.userGroups = []string{"system:authenticated", "system:authenticated:oauth"}
	return t
}

func (t crudTest) unprivilegedServiceAccount() crudTest {
	t.testData.username = "system:serviceaccounts:unpriv-ns"
	t.testData.userGroups = []string{"system:serviceaccounts:unpriv-ns", "cluster-admins", "system:authenticated", "system:authenticated:oauth"}
	return t
}

func (t crudTest) backplaneClusterAdmin() crudTest {
	t.testData.username = "backplane-cluster-admin"
	t.testData.userGroups = []string{"system:authenticated", "system:authenticated:oauth"}
	return t
}

func (t crudTest) allowedServiceAccount() crudTest {
	t.testData.username = "system:serviceaccounts:openshift-test-ns"
	t.testData.userGroups = []string{"system:serviceaccounts:openshift-test-ns", "system:authenticated", "system:authenticated:oauth"}
	return t
}

func (t crudTest) redhatServiceAccount() crudTest {
	t.testData.username = "system:serviceaccounts:redhat-ns:test-operator"
	t.testData.userGroups = []string{"system:serviceaccounts:redhat-ns:test-operator", "system:authenticated", "system:authenticated:oauth"}
	return t
}

func (t crudTest) namespace(namespace string) crudTest {
	t.testData.targetNamespace = namespace
	return t
}

func (t crudTest) podSelector(label, value string) crudTest {
	t.testData.podSelectorLabels[label] = value
	return t
}

func (t crudTest) shouldBeAllowed() []networkPolicyTestSuites {
	return t.renderCRUDTests(true)
}

func (t crudTest) shouldBeDenied() []networkPolicyTestSuites {
	return t.renderCRUDTests(false)
}

func (t crudTest) renderCRUDTests(allowed bool) []networkPolicyTestSuites {
	cases := []networkPolicyTestSuites{}

	for _, verb := range []admissionv1.Operation{admissionv1.Create, admissionv1.Update, admissionv1.Delete} {
		cases = append(cases, networkPolicyTestSuites{
			testID:            strings.ToLower(string(verb)) + "-" + t.name,
			username:          t.testData.username,
			targetNamespace:   t.testData.targetNamespace,
			targetResource:    t.testData.targetResource,
			userGroups:        t.testData.userGroups,
			operation:         admissionv1.Create,
			shouldBeAllowed:   allowed,
			podSelectorLabels: t.testData.podSelectorLabels,
		})
	}

	return cases

}

func createRawJSONString(namespace string, podSelectorLabels map[string]string) string {
	networkPolicy := networkingv1.NetworkPolicy{
		TypeMeta: metav1.TypeMeta{
			APIVersion: "networking.k8s.io/v1",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test",
			Namespace: namespace,
			UID:       "1234",
		},
		Spec: networkingv1.NetworkPolicySpec{
			PodSelector: metav1.LabelSelector{
				MatchLabels: podSelectorLabels,
			},
		},
	}

	rawNetworkPolicy, err := json.Marshal(networkPolicy)
	if err != nil {
		panic(err)
	}

	return string(rawNetworkPolicy)
}

func runNetworkPolicyTests(t *testing.T, tests []networkPolicyTestSuites) {
	gvk := metav1.GroupVersionKind{
		Group:   "networking.k8s.io",
		Version: "v1",
		Kind:    "NetworkPolicy",
	}
	gvr := metav1.GroupVersionResource{
		Group:    "networking.k8s.io",
		Version:  "v1",
		Resource: "networkpolicies",
	}

	for _, test := range tests {
		rawObjString := createRawJSONString(test.targetNamespace, test.podSelectorLabels)

		obj := runtime.RawExtension{
			Raw: []byte(rawObjString),
		}

		oldObj := runtime.RawExtension{
			Raw: []byte(rawObjString),
		}

		hook := NewWebhook()
		httprequest, err := testutils.CreateHTTPRequest(hook.GetURI(),
			test.testID, gvk, gvr, test.operation, test.username, test.userGroups, "", &obj, &oldObj)
		if err != nil {
			t.Fatalf("Expected no error, got %s", err.Error())
		}

		response, err := testutils.SendHTTPRequest(httprequest, hook)
		if err != nil {
			t.Fatalf("Expected no error, got %s", err.Error())
		}

		if response.Allowed != test.shouldBeAllowed {
			t.Fatalf("Mismatch: %s (groups=%s) %s %s the Test's expectation is that the user %s. Test: %s, PodSelector: %v", test.username, test.userGroups, testutils.CanCanNot(response.Allowed), test.operation, testutils.CanCanNot(test.shouldBeAllowed), test.testID, test.podSelectorLabels)
		}
	}
}
func TestUsers(t *testing.T) {
	tests := []networkPolicyTestSuites{
		{
			// osde2e-related things can delete a networkpolicy
			testID:          "osde2e-oao-delete-networkpolicy",
			targetNamespace: "openshift-ocm-agent-operator",
			username:        "system:serviceaccount:osde2e-h-9a47q:cluster-admin",
			userGroups:      []string{"system:serviceaccounts:osde2e-h-9a47q", "system:authenticated", "system:authenticated:oauth"},
			operation:       admissionv1.Delete,
			shouldBeAllowed: true,
		},
	}
	tests = append(tests, newCrudTest("regular-user-networkpolicy-managed-namespaces").
		namespace("openshift-kube-apiserver").regularUser().shouldBeDenied()...)
	tests = append(tests, newCrudTest("regular-user-networkpolicy-user-namespaces").
		namespace("my-monitoring").regularUser().shouldBeAllowed()...)
	tests = append(tests, newCrudTest("unprivileged-sa-managed-namespaces").
		namespace("openshift-kube-apiserver").unprivilegedServiceAccount().shouldBeDenied()...)
	tests = append(tests, newCrudTest("backplane-cluster-admin-managed-namespaces").
		namespace("openshift-kube-apiserver").backplaneClusterAdmin().shouldBeAllowed()...)
	tests = append(tests, newCrudTest("allowed-sa-managed-namespaces").
		namespace("openshift-kube-apiserver").allowedServiceAccount().shouldBeAllowed()...)
	tests = append(tests, newCrudTest("serviceaccount-managed-namespace-redhat-rhoam-observability").
		namespace("redhat-rhoam-observability").redhatServiceAccount().shouldBeAllowed()...)

	tests = append(tests, newCrudTest("regular-user-openshift-ingress-no-podselector").
		namespace("openshift-ingress").regularUser().shouldBeDenied()...)
	tests = append(tests, newCrudTest("regular-user-openshift-ingress-default-ingress").
		namespace("openshift-ingress").
		podSelector("ingresscontroller.operator.openshift.io/deployment-ingresscontroller", "default").
		regularUser().shouldBeDenied()...)
	tests = append(tests, newCrudTest("regular-user-openshift-ingress-custom-ingress").
		namespace("openshift-ingress").
		podSelector("ingresscontroller.operator.openshift.io/deployment-ingresscontroller", "custom-ingresscontroller").
		regularUser().shouldBeAllowed()...)
	runNetworkPolicyTests(t, tests)
}
