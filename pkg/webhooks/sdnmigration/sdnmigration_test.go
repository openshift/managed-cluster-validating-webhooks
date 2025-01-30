package sdnmigration

import (
	"reflect"
	"testing"

	"github.com/openshift/managed-cluster-validating-webhooks/pkg/webhooks/utils"
	admissionv1 "k8s.io/api/admission/v1"
	admissionregv1 "k8s.io/api/admissionregistration/v1"
	authenticationv1 "k8s.io/api/authentication/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	admissionctl "sigs.k8s.io/controller-runtime/pkg/webhook/admission"
)

func TestAuthorized(t *testing.T) {
	tests := []struct {
		Name          string
		Request       admissionctl.Request
		ExpectAllowed bool
	}{
		{
			Name: "privileged account should be allowed",
			Request: admissionctl.Request{
				AdmissionRequest: admissionv1.AdmissionRequest{
					UserInfo: authenticationv1.UserInfo{
						Groups: []string{
							"system:serviceaccounts:openshift-backplane-srep",
						},
					},
				},
			},
			ExpectAllowed: true,
		},
		// Hive uses the admin user and we need to bypass the webhook for Hive
		{
			Name: "system admin should be allowed",
			Request: admissionctl.Request{
				AdmissionRequest: admissionv1.AdmissionRequest{
					UserInfo: authenticationv1.UserInfo{
						Username: "system:admin",
					},
				},
			},
			ExpectAllowed: true,
		},
		{
			Name: "non-privileged account should be denied",
			Request: admissionctl.Request{
				AdmissionRequest: admissionv1.AdmissionRequest{
					UserInfo: authenticationv1.UserInfo{
						Groups: []string{},
					},
				},
			},
			ExpectAllowed: false,
		},
		{
			Name: "disallow requests to modify the networkType from SDN to OVN",
			Request: admissionctl.Request{
				AdmissionRequest: admissionv1.AdmissionRequest{
					UserInfo: authenticationv1.UserInfo{
						Username: "test",
					},
					Kind: metav1.GroupVersionKind{
						Kind: "Networks",
					},
					Operation: admissionv1.Update,
					Object: runtime.RawExtension{
						Raw: []byte(`{
						"apiVersion": "config.openshift.io/v1",
						"kind": "Network",
						"spec": {
							"networkType": "OVNKubernetes"
						}
					}`),
					},
					OldObject: runtime.RawExtension{
						Raw: []byte(`{
						"apiVersion": "config.openshift.io/v1",
						"kind": "Network",
						"status": {
							"networkType": "OpenShiftSDN"
						}
					}`),
					},
				},
			},
			ExpectAllowed: false,
		},
		{
			Name: "disallow requests to modify the networkType from OVN to SDN",
			Request: admissionctl.Request{
				AdmissionRequest: admissionv1.AdmissionRequest{
					UserInfo: authenticationv1.UserInfo{
						Username: "test",
					},
					Kind: metav1.GroupVersionKind{
						Kind: "Networks",
					},
					Operation: admissionv1.Update,
					Object: runtime.RawExtension{
						Raw: []byte(`{
						"apiVersion": "config.openshift.io/v1",
						"kind": "Network",
						"spec": {
							"networkType": "OpenshiftSDN"
						}
					}`),
					},
					OldObject: runtime.RawExtension{
						Raw: []byte(`{
						"apiVersion": "config.openshift.io/v1",
						"kind": "Network",
						"status": {
							"networkType": "OVNKubernetes"
						}
					}`),
					},
				},
			},
			ExpectAllowed: false,
		},
		{
			Name: "allow adding annotations",
			Request: admissionctl.Request{
				AdmissionRequest: admissionv1.AdmissionRequest{
					UserInfo: authenticationv1.UserInfo{
						Username: "test",
					},
					Kind: metav1.GroupVersionKind{
						Kind: "Networks",
					},
					Operation: admissionv1.Update,
					Object: runtime.RawExtension{
						Raw: []byte(`{
						"apiVersion": "config.openshift.io/v1",
						"kind": "Network",
						"metadata": {
							"annotations": {
								"unsupported-red-hat-internal-testing": "true"
							},
							"name": "cluster"
						},
						"spec": {
							"networkType": "OVNKubernetes"
						}
					}`),
					},
					OldObject: runtime.RawExtension{
						Raw: []byte(`{
						"apiVersion": "config.openshift.io/v1",
						"kind": "Network",
						"metadata": {
							"name": "cluster"
						},
						"status": {
							"networkType": "OVNKubernetes"
						}
					}`),
					},
				},
			},
			ExpectAllowed: true,
		},
		{
			Name: "allow requests to modify the networkType from SDN to OVN with override annotation",
			Request: admissionctl.Request{
				AdmissionRequest: admissionv1.AdmissionRequest{
					UserInfo: authenticationv1.UserInfo{
						Username: "test",
					},
					Kind: metav1.GroupVersionKind{
						Kind: "Networks",
					},
					Operation: admissionv1.Update,
					Object: runtime.RawExtension{
						Raw: []byte(`{
						"apiVersion": "config.openshift.io/v1",
						"kind": "Network",
						"metadata": {
							"annotations": {
								"unsupported-red-hat-internal-testing": "true"
							}
						},
						"spec": {
							"networkType": "OVNKubernetes"
						}
					}`),
					},
					OldObject: runtime.RawExtension{
						Raw: []byte(`{
						"apiVersion": "config.openshift.io/v1",
						"kind": "Network",
						"metadata": {
							"annotations": {
								"unsupported-red-hat-internal-testing": "true"
							}
						},
						"status": {
							"networkType": "OpenShiftSDN"
						}
					}`),
					},
				},
			},
			ExpectAllowed: true,
		},
	}

	for _, test := range tests {
		t.Run(test.Name, func(t *testing.T) {
			w := NewWebhook()
			ret := w.Authorized(test.Request)

			if ret.Allowed != test.ExpectAllowed {
				t.Errorf("TestAuthorized() %s: request %v - allowed: %t, expected: %t\n", test.Name, test.Request, ret.Allowed, test.ExpectAllowed)
			}
		})
	}
}

func TestGetURI(t *testing.T) {
	uri := NewWebhook().GetURI()

	if uri != "/sdnmigration-validation" {
		t.Errorf("TestGetURI(): expected \"/sdnmigration-validation\", got: %s", uri)
	}
}

func TestValidate(t *testing.T) {
	tests := []struct {
		Name        string
		Request     admissionctl.Request
		ExpectValid bool
	}{
		{
			Name: "invalidate requests without a username",
			Request: admissionctl.Request{
				AdmissionRequest: admissionv1.AdmissionRequest{
					UserInfo: authenticationv1.UserInfo{
						Username: "",
					},
					Kind: metav1.GroupVersionKind{
						Kind: "Network",
					},
				},
			},
			ExpectValid: false,
		},
		{
			Name: "invalidate requests without a kind",
			Request: admissionctl.Request{
				AdmissionRequest: admissionv1.AdmissionRequest{
					UserInfo: authenticationv1.UserInfo{
						Username: "test",
					},
				},
			},
			ExpectValid: false,
		},
	}

	for _, test := range tests {
		t.Run(test.Name, func(t *testing.T) {
			w := NewWebhook()
			valid := w.Validate(test.Request)

			if valid != test.ExpectValid {
				t.Errorf("TestValidate() %s: expected %t, got %t\n", test.Name, test.ExpectValid, valid)
			}
		})
	}
}

func TestName(t *testing.T) {
	name := NewWebhook().Name()

	if name != "sdn-migration-validation" {
		t.Errorf("Name(): expected \"sdn-migration-validation\", got \"%s\"\n", name)
	}
}

func TestFailurePolicy(t *testing.T) {
	policy := NewWebhook().FailurePolicy()

	if policy != admissionregv1.Ignore {
		t.Errorf("TestFailurePolicy(): expected Ignore, got %s\n", policy)
	}
}

func TestMatchPolicy(t *testing.T) {
	policy := NewWebhook().MatchPolicy()

	if policy != admissionregv1.Equivalent {
		t.Errorf("TestFailurePolicy(): expected Equivalent, got %s\n", policy)
	}
}

func TestRules(t *testing.T) {
	scope := admissionregv1.ClusterScope
	expectedRules := []admissionregv1.RuleWithOperations{
		{
			Operations: []admissionregv1.OperationType{"UPDATE"},
			Rule: admissionregv1.Rule{
				APIGroups:   []string{"config.openshift.io"},
				APIVersions: []string{"*"},
				Resources:   []string{"networks"},
				Scope:       &scope,
			},
		},
	}

	rules := NewWebhook().Rules()

	if !reflect.DeepEqual(expectedRules, rules) {
		t.Errorf("TestRules(): expected %v, got %v\n", expectedRules, rules)
	}
}

func TestObjectSelector(t *testing.T) {
	labelSelector := NewWebhook().ObjectSelector()

	if labelSelector != nil {
		t.Errorf("TestObjectSelector(): expected nil, got %v\n", labelSelector)
	}
}

func TestSideEffects(t *testing.T) {
	sideEffects := NewWebhook().SideEffects()

	if sideEffects != admissionregv1.SideEffectClassNone {
		t.Errorf("TestSideEffects(): expected %v, got %v\n", admissionregv1.SideEffectClassNone, sideEffects)
	}
}

func TestTimeoutSeconds(t *testing.T) {
	timeout := NewWebhook().TimeoutSeconds()

	if timeout != 2 {
		t.Errorf("TestTimeoutSeconds(): expected 2, got %d\n", timeout)
	}
}

func TestDoc(t *testing.T) {
	docs := NewWebhook().Doc()

	if len(docs) == 0 {
		t.Error("TestDoc(): expected content, recieved none")
	}
}

func TestSyncSetLabelSelector(t *testing.T) {
	labelSelector := NewWebhook().SyncSetLabelSelector()

	if !reflect.DeepEqual(labelSelector, utils.DefaultLabelSelector()) {
		t.Errorf("TestSyncSetLabelSelector(): expected %v, got %v\n", utils.DefaultLabelSelector(), labelSelector)
	}
}

func TestHypershiftEnabled(t *testing.T) {
	enabled := NewWebhook().HypershiftEnabled()

	if enabled {
		t.Error("TestHypershiftEnabled(): expected disabled")
	}
}
