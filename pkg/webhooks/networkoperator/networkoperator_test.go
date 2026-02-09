package networkoperator

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
			Name: "cluster-admin user modifying migration.networkType should be denied",
			Request: admissionctl.Request{
				AdmissionRequest: admissionv1.AdmissionRequest{
					UserInfo: authenticationv1.UserInfo{
						Username: "kube:admin",
						Groups:   []string{"system:cluster-admins"},
					},
					Kind: metav1.GroupVersionKind{
						Group: "operator.openshift.io",
						Kind:  "Network",
					},
					Operation: admissionv1.Update,
					Object: runtime.RawExtension{
						Raw: []byte(`{
							"apiVersion": "operator.openshift.io/v1",
							"kind": "Network",
							"metadata": {
								"name": "cluster"
							},
							"spec": {
								"migration": {
									"networkType": "OVNKubernetes"
								}
							}
						}`),
					},
					OldObject: runtime.RawExtension{
						Raw: []byte(`{
							"apiVersion": "operator.openshift.io/v1",
							"kind": "Network",
							"metadata": {
								"name": "cluster"
							},
							"spec": {
								"migration": {
									"networkType": "OpenShiftSDN"
								}
							}
						}`),
					},
				},
			},
			ExpectAllowed: false,
		},
		{
			Name: "regular user modifying migration.networkType should be denied",
			Request: admissionctl.Request{
				AdmissionRequest: admissionv1.AdmissionRequest{
					UserInfo: authenticationv1.UserInfo{
						Username: "test-user",
						Groups:   []string{},
					},
					Kind: metav1.GroupVersionKind{
						Group: "operator.openshift.io",
						Kind:  "Network",
					},
					Operation: admissionv1.Update,
					Object: runtime.RawExtension{
						Raw: []byte(`{
							"apiVersion": "operator.openshift.io/v1",
							"kind": "Network",
							"metadata": {
								"name": "cluster"
							},
							"spec": {
								"migration": {
									"networkType": "OVNKubernetes"
								}
							}
						}`),
					},
					OldObject: runtime.RawExtension{
						Raw: []byte(`{
							"apiVersion": "operator.openshift.io/v1",
							"kind": "Network",
							"metadata": {
								"name": "cluster"
							},
							"spec": {
								"migration": {
									"networkType": "OpenShiftSDN"
								}
							}
						}`),
					},
				},
			},
			ExpectAllowed: false,
		},
		{
			Name: "SRE service account modifying migration.networkType should be allowed",
			Request: admissionctl.Request{
				AdmissionRequest: admissionv1.AdmissionRequest{
					UserInfo: authenticationv1.UserInfo{
						Username: "system:serviceaccount:openshift-backplane-srep:test-sa",
						Groups: []string{
							"system:serviceaccounts:openshift-backplane-srep",
						},
					},
					Kind: metav1.GroupVersionKind{
						Group: "operator.openshift.io",
						Kind:  "Network",
					},
					Operation: admissionv1.Update,
					Object: runtime.RawExtension{
						Raw: []byte(`{
							"apiVersion": "operator.openshift.io/v1",
							"kind": "Network",
							"metadata": {
								"name": "cluster"
							},
							"spec": {
								"migration": {
									"networkType": "OVNKubernetes"
								}
							}
						}`),
					},
					OldObject: runtime.RawExtension{
						Raw: []byte(`{
							"apiVersion": "operator.openshift.io/v1",
							"kind": "Network",
							"metadata": {
								"name": "cluster"
							},
							"spec": {
								"migration": {
									"networkType": "OpenShiftSDN"
								}
							}
						}`),
					},
				},
			},
			ExpectAllowed: true,
		},
		{
			Name: "modifying migration.mode should be denied",
			Request: admissionctl.Request{
				AdmissionRequest: admissionv1.AdmissionRequest{
					UserInfo: authenticationv1.UserInfo{
						Username: "kube:admin",
					},
					Kind: metav1.GroupVersionKind{
						Group: "operator.openshift.io",
						Kind:  "Network",
					},
					Operation: admissionv1.Update,
					Object: runtime.RawExtension{
						Raw: []byte(`{
							"apiVersion": "operator.openshift.io/v1",
							"kind": "Network",
							"metadata": {
								"name": "cluster"
							},
							"spec": {
								"migration": {
									"mode": "Live"
								}
							}
						}`),
					},
					OldObject: runtime.RawExtension{
						Raw: []byte(`{
							"apiVersion": "operator.openshift.io/v1",
							"kind": "Network",
							"metadata": {
								"name": "cluster"
							},
							"spec": {}
						}`),
					},
				},
			},
			ExpectAllowed: false,
		},
		{
			Name: "adding migration field when it was nil should be denied",
			Request: admissionctl.Request{
				AdmissionRequest: admissionv1.AdmissionRequest{
					UserInfo: authenticationv1.UserInfo{
						Username: "kube:admin",
					},
					Kind: metav1.GroupVersionKind{
						Group: "operator.openshift.io",
						Kind:  "Network",
					},
					Operation: admissionv1.Update,
					Object: runtime.RawExtension{
						Raw: []byte(`{
							"apiVersion": "operator.openshift.io/v1",
							"kind": "Network",
							"metadata": {
								"name": "cluster"
							},
							"spec": {
								"migration": {
									"networkType": "OVNKubernetes"
								}
							}
						}`),
					},
					OldObject: runtime.RawExtension{
						Raw: []byte(`{
							"apiVersion": "operator.openshift.io/v1",
							"kind": "Network",
							"metadata": {
								"name": "cluster"
							},
							"spec": {}
						}`),
					},
				},
			},
			ExpectAllowed: false,
		},
		{
			Name: "removing migration field should be denied",
			Request: admissionctl.Request{
				AdmissionRequest: admissionv1.AdmissionRequest{
					UserInfo: authenticationv1.UserInfo{
						Username: "kube:admin",
					},
					Kind: metav1.GroupVersionKind{
						Group: "operator.openshift.io",
						Kind:  "Network",
					},
					Operation: admissionv1.Update,
					Object: runtime.RawExtension{
						Raw: []byte(`{
							"apiVersion": "operator.openshift.io/v1",
							"kind": "Network",
							"metadata": {
								"name": "cluster"
							},
							"spec": {}
						}`),
					},
					OldObject: runtime.RawExtension{
						Raw: []byte(`{
							"apiVersion": "operator.openshift.io/v1",
							"kind": "Network",
							"metadata": {
								"name": "cluster"
							},
							"spec": {
								"migration": {
									"networkType": "OVNKubernetes"
								}
							}
						}`),
					},
				},
			},
			ExpectAllowed: false,
		},
		{
			Name: "modifying non-critical fields should be allowed",
			Request: admissionctl.Request{
				AdmissionRequest: admissionv1.AdmissionRequest{
					UserInfo: authenticationv1.UserInfo{
						Username: "kube:admin",
					},
					Kind: metav1.GroupVersionKind{
						Group: "operator.openshift.io",
						Kind:  "Network",
					},
					Operation: admissionv1.Update,
					Object: runtime.RawExtension{
						Raw: []byte(`{
							"apiVersion": "operator.openshift.io/v1",
							"kind": "Network",
							"metadata": {
								"name": "cluster",
								"annotations": {
									"test": "value"
								}
							},
							"spec": {
								"serviceNetwork": ["172.30.0.0/16"]
							}
						}`),
					},
					OldObject: runtime.RawExtension{
						Raw: []byte(`{
							"apiVersion": "operator.openshift.io/v1",
							"kind": "Network",
							"metadata": {
								"name": "cluster"
							},
							"spec": {
								"serviceNetwork": ["172.30.0.0/16"]
							}
						}`),
					},
				},
			},
			ExpectAllowed: true,
		},
		{
			Name: "CREATE operation should be allowed",
			Request: admissionctl.Request{
				AdmissionRequest: admissionv1.AdmissionRequest{
					UserInfo: authenticationv1.UserInfo{
						Username: "kube:admin",
					},
					Kind: metav1.GroupVersionKind{
						Group: "operator.openshift.io",
						Kind:  "Network",
					},
					Operation: admissionv1.Create,
					Object: runtime.RawExtension{
						Raw: []byte(`{
							"apiVersion": "operator.openshift.io/v1",
							"kind": "Network",
							"metadata": {
								"name": "cluster"
							},
							"spec": {
								"migration": {
									"networkType": "OVNKubernetes"
								}
							}
						}`),
					},
				},
			},
			ExpectAllowed: true,
		},
		{
			Name: "DELETE operation should be allowed",
			Request: admissionctl.Request{
				AdmissionRequest: admissionv1.AdmissionRequest{
					UserInfo: authenticationv1.UserInfo{
						Username: "kube:admin",
					},
					Kind: metav1.GroupVersionKind{
						Group: "operator.openshift.io",
						Kind:  "Network",
					},
					Operation: admissionv1.Delete,
					OldObject: runtime.RawExtension{
						Raw: []byte(`{
							"apiVersion": "operator.openshift.io/v1",
							"kind": "Network",
							"metadata": {
								"name": "cluster"
							}
						}`),
					},
				},
			},
			ExpectAllowed: true,
		},
		{
			Name: "UPDATE with no migration field changes should be allowed",
			Request: admissionctl.Request{
				AdmissionRequest: admissionv1.AdmissionRequest{
					UserInfo: authenticationv1.UserInfo{
						Username: "kube:admin",
					},
					Kind: metav1.GroupVersionKind{
						Group: "operator.openshift.io",
						Kind:  "Network",
					},
					Operation: admissionv1.Update,
					Object: runtime.RawExtension{
						Raw: []byte(`{
							"apiVersion": "operator.openshift.io/v1",
							"kind": "Network",
							"metadata": {
								"name": "cluster"
							},
							"spec": {
								"migration": {
									"networkType": "OVNKubernetes"
								}
							}
						}`),
					},
					OldObject: runtime.RawExtension{
						Raw: []byte(`{
							"apiVersion": "operator.openshift.io/v1",
							"kind": "Network",
							"metadata": {
								"name": "cluster"
							},
							"spec": {
								"migration": {
									"networkType": "OVNKubernetes"
								}
							}
						}`),
					},
				},
			},
			ExpectAllowed: true,
		},
		{
			Name: "backplane-cluster-admin modifying migration.networkType should be allowed",
			Request: admissionctl.Request{
				AdmissionRequest: admissionv1.AdmissionRequest{
					UserInfo: authenticationv1.UserInfo{
						Username: "backplane-cluster-admin",
					},
					Kind: metav1.GroupVersionKind{
						Group: "operator.openshift.io",
						Kind:  "Network",
					},
					Operation: admissionv1.Update,
					Object: runtime.RawExtension{
						Raw: []byte(`{
							"apiVersion": "operator.openshift.io/v1",
							"kind": "Network",
							"metadata": {
								"name": "cluster"
							},
							"spec": {
								"migration": {
									"networkType": "OVNKubernetes"
								}
							}
						}`),
					},
					OldObject: runtime.RawExtension{
						Raw: []byte(`{
							"apiVersion": "operator.openshift.io/v1",
							"kind": "Network",
							"metadata": {
								"name": "cluster"
							},
							"spec": {
								"migration": {
									"networkType": "OpenShiftSDN"
								}
							}
						}`),
					},
				},
			},
			ExpectAllowed: true,
		},
		{
			Name: "modifying migration.features should be denied",
			Request: admissionctl.Request{
				AdmissionRequest: admissionv1.AdmissionRequest{
					UserInfo: authenticationv1.UserInfo{
						Username: "kube:admin",
					},
					Kind: metav1.GroupVersionKind{
						Group: "operator.openshift.io",
						Kind:  "Network",
					},
					Operation: admissionv1.Update,
					Object: runtime.RawExtension{
						Raw: []byte(`{
							"apiVersion": "operator.openshift.io/v1",
							"kind": "Network",
							"metadata": {
								"name": "cluster"
							},
							"spec": {
								"migration": {
									"networkType": "OVNKubernetes",
									"features": {
										"egressIP": true,
										"egressFirewall": true
									}
								}
							}
						}`),
					},
					OldObject: runtime.RawExtension{
						Raw: []byte(`{
							"apiVersion": "operator.openshift.io/v1",
							"kind": "Network",
							"metadata": {
								"name": "cluster"
							},
							"spec": {
								"migration": {
									"networkType": "OVNKubernetes",
									"features": {
										"egressIP": false,
										"egressFirewall": false
									}
								}
							}
						}`),
					},
				},
			},
			ExpectAllowed: false,
		},
		{
			Name: "adding migration.features when it was nil should be denied",
			Request: admissionctl.Request{
				AdmissionRequest: admissionv1.AdmissionRequest{
					UserInfo: authenticationv1.UserInfo{
						Username: "kube:admin",
					},
					Kind: metav1.GroupVersionKind{
						Group: "operator.openshift.io",
						Kind:  "Network",
					},
					Operation: admissionv1.Update,
					Object: runtime.RawExtension{
						Raw: []byte(`{
							"apiVersion": "operator.openshift.io/v1",
							"kind": "Network",
							"metadata": {
								"name": "cluster"
							},
							"spec": {
								"migration": {
									"networkType": "OVNKubernetes",
									"features": {
										"egressIP": true
									}
								}
							}
						}`),
					},
					OldObject: runtime.RawExtension{
						Raw: []byte(`{
							"apiVersion": "operator.openshift.io/v1",
							"kind": "Network",
							"metadata": {
								"name": "cluster"
							},
							"spec": {
								"migration": {
									"networkType": "OVNKubernetes"
								}
							}
						}`),
					},
				},
			},
			ExpectAllowed: false,
		},
		{
			Name: "modifying migration.mtu.network should be denied",
			Request: admissionctl.Request{
				AdmissionRequest: admissionv1.AdmissionRequest{
					UserInfo: authenticationv1.UserInfo{
						Username: "kube:admin",
					},
					Kind: metav1.GroupVersionKind{
						Group: "operator.openshift.io",
						Kind:  "Network",
					},
					Operation: admissionv1.Update,
					Object: runtime.RawExtension{
						Raw: []byte(`{
							"apiVersion": "operator.openshift.io/v1",
							"kind": "Network",
							"metadata": {
								"name": "cluster"
							},
							"spec": {
								"migration": {
									"networkType": "OVNKubernetes",
									"mtu": {
										"network": {
											"from": 1500,
											"to": 9000
										}
									}
								}
							}
						}`),
					},
					OldObject: runtime.RawExtension{
						Raw: []byte(`{
							"apiVersion": "operator.openshift.io/v1",
							"kind": "Network",
							"metadata": {
								"name": "cluster"
							},
							"spec": {
								"migration": {
									"networkType": "OVNKubernetes",
									"mtu": {
										"network": {
											"from": 1500,
											"to": 1500
										}
									}
								}
							}
						}`),
					},
				},
			},
			ExpectAllowed: false,
		},
		{
			Name: "modifying migration.mtu.machine should be denied",
			Request: admissionctl.Request{
				AdmissionRequest: admissionv1.AdmissionRequest{
					UserInfo: authenticationv1.UserInfo{
						Username: "kube:admin",
					},
					Kind: metav1.GroupVersionKind{
						Group: "operator.openshift.io",
						Kind:  "Network",
					},
					Operation: admissionv1.Update,
					Object: runtime.RawExtension{
						Raw: []byte(`{
							"apiVersion": "operator.openshift.io/v1",
							"kind": "Network",
							"metadata": {
								"name": "cluster"
							},
							"spec": {
								"migration": {
									"networkType": "OVNKubernetes",
									"mtu": {
										"machine": {
											"from": 1500,
											"to": 9000
										}
									}
								}
							}
						}`),
					},
					OldObject: runtime.RawExtension{
						Raw: []byte(`{
							"apiVersion": "operator.openshift.io/v1",
							"kind": "Network",
							"metadata": {
								"name": "cluster"
							},
							"spec": {
								"migration": {
									"networkType": "OVNKubernetes",
									"mtu": {
										"machine": {
											"from": 1500,
											"to": 1500
										}
									}
								}
							}
						}`),
					},
				},
			},
			ExpectAllowed: false,
		},
		{
			Name: "adding migration.mtu when it was nil should be denied",
			Request: admissionctl.Request{
				AdmissionRequest: admissionv1.AdmissionRequest{
					UserInfo: authenticationv1.UserInfo{
						Username: "kube:admin",
					},
					Kind: metav1.GroupVersionKind{
						Group: "operator.openshift.io",
						Kind:  "Network",
					},
					Operation: admissionv1.Update,
					Object: runtime.RawExtension{
						Raw: []byte(`{
							"apiVersion": "operator.openshift.io/v1",
							"kind": "Network",
							"metadata": {
								"name": "cluster"
							},
							"spec": {
								"migration": {
									"networkType": "OVNKubernetes",
									"mtu": {
										"network": {
											"from": 1500,
											"to": 9000
										}
									}
								}
							}
						}`),
					},
					OldObject: runtime.RawExtension{
						Raw: []byte(`{
							"apiVersion": "operator.openshift.io/v1",
							"kind": "Network",
							"metadata": {
								"name": "cluster"
							},
							"spec": {
								"migration": {
									"networkType": "OVNKubernetes"
								}
							}
						}`),
					},
				},
			},
			ExpectAllowed: false,
		},
	}

	for _, test := range tests {
		t.Run(test.Name, func(t *testing.T) {
			w := NewWebhook()
			ret := w.Authorized(test.Request)

			if ret.Allowed != test.ExpectAllowed {
				t.Errorf("TestAuthorized() %s: request %v - allowed: %t, expected: %t, reason: %s\n",
					test.Name, test.Request, ret.Allowed, test.ExpectAllowed, ret.Result.Message)
			}
		})
	}
}

func TestGetURI(t *testing.T) {
	uri := NewWebhook().GetURI()

	if uri != "/network-operator-validation" {
		t.Errorf("TestGetURI(): expected \"/network-operator-validation\", got: %s", uri)
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
						Group: "operator.openshift.io",
						Kind:  "Network",
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
		{
			Name: "invalidate requests with wrong kind",
			Request: admissionctl.Request{
				AdmissionRequest: admissionv1.AdmissionRequest{
					UserInfo: authenticationv1.UserInfo{
						Username: "test",
					},
					Kind: metav1.GroupVersionKind{
						Group: "operator.openshift.io",
						Kind:  "IngressController",
					},
				},
			},
			ExpectValid: false,
		},
		{
			Name: "invalidate requests with wrong group",
			Request: admissionctl.Request{
				AdmissionRequest: admissionv1.AdmissionRequest{
					UserInfo: authenticationv1.UserInfo{
						Username: "test",
					},
					Kind: metav1.GroupVersionKind{
						Group: "config.openshift.io",
						Kind:  "Network",
					},
				},
			},
			ExpectValid: false,
		},
		{
			Name: "validate correct requests",
			Request: admissionctl.Request{
				AdmissionRequest: admissionv1.AdmissionRequest{
					UserInfo: authenticationv1.UserInfo{
						Username: "test",
					},
					Kind: metav1.GroupVersionKind{
						Group: "operator.openshift.io",
						Kind:  "Network",
					},
				},
			},
			ExpectValid: true,
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

	if name != "network-operator-validation" {
		t.Errorf("Name(): expected \"network-operator-validation\", got \"%s\"\n", name)
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
		t.Errorf("TestMatchPolicy(): expected Equivalent, got %s\n", policy)
	}
}

func TestRules(t *testing.T) {
	scope := admissionregv1.ClusterScope
	expectedRules := []admissionregv1.RuleWithOperations{
		{
			Operations: []admissionregv1.OperationType{"UPDATE"},
			Rule: admissionregv1.Rule{
				APIGroups:   []string{"operator.openshift.io"},
				APIVersions: []string{"*"},
				Resources:   []string{"network", "networks"},
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
		t.Error("TestDoc(): expected content, received none")
	}
}

func TestSyncSetLabelSelector(t *testing.T) {
	labelSelector := NewWebhook().SyncSetLabelSelector()

	if !reflect.DeepEqual(labelSelector, utils.DefaultLabelSelector()) {
		t.Errorf("TestSyncSetLabelSelector(): expected %v, got %v\n", utils.DefaultLabelSelector(), labelSelector)
	}
}

func TestClassicEnabled(t *testing.T) {
	enabled := NewWebhook().ClassicEnabled()

	if !enabled {
		t.Error("TestClassicEnabled(): expected disabled")
	}
}

func TestHypershiftEnabled(t *testing.T) {
	enabled := NewWebhook().HypershiftEnabled()

	if !enabled {
		t.Error("TestHypershiftEnabled(): expected disabled")
	}
}
