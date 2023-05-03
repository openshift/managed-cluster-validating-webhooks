package imagecontentpolicies

import (
	"fmt"
	"net/http"
	"testing"

	configv1 "github.com/openshift/api/config/v1"
	operatorv1alpha1 "github.com/openshift/api/operator/v1alpha1"
	"github.com/openshift/managed-cluster-validating-webhooks/pkg/testutils"
	admissionv1 "k8s.io/api/admission/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"
)

func Test_authorizeImageContentPolicy(t *testing.T) {
	tests := []struct {
		name     string
		icp      configv1.ImageContentPolicy
		expected bool
	}{
		{
			name: "quay.io",
			icp: configv1.ImageContentPolicy{
				Spec: configv1.ImageContentPolicySpec{
					RepositoryDigestMirrors: []configv1.RepositoryDigestMirrors{
						{
							Source: "quay.io",
						},
						{
							Source: "quay.io/something",
						},
					},
				},
			},
			expected: false,
		},
		{
			name: "registry.redhat.io",
			icp: configv1.ImageContentPolicy{
				Spec: configv1.ImageContentPolicySpec{
					RepositoryDigestMirrors: []configv1.RepositoryDigestMirrors{
						{
							Source: "registry.redhat.io",
						},
					},
				},
			},
			expected: false,
		},
		{
			name: "registry.access.redhat.com",
			icp: configv1.ImageContentPolicy{
				Spec: configv1.ImageContentPolicySpec{
					RepositoryDigestMirrors: []configv1.RepositoryDigestMirrors{
						{
							Source: "registry.access.redhat.com",
						},
						{
							Source: "registry.access.redhat.com/something",
						},
					},
				},
			},
			expected: false,
		},
		{
			name: "example.com",
			icp: configv1.ImageContentPolicy{
				Spec: configv1.ImageContentPolicySpec{
					RepositoryDigestMirrors: []configv1.RepositoryDigestMirrors{
						{
							Source: "registry.redhat.io/something",
						},
						{
							Source: "example.com",
						},
					},
				},
			},
			expected: true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if actual := authorizeImageContentPolicy(test.icp); actual != test.expected {
				t.Errorf("expected %v, got %v", test.expected, actual)
			}
		})
	}
}

func Test_authorizeImageContentSourcePolicy(t *testing.T) {
	tests := []struct {
		name     string
		icsp     operatorv1alpha1.ImageContentSourcePolicy
		expected bool
	}{
		{
			name: "quay.io",
			icsp: operatorv1alpha1.ImageContentSourcePolicy{
				Spec: operatorv1alpha1.ImageContentSourcePolicySpec{
					RepositoryDigestMirrors: []operatorv1alpha1.RepositoryDigestMirrors{
						{
							Source: "quay.io",
						},
						{
							Source: "quay.io/something",
						},
					},
				},
			},
			expected: false,
		},
		{
			name: "registry.redhat.io",
			icsp: operatorv1alpha1.ImageContentSourcePolicy{
				Spec: operatorv1alpha1.ImageContentSourcePolicySpec{
					RepositoryDigestMirrors: []operatorv1alpha1.RepositoryDigestMirrors{
						{
							Source: "registry.redhat.io/something",
						},
						{
							Source: "registry.redhat.io",
						},
					},
				},
			},
			expected: false,
		},
		{
			name: "registry.access.redhat.com",
			icsp: operatorv1alpha1.ImageContentSourcePolicy{
				Spec: operatorv1alpha1.ImageContentSourcePolicySpec{
					RepositoryDigestMirrors: []operatorv1alpha1.RepositoryDigestMirrors{
						{
							Source: "registry.access.redhat.com",
						},
						{
							Source: "registry.access.redhat.com/something",
						},
					},
				},
			},
			expected: false,
		},
		{
			name: "example.com",
			icsp: operatorv1alpha1.ImageContentSourcePolicy{
				Spec: operatorv1alpha1.ImageContentSourcePolicySpec{
					RepositoryDigestMirrors: []operatorv1alpha1.RepositoryDigestMirrors{
						{
							Source: "example.com",
						},
					},
				},
			},
			expected: true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if actual := authorizeImageContentSourcePolicy(test.icsp); actual != test.expected {
				t.Errorf("expected %v, got %v", test.expected, actual)
			}
		})
	}
}

const (
	rawImageContentPolicy string = `{
	"apiVersion": "config.openshift.io/v1",
	"kind": "ImageContentPolicy",
	"metadata": {
        "name": "test"
	},
	"spec": {
		"repositoryDigestMirrors": [
			{
				"source": "%s"
			}
		]
	}
}`
	rawImageContentSourcePolicy string = `{
	"apiVersion": "operator.openshift.io/v1alpha1",
	"kind": "ImageContentSourcePolicy",
	"metadata": {
        "name": "test"
	},
	"spec": {
		"repositoryDigestMirrors": [
			{
				"source": "%s"
			}
		]
	}
}`
)

func TestImageContentPolicy(t *testing.T) {
	icpgvk := metav1.GroupVersionKind{
		Group:   configv1.GroupName,
		Version: configv1.GroupVersion.Version,
		Kind:    "ImageContentPolicy",
	}
	icpgvr := metav1.GroupVersionResource{
		Group:    configv1.GroupName,
		Version:  configv1.GroupVersion.Version,
		Resource: "imagecontentpolicies",
	}
	icspgvk := metav1.GroupVersionKind{
		Group:   operatorv1alpha1.GroupName,
		Version: operatorv1alpha1.GroupVersion.Version,
		Kind:    "ImageContentSourcePolicy",
	}
	icspgvr := metav1.GroupVersionResource{
		Group:    operatorv1alpha1.GroupName,
		Version:  operatorv1alpha1.GroupVersion.Version,
		Resource: "imagecontentsourcepolicies",
	}
	tests := []struct {
		name    string
		op      admissionv1.Operation
		gvk     metav1.GroupVersionKind
		gvr     metav1.GroupVersionResource
		obj     *runtime.RawExtension
		oldObj  *runtime.RawExtension
		allowed bool
	}{
		{
			name: "allowed-creation-icp",
			op:   admissionv1.Create,
			obj: &runtime.RawExtension{
				Raw: []byte(fmt.Sprintf(rawImageContentPolicy, "example.com")),
			},
			gvk:     icpgvk,
			gvr:     icpgvr,
			allowed: true,
		},
		{
			name: "authorized-update-icp",
			op:   admissionv1.Create,
			oldObj: &runtime.RawExtension{
				Raw: []byte(fmt.Sprintf(rawImageContentPolicy, "registry.access.redhat.com")),
			},
			obj: &runtime.RawExtension{
				Raw: []byte(fmt.Sprintf(rawImageContentPolicy, "example.com")),
			},
			gvk:     icpgvk,
			gvr:     icpgvr,
			allowed: true,
		},
		{
			name: "unauthorized-creation-icp",
			op:   admissionv1.Create,
			obj: &runtime.RawExtension{
				Raw: []byte(fmt.Sprintf(rawImageContentPolicy, "quay.io")),
			},
			gvk:     icpgvk,
			gvr:     icpgvr,
			allowed: false,
		},
		{
			name: "unauthorized-update-icp",
			op:   admissionv1.Create,
			oldObj: &runtime.RawExtension{
				Raw: []byte(fmt.Sprintf(rawImageContentPolicy, "example.com")),
			},
			obj: &runtime.RawExtension{
				Raw: []byte(fmt.Sprintf(rawImageContentPolicy, "registry.redhat.io")),
			},
			gvk:     icpgvk,
			gvr:     icpgvr,
			allowed: false,
		},
		{
			name: "allowed-creation-icsp",
			op:   admissionv1.Create,
			obj: &runtime.RawExtension{
				Raw: []byte(fmt.Sprintf(rawImageContentSourcePolicy, "example.com")),
			},
			gvk:     icspgvk,
			gvr:     icspgvr,
			allowed: true,
		},
		{
			name: "authorized-update-icp",
			op:   admissionv1.Create,
			oldObj: &runtime.RawExtension{
				Raw: []byte(fmt.Sprintf(rawImageContentSourcePolicy, "registry.access.redhat.com")),
			},
			obj: &runtime.RawExtension{
				Raw: []byte(fmt.Sprintf(rawImageContentSourcePolicy, "example.com")),
			},
			gvk:     icspgvk,
			gvr:     icspgvr,
			allowed: true,
		},
		{
			name: "unauthorized-creation-icp",
			op:   admissionv1.Create,
			obj: &runtime.RawExtension{
				Raw: []byte(fmt.Sprintf(rawImageContentSourcePolicy, "quay.io")),
			},
			gvk:     icspgvk,
			gvr:     icspgvr,
			allowed: false,
		},
		{
			name: "unauthorized-update-icp",
			op:   admissionv1.Create,
			oldObj: &runtime.RawExtension{
				Raw: []byte(fmt.Sprintf(rawImageContentSourcePolicy, "example.com")),
			},
			obj: &runtime.RawExtension{
				Raw: []byte(fmt.Sprintf(rawImageContentSourcePolicy, "registry.redhat.io")),
			},
			gvk:     icspgvk,
			gvr:     icspgvr,
			allowed: false,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			hook := NewWebhook()
			req, err := testutils.CreateHTTPRequest(hook.GetURI(), test.name, test.gvk, test.gvr, test.op, "", []string{}, test.obj, test.oldObj)
			if err != nil {
				t.Errorf("failed to create test HTTP request: %v", err)
			}

			resp, err := testutils.SendHTTPRequest(req, hook)
			if err != nil {
				t.Errorf("failed to send test HTTP request: %v", err)
			}

			if resp.Allowed != test.allowed {
				t.Errorf("expected allowed: %v, got allowed: %v", test.allowed, resp.Allowed)
			}

			if resp.UID == "" {
				t.Errorf("all allow/deny responses require a UID")
			}

			if test.allowed {
				if resp.Result.Code != int32(http.StatusOK) {
					t.Errorf("expected allowed request with code: %d, got %d", http.StatusOK, resp.Result.Code)
				}
			} else {
				if resp.Result.Code != int32(http.StatusForbidden) {
					t.Errorf("expected allowed request with code: %d, got %d", http.StatusForbidden, resp.Result.Code)
				}
			}
		})
	}
}

func TestAuthorized(t *testing.T) {
	tests := []struct {
		name            string
		request         admission.Request
		expectedAllowed bool
	}{
		{
			name: "denied icp create",
			request: admission.Request{
				AdmissionRequest: admissionv1.AdmissionRequest{
					UID: "uid123",
					Kind: metav1.GroupVersionKind{
						Group:   configv1.GroupName,
						Version: configv1.GroupVersion.Version,
						Kind:    "ImageContentPolicy",
					},
					RequestKind: &metav1.GroupVersionKind{
						Group:   configv1.GroupName,
						Version: configv1.GroupVersion.Version,
						Kind:    "ImageContentPolicy",
					},
					Name:      "test",
					Operation: admissionv1.Create,
					Object: runtime.RawExtension{
						Raw: []byte(`{
				    	"apiVersion": "config.openshift.io/v1",
				    	"kind": "ImageContentPolicy",
				    	"metadata": {
					        "name": "test"
					    },
					    "spec": {
					        "repositoryDigestMirrors": [
				        	    {
				    	            "source": "registry.redhat.io"
					            }
					        ]
					    }
					}`),
					},
				},
			},
			expectedAllowed: false,
		},
		{
			name: "allowed icp create",
			request: admission.Request{
				AdmissionRequest: admissionv1.AdmissionRequest{
					UID: "uid123",
					Kind: metav1.GroupVersionKind{
						Group:   configv1.GroupName,
						Version: configv1.GroupVersion.Version,
						Kind:    "ImageContentPolicy",
					},
					RequestKind: &metav1.GroupVersionKind{
						Group:   configv1.GroupName,
						Version: configv1.GroupVersion.Version,
						Kind:    "ImageContentPolicy",
					},
					Name:      "test",
					Operation: admissionv1.Create,
					Object: runtime.RawExtension{
						Raw: []byte(`{
				    	"apiVersion": "config.openshift.io/v1",
				    	"kind": "ImageContentPolicy",
				    	"metadata": {
					        "name": "test"
					    },
					    "spec": {
					        "repositoryDigestMirrors": [
				        	    {
				    	            "source": "example.com"
					            }
					        ]
					    }
					}`),
					},
				},
			},
			expectedAllowed: true,
		},
		{
			name: "denied icsp update",
			request: admission.Request{
				AdmissionRequest: admissionv1.AdmissionRequest{
					UID: "uid123",
					Kind: metav1.GroupVersionKind{
						Group:   operatorv1alpha1.GroupName,
						Version: operatorv1alpha1.GroupVersion.Version,
						Kind:    "ImageContentSourcePolicy",
					},
					RequestKind: &metav1.GroupVersionKind{
						Group:   operatorv1alpha1.GroupName,
						Version: operatorv1alpha1.GroupVersion.Version,
						Kind:    "ImageContentSourcePolicy",
					},
					Name:      "test",
					Operation: admissionv1.Update,
					Object: runtime.RawExtension{
						Raw: []byte(`{
				    	"apiVersion": "operator.openshift.io/v1alpha1",
				    	"kind": "ImageContentSourcePolicy",
				    	"metadata": {
					        "name": "test"
					    },
					    "spec": {
					        "repositoryDigestMirrors": [
				        	    {
				    	            "source": "registry.access.redhat.com"
					            }
					        ]
					    }
					}`),
					},
					OldObject: runtime.RawExtension{
						Raw: []byte(`{
				    	"apiVersion": "operator.openshift.io/v1alpha1",
				    	"kind": "ImageContentSourcePolicy",
				    	"metadata": {
					        "name": "test"
					    },
					    "spec": {
					        "repositoryDigestMirrors": [
				        	    {
				    	            "source": "example.com"
					            }
					        ]
					    }
					}`),
					},
				},
			},
			expectedAllowed: false,
		},
		{
			name: "invalid",
			request: admission.Request{
				AdmissionRequest: admissionv1.AdmissionRequest{
					Name:      "test",
					Operation: admissionv1.Update,
					Object:    runtime.RawExtension{},
				},
			},
			expectedAllowed: false,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			w := NewWebhook()
			actual := admission.Response{
				AdmissionResponse: admissionv1.AdmissionResponse{Allowed: false},
			}

			if w.Validate(test.request) {
				actual = w.Authorized(test.request)
			}
			if actual.Allowed != test.expectedAllowed {
				t.Errorf("expected: %v, got %v", test.expectedAllowed, actual.Allowed)
			}
		})
	}
}
