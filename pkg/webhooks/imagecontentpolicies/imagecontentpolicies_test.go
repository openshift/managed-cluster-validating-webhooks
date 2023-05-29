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

func Test_authorizeImageDigestMirrorSet(t *testing.T) {
	tests := []struct {
		name     string
		idms     configv1.ImageDigestMirrorSet
		expected bool
	}{
		{
			name: "quay.io",
			idms: configv1.ImageDigestMirrorSet{
				Spec: configv1.ImageDigestMirrorSetSpec{
					ImageDigestMirrors: []configv1.ImageDigestMirrors{
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
			idms: configv1.ImageDigestMirrorSet{
				Spec: configv1.ImageDigestMirrorSetSpec{
					ImageDigestMirrors: []configv1.ImageDigestMirrors{
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
			idms: configv1.ImageDigestMirrorSet{
				Spec: configv1.ImageDigestMirrorSetSpec{
					ImageDigestMirrors: []configv1.ImageDigestMirrors{
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
			idms: configv1.ImageDigestMirrorSet{
				Spec: configv1.ImageDigestMirrorSetSpec{
					ImageDigestMirrors: []configv1.ImageDigestMirrors{
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
			if actual := authorizeImageDigestMirrorSet(test.idms); actual != test.expected {
				t.Errorf("expected %v, got %v", test.expected, actual)
			}
		})
	}
}

func Test_authorizeImageTagMirrorSet(t *testing.T) {
	tests := []struct {
		name     string
		itms     configv1.ImageTagMirrorSet
		expected bool
	}{
		{
			name: "quay.io",
			itms: configv1.ImageTagMirrorSet{
				Spec: configv1.ImageTagMirrorSetSpec{
					ImageTagMirrors: []configv1.ImageTagMirrors{
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
			itms: configv1.ImageTagMirrorSet{
				Spec: configv1.ImageTagMirrorSetSpec{
					ImageTagMirrors: []configv1.ImageTagMirrors{
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
			itms: configv1.ImageTagMirrorSet{
				Spec: configv1.ImageTagMirrorSetSpec{
					ImageTagMirrors: []configv1.ImageTagMirrors{
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
			itms: configv1.ImageTagMirrorSet{
				Spec: configv1.ImageTagMirrorSetSpec{
					ImageTagMirrors: []configv1.ImageTagMirrors{
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
			if actual := authorizeImageTagMirrorSet(test.itms); actual != test.expected {
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
	rawImageDigestMirrorSet string = `{
	"apiVersion": "config.openshift.io/v1",
	"kind": "ImageDigestMirrorSet",
	"metadata": {
		"name": "test"
	},
	"spec": {
		"imageDigestMirrors": [
			{
				"source": "%s"
			}
		]
	}
}`
	rawImageTagMirrorSet string = `{
	"apiVersion": "config.openshift.io/v1",
	"kind": "ImageTagMirrorSet",
	"metadata": {
		"name": "test"
	},
	"spec": {
		"imageTagMirrors": [
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
	idmsgvk := metav1.GroupVersionKind{
		Group:   configv1.GroupName,
		Version: configv1.GroupVersion.Version,
		Kind:    "ImageDigestMirrorSet",
	}
	idmsgvr := metav1.GroupVersionResource{
		Group:    configv1.GroupName,
		Version:  configv1.GroupVersion.Version,
		Resource: "imagedigestmirrorsets",
	}
	itmsgvk := metav1.GroupVersionKind{
		Group:   configv1.GroupName,
		Version: configv1.GroupVersion.Version,
		Kind:    "ImageTagMirrorSet",
	}
	itmsgvr := metav1.GroupVersionResource{
		Group:    configv1.GroupName,
		Version:  configv1.GroupVersion.Version,
		Resource: "imagetagmirrorset",
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
			name: "allowed-creation-idms",
			op:   admissionv1.Create,
			obj: &runtime.RawExtension{
				Raw: []byte(fmt.Sprintf(rawImageDigestMirrorSet, "example.com")),
			},
			gvk:     idmsgvk,
			gvr:     idmsgvr,
			allowed: true,
		},
		{
			name: "authorized-update-idms",
			op:   admissionv1.Create,
			oldObj: &runtime.RawExtension{
				Raw: []byte(fmt.Sprintf(rawImageDigestMirrorSet, "registry.access.redhat.com")),
			},
			obj: &runtime.RawExtension{
				Raw: []byte(fmt.Sprintf(rawImageDigestMirrorSet, "example.com")),
			},
			gvk:     idmsgvk,
			gvr:     idmsgvr,
			allowed: true,
		},
		{
			name: "unauthorized-creation-idms",
			op:   admissionv1.Create,
			obj: &runtime.RawExtension{
				Raw: []byte(fmt.Sprintf(rawImageDigestMirrorSet, "quay.io")),
			},
			gvk:     idmsgvk,
			gvr:     idmsgvr,
			allowed: false,
		},
		{
			name: "unauthorized-update-idms",
			op:   admissionv1.Create,
			oldObj: &runtime.RawExtension{
				Raw: []byte(fmt.Sprintf(rawImageDigestMirrorSet, "example.com")),
			},
			obj: &runtime.RawExtension{
				Raw: []byte(fmt.Sprintf(rawImageDigestMirrorSet, "registry.redhat.io")),
			},
			gvk:     idmsgvk,
			gvr:     idmsgvr,
			allowed: false,
		},
		{
			name: "allowed-creation-itms",
			op:   admissionv1.Create,
			obj: &runtime.RawExtension{
				Raw: []byte(fmt.Sprintf(rawImageTagMirrorSet, "example.com")),
			},
			gvk:     itmsgvk,
			gvr:     itmsgvr,
			allowed: true,
		},
		{
			name: "authorized-update-itms",
			op:   admissionv1.Create,
			oldObj: &runtime.RawExtension{
				Raw: []byte(fmt.Sprintf(rawImageTagMirrorSet, "registry.access.redhat.com")),
			},
			obj: &runtime.RawExtension{
				Raw: []byte(fmt.Sprintf(rawImageTagMirrorSet, "example.com")),
			},
			gvk:     itmsgvk,
			gvr:     itmsgvr,
			allowed: true,
		},
		{
			name: "unauthorized-creation-itms",
			op:   admissionv1.Create,
			obj: &runtime.RawExtension{
				Raw: []byte(fmt.Sprintf(rawImageTagMirrorSet, "quay.io")),
			},
			gvk:     itmsgvk,
			gvr:     itmsgvr,
			allowed: false,
		},
		{
			name: "unauthorized-update-itms",
			op:   admissionv1.Create,
			oldObj: &runtime.RawExtension{
				Raw: []byte(fmt.Sprintf(rawImageTagMirrorSet, "example.com")),
			},
			obj: &runtime.RawExtension{
				Raw: []byte(fmt.Sprintf(rawImageTagMirrorSet, "registry.redhat.io")),
			},
			gvk:     itmsgvk,
			gvr:     itmsgvr,
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
			name: "denied idms create",
			request: admission.Request{
				AdmissionRequest: admissionv1.AdmissionRequest{
					UID: "uid123",
					Kind: metav1.GroupVersionKind{
						Group:   configv1.GroupName,
						Version: configv1.GroupVersion.Version,
						Kind:    "ImageDigestMirrorSet",
					},
					RequestKind: &metav1.GroupVersionKind{
						Group:   configv1.GroupName,
						Version: configv1.GroupVersion.Version,
						Kind:    "ImageDigestMirrorSet",
					},
					Name:      "test",
					Operation: admissionv1.Create,
					Object: runtime.RawExtension{
						Raw: []byte(`{
						"apiVersion": "config.openshift.io/v1",
						"kind": "ImageDigestMirrorSet",
						"metadata": {
							"name": "test"
						},
						"spec": {
							"imageDigestMirrors": [
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
			name: "allowed idms create",
			request: admission.Request{
				AdmissionRequest: admissionv1.AdmissionRequest{
					UID: "uid123",
					Kind: metav1.GroupVersionKind{
						Group:   configv1.GroupName,
						Version: configv1.GroupVersion.Version,
						Kind:    "ImageDigestMirrorSet",
					},
					RequestKind: &metav1.GroupVersionKind{
						Group:   configv1.GroupName,
						Version: configv1.GroupVersion.Version,
						Kind:    "ImageDigestMirrorSet",
					},
					Name:      "test",
					Operation: admissionv1.Create,
					Object: runtime.RawExtension{
						Raw: []byte(`{
						"apiVersion": "config.openshift.io/v1",
						"kind": "ImageDigestMirrorSet",
						"metadata": {
							"name": "test"
						},
						"spec": {
							"imageDigestMirrors": [
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
			name: "denied itms create",
			request: admission.Request{
				AdmissionRequest: admissionv1.AdmissionRequest{
					UID: "uid123",
					Kind: metav1.GroupVersionKind{
						Group:   configv1.GroupName,
						Version: configv1.GroupVersion.Version,
						Kind:    "ImageTagMirrorSet",
					},
					RequestKind: &metav1.GroupVersionKind{
						Group:   configv1.GroupName,
						Version: configv1.GroupVersion.Version,
						Kind:    "ImageTagMirrorSet",
					},
					Name:      "test",
					Operation: admissionv1.Create,
					Object: runtime.RawExtension{
						Raw: []byte(`{
						"apiVersion": "config.openshift.io/v1",
						"kind": "ImageTagMirrorSet",
						"metadata": {
							"name": "test"
						},
						"spec": {
							"imageTagMirrors": [
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
			name: "allowed itms create",
			request: admission.Request{
				AdmissionRequest: admissionv1.AdmissionRequest{
					UID: "uid123",
					Kind: metav1.GroupVersionKind{
						Group:   configv1.GroupName,
						Version: configv1.GroupVersion.Version,
						Kind:    "ImageTagMirrorSet",
					},
					RequestKind: &metav1.GroupVersionKind{
						Group:   configv1.GroupName,
						Version: configv1.GroupVersion.Version,
						Kind:    "ImageTagMirrorSet",
					},
					Name:      "test",
					Operation: admissionv1.Create,
					Object: runtime.RawExtension{
						Raw: []byte(`{
						"apiVersion": "config.openshift.io/v1",
						"kind": "ImageTagMirrorSet",
						"metadata": {
							"name": "test"
						},
						"spec": {
							"imageTagMirrors": [
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
			name: "denied icsp create",
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
					Operation: admissionv1.Create,
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
				},
			},
			expectedAllowed: false,
		},
		{
			name: "allowed icsp create",
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
					Operation: admissionv1.Create,
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
