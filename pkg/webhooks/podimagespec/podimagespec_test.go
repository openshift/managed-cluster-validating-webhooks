package podimagespec

import (
	"context"
	"reflect"
	"testing"

	configv1 "github.com/openshift/api/imageregistry/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

type OutputImageSpecRegex struct {
	matched   bool
	namespace string
	image     string
	tag       string
}

func TestCheckContainerImageSpecByRegex(t *testing.T) {

	tests := []struct {
		name      string
		imagespec string
		expected  OutputImageSpecRegex
	}{
		{
			name:      "test uninteresting short imagespec",
			imagespec: "ubuntu",
			expected: OutputImageSpecRegex{
				matched:   false,
				namespace: "",
				image:     "",
				tag:       "",
			},
		},
		{
			name:      "test uninteresting short tagged imagespec",
			imagespec: "ubuntu:latest",
			expected: OutputImageSpecRegex{
				matched:   false,
				namespace: "",
				image:     "",
				tag:       "",
			},
		},
		{
			name:      "test uninteresting fully qualified tagged imagespec",
			imagespec: "docker.io/library/ubuntu:latest",
			expected: OutputImageSpecRegex{
				matched:   false,
				namespace: "",
				image:     "",
				tag:       "",
			},
		},
		{
			name:      "test uninteresting fully qualified SHA imagespec",
			imagespec: "quay.io/openshift-release-dev/ocp-release@sha256:4dbe2a75a516a947eab036ef6a1d086f1b1610f6bd21c6ab5f95db68ec177ea2",
			expected: OutputImageSpecRegex{
				matched:   false,
				namespace: "",
				image:     "",
				tag:       "",
			},
		},
		/// TODO: Need to add functionality to replace this with a fully qualified quay.io image.
		{
			name:      "test interesting fully qualified SHA imagespec",
			imagespec: "image-registry.openshift-image-registry.svc:5000/openshift/cli@sha256:4dbe2a75a516a947eab036ef6a1d086f1b1610f6bd21c6ab5f95db68ec177ea2",
			expected: OutputImageSpecRegex{
				matched:   false,
				namespace: "",
				image:     "",
				tag:       "",
			},
		},
		{
			name:      "test interesting fully qualified tagged imagespec",
			imagespec: "image-registry.openshift-image-registry.svc:5000/openshift/cli:latest",
			expected: OutputImageSpecRegex{
				matched:   true,
				namespace: "openshift",
				image:     "cli",
				tag:       "latest",
			},
		},
	}

	for _, test := range tests {
		actual := OutputImageSpecRegex{}
		actual.matched, actual.namespace, actual.image, actual.tag = checkContainerImageSpecByRegex(test.imagespec)
		if !reflect.DeepEqual(actual, test.expected) {
			t.Errorf("TestCheckContainerImageSpecByRegex() %s -\n imagespec: %s \n actual: %v\n expected: %v\n", test.name, test.imagespec, actual, test.expected)
		}
	}

}
func NewMock(obs ...client.Object) (client.Client, error) {
	s := runtime.NewScheme()
	if err := configv1.Install(s); err != nil {
		return nil, err
	}

	return fake.NewClientBuilder().WithScheme(s).WithObjects(obs...).Build(), nil
}

func TestCheckImageRegistryStatus(t *testing.T) {
	tests := []struct {
		name     string
		config   *configv1.Config
		expected bool
	}{
		{
			name: "test",
			config: &configv1.Config{
				ObjectMeta: metav1.ObjectMeta{
					Name: "notfound",
				},
				Spec:   configv1.ImageRegistrySpec{},
				Status: configv1.ImageRegistryStatus{},
			},
			expected: false,
		},
	}

	for _, test := range tests {
		s := NewWebhook()
		s.kubeClient, _ = NewMock(test.config)
		actual, _ := s.checkImageRegistryStatus(context.Background())
		if actual != test.expected {
			t.Error("failed")
		}
	}

}
